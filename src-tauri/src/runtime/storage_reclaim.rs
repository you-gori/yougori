use super::RuntimeManager;
use crate::models::{RuntimeProviderKind, StorageCleanupResult};
use serde::Deserialize;
use std::time::Duration;

/// True when the file holds more than its data clusters plus the most metadata
/// a compacted copy could need (header, full L1/L2, refcounts, rounding). Any
/// excess is trimmed space an offline rewrite would return to the host.
fn qcow2_has_free_clusters(info: &serde_json::Value, check: &serde_json::Value) -> Option<bool> {
    let physical = info["actual-size"].as_u64()?;
    let virtual_size = info["virtual-size"].as_u64()?;
    let cluster = info["cluster-size"].as_u64()?;
    let data = check["allocated-clusters"].as_u64()?;
    let format = &info["format-specific"]["data"];
    // Internal snapshots and bitmaps own clusters this bound does not model.
    if info["snapshots"].as_array().is_some_and(|s| !s.is_empty()) || format["bitmaps"].as_array().is_some_and(|b| !b.is_empty()) { return Some(true); }
    let entry = if format["extended-l2"].as_bool() == Some(true) { 16 } else { 8 };
    let refcount_bits = format["refcount-bits"].as_u64().unwrap_or(16).max(1);
    let clusters = |bytes: u64| bytes.div_ceil(cluster);
    let l2 = clusters(virtual_size).div_ceil(cluster / entry);
    let l1 = clusters(l2 * 8);
    let file_clusters = clusters(physical);
    let refcount_blocks = file_clusters.div_ceil(cluster * 8 / refcount_bits);
    let refcount_table = clusters(refcount_blocks * 8);
    let metadata = 1 + l1 + l2 + refcount_blocks + refcount_table + 1;
    Some(file_clusters > data + metadata)
}

#[derive(Deserialize)]
struct TrimResult {
    busy: bool,
    warnings: Vec<String>,
}

// Generated in the verified appliance directory, never from user input.
// Drop also attempts cleanup when a caller cancels maintenance.
struct CompactScratch(std::path::PathBuf);
impl Drop for CompactScratch {
    fn drop(&mut self) { let _ = std::fs::remove_file(&self.0); }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::*;
    use std::path::Path;

    #[test]
    fn compaction_runs_only_when_trimmed_clusters_exist() {
        let info = |snapshots: serde_json::Value| serde_json::json!({ "actual-size": 8_094_154_752_u64, "virtual-size": 82_678_120_448_u64, "cluster-size": 65536, "snapshots": snapshots, "format-specific": { "data": { "refcount-bits": 16, "extended-l2": false } } });
        let check = |allocated: u64| serde_json::json!({ "allocated-clusters": allocated });
        // Measured on a live appliance disk: data plus metadata fills the file.
        assert_eq!(qcow2_has_free_clusters(&info(serde_json::json!([])), &check(123_434)), Some(false));
        // One trimmed cluster beyond the metadata bound is still returned.
        assert_eq!(qcow2_has_free_clusters(&info(serde_json::json!([])), &check(123_344)), Some(true));
        assert_eq!(qcow2_has_free_clusters(&info(serde_json::json!([{ "id": "1" }])), &check(123_434)), Some(true));
        assert_eq!(qcow2_has_free_clusters(&serde_json::json!({}), &check(1)), None);
    }

    #[tokio::test]
    #[ignore = "boots disposable containers and measures actual host allocation"]
    async fn deletion_reclaims_disk_blocks_and_preserves_peer() -> Result<(), String> {
        macro_rules! check { ($condition:expr) => { if !$condition { return Err(format!("Reclamation check failed: {}", stringify!($condition))); } }; }
        let data = tempfile::tempdir().unwrap();
        let runtime = RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")), data.path())?;
        let policy = ResourcePolicy {
            cpu: ResourceRange { min: 1.0, preferred: 1.0, max: 1.0, current: 0.0 },
            memory_gb: ResourceRange { min: 0.5, preferred: 0.5, max: 0.5, current: 0.0 },
            priority: Priority::Normal, dynamic: true,
        };
        let result = async {
            for id in ["reclaim-delete", "reclaim-keep"] {
                let command = if id == "reclaim-keep" {
                    "while [ ! -f /root/exit-request ]; do sleep 1; done; rm /root/exit-request"
                } else { "sleep 2147483647" };
                runtime.provision_container(id, "quay.io/libpod/alpine:latest", command, &policy, false, false).await?;
                runtime.container_action(id, "start", false).await?;
            }
            let marker = runtime.execute_container_command("reclaim-keep", "echo peer-safe > /root/marker; sync").await?;
            check!(marker.exit_code == 0);
            let output = runtime.execute_container_command("reclaim-delete", "dd if=/dev/urandom of=/root/reclaim-test bs=1048576 count=256; sync").await?;
            check!(output.exit_code == 0);
            runtime.delete_container("reclaim-delete").await?;
            let result = runtime.reclaim_container_storage(&RuntimeProviderKind::YougoriOci).await?;
            eprintln!("Reclaim result: {}", serde_json::to_string(&result).unwrap());
            #[cfg(windows)] check!(result.warnings.iter().any(|w| w.contains("running or paused")));
            let output = runtime.execute_container_command("reclaim-keep", "cat /root/marker").await?;
            check!(output.stdout.trim() == "peer-safe");
            // A workload can exit without a dashboard Stop action clearing
            // the conservative active-container cache.
            check!(runtime.execute_container_command("reclaim-keep", "touch /root/exit-request").await?.exit_code == 0);
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            while runtime.container_failure_detail("reclaim-keep").await?.is_none() {
                if tokio::time::Instant::now() >= deadline { return Err("Test container did not exit".into()); }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            let compacted = runtime.reclaim_container_storage(&RuntimeProviderKind::YougoriOci).await?;
            eprintln!("Idle compaction: {}", serde_json::to_string(&compacted).unwrap());
            check!(compacted.warnings.is_empty());
            #[cfg(windows)] check!(runtime.appliance.lock().await.is_none());
            check!(result.reclaimed_disk_bytes + compacted.reclaimed_disk_bytes > 128 * 1024 * 1024);
            runtime.container_action("reclaim-keep", "start", false).await?;
            check!(runtime.execute_container_command("reclaim-keep", "cat /root/marker").await?.stdout.trim() == "peer-safe");
            runtime.container_action("reclaim-keep", "stop", false).await?;
            let again = runtime.reclaim_container_storage(&RuntimeProviderKind::YougoriOci).await?;
            check!(again.warnings.is_empty());
            Ok(())
        }.await;
        runtime.shutdown_all().await;
        result
    }
}

impl RuntimeManager {
    pub async fn reclaim_pending_container_storage(&self, id: &str, provider: &RuntimeProviderKind) -> Result<(), String> {
        if *provider == RuntimeProviderKind::YougoriCuda {
            let mut pending = self.reclaim_marker(provider).try_exists().map_err(|e| e.to_string())?;
            for engine in self.registered_storage_runtimes() {
                pending |= engine?.reclaim_marker(provider).try_exists().map_err(|e| e.to_string())?;
            }
            if pending {
                for warning in self.reclaim_container_storage(provider).await?.warnings { eprintln!("Pending storage cleanup: {warning}"); }
            }
            return Ok(());
        }
        if let Some(engine) = self.storage_runtime(id)? {
            return Box::pin(engine.reclaim_pending_container_storage(id, provider)).await;
        }
        if provider.is_container() && self.reclaim_marker(provider).try_exists().map_err(|e| e.to_string())? {
            let result = self.reclaim_container_storage_here(provider).await?;
            for warning in result.warnings { eprintln!("Pending storage cleanup: {warning}"); }
        }
        Ok(())
    }

    fn reclaim_marker(&self, provider: &RuntimeProviderKind) -> std::path::PathBuf {
        self.data_root.join(if *provider == RuntimeProviderKind::YougoriCuda { "cuda-reclaim-pending" } else { "oci-reclaim-pending" })
    }

    /// No filesystem formatting or stopping peers. The
    /// writer lease excludes provision/start/snapshot/exec operations while an
    /// idle CUDA disk is detached and compacted. FITRIM itself is live-safe.
    pub async fn reclaim_container_storage(&self, provider: &RuntimeProviderKind) -> Result<StorageCleanupResult, String> {
        if *provider == RuntimeProviderKind::YougoriCuda {
            // WSL may keep a detached disk open while another distribution
            // runs. Reclaim independent GPU pools together so every idle pool
            // shuts down before the native compaction handle retry expires.
            let engines = self.registered_storage_runtimes();
            let children = futures_util::future::join_all(engines.iter().map(|engine| async move {
                match engine { Ok(engine) => engine.reclaim_container_storage_here(provider).await, Err(error) => Err(error.clone()) }
            }));
            let (local, children) = tokio::join!(self.reclaim_container_storage_here(provider), children);
            let mut total = StorageCleanupResult::default();
            for result in std::iter::once(local).chain(children) {
                match result {
                    Ok(result) => {
                        total.reclaimed_disk_bytes = total.reclaimed_disk_bytes.saturating_add(result.reclaimed_disk_bytes);
                        total.notes.extend(result.notes);
                        total.warnings.extend(result.warnings);
                    }
                    Err(error) => total.warnings.push(error),
                }
            }
            return Ok(total);
        }
        let mut total = self.reclaim_container_storage_here(provider).await?;
        for engine in self.registered_storage_runtimes() {
            let result = match engine { Ok(engine) => engine.reclaim_container_storage_here(provider).await, Err(error) => Err(error) };
            match result {
                Ok(result) => {
                    total.reclaimed_cache_bytes = total.reclaimed_cache_bytes.saturating_add(result.reclaimed_cache_bytes);
                    total.reclaimed_disk_bytes = total.reclaimed_disk_bytes.saturating_add(result.reclaimed_disk_bytes);
                    total.notes.extend(result.notes);
                    total.warnings.extend(result.warnings);
                }
                Err(error) => total.warnings.push(error),
            }
        }
        Ok(total)
    }

    async fn reclaim_container_storage_here(&self, provider: &RuntimeProviderKind) -> Result<StorageCleanupResult, String> {
        if !provider.is_container() { return Err("Only managed container pools support shared-disk reclamation.".into()); }
        let _lease = self.appliance_operations.write().await;
        let cuda = *provider == RuntimeProviderKind::YougoriCuda;
        let path = if cuda { self.cuda.storage_path() } else { self.data_root.join("appliance/system.qcow2") };
        if !path.exists() { return Ok(StorageCleanupResult::default()); }
        // Survives app restarts. Normal stops retry deferred compaction;
        // GPU pools coordinate after their final workload stops across drives.
        let marker = self.reclaim_marker(provider);
        std::fs::write(&marker, b"pending").map_err(|e| format!("Record pending storage cleanup: {e}"))?;
        let before = if cuda { self.cuda.storage_sizes()?.1 } else { (self.inspect_storage(&path, true).await?.physical_gb * 1_073_741_824.0) as u64 };
        if cuda && self.cuda.current_endpoint().await.is_err() {
            let status = self.cuda_status().await;
            if status.update_available || !status.supported {
                // Host-side VHDX compaction does not depend on the guest agent
                // version or GPU prerequisites. Never boot or terminate a WSL
                // distribution just to work around a failed CUDA update.
                self.cuda.compact_stopped_storage().await?;
                let after = self.cuda.storage_sizes()?.1;
                return Ok(StorageCleanupResult {
                    reclaimed_disk_bytes: before.saturating_sub(after),
                    notes: vec!["Compacted the stopped GPU disk without starting CUDA. Update CUDA before running GPU containers or trimming additional free blocks.".into()],
                    ..Default::default()
                });
            }
        }
        let endpoint = self.provider_endpoint(provider).await?;
        let response = self.client.post(format!("{}/v1/storage/reclaim", endpoint.base_url))
            .bearer_auth(&endpoint.token).timeout(Duration::from_secs(100)).send().await
            .map_err(|e| format!("Storage cleanup could not reach the runtime: {e}. Retry Storage → Reclaim space."))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err("This runtime needs the updated storage helper. Close Yougori normally and reopen it (update NVIDIA CUDA under New environment → GPU if requested), then choose Storage → Reclaim space. Container data was kept.".into());
        }
        let result: TrimResult = response.error_for_status().map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;
        let mut cleanup = StorageCleanupResult { warnings: result.warnings, ..Default::default() };
        if cuda || cfg!(windows) {
            if result.busy {
                cleanup.warnings.push(format!("{} containers are still running or paused. Free space is reusable inside their disk; Windows disk compaction will retry automatically when the last container is stopped. Storage → Reclaim space also retries it. No workloads were stopped.", if cuda { "GPU" } else { "Standard" }));
            } else {
                // The agent verified no running/paused containers while the
                // writer lease excludes new starts. Workloads that exit on
                // their own can leave conservative start tracking stale.
                if !cuda {
                    if let Some(process) = self.appliance.lock().await.as_mut() {
                        process.active_containers.clear();
                    }
                }
                let compact = if cuda { self.cuda.compact_idle_storage().await } else { self.compact_idle_appliance().await };
                if let Err(error) = compact { cleanup.warnings.push(error); }
            }
        }
        let after = if cuda { self.cuda.storage_sizes().map(|s| s.1) } else { self.inspect_storage(&path, true).await.map(|s| (s.physical_gb * 1_073_741_824.0) as u64) };
        match after {
            Ok(after) => cleanup.reclaimed_disk_bytes = before.saturating_sub(after),
            Err(error) => cleanup.warnings.push(format!("Cleanup ran, but reclaimed space could not be measured: {error}")),
        }
        cleanup.notes.push("Container images, snapshots, recovery disks, original installers and exported backups were kept.".into());
        if cleanup.warnings.is_empty() {
            if let Err(error) = std::fs::remove_file(marker) { cleanup.warnings.push(format!("Clear completed storage cleanup: {error}")); }
        }
        Ok(cleanup)
    }

    /// Whether a rewrite could shrink the disk at all. Measurement failures
    /// fall back to compacting, as before this check existed.
    async fn appliance_has_trimmed_clusters(&self, disk: &std::path::Path) -> bool {
        let measure = async {
            let info = super::command_output(&self.layout.qemu_img, &["info".into(), "--force-share".into(), "--output=json".into(), super::path_string(disk)], "inspect container disk").await?;
            let check = super::command_output(&self.layout.qemu_img, &["check".into(), "--force-share".into(), "--output=json".into(), super::path_string(disk)], "measure container disk").await?;
            let info: serde_json::Value = serde_json::from_slice(&info.stdout).map_err(|e| e.to_string())?;
            let check: serde_json::Value = serde_json::from_slice(&check.stdout).map_err(|e| e.to_string())?;
            qcow2_has_free_clusters(&info, &check).ok_or_else(|| "Unexpected qemu-img output".to_string())
        };
        measure.await.unwrap_or(true)
    }

    async fn compact_idle_appliance(&self) -> Result<(), String> {
        // QEMU caches qcow2 metadata in memory. Pausing the idle runtime flushes
        // it to the file, so the size check sees the blocks the guest just trimmed.
        let qmp_port = self.appliance.lock().await.as_ref().map(|process| process.qmp_port);
        let paused = match qmp_port {
            Some(port) => super::vm::qmp_execute_bounded(port, "stop", None, Duration::from_secs(15)).await,
            None => Err(String::new()),
        };
        // An unreachable control socket means nothing was paused (for example the
        // runtime just exited). Otherwise resume, even after a timed-out pause.
        if let Some(port) = qmp_port.filter(|_| !matches!(&paused, Err(error) if error.is_empty() || error.starts_with("connect to virtual machine control socket"))) {
            let mut resumed = Err(String::new());
            for _ in 0..5 {
                resumed = super::vm::qmp_execute_bounded(port, "cont", None, Duration::from_secs(5)).await;
                if resumed.is_ok() { break; }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            resumed.map_err(|error| format!("The container runtime could not resume after flushing its disk: {error}. Restart Yougori if containers stop responding."))?;
        }
        if !self.appliance_has_trimmed_clusters(&self.data_root.join("appliance/system.qcow2")).await { return Ok(()); }
        let mut guard = self.appliance.lock().await;
        if let Some(process) = guard.as_mut() {
            if !process.active_containers.is_empty() { return Err("Standard containers are still running or paused; stop them before reclaiming space.".into()); }
            if process.child.try_wait().map_err(|e| e.to_string())?.is_none() {
                self.client.post(format!("{}/v1/system/shutdown", process.endpoint.base_url))
                    .bearer_auth(&process.endpoint.token).timeout(Duration::from_secs(5)).send().await.map_err(|e| e.to_string())?
                    .error_for_status().map_err(|e| e.to_string())?;
                let status = tokio::time::timeout(Duration::from_secs(30), process.child.wait()).await
                    .map_err(|_| "The idle container runtime is still shutting down. Retry Reclaim space; it was not force-stopped.")?.map_err(|e| e.to_string())?;
                if !status.success() { return Err("Container runtime did not shut down cleanly. Its disk was kept unchanged.".into()); }
                self.record_appliance_overlay_state()?;
            }
        }
        guard.take();
        self.check_external_appliance(false).await?;
        let directory = self.data_root.join("appliance").canonicalize().map_err(|e| e.to_string())?;
        if directory.parent() != Some(self.data_root.canonicalize().map_err(|e| e.to_string())?.as_path()) {
            return Err("Container storage was redirected; compaction was refused.".into());
        }
        let disk = directory.join("system.qcow2");
        let metadata = std::fs::symlink_metadata(&disk).map_err(|e| e.to_string())?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || disk.canonicalize().map_err(|e| e.to_string())? != disk {
            return Err("Container disk is not a regular owned file.".into());
        }
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(windows)] { use std::os::windows::fs::OpenOptionsExt; options.share_mode(1 | 4); }
        // On Windows, allow readers and atomic replacement, but deny new writers.
        let _disk_guard = options.open(&disk).map_err(|e| format!("Lock idle container disk: {e}"))?;
        let allocation = self.inspect_storage(&disk, true).await?;
        let disks = sysinfo::Disks::new_with_refreshed_list();
        let available = super::storage::runtime_disk(&disks, &directory).ok_or("Cannot read free space for compaction")?.available_space();
        let required = (allocation.physical_gb * 1_073_741_824.0) as u64 + 256 * 1024 * 1024;
        if available < required { return Err(format!("Safe compaction needs {:.2} GB of temporary free space on the Yougori drive. Data was kept; free some space and retry Reclaim space.", required as f64 / 1_073_741_824.0)); }
        let temporary = directory.join(format!(".compact-{}.qcow2", uuid::Uuid::new_v4().simple()));
        let _scratch = CompactScratch(temporary.clone());
        let result = tokio::time::timeout(Duration::from_secs(600), async {
            super::command_output(&self.layout.qemu_img, &[
                "convert".into(), "-W".into(), "-f".into(), "qcow2".into(), "-O".into(), "qcow2".into(),
                "-B".into(), super::path_string(&self.appliance_overlay_base), "-F".into(), "qcow2".into(),
                super::path_string(&disk), super::path_string(&temporary),
            ], "compact idle container disk").await?;
            super::command_output(&self.layout.qemu_img, &["check".into(), "-q".into(), super::path_string(&temporary)], "verify compacted container disk").await?;
            super::command_output(&self.layout.qemu_img, &["compare".into(), "-f".into(), "qcow2".into(), "-F".into(), "qcow2".into(), super::path_string(&disk), super::path_string(&temporary)], "verify container data is unchanged").await?;
            std::fs::OpenOptions::new().read(true).write(true).open(&temporary).and_then(|f| f.sync_all()).map_err(|e| format!("Flush compacted disk: {e}"))?;
            // One atomic replacement only after content comparison. Failure
            // keeps the original; no remove-then-rename crash window.
            std::fs::rename(&temporary, &disk).map_err(|e| format!("Commit compacted disk: {e}"))?;
            self.record_appliance_overlay_state()?;
            Ok::<_, String>(())
        }).await.map_err(|_| "Container disk compaction took too long. The original disk was kept; retry Reclaim space.".to_string())?;
        result
    }
}
