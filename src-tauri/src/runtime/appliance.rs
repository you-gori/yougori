use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    path::PathBuf,
    process::Stdio,
    time::{Duration, Instant, UNIX_EPOCH},
};

use reqwest::{Response, StatusCode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio_util::io::ReaderStream;
use uuid::Uuid;

use super::{
    command_output, configure_background_process, path_string, AgentEndpoint,
    ApplianceProcess, PerfSpan, RuntimeManager,
};
use crate::models::{CommandResult, ConnectionDirection, PermissionKind, ResourcePolicy};

#[derive(Debug, Clone)]
pub struct SnapshotArtifact {
    pub provider_snapshot_id: String,
    pub path: PathBuf,
    pub size_bytes: u64,
    pub checksum_sha256: String,
}

#[derive(Debug, Clone, Default)]
pub struct ContainerStats {
    pub cpu_percent: f64,
    pub memory_bytes: u64,
    pub network_rx_mbps: f64,
}

#[derive(Debug, Clone)]
pub struct ContainerTelemetry {
    pub id: String,
    pub running: bool,
    pub paused: bool,
    pub stats: ContainerStats,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProvisionRequest<'a> {
    options: serde_json::Value,
    storage_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    original_id: Option<&'a str>,
    id: &'a str,
    image: &'a str,
    command: &'a str,
    cpus: f64,
    memory_bytes: i64,
    network_access: bool,
    gpu_access: bool,
}

#[derive(Debug, Serialize)]
struct ActionRequest<'a> {
    id: &'a str,
    action: &'a str,
    #[serde(rename = "networkAccess")]
    network_access: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConfigurationRequest<'a> {
    options: serde_json::Value,
    id: &'a str,
    network_access: bool,
    gpu_access: bool,
    previous_network_access: bool,
    previous_gpu_access: bool,
    command: &'a str,
    cpus: f64,
    #[serde(rename = "memoryBytes")]
    memory_bytes: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ResourcesRequest<'a> {
    id: &'a str,
    cpus: f64,
    memory_bytes: i64,
}

#[derive(Debug, Serialize)]
struct ExecRequest<'a> {
    id: &'a str,
    command: &'a str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SnapshotRequest<'a> {
    id: &'a str,
    snapshot_id: &'a str,
    image: &'a str,
    command: &'a str,
    network_access: bool,
    gpu_access: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConnectionRequest<'a> {
    id: &'a str,
    source_id: &'a str,
    target_id: &'a str,
    bidirectional: bool,
    ports: &'a [u16],
    allow_network: bool,
    shared_path: bool,
    allow_secrets: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AgentCommandOutput {
    stdout: String,
    stderr: String,
    exit_code: i32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AgentSnapshot {
    provider_snapshot_id: String,
    size_bytes: u64,
    checksum_sha256: String,
}

#[derive(Debug, Serialize)]
struct StatsBatchRequest<'a> {
    ids: &'a [String],
}

#[derive(Debug, Deserialize)]
struct StatsBatchResponse {
    entries: Vec<StatsBatchEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StatsBatchEntry {
    id: String,
    running: bool,
    #[serde(default)]
    paused: bool,
    cpu_percent: f64,
    memory_bytes: u64,
    network_rx_bytes: u64,
}

const APPLIANCE_OVERLAY_MARKER_VERSION: u32 = 1;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct ApplianceOverlayMarker {
    schema_version: u32,
    base_sha256: String,
    backing_path: String,
    overlay: ApplianceOverlayFingerprint,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct ApplianceOverlayFingerprint {
    length: u64,
    modified_unix_nanos: u64,
}

#[derive(Debug, Clone)]
struct ExistingApplianceMarker {
    base_sha256: String,
    backing_path: Option<String>,
    overlay: Option<ApplianceOverlayFingerprint>,
}

impl RuntimeManager {
    #[cfg(test)]
    pub async fn provision_container(
        &self,
        id: &str,
        image: &str,
        command: &str,
        policy: &ResourcePolicy,
        network_access: bool,
        gpu_access: bool,
    ) -> Result<(), String> {
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.provision_container(id, image, command, policy, network_access, gpu_access)).await; }

        self.provision_container_with_storage(id, image, command, policy, network_access, gpu_access, 20.0).await
    }

    pub async fn provision_container_with_storage(
        &self, id: &str, image: &str, command: &str, policy: &ResourcePolicy,
        network_access: bool, gpu_access: bool, storage_gb: f64,
    ) -> Result<(), String> {
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.provision_container_with_storage(id, image, command, policy, network_access, gpu_access, storage_gb)).await; }

        let storage_bytes = super::storage::storage_bytes(storage_gb)?;
        if storage_gb > self.new_vm_storage()?.maximum_gb.min(16380.0) {
            return Err("Not enough free space on the Yougori drive for this container storage limit.".into());
        }
        let request = ProvisionRequest {
            options: Box::pin(self.prepare_workload_binds(id)).await?,
            storage_bytes,
            original_id: None,
            id,
            image,
            command,
            cpus: policy.cpu.preferred,
            memory_bytes: gibibytes(policy.memory_gb.preferred)?,
            network_access,
            gpu_access,
        };
        let _: serde_json::Value = Box::pin(self.agent_post("/v1/containers/provision", &request)).await?;
        Ok(())
    }

    pub async fn provision_reset_container(&self, id: &str, old_id: &str, environment: &crate::models::Environment) -> Result<(), String> {
        self.inherit_storage(id, old_id)?;
        if let Some(engine) = self.storage_runtime(old_id)? { return Box::pin(engine.provision_reset_container(id, old_id, environment)).await; }

        self.register_container_provider(id, &self.container_provider(old_id)?)?;
        self.save_workload_options(id, &self.workload_options(old_id)?)?;
        let request = ProvisionRequest {
            options: Box::pin(self.prepare_workload_binds(id)).await?,
            storage_bytes: super::storage::storage_bytes(environment.storage_limit_gb.unwrap_or(20.0))?,
            original_id: Some(old_id), id, image: &environment.runtime,
            command: environment.container_command.as_deref().unwrap_or_default(),
            cpus: environment.resource_policy.cpu.preferred,
            memory_bytes: gibibytes(environment.resource_policy.memory_gb.preferred)?,
            network_access: environment.network_access, gpu_access: environment.gpu_access,
        };
        let _: serde_json::Value = self.agent_post("/v1/containers/provision", &request).await?;
        Ok(())
    }

    pub async fn container_action(
        &self,
        id: &str,
        action: &str,
        network_access: bool,
    ) -> Result<(), String> {
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.container_action(id, action, network_access)).await; }

        if matches!(action, "start" | "resume") { Box::pin(self.prepare_workload_binds(id)).await?; }
        let _lease = self.appliance_operations.read().await;
        // Mark starts conservatively before sending: a timed-out request may
        // have started a process, so resizing must wait for an explicit stop.
        if matches!(action, "start" | "resume") {
            self.container_endpoint(id).await?;
            if let Some(process) = self.appliance.lock().await.as_mut().filter(|_| self.container_provider(id).is_ok_and(|p| p == crate::models::RuntimeProviderKind::YougoriOci)) {
                process.active_containers.insert(id.to_owned());
            }
        }
        let _: AgentCommandOutput = self
            .agent_post_unlocked(
                "/v1/containers/action",
                &ActionRequest {
                    id,
                    action,
                    network_access,
                },
            )
            .await?;
        if action == "stop" {
            if let Some(process) = self.appliance.lock().await.as_mut() {
                process.active_containers.remove(id);
            }
        }
        Ok(())
    }

    pub async fn container_failure_detail(&self, id: &str) -> Result<Option<String>, String> {
        Ok(self.container_exit_detail(id).await?.map(|(_,message)|message))
    }

    pub async fn container_exit_detail(&self,id:&str)->Result<Option<(bool,String)>,String>{
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.container_exit_detail(id)).await; }

        let _lease = self.appliance_operations.read().await;
        let endpoint = self.container_endpoint(id).await?;
        let response = self.client
            .get(format!("{}/v1/containers/status/{id}", endpoint.base_url))
            .bearer_auth(&endpoint.token)
            .timeout(Duration::from_secs(if cfg!(target_arch = "aarch64") { 125 } else { 18 }))
            .send().await.map_err(|e| e.to_string())?;
        let value: serde_json::Value = successful_response(response).await?
            .json().await.map_err(|e| e.to_string())?;
        if value["running"].as_bool() == Some(true) {
            return Ok(None);
        }
        Ok(Some((value["cleanExit"]==true,value["message"].as_str().filter(|m| !m.is_empty())
            .unwrap_or("The container process exited. Check its startup command and memory allocation.")
            .to_owned())))
    }

    pub async fn update_container_internet(&self, id: &str, enabled: bool) -> Result<(), String> {
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.update_container_internet(id, enabled)).await; }

        let _: AgentCommandOutput = self.agent_post(
            "/v1/containers/internet",
            &ActionRequest { id, action: "internet", network_access: enabled },
        ).await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_container_configuration(
        &self,
        id: &str,
        network_access: bool,
        gpu_access: bool,
        previous_network_access: bool,
        previous_gpu_access: bool,
        command: &str,
        policy: &ResourcePolicy,
    ) -> Result<(), String> {
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.update_container_configuration(id, network_access, gpu_access, previous_network_access, previous_gpu_access, command, policy)).await; }

        let _: AgentCommandOutput = self
            .agent_post(
                "/v1/containers/configuration",
                &ConfigurationRequest {
                    options: Box::pin(self.prepare_workload_binds(id)).await?,
                    id,
                    network_access,
                    gpu_access,
                    previous_network_access,
                    previous_gpu_access,
                    command,
                    cpus: policy.cpu.preferred,
                    memory_bytes: gibibytes(policy.memory_gb.preferred)?,
                },
            )
            .await?;
        Ok(())
    }

    pub async fn update_container_startup(
        &self,
        environment: &crate::models::Environment,
        command: &str,
    ) -> Result<(), String> {
        if let Some(engine) = self.storage_runtime(environment.runtime_id.as_deref().unwrap_or(&environment.id))? { return Box::pin(engine.update_container_startup(environment, command)).await; }

        let _: AgentCommandOutput = self.agent_post(
            "/v1/containers/startup",
            &serde_json::json!({
                "id": environment.runtime_id.as_deref().unwrap_or(&environment.id),
                "command": command,
                "image": environment.runtime,
            }),
        ).await?;
        Ok(())
    }

    pub async fn delete_container(&self, id: &str) -> Result<(), String> {
        self.delete_container_inner(id, false).await
    }

    pub async fn delete_container_and_model_cache(&self, id: &str) -> Result<(), String> {
        self.delete_container_inner(id, true).await
    }

    async fn delete_container_inner(&self, id: &str, remove_model_cache: bool) -> Result<(), String> {
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.delete_container_inner(id, remove_model_cache)).await; }

        let _lease = self.appliance_operations.write().await;
        let caches = if remove_model_cache { self.unshared_model_caches(id)? } else { Vec::new() };
        // Persist before deleting anything: a crash must not lose the need to
        // return freed blocks to Windows on the next idle maintenance pass.
        self.mark_storage_reclaim(&self.container_provider(id)?)?;
        let _: AgentCommandOutput = self
            .agent_post_unlocked(
                "/v1/containers/delete",
                &ActionRequest {
                    id,
                    action: "delete",
                    network_access: false,
                },
            )
            .await?;
        // Keep workload metadata until cleanup succeeds, so a failed removal
        // can be retried after the container itself has already gone.
        for name in caches {
            let result = self.volume_request_unlocked(
                &self.container_provider(id)?, &serde_json::json!({"action":"remove","name":name}),
            ).await;
            if let Err(error) = result {
                if !error.contains("no volume named") {
                    return Err(format!("Container removed, but model cache {name} cleanup is pending. Retry deleting this environment: {error}"));
                }
            }
        }
        if let Some(process) = self.appliance.lock().await.as_mut() {
            process.active_containers.remove(id);
        }
        self.network_samples.lock().await.remove(id);
        self.workload_shares.lock().await.remove(id);
        let _=std::fs::remove_file(self.data_root.join("workload-options").join(format!("{id}.json")));
        Ok(())
    }

    pub async fn update_container_resources(
        &self,
        id: &str,
        cpus: f64,
        memory_gb: f64,
    ) -> Result<(), String> {
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.update_container_resources(id, cpus, memory_gb)).await; }

        let _lease = self.appliance_operations.read().await;
        self.container_endpoint(id).await?;
        if self.container_provider(id)? == crate::models::RuntimeProviderKind::YougoriCuda {
            let (cpu_capacity, memory_capacity) = self.cuda_capacity().await?;
            if cpus > cpu_capacity || memory_gb > memory_capacity {
                return Err(format!("CUDA allocation exceeds WSL's current budget of {cpu_capacity:.0} CPUs and {memory_capacity:.3} GB. Lower the allocation; your host may have more RAM than WSL."));
            }
        }
        let requested = super::appliance_capacity::ApplianceCapacity::for_workloads(cpus, memory_gb)?;
        if self.container_provider(id)? == crate::models::RuntimeProviderKind::YougoriOci && !self.appliance.lock().await.as_ref().is_some_and(|p| p.capacity.contains(requested)) {
            return Err("Stop all containers and retry to expand the shared runtime before applying these limits".into());
        }
        let request = ResourcesRequest {
            id,
            cpus,
            memory_bytes: gibibytes(memory_gb)?,
        };
        let _: AgentCommandOutput = self
            .agent_post_unlocked("/v1/containers/resources", &request)
            .await?;
        Ok(())
    }

    pub async fn execute_container_command(
        &self,
        id: &str,
        command: &str,
    ) -> Result<CommandResult, String> {
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.execute_container_command(id, command)).await; }

        let output: AgentCommandOutput = self
            .agent_post("/v1/containers/exec", &ExecRequest { id, command })
            .await?;
        Ok(CommandResult {
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code: output.exit_code,
        })
    }

    pub async fn container_logs(&self,id:&str)->Result<String,String>{
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.container_logs(id)).await; }
let result:serde_json::Value=self.agent_post("/v1/containers/logs",&serde_json::json!({"id":id,"tail":200})).await?;Ok(result["logs"].as_str().unwrap_or("").into())}
    pub async fn image_action(&self,action:&str,image:&str)->Result<serde_json::Value,String>{self.agent_post("/v1/images/action",&serde_json::json!({"action":action,"image":image})).await}

    pub async fn create_container_snapshot(
        &self,
        id: &str,
        snapshot_id: &str,
        _image: &str,
        _command: &str,
    ) -> Result<SnapshotArtifact, String> {
        self.inherit_storage(snapshot_id, id)?;
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.create_container_snapshot(id, snapshot_id, _image, _command)).await; }

        self.stream_container_snapshot(id, snapshot_id).await
    }

    async fn release_container_snapshot_data(&self, snapshot_id: &str) -> Result<(), String> {
        let _: serde_json::Value = self
            .agent_post(
                "/v1/snapshots/release",
                &SnapshotRequest {
                    id: "",
                    snapshot_id,
                    image: "",
                    command: "",
                    network_access: false,
                    gpu_access: false,
                },
            )
            .await?;
        Ok(())
    }

    pub async fn restore_container_snapshot(
        &self,
        id: &str,
        snapshot_id: &str,
        image: &str,
        command: &str,
        network_access: bool,
        gpu_access: bool,
    ) -> Result<(), String> {
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.restore_container_snapshot(id, snapshot_id, image, command, network_access, gpu_access)).await; }

        self.register_container_provider(id, &self.read_route("snapshots", snapshot_id)?)?;
        let _: serde_json::Value = self
            .agent_post(
                "/v1/snapshots/restore",
                &SnapshotRequest {
                    id,
                    snapshot_id,
                    image,
                    command,
                    network_access,
                    gpu_access,
                },
            )
            .await?;
        if let Err(error) = self.release_container_snapshot_data(snapshot_id).await {
            // The container recreation already committed successfully. Report
            // cleanup diagnostically while keeping the restored runtime state
            // and host artifact usable for a later idempotent retry.
            eprintln!("Yougori snapshot {snapshot_id} guest cleanup deferred: {error}");
        }
        Ok(())
    }

    pub async fn import_container_snapshot(
        &self,
        snapshot_id: &str,
        artifact_path: &std::path::Path,
    ) -> Result<SnapshotArtifact, String> {
        if let Some(engine) = self.storage_runtime(snapshot_id)? { return Box::pin(engine.import_container_snapshot(snapshot_id, artifact_path)).await; }

        let metadata = tokio::fs::metadata(artifact_path)
            .await
            .map_err(|error| format!("inspect restored OCI snapshot artifact: {error}"))?;
        if !metadata.is_file() || metadata.len() == 0 {
            return Err("restored OCI snapshot artifact is empty or not a file".into());
        }
        let mut checksum_file = File::open(artifact_path)
            .map_err(|error| format!("open restored OCI snapshot artifact: {error}"))?;
        let mut digest = Sha256::new();
        let mut buffer = vec![0_u8; 1024 * 1024];
        loop {
            let count = checksum_file
                .read(&mut buffer)
                .map_err(|error| format!("hash restored OCI snapshot artifact: {error}"))?;
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
        }
        let checksum_sha256 = hex::encode(digest.finalize());
        let file = tokio::fs::File::open(artifact_path)
            .await
            .map_err(|error| format!("open restored OCI snapshot artifact: {error}"))?;
        let snapshot_lease = self.appliance_operations.read().await;
        let endpoint = self.provider_endpoint(&self.read_route("snapshots", snapshot_id)?).await?;
        let response = self
            .client
            .post(format!(
                "{}/v1/snapshots/import/{}",
                endpoint.base_url, snapshot_id
            ))
            .bearer_auth(&endpoint.token)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/vnd.oci.image.layout.v1.tar",
            )
            .header(reqwest::header::CONTENT_LENGTH, metadata.len())
            .body(reqwest::Body::wrap_stream(ReaderStream::new(file)))
            .send()
            .await
            .map_err(|error| format!("upload restored OCI snapshot to appliance: {error}"))?;
        let response = successful_response(response).await?;
        let imported: AgentSnapshot = response
            .json()
            .await
            .map_err(|error| format!("decode imported OCI snapshot response: {error}"))?;
        drop(snapshot_lease);
        if imported.size_bytes != metadata.len()
            || !imported
                .checksum_sha256
                .eq_ignore_ascii_case(&checksum_sha256)
        {
            let _ = self.release_container_snapshot_data(snapshot_id).await;
            return Err(format!(
                "uploaded OCI snapshot verification failed: expected {} bytes with checksum {checksum_sha256}, appliance received {} bytes with checksum {}",
                metadata.len(), imported.size_bytes, imported.checksum_sha256
            ));
        }
        let local_path = self
            .data_root
            .join("snapshots")
            .join(format!("{snapshot_id}.oci.tar"));
        if artifact_path != local_path {
            let temporary = local_path.with_extension("tar.import.part");
            let _ = tokio::fs::remove_file(&temporary).await;
            tokio::fs::copy(artifact_path, &temporary)
                .await
                .map_err(|error| format!("store restored OCI snapshot locally: {error}"))?;
            let copied = tokio::fs::OpenOptions::new()
                .write(true)
                .open(&temporary)
                .await
                .map_err(|error| format!("open copied OCI snapshot artifact: {error}"))?;
            copied
                .sync_all()
                .await
                .map_err(|error| format!("flush copied OCI snapshot artifact: {error}"))?;
            drop(copied);
            let _ = tokio::fs::remove_file(&local_path).await;
            tokio::fs::rename(&temporary, &local_path)
                .await
                .map_err(|error| format!("finalize restored OCI snapshot artifact: {error}"))?;
        }
        Ok(SnapshotArtifact {
            provider_snapshot_id: imported.provider_snapshot_id,
            path: local_path,
            size_bytes: metadata.len(),
            checksum_sha256,
        })
    }

    pub async fn delete_container_snapshot(
        &self,
        id: &str,
        snapshot_id: &str,
    ) -> Result<(), String> {
        if let Some(engine) = self.storage_runtime(id)? { return Box::pin(engine.delete_container_snapshot(id, snapshot_id)).await; }
        self.mark_storage_reclaim(&self.container_provider(id)?)?;
        let _: serde_json::Value = self
            .agent_post(
                "/v1/snapshots/delete",
                &SnapshotRequest {
                    id,
                    snapshot_id,
                    image: "",
                    command: "",
                    network_access: false,
                    gpu_access: false,
                },
            )
            .await?;
        let path = self
            .data_root
            .join("snapshots")
            .join(format!("{snapshot_id}.oci.tar"));
        match tokio::fs::remove_file(path).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("remove local snapshot artifact: {error}")),
        }
    }

    pub async fn apply_container_connection(
        &self,
        id: &str,
        source_id: &str,
        target_id: &str,
        direction: &ConnectionDirection,
        permissions: &[PermissionKind],
        ports: &[u16],
    ) -> Result<String, String> {
        if let Some(engine) = self.storage_runtime(source_id)? { return Box::pin(engine.apply_container_connection(id, source_id, target_id, direction, permissions, ports)).await; }

        let request = ConnectionRequest {
            id,
            source_id,
            target_id,
            bidirectional: *direction == ConnectionDirection::Bidirectional,
            ports,
            allow_network: permissions.contains(&PermissionKind::Network),
            shared_path: permissions.iter().any(|permission| {
                matches!(
                    permission,
                    PermissionKind::Files | PermissionKind::Volumes | PermissionKind::Data
                )
            }),
            allow_secrets: permissions.contains(&PermissionKind::Secrets),
        };
        let value: serde_json::Value = self.agent_post("/v1/connections/apply", &request).await?;
        value
            .get("ruleId")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| "the appliance did not return a connection rule identifier".into())
    }

    pub async fn remove_container_connection(
        &self,
        id: &str,
        source_id: &str,
        target_id: &str,
    ) -> Result<(), String> {
        if let Some(engine) = self.storage_runtime(source_id)? { return Box::pin(engine.remove_container_connection(id, source_id, target_id)).await; }

        let request = ConnectionRequest {
            id,
            source_id,
            target_id,
            bidirectional: false,
            ports: &[],
            allow_network: false,
            shared_path: false,
            allow_secrets: false,
        };
        let _: serde_json::Value = self.agent_post("/v1/connections/remove", &request).await?;
        Ok(())
    }

    pub async fn container_telemetry(
        &self,
        ids: &[String],
    ) -> Result<Vec<ContainerTelemetry>, String> {
        let mut remote = Vec::new();
        let mut local = Vec::new();
        for (engine, group) in self.storage_groups(ids)? {
            if let Some(engine) = engine { remote.extend(Box::pin(engine.container_telemetry(&group)).await?); }
            else { local = group; }
        }
        let ids = &local;
        if ids.is_empty() {
            return Ok(remote);
        }
        const MAX_BATCH_IDS: usize = 256;
        let mut entries = Vec::with_capacity(ids.len());
        let mut qemu_ids = Vec::new();
        let mut cuda_ids = Vec::new();
        for id in ids {
            if self.container_provider(id)? == crate::models::RuntimeProviderKind::YougoriCuda { cuda_ids.push(id.clone()); }
            else { qemu_ids.push(id.clone()); }
        }
        for chunk in qemu_ids.chunks(MAX_BATCH_IDS).chain(cuda_ids.chunks(MAX_BATCH_IDS)) {
            let mut response: StatsBatchResponse = self
                .agent_post("/v1/stats/batch", &StatsBatchRequest { ids: chunk })
                .await?;
            entries.append(&mut response.entries);
        }
        let now = Instant::now();
        let mut samples = self.network_samples.lock().await;
        let mut telemetry: Vec<_> = entries
            .into_iter()
            .map(|entry| {
                let network_rx_mbps = if entry.running {
                    samples
                        .insert(entry.id.clone(), (entry.network_rx_bytes, now))
                        .and_then(|(previous_bytes, previous_time)| {
                            entry
                                .network_rx_bytes
                                .checked_sub(previous_bytes)
                                .map(|bytes| {
                                    (bytes, now.duration_since(previous_time).as_secs_f64())
                                })
                        })
                        .filter(|(_, elapsed)| *elapsed > 0.0)
                        .map(|(bytes, elapsed)| bytes as f64 * 8.0 / elapsed / 1_000_000.0)
                        .unwrap_or_default()
                } else {
                    samples.remove(&entry.id);
                    0.0
                };
                ContainerTelemetry {
                    id: entry.id,
                    running: entry.running,
                    paused: entry.paused,
                    stats: ContainerStats {
                        cpu_percent: entry.cpu_percent,
                        memory_bytes: entry.memory_bytes,
                        network_rx_mbps,
                    },
                }
            })
            .collect();
        telemetry.extend(remote);
        Ok(telemetry)
    }

    pub(super) async fn agent_post<B, R>(&self, path: &str, body: &B) -> Result<R, String>
    where
        B: Serialize + ?Sized,
        R: DeserializeOwned,
    {
        let _lease = self.appliance_operations.read().await;
        self.agent_post_unlocked(path, body).await
    }

    async fn agent_post_unlocked<B, R>(&self, path: &str, body: &B) -> Result<R, String>
    where B: Serialize + ?Sized, R: DeserializeOwned,
    {
        let body = serde_json::to_value(body).map_err(|e| e.to_string())?;
        let provider = self.request_provider(path, &body)?;
        if provider == crate::models::RuntimeProviderKind::YougoriCuda
            && matches!(path, "/v1/containers/delete" | "/v1/snapshots/delete")
        {
            return serde_json::from_value(self.cuda_cleanup_request(path, &body).await?)
                .map_err(|error| format!("Decode CUDA cleanup response: {error}"));
        }
        let endpoint = self.provider_endpoint(&provider).await?;
        let response = self.client.post(format!("{}{}", endpoint.base_url, path))
            .bearer_auth(&endpoint.token).json(&body).send().await
            .map_err(appliance_request_error)?;
        let response = successful_response(response).await?;
        response
            .json::<R>()
            .await
            .map_err(|error| format!("decode Yougori appliance response: {error}"))
    }

    pub(super) async fn appliance_endpoint(&self) -> Result<AgentEndpoint, String> {
        let _gpu_lease = self.gpu_launches.read().await;
        let mut process_guard = self.appliance.lock().await;
        if let Some(process) = process_guard.as_mut() {
            match process.child.try_wait() {
                Ok(None) => {
                    if self.health(&process.endpoint).await.is_ok() {
                        return Ok(process.endpoint.clone());
                    }
                }
                Ok(Some(_)) => {
                    process_guard.take();
                }
                Err(error) => return Err(format!("inspect Yougori appliance process: {error}")),
            }
        }

        if let Some(mut stale) = process_guard.take() {
            let _ = stale.child.kill().await;
            let _ = stale.child.wait().await;
        }
        // Never inspect, rebase, or archive a disk still owned by an older app's VM.
        self.check_external_appliance(false).await?;
        self.prepare_appliance_overlay().await?;
        self.prepare_container_pool_capacity().await?;
        let _boot_trace = PerfSpan::new("appliance boot");
        let mut port_reservations = super::vm::VmPortReservations::new();
        let agent_port = port_reservations.reserve_available(&[])?;
        let qmp_port = port_reservations.reserve_available(&[agent_port])?;
        let endpoint = AgentEndpoint {
            base_url: format!("http://127.0.0.1:{agent_port}"),
            token: format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple()),
        };

        let accelerators = super::host_platform::x86_accelerators(std::env::consts::OS, std::env::consts::ARCH, false);
        let mut last_error = String::new();
        let mut capacity = *self.appliance_capacity.lock().map_err(|_| "Container capacity lock poisoned")?;
        // Idle vCPU threads do not reserve physical cores. Make the host's CPUs
        // available from boot; each container still has its own cgroup limit.
        capacity.cpus = std::thread::available_parallelism().map(usize::from).unwrap_or(1).min(255);
        let mut host = sysinfo::System::new();
        host.refresh_memory();
        let max_memory_mib = ((host.total_memory() / 1_048_576) as usize / 128 * 128).max(capacity.memory_mib);
        let gpu_launch = self.prepare_gpu_launch(&self.data_root.join("appliance")).await?;
        if !cfg!(target_os = "windows") && gpu_launch.explicit() {
            return Err("The saved GPU selection requires the Windows GPU runtime. No GPU fallback was started.".into());
        }
        // Non-Windows QEMU does not include the custom graphics bridge. Skip
        // that attempt entirely instead of failing before the ordinary boot.
        for gpu_enabled in if cfg!(target_os = "windows") { vec![true, false] } else { vec![false] } {
            if !gpu_enabled && gpu_launch.explicit() { break; }
            for accelerator in accelerators {
                let internet = super::microvm_network::MicroVmNetwork::new(true, qmp_port).await?;
                let (mut child, boot_token) = self.spawn_appliance(&endpoint, accelerator, gpu_enabled, &gpu_launch, capacity, max_memory_mib, qmp_port, internet.arguments())?;
                let boot_timeout = super::host_platform::guest_boot_timeout();
                let boot_started = Instant::now();
                let storage_deadline = Instant::now() + Duration::from_secs(31 * 60);
                let mut progress_at = Instant::now();
                let mut log_size = 0;
                loop {
                    if let Some(status) = child
                        .try_wait()
                        .map_err(|error| format!("inspect Yougori appliance boot: {error}"))?
                    {
                        last_error = format!(
                            "Yougori appliance exited during boot with {status}: {}",
                            self.appliance_log_tail()
                        );
                        break;
                    }
                    if self.health(&endpoint).await.is_ok() {
                        if let Err(error) = internet.set_enabled(true).await {
                            let _ = child.kill().await;
                            let _ = child.wait().await;
                            return Err(error);
                        }
                        let gpu = if gpu_enabled {
                            match gpu_launch.verify(child.id().ok_or("Graphics runtime has no process ID")?) {
                                Ok(gpu) => gpu,
                                Err(error) => { let _ = child.kill().await; let _ = child.wait().await; return Err(error); }
                            }
                        } else { None };
                        *process_guard = Some(ApplianceProcess {
                            internet,
                            _boot_token: boot_token,
                            child,
                            endpoint: endpoint.clone(),
                            qmp_port,
                            max_memory_mib,
                            _port_reservations: port_reservations,
                            capacity,
                            active_containers: Default::default(),
                            gpu,
                        });
                        return Ok(endpoint);
                    }
                    if let Ok(metadata) = std::fs::metadata(self.data_root.join("appliance/serial.log")) {
                        if metadata.len() != log_size {
                            log_size = metadata.len();
                            progress_at = Instant::now();
                        }
                    }
                    if appliance_boot_expired(boot_started.elapsed(), boot_timeout, progress_at.elapsed(), cfg!(target_arch = "aarch64"))
                        && !(Instant::now() < storage_deadline && storage_preparation_in_progress(&self.appliance_log_tail())) {
                        last_error = format!(
                            "Yougori appliance did not become ready after {} seconds (maximum {} seconds; last boot progress {} seconds ago). {}Boot log: {}",
                            boot_started.elapsed().as_secs(), boot_timeout.as_secs(), progress_at.elapsed().as_secs(),
                            if cfg!(target_arch = "aarch64") { "This ARM64 host runs the x86-64 appliance through software emulation. " } else { "" },
                            self.appliance_log_tail()
                        );
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(350)).await;
                }
                let _ = child.kill().await;
                let _ = child.wait().await;
            }
        }
        Err(if gpu_launch.explicit() { format!("Selected GPU runtime failed. No fallback was started. {last_error}") } else { last_error })
    }

    async fn health(&self, endpoint: &AgentEndpoint) -> Result<(), String> {
        let response = self
            .client
            .get(format!("{}/v1/health", endpoint.base_url))
            .bearer_auth(&endpoint.token)
            .timeout(Duration::from_secs(2))
            .send()
            .await
            .map_err(|error| error.to_string())?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!("appliance health returned {}", response.status()))
        }
    }

    pub(crate) async fn prepare_appliance_overlay(&self) -> Result<bool, String> {
        self.appliance_preparation
            .get_or_try_init(|| async { self.prepare_appliance_overlay_once().await })
            .await
            .copied()
    }

    async fn prepare_appliance_overlay_once(&self) -> Result<bool, String> {
        self.check_external_appliance(false).await?;
        let _prepare_trace = PerfSpan::new("appliance overlay preparation");
        validate_previous_appliance_disk(&self.data_root)?;
        let overlay = self.data_root.join("appliance/system.qcow2");
        let marker_path = self
            .data_root
            .join("appliance/appliance-overlay-state.json");
        let legacy_marker = self.data_root.join("appliance/appliance-base.sha256");
        let base_digest = &self.appliance_overlay_base_digest;
        let backing_path = canonical_path(&self.appliance_overlay_base);
        let recorded = read_appliance_marker(&marker_path, &legacy_marker);
        // A qcow2 overlay is inseparable from the exact backing-file contents.
        // Older builds did not record that identity, so rebasing those overlays
        // onto a newly bundled appliance could silently corrupt the guest disk.
        let base_changed = appliance_base_changed(
            recorded.as_ref().map(|marker| marker.base_sha256.as_str()),
            base_digest,
        );
        if overlay.exists() && base_changed {
            return Err(format!("Container runtime upgrade is blocked because this disk requires a different backing image. Existing container data and recovery disks were left untouched. Restore the previous Yougori runtime and export your environments before upgrading. Disk: {}", overlay.display()));
        }
        archive_overlay_base(&self.data_root, &self.appliance_overlay_source, base_digest)?;
        if overlay.exists() {
            let fingerprint = appliance_overlay_fingerprint(&overlay)?;
            let marker_is_current = recorded.as_ref().is_some_and(|marker| {
                marker.base_sha256 == *base_digest
                    && marker.backing_path.as_deref() == Some(backing_path.as_str())
                    && marker.overlay.as_ref() == Some(&fingerprint)
            });
            if marker_is_current {
                return Ok(false);
            }

            let backing_path_changed = recorded
                .as_ref()
                .and_then(|marker| marker.backing_path.as_deref())
                != Some(backing_path.as_str());
            if backing_path_changed {
                command_output(
                    &self.layout.qemu_img,
                    &[
                        "rebase".into(),
                        "-u".into(),
                        "-f".into(),
                        "qcow2".into(),
                        "-F".into(),
                        "qcow2".into(),
                        "-b".into(),
                        path_string(&self.appliance_overlay_base),
                        path_string(&overlay),
                    ],
                    "rebase Yougori appliance data",
                )
                .await?;
            }
            if let Err(error) = check_appliance_overlay(&self.layout.qemu_img, &overlay).await
            {
                // Never silently replace the only copy of container data or delete
                // previous recovery archives after a failed integrity check.
                return Err(format!("Container disk needs recovery; it was left in place and no empty replacement was created. {error}"));
            } else {
                write_appliance_marker(&marker_path, base_digest, &backing_path, &overlay)?;
                let _ = fs::remove_file(&legacy_marker);
                return Ok(false);
            }
        }
        command_output(
            &self.layout.qemu_img,
            &[
                "create".into(),
                "-f".into(),
                "qcow2".into(),
                "-F".into(),
                "qcow2".into(),
                "-b".into(),
                path_string(&self.appliance_overlay_base),
                path_string(&overlay),
            ],
            "create Yougori appliance data",
        )
        .await?;
        write_appliance_marker(&marker_path, base_digest, &backing_path, &overlay)?;
        let _ = fs::remove_file(&legacy_marker);
        Ok(false)
    }

    pub(super) fn record_appliance_overlay_state(&self) -> Result<(), String> {
        let overlay = self.data_root.join("appliance/system.qcow2");
        if !overlay.is_file() {
            return Ok(());
        }
        write_appliance_marker(
            &self
                .data_root
                .join("appliance/appliance-overlay-state.json"),
            &self.appliance_overlay_base_digest,
            &canonical_path(&self.appliance_overlay_base),
            &overlay,
        )
    }

    fn spawn_appliance(
        &self,
        endpoint: &AgentEndpoint,
        accelerator: &str,
        gpu_enabled: bool,
        gpu_launch: &super::gpu::GpuLaunch,
        capacity: super::appliance_capacity::ApplianceCapacity,
        max_memory_mib: usize,
        qmp_port: u16,
        network_arguments: &[String],
    ) -> Result<(tokio::process::Child, super::boot_token::BootTokenFile), String> {
        let port = endpoint
            .base_url
            .rsplit(':')
            .next()
            .ok_or("invalid appliance endpoint")?;
        let overlay = self.data_root.join("appliance/system.qcow2");
        let boot_token = super::boot_token::BootTokenFile::create(&self.data_root.join("appliance"), &endpoint.token)?;
        let log_path = self.data_root.join("appliance/serial.log");
        let error_path = self.data_root.join("appliance/qemu.log");
        File::create(&log_path)
            .map_err(|error| format!("reset {}: {error}", log_path.display()))?;
        let error_log = File::create(&error_path)
            .map_err(|error| format!("create {}: {error}", error_path.display()))?;
        let appliance_cpus = capacity.cpus.to_string();
        let appliance_memory = format!("{},slots=64,maxmem={}M", capacity.memory_mib, max_memory_mib);
        let mut command = tokio::process::Command::new(&self.layout.qemu_system);
        command
            .current_dir(self.layout.qemu_system.parent().unwrap_or(&self.layout.root))
            .args([
                "-name",
                "Yougori Internal OCI Runtime",
                "-machine",
                if accelerator == "whpx" { "q35,kernel-irqchip=off" } else { "q35" },
                "-accel",
                accelerator,
                // qemu64 hides SSE4/AVX and breaks current database images.
                // KVM/HVF can pass through the host; WHPX/TCG use QEMU's
                // maximum supported feature set for the selected accelerator.
                "-cpu",
                super::vm::full_vm_cpu_model(accelerator),
                "-smp",
                &appliance_cpus,
                "-m",
                &appliance_memory,
                "-no-user-config",
                "-nodefaults",
                "-kernel",
                &path_string(&self.layout.appliance_kernel),
                "-initrd",
                &path_string(&self.layout.appliance_initramfs),
                "-append",
                &format!(
                    "root=/dev/vda rw rootfstype=ext4 console=ttyS0 modules=virtio_pci,virtio_blk,virtio_net,virtio_gpu,drm,ext4 opendock.token-source=fwcfg{}",
                    if cfg!(target_arch = "aarch64") { " opendock.emulated=1" } else { "" }
                ),
                "-fw_cfg",
                &boot_token.argument(),
                "-blockdev",
                &serde_json::json!({
                    "driver": "file",
                    "filename": path_string(&overlay),
                    "discard": "unmap",
                    "node-name": "yougori-appliance-file"
                })
                .to_string(),
                "-blockdev",
                &serde_json::json!({
                    "driver": "qcow2",
                    "file": "yougori-appliance-file",
                    "discard": "unmap",
                    "node-name": "yougori-appliance-disk"
                })
                .to_string(),
                "-device",
                "virtio-blk-pci,drive=yougori-appliance-disk",
                "-netdev",
                &format!("user,id=net0,hostfwd=tcp:127.0.0.1:{port}-:7443"),
                "-device",
                "virtio-net-pci,netdev=net0",
                "-device",
                "virtio-rng-pci",
                "-serial",
                &format!("file:{}", path_string(&log_path)),
                "-monitor",
                "none",
                "-qmp",
                &format!("tcp:127.0.0.1:{qmp_port},server=on,wait=off"),
                "-no-reboot",
                "-rtc",
                "base=utc",
                "-L",
                &path_string(&self.layout.qemu_data()),
            ]);
        if gpu_enabled {
            command.args([
                "-device",
                "virtio-gpu-gl-pci,max_outputs=1",
                "-display",
                "egl-headless",
            ]);
        } else {
            command.args(["-display", "none"]);
        }
        command.args(network_arguments);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(error_log));
        configure_background_process(&mut command);
        super::configure_qemu_sandbox(&mut command);
        if gpu_enabled { gpu_launch.configure(&mut command)?; }
        let child = command
            .spawn()
            .map_err(|error| format!("start bundled Yougori appliance: {error}"))?;
        super::guest_job::contain(&child)?;
        Ok((child, boot_token))
    }

    fn appliance_log_tail(&self) -> String {
        let paths = [
            self.data_root.join("appliance/qemu.log"),
            self.data_root.join("appliance/serial.log"),
        ];
        let mut combined = String::new();
        for path in paths {
            if let Ok(mut file) = File::open(path) {
                const TAIL_BYTES: u64 = 8 * 1024;
                let length = file.metadata().map(|metadata| metadata.len()).unwrap_or(0);
                if length > TAIL_BYTES {
                    let _ = file.seek(SeekFrom::Start(length - TAIL_BYTES));
                }
                let mut bytes = Vec::new();
                let _ = file.take(TAIL_BYTES).read_to_end(&mut bytes);
                combined.push_str(&String::from_utf8_lossy(&bytes));
            }
        }
        combined.trim().to_string()
    }
}

async fn check_appliance_overlay(qemu_img: &std::path::Path, overlay: &std::path::Path) -> Result<(), String> {
    let mut command = tokio::process::Command::new(qemu_img);
    command.args(["check", "--output=json", &path_string(overlay)]);
    configure_background_process(&mut command);
    let output = command
        .output()
        .await
        .map_err(|error| format!("check Yougori appliance data: {error}"))?;
    // Leaked clusters waste space but do not compromise guest data. Inspect
    // QEMU's structured counts; stderr can contain thousands of leak lines
    // and must not be treated as evidence of corruption on its own.
    if appliance_check_usable(output.status.code(), &output.stdout) {
        return Ok(());
    }
    if let Ok(check) = serde_json::from_slice::<serde_json::Value>(&output.stdout) {
        if let (Some(errors), Some(corruptions)) = (check["check-errors"].as_u64(), check.get("corruptions").map(serde_json::Value::as_u64).unwrap_or(Some(0))) {
            return Err(format!("check Yougori appliance data: {corruptions} corruptions and {errors} check errors. The container disk was not changed."));
        }
    }
    let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(if detail.is_empty() {
        format!("check Yougori appliance data failed with {}", output.status)
    } else {
        format!("check Yougori appliance data: {}", detail.chars().take(400).collect::<String>())
    })
}

fn appliance_check_usable(exit_code: Option<i32>, stdout: &[u8]) -> bool {
    if !matches!(exit_code, Some(0 | 2 | 3)) { return false; }
    let Ok(check) = serde_json::from_slice::<serde_json::Value>(stdout) else { return false; };
    check["format"] == "qcow2"
        && check["check-errors"].as_u64() == Some(0)
        && check.get("corruptions").map(serde_json::Value::as_u64).unwrap_or(Some(0)) == Some(0)
        && check["filename"].is_string()
}

fn appliance_boot_expired(elapsed: Duration, maximum: Duration, quiet: Duration, emulated_arm: bool) -> bool {
    elapsed >= maximum || (emulated_arm && elapsed >= Duration::from_secs(600) && quiet >= Duration::from_secs(180))
}

fn storage_preparation_in_progress(log: &str) -> bool {
    let started = log.rfind("Yougori storage preparation started");
    let ended = log.rfind("Yougori storage preparation finished").max(log.rfind("Yougori storage preparation failed"));
    started.is_some() && started > ended
}

fn appliance_request_error(error: reqwest::Error) -> String {
    use std::error::Error;

    let mut message = format!("request Yougori appliance operation: {error}");
    let mut source = error.source();
    while let Some(cause) = source {
        message.push_str(&format!(": {cause}"));
        source = cause.source();
    }
    message
}

pub(super) async fn successful_response(response: Response) -> Result<Response, String> {
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    let detail = serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|value| value.get("error")?.as_str().map(str::to_owned))
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| {
            status
                .canonical_reason()
                .unwrap_or("runtime request failed")
                .into()
        });
    let prefix = match status {
        StatusCode::CONFLICT => "runtime rejected the operation",
        StatusCode::BAD_REQUEST => "invalid runtime operation",
        StatusCode::UNAUTHORIZED => "runtime authentication failed",
        _ => "runtime operation failed",
    };
    Err(format!("{prefix}: {detail}"))
}

fn gibibytes(value: f64) -> Result<i64, String> {
    if !value.is_finite() || value <= 0.0 || value > 1024.0 {
        return Err("memory allocation is outside the supported range".into());
    }
    Ok((value * 1_073_741_824.0).round() as i64)
}

fn read_appliance_marker(
    marker_path: &std::path::Path,
    legacy_marker: &std::path::Path,
) -> Option<ExistingApplianceMarker> {
    let previous_path = appliance_marker_previous_path(marker_path);
    for candidate in [marker_path, previous_path.as_path()] {
        if let Ok(contents) = fs::read(candidate) {
            if let Ok(marker) = serde_json::from_slice::<ApplianceOverlayMarker>(&contents) {
                if marker.schema_version == APPLIANCE_OVERLAY_MARKER_VERSION {
                    return Some(ExistingApplianceMarker {
                        base_sha256: marker.base_sha256,
                        backing_path: Some(marker.backing_path),
                        overlay: Some(marker.overlay),
                    });
                }
            }
        }
    }
    fs::read_to_string(legacy_marker)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .map(|base_sha256| ExistingApplianceMarker {
            base_sha256,
            backing_path: None,
            overlay: None,
        })
}

// A previous release may have left its verified base image in place after a
// source checkout or app update supplied a different bundled base. Keep using
// that exact image for its existing overlay; a new image is never a safe
// replacement for a QCOW2 backing file. New disks still use the bundled base.
pub(super) fn existing_overlay_base(
    data_root: &std::path::Path,
    bundled_base: &std::path::Path,
    bundled_digest: &str,
) -> Option<(PathBuf, String)> {
    let directory = data_root.join("appliance");
    let overlay = directory.join("system.qcow2");
    if !overlay.is_file() { return None; }
    let marker = read_appliance_marker(
        &directory.join("appliance-overlay-state.json"),
        &directory.join("appliance-base.sha256"),
    )?;
    if marker.base_sha256.eq_ignore_ascii_case(bundled_digest) { return None; }
    let recorded_path = PathBuf::from(marker.backing_path?);
    let actual_backing = read_qcow2_backing_path(&overlay).ok()??;
    // A renamed app-data directory can leave the overlay header and marker
    // pointing to the same old path, even though the original base was copied
    // into our current archive directory. The archived bytes must match the
    // recorded digest before we permit the header-only rebase below. Never
    // substitute the newly bundled base, which may have different contents.
    let expected = directory.join(format!("backing-{}.qcow2", marker.base_sha256));
    let actual_path = if canonical_path(&recorded_path) == canonical_path(&actual_backing) {
        if recorded_path.is_file() { recorded_path } else { expected }
    } else {
        // An interrupted archive migration may have switched the QCOW2 header
        // before the marker was committed. Only accept our own archive name.
        if canonical_path(&actual_backing) != canonical_path(&expected) { return None; }
        actual_backing
    };
    if !actual_path.is_absolute() || !actual_path.is_file()
        || canonical_path(&actual_path) == canonical_path(bundled_base)
    { return None; }
    let digest = super::file_sha256(&actual_path).ok()?;
    if !digest.eq_ignore_ascii_case(&marker.base_sha256) { return None; }
    Some((actual_path, digest))
}

pub(super) fn archive_overlay_base(
    data_root: &std::path::Path,
    source: &std::path::Path,
    digest: &str,
) -> Result<PathBuf, String> {
    let directory = data_root.join("appliance");
    fs::create_dir_all(&directory).map_err(|error| format!("prepare container backing directory: {error}"))?;
    let archived = archive_overlay_path(data_root, digest);
    if archived.is_file() {
        if !super::file_sha256(&archived)?.eq_ignore_ascii_case(digest) {
            return Err(format!("Container backing archive failed its checksum and was left untouched: {}", archived.display()));
        }
        return Ok(archived);
    }
    let temporary = tempfile::NamedTempFile::new_in(&directory)
        .map_err(|error| format!("stage container backing archive: {error}"))?;
    fs::copy(source, temporary.path()).map_err(|error| format!("copy container backing image: {error}"))?;
    temporary.as_file().sync_all().map_err(|error| format!("flush container backing archive: {error}"))?;
    if !super::file_sha256(temporary.path())?.eq_ignore_ascii_case(digest) {
        return Err("Copied container backing image failed its checksum; the original was kept".into());
    }
    temporary.persist_noclobber(&archived)
        .map_err(|error| format!("save container backing archive: {}", error.error))?;
    Ok(archived)
}

pub(super) fn archive_overlay_path(data_root: &std::path::Path, digest: &str) -> PathBuf {
    data_root.join("appliance").join(format!("backing-{digest}.qcow2"))
}

fn read_qcow2_backing_path(overlay: &std::path::Path) -> Result<Option<PathBuf>, String> {
    let mut file = File::open(overlay).map_err(|error| error.to_string())?;
    let mut header = [0_u8; 20];
    file.read_exact(&mut header).map_err(|error| error.to_string())?;
    if &header[..4] != b"QFI\xfb" || !matches!(u32::from_be_bytes(header[4..8].try_into().unwrap()), 2 | 3) {
        return Err("Invalid appliance QCOW2 header".into());
    }
    let offset = u64::from_be_bytes(header[8..16].try_into().unwrap());
    let length = u32::from_be_bytes(header[16..20].try_into().unwrap()) as usize;
    if offset == 0 || length == 0 { return Ok(None); }
    let file_length = file.metadata().map_err(|error| error.to_string())?.len();
    if length > 4096 || offset.checked_add(length as u64).is_none_or(|end| end > file_length) {
        return Err("Invalid appliance QCOW2 backing path".into());
    }
    file.seek(SeekFrom::Start(offset)).map_err(|error| error.to_string())?;
    let mut bytes = vec![0; length];
    file.read_exact(&mut bytes).map_err(|error| error.to_string())?;
    let path = String::from_utf8(bytes).map_err(|error| error.to_string())?;
    Ok(Some(PathBuf::from(path)))
}

fn write_appliance_marker(
    marker_path: &std::path::Path,
    base_sha256: &str,
    backing_path: &str,
    overlay: &std::path::Path,
) -> Result<(), String> {
    let marker = ApplianceOverlayMarker {
        schema_version: APPLIANCE_OVERLAY_MARKER_VERSION,
        base_sha256: base_sha256.to_owned(),
        backing_path: backing_path.to_owned(),
        overlay: appliance_overlay_fingerprint(overlay)?,
    };
    let parent = marker_path
        .parent()
        .ok_or_else(|| format!("invalid appliance marker path: {}", marker_path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("create appliance marker directory: {error}"))?;
    let temporary = parent.join(format!(
        ".appliance-overlay-state-{}.tmp",
        Uuid::new_v4().simple()
    ));
    let contents = serde_json::to_vec(&marker)
        .map_err(|error| format!("encode appliance state marker: {error}"))?;
    fs::write(&temporary, contents)
        .map_err(|error| format!("write appliance state marker: {error}"))?;
    let previous = appliance_marker_previous_path(marker_path);
    if previous.exists() {
        fs::remove_file(&previous)
            .map_err(|error| format!("remove stale appliance state marker: {error}"))?;
    }
    let had_current = marker_path.exists();
    if had_current {
        fs::rename(marker_path, &previous)
            .map_err(|error| format!("stage previous appliance state marker: {error}"))?;
    }
    match fs::rename(&temporary, marker_path) {
        Ok(()) => {
            let _ = fs::remove_file(previous);
            Ok(())
        }
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            if had_current {
                let _ = fs::rename(&previous, marker_path);
            }
            Err(format!("commit appliance state marker: {error}"))
        }
    }
}

fn appliance_marker_previous_path(marker_path: &std::path::Path) -> PathBuf {
    marker_path.with_file_name("appliance-overlay-state.previous.json")
}

fn appliance_overlay_fingerprint(
    overlay: &std::path::Path,
) -> Result<ApplianceOverlayFingerprint, String> {
    let metadata = fs::metadata(overlay)
        .map_err(|error| format!("inspect appliance data {}: {error}", overlay.display()))?;
    let modified_unix_nanos = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos().min(u64::MAX as u128) as u64)
        .unwrap_or_default();
    Ok(ApplianceOverlayFingerprint {
        length: metadata.len(),
        modified_unix_nanos,
    })
}

fn canonical_path(path: &std::path::Path) -> String {
    fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

fn appliance_base_changed(recorded_digest: Option<&str>, current_digest: &str) -> bool {
    recorded_digest != Some(current_digest)
}

fn validate_previous_appliance_disk(root:&std::path::Path) -> Result<(),String> {
    let directory = root.join("appliance");
    let disk = directory.join("system.qcow2");
    match fs::symlink_metadata(&disk) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err("Container durable disk is redirected or not a regular file; it was not replaced".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if ["appliance-overlay-state.json","appliance-overlay-state.previous.json","appliance-base.sha256"].iter().any(|name|fs::symlink_metadata(directory.join(name)).is_ok()) {
                Err(format!("{} A previous container pool is recorded, but its durable disk is missing. Restore the original system.qcow2; no empty replacement was created",super::recovery::MISSING_OCI_STORAGE))
            } else {Ok(())}
        },
        Err(error) => Err(format!("Cannot verify container durable disk: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slow_arm_boot_requires_progress_and_a_finite_outer_budget() {
        let maximum = Duration::from_secs(1200);
        assert!(!appliance_boot_expired(Duration::from_secs(700), maximum, Duration::from_secs(10), true));
        assert!(appliance_boot_expired(Duration::from_secs(700), maximum, Duration::from_secs(180), true));
        assert!(!appliance_boot_expired(Duration::from_secs(599), maximum, Duration::from_secs(300), true));
        assert!(appliance_boot_expired(maximum, maximum, Duration::ZERO, true));
        assert!(!appliance_boot_expired(Duration::from_secs(119), Duration::from_secs(120), Duration::from_secs(119), false));
        assert!(appliance_boot_expired(Duration::from_secs(120), Duration::from_secs(120), Duration::ZERO, false));
    }
    #[test]
    fn absent_previous_appliance_disk_is_never_treated_as_a_fresh_pool() {
        let data = tempfile::tempdir().unwrap();
        fs::create_dir(data.path().join("appliance")).unwrap();
        assert!(validate_previous_appliance_disk(data.path()).is_ok());
        for name in ["appliance-overlay-state.json","appliance-overlay-state.previous.json","appliance-base.sha256"] {
            let marker = data.path().join("appliance").join(name);
            fs::write(&marker,b"existing pool evidence").unwrap();
            assert!(validate_previous_appliance_disk(data.path()).unwrap_err().contains(super::super::recovery::MISSING_OCI_STORAGE));
            assert!(!data.path().join("appliance/system.qcow2").exists());
            assert_eq!(fs::read(&marker).unwrap(),b"existing pool evidence");
            fs::remove_file(marker).unwrap();
        }
    }

    #[test]
    fn appliance_check_only_accepts_clean_or_leaked_clusters() {
        let clean = br#"{"filename":"disk.qcow2","format":"qcow2","check-errors":0,"corruptions":0,"leaks":0}"#;
        let leaks = br#"{"filename":"disk.qcow2","format":"qcow2","check-errors":0,"corruptions":0,"leaks":42}"#;
        assert!(appliance_check_usable(Some(0), clean));
        assert!(appliance_check_usable(Some(3), leaks));
        assert!(appliance_check_usable(Some(2), leaks));
        for code in [None, Some(1), Some(2), Some(63)] {
            assert!(!appliance_check_usable(code, br#"{"filename":"disk.qcow2","format":"qcow2","check-errors":0,"corruptions":1}"#));
        }
        assert!(!appliance_check_usable(Some(3), b"not json"));
        assert!(!appliance_check_usable(Some(0), br#"{"format":"qcow2","check-errors":1}"#));
    }

    #[tokio::test]
    async fn appliance_transport_failure_reports_the_connection_error() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            let _read = stream.read(&mut request).await.unwrap();
            // Model a runtime disappearing after accepting an operation.
        });
        let error = reqwest::Client::builder().no_proxy()
            .timeout(Duration::from_secs(5)).build().unwrap()
            .post(format!("http://{address}/v1/containers/action"))
            .send().await.unwrap_err();
        server.await.unwrap();
        let message = appliance_request_error(error);
        assert!(message.contains("/v1/containers/action"), "{message}");
        assert!(message.contains("closed") || message.contains("reset"), "{message}");
    }

    #[test]
    fn converts_gibibytes_without_decimal_unit_confusion() {
        assert_eq!(gibibytes(1.5).unwrap(), 1_610_612_736);
    }

    #[test]
    fn rejects_unversioned_or_mismatched_appliance_overlays() {
        assert!(appliance_base_changed(None, "current"));
        assert!(appliance_base_changed(Some("previous"), "current"));
        assert!(!appliance_base_changed(Some("current"), "current"));
    }

    #[test]
    fn overlay_marker_detects_an_unrecorded_disk_change() {
        let directory = tempfile::tempdir().unwrap();
        let overlay = directory.path().join("system.qcow2");
        let marker = directory.path().join("state.json");
        let legacy = directory.path().join("legacy.sha256");
        fs::write(&overlay, b"initial-overlay").unwrap();
        write_appliance_marker(&marker, "base-digest", "C:/runtime/base.qcow2", &overlay).unwrap();
        let recorded = read_appliance_marker(&marker, &legacy).unwrap();
        assert_eq!(
            recorded.overlay,
            Some(appliance_overlay_fingerprint(&overlay).unwrap())
        );

        fs::write(&overlay, b"changed-overlay-with-a-different-length").unwrap();
        assert_ne!(
            recorded.overlay,
            Some(appliance_overlay_fingerprint(&overlay).unwrap())
        );
    }

    #[test]
    fn existing_overlay_uses_only_its_verified_original_backing_image() {
        let directory = tempfile::tempdir().unwrap();
        let runtime = directory.path().join("runtime");
        let appliance = runtime.join("appliance");
        fs::create_dir_all(&appliance).unwrap();
        let old_base = directory.path().join("old-base.qcow2");
        let new_base = directory.path().join("new-base.qcow2");
        fs::write(&old_base, b"original base contents").unwrap();
        fs::write(&new_base, b"new base contents").unwrap();
        let old_digest = super::super::file_sha256(&old_base).unwrap();
        let new_digest = super::super::file_sha256(&new_base).unwrap();
        let overlay = appliance.join("system.qcow2");
        let backing = canonical_path(&old_base);
        let mut header = vec![0_u8; 104];
        header[..4].copy_from_slice(b"QFI\xfb");
        header[4..8].copy_from_slice(&3_u32.to_be_bytes());
        header[8..16].copy_from_slice(&104_u64.to_be_bytes());
        header[16..20].copy_from_slice(&(backing.len() as u32).to_be_bytes());
        header.extend_from_slice(backing.as_bytes());
        fs::write(&overlay, header).unwrap();
        write_appliance_marker(&appliance.join("appliance-overlay-state.json"), &old_digest, &backing, &overlay).unwrap();

        assert_eq!(existing_overlay_base(&runtime, &new_base, &new_digest), Some((PathBuf::from(&backing), old_digest.clone())));
        let archived = archive_overlay_base(&runtime, &old_base, &super::super::file_sha256(&old_base).unwrap()).unwrap();
        assert_eq!(super::super::file_sha256(&archived).unwrap(), super::super::file_sha256(&old_base).unwrap());
        // After the app-data directory is renamed, the recorded path can be
        // gone while our verified archive remains. Recover this exact base.
        fs::remove_file(&old_base).unwrap();
        assert_eq!(existing_overlay_base(&runtime, &new_base, &new_digest), Some((archived.clone(), old_digest.clone())));
        fs::write(&old_base, b"original base contents").unwrap();
        // A crash after changing the QCOW2 header but before committing the
        // marker must recover the verified archive rather than use the new base.
        let archived_path = canonical_path(&archived);
        let mut header = vec![0_u8; 104];
        header[..4].copy_from_slice(b"QFI\xfb");
        header[4..8].copy_from_slice(&3_u32.to_be_bytes());
        header[8..16].copy_from_slice(&104_u64.to_be_bytes());
        header[16..20].copy_from_slice(&(archived_path.len() as u32).to_be_bytes());
        header.extend_from_slice(archived_path.as_bytes());
        fs::write(&overlay, header).unwrap();
        assert_eq!(existing_overlay_base(&runtime, &new_base, &new_digest), Some((PathBuf::from(archived_path), super::super::file_sha256(&old_base).unwrap())));
        fs::write(&old_base, b"changed base contents").unwrap();
        assert!(existing_overlay_base(&runtime, &new_base, &new_digest).is_some());
        fs::write(&archived, b"changed archive contents").unwrap();
        assert!(existing_overlay_base(&runtime, &new_base, &new_digest).is_none());
    }

    #[tokio::test]
    async fn incompatible_appliance_keeps_active_disk_markers_and_every_recovery_archive() {
        let directory = tempfile::tempdir().unwrap();
        let runtime = RuntimeManager::new(std::path::Path::new(env!("CARGO_MANIFEST_DIR")), directory.path()).unwrap();
        let parent = runtime.data_root.join("appliance");
        fs::create_dir_all(&parent).unwrap();
        let originals = [
            ("system.qcow2", "only-copy-of-container-data"),
            ("appliance-base.sha256", "old-base-checksum"),
            ("system-incompatible-old-a.qcow2", "recovery-a"),
            ("system-incompatible-old-b.qcow2", "recovery-b"),
        ];
        for (name, bytes) in originals { fs::write(parent.join(name), bytes).unwrap(); }
        for _ in 0..2 {
            let error = runtime.prepare_appliance_overlay().await.unwrap_err();
            assert!(error.contains("upgrade is blocked"), "{error}");
            for (name, bytes) in originals {
                assert_eq!(fs::read(parent.join(name)).unwrap(), bytes.as_bytes());
            }
            assert!(!parent.join("appliance-overlay-state.json").exists());
        }
    }

    #[tokio::test]
    async fn appliance_preparation_state_runs_successful_work_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let cell = tokio::sync::OnceCell::new();
        let calls = AtomicUsize::new(0);
        for _ in 0..3 {
            let prepared = cell
                .get_or_try_init(|| async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok::<bool, String>(false)
                })
                .await
                .unwrap();
            assert!(!prepared);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "boots the bundled appliance and pulls a real OCI image"]
    async fn bundled_appliance_runs_snapshots_and_enforces_connections() {
        use crate::models::{Priority, ResourceRange};

        let app_data = tempfile::tempdir().unwrap();
        let manifest_directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let manager = RuntimeManager::new(&manifest_directory, app_data.path()).unwrap();
        let policy = ResourcePolicy {
            cpu: ResourceRange {
                min: 0.25,
                preferred: 0.5,
                max: 1.0,
                current: 0.0,
            },
            memory_gb: ResourceRange {
                min: 0.125,
                preferred: 0.125,
                max: 0.5,
                current: 0.0,
            },
            priority: Priority::Normal,
            dynamic: true,
        };
        let source = "env-appliance-source";
        let target = "env-appliance-target";
        let internet = "env-appliance-internet";
        let gpu = "env-appliance-gpu";
        let image = "quay.io/libpod/alpine:latest";
        for id in [source, target] {
            manager
                .provision_container(id, image, "sleep 2147483647", &policy, false, false)
                .await
                .unwrap();
            manager.container_action(id, "start", false).await.unwrap();
        }

        let deleted = "env-appliance-deleted";
        manager
            .provision_container(deleted, image, "sleep 2147483647", &policy, false, false)
            .await
            .unwrap();
        manager.delete_container(deleted).await.unwrap();
        manager.delete_container(deleted).await.unwrap();
        let missing = "env-appliance-missing";
        let telemetry = manager
            .container_telemetry(&[source.to_owned(), deleted.to_owned(), missing.to_owned()])
            .await
            .unwrap();
        assert_eq!(telemetry.len(), 3, "{telemetry:?}");
        let source_telemetry = telemetry.iter().find(|entry| entry.id == source).unwrap();
        assert!(source_telemetry.running, "{source_telemetry:?}");
        assert!(
            source_telemetry.stats.memory_bytes > 0,
            "{source_telemetry:?}"
        );
        for absent in [deleted, missing] {
            let absent_telemetry = telemetry.iter().find(|entry| entry.id == absent).unwrap();
            assert!(!absent_telemetry.running, "{absent_telemetry:?}");
            assert_eq!(absent_telemetry.stats.memory_bytes, 0);
            assert_eq!(absent_telemetry.stats.cpu_percent, 0.0);
            assert_eq!(absent_telemetry.stats.network_rx_mbps, 0.0);
        }

        let command = manager
            .execute_container_command(source, "printf 'real-runtime'")
            .await
            .unwrap();
        assert_eq!(command.exit_code, 0);
        assert_eq!(command.stdout, "real-runtime");

        manager
            .provision_container(internet, image, "sleep 2147483647", &policy, false, false)
            .await
            .unwrap();
        manager
            .update_container_configuration(
                internet,
                true,
                false,
                false,
                false,
                "sleep 2147483647",
                &policy,
            )
            .await
            .unwrap();
        manager
            .container_action(internet, "start", true)
            .await
            .unwrap();
        let public_internet = manager
            .execute_container_command(
                internet,
                "wget -qO- https://example.com | grep -q 'Example Domain'",
            )
            .await
            .unwrap();
        assert_eq!(public_internet.exit_code, 0, "{}", public_internet.stderr);
        let private_network = manager
            .execute_container_command(internet, "ping -c 1 -W 1 10.0.2.2")
            .await
            .unwrap();
        assert_ne!(private_network.exit_code, 0);

        manager
            .provision_container(gpu, image, "sleep 2147483647", &policy, false, true)
            .await
            .unwrap();
        manager.container_action(gpu, "start", false).await.unwrap();
        let shared_gpu = manager
            .execute_container_command(gpu, "test -c /dev/dri/renderD128")
            .await
            .unwrap();
        assert_eq!(shared_gpu.exit_code, 0, "{}", shared_gpu.stderr);

        let connection = "connection-appliance-test";
        manager
            .apply_container_connection(
                connection,
                source,
                target,
                &ConnectionDirection::OneWay,
                &[
                    PermissionKind::Ports,
                    PermissionKind::Files,
                    PermissionKind::Secrets,
                ],
                &[45678],
            )
            .await
            .unwrap();
        let source_write = manager
            .execute_container_command(
                source,
                &format!(
                    "printf shared-value > /yougori/shared/{connection}/value && printf secret-value > /opendock/secrets/{connection}/value"
                ),
            )
            .await
            .unwrap();
        assert_eq!(source_write.exit_code, 0, "{}", source_write.stderr);
        let target_read = manager
            .execute_container_command(
                target,
                &format!(
                    "cat /yougori/shared/{connection}/value /opendock/secrets/{connection}/value"
                ),
            )
            .await
            .unwrap();
        assert_eq!(target_read.exit_code, 0, "{}", target_read.stderr);
        assert_eq!(target_read.stdout, "shared-valuesecret-value");
        let target_write = manager
            .execute_container_command(
                target,
                &format!("printf forbidden > /yougori/shared/{connection}/target-write"),
            )
            .await
            .unwrap();
        assert_ne!(target_write.exit_code, 0);

        let server = manager
            .execute_container_command(
                target,
                "/bin/busybox sh -c 'while true; do printf allowed | /bin/busybox nc -l -p 45678; done' </dev/null >/tmp/opendock-server.log 2>&1 &",
            )
            .await
            .unwrap();
        assert_eq!(server.exit_code, 0, "{}", server.stderr);
        let allowed = manager
            .execute_container_command(
                source,
                &format!("/bin/busybox nc -w 3 {target} 45678 </dev/null"),
            )
            .await
            .unwrap();
        assert_eq!(allowed.exit_code, 0, "{}", allowed.stderr);
        assert_eq!(allowed.stdout, "allowed");
        let denied = manager
            .execute_container_command(source, &format!("/bin/busybox ping -c 1 -W 1 {target}"))
            .await
            .unwrap();
        assert_ne!(denied.exit_code, 0);

        manager
            .remove_container_connection(connection, source, target)
            .await
            .unwrap();
        let checkpoint = manager
            .execute_container_command(source, "printf snapshot-state > /snapshot-proof")
            .await
            .unwrap();
        assert_eq!(checkpoint.exit_code, 0, "{}", checkpoint.stderr);
        let snapshot_id = "snapshot-appliance-test";
        let snapshot = manager
            .create_container_snapshot(source, snapshot_id, image, "sleep 2147483647")
            .await
            .unwrap();
        assert!(snapshot.size_bytes > 0);
        assert!(snapshot.path.is_file());
        assert_eq!(snapshot.checksum_sha256.len(), 64);
        // Creation already released both guest copies. A second release proves
        // the authenticated cleanup operation is idempotent.
        manager
            .release_container_snapshot_data(snapshot_id)
            .await
            .unwrap();
        let changed = manager
            .execute_container_command(source, "printf changed > /snapshot-proof")
            .await
            .unwrap();
        assert_eq!(changed.exit_code, 0, "{}", changed.stderr);
        manager
            .import_container_snapshot(snapshot_id, &snapshot.path)
            .await
            .unwrap();
        manager
            .restore_container_snapshot(
                source,
                snapshot_id,
                image,
                "sleep 2147483647",
                false,
                false,
            )
            .await
            .unwrap();
        manager
            .release_container_snapshot_data(snapshot_id)
            .await
            .unwrap();
        manager
            .update_container_resources(source, policy.cpu.preferred, policy.memory_gb.preferred)
            .await
            .unwrap();
        manager
            .container_action(source, "start", false)
            .await
            .unwrap();
        let restored = manager
            .execute_container_command(source, "cat /snapshot-proof")
            .await
            .unwrap();
        assert_eq!(restored.exit_code, 0, "{}", restored.stderr);
        assert_eq!(restored.stdout, "snapshot-state");
        manager
            .delete_container_snapshot(source, snapshot_id)
            .await
            .unwrap();
        manager
            .delete_container_snapshot(source, snapshot_id)
            .await
            .unwrap();
        for id in [source, target, internet, gpu] {
            manager.delete_container(id).await.unwrap();
        }
        manager.shutdown_all().await;
    }
}
