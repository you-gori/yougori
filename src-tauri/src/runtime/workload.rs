use super::RuntimeManager;
use yougori_cli::workload::Options;
impl RuntimeManager {
    /// Only generated model caches are owned by model deletion. Named user
    /// volumes and PC binds retain their independent lifetime. Check saved
    /// workloads too: stopped/unprovisioned peers may not exist in the agent.
    pub(super) fn unshared_model_caches(&self, id: &str) -> Result<Vec<String>, String> {
        let options = self.workload_options(id)?;
        let mut names = model_cache_names(&options);
        if names.is_empty() { return Ok(names); }
        for entry in std::fs::read_dir(self.data_root.join("workload-options")).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") { continue; }
            let peer = path.file_stem().and_then(|s| s.to_str()).ok_or("Invalid workload metadata filename")?;
            if peer == id { continue; }
            let peer = self.workload_options(peer)?;
            names.retain(|name| !peer.volumes.iter().any(|volume| &volume.source == name));
        }
        Ok(names)
    }

    pub fn save_micro_workload(&self, id: &str, spec: &serde_json::Value) -> Result<(), String> {
        let directory = self
            .environment_storage_root(id)?
            .join("environments")
            .join(id);
        std::fs::create_dir_all(&directory).map_err(|e| e.to_string())?;
        let mut f = tempfile::NamedTempFile::new_in(&directory).map_err(|e| e.to_string())?;
        serde_json::to_writer(&mut f, spec).map_err(|e| e.to_string())?;
        f.as_file().sync_all().map_err(|e| e.to_string())?;
        f.persist(directory.join("oci-workload.json"))
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    pub fn is_micro_workload(&self, id: &str) -> Result<bool, String> {
        Ok(self
            .environment_storage_root(id)?
            .join("environments")
            .join(id)
            .join("oci-workload.json")
            .is_file())
    }
    pub async fn start_micro_workload(&self, id: &str) -> Result<(), String> {
        if let Some(engine) = self.storage_runtime(id)? {
            return Box::pin(engine.start_micro_workload(id)).await;
        }
        let path = self
            .data_root
            .join("environments")
            .join(id)
            .join("oci-workload.json");
        if !path.is_file() {
            return Ok(());
        }
        if std::fs::metadata(&path).map_err(|e| e.to_string())?.len() > 256 * 1024 {
            return Err("Invalid microVM workload metadata".into());
        }
        let mut spec: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        let options: Options = serde_json::from_value(spec["options"].clone()).map_err(|_| "Invalid microVM workload options")?;
        crate::projects::secrets::inject(&mut spec["options"], &options.secret_environment)?;
        // Existing helper waits for the guest agent to finish booting.
        self.execute_micro_vm_command(id, "true").await?;
        let endpoint = self
            .vms
            .lock()
            .await
            .get(id)
            .and_then(|v| v.micro_endpoint.clone())
            .ok_or("MicroVM agent unavailable")?;
        let response = self
            .client
            .post(format!("{}/v1/microvm/workload", endpoint.base_url))
            .bearer_auth(endpoint.token)
            .json(&spec)
            .timeout(std::time::Duration::from_secs(1250))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !response.status().is_success() {
            return Err(format!(
                "MicroVM workload: {}",
                response.text().await.unwrap_or_default()
            ));
        }
        Ok(())
    }
    pub async fn execute_micro_workload_command(
        &self,
        id: &str,
        command: &str,
    ) -> Result<crate::models::CommandResult, String> {
        if self.is_micro_workload(id)? {
            self.execute_micro_vm_command(
                id,
                &format!(
                    "nerdctl --namespace yougori-workload exec app /bin/sh -lc '{}'",
                    command.replace('\'', "'\"'\"'")
                ),
            )
            .await
        } else {
            self.execute_micro_vm_command(id, command).await
        }
    }
    pub async fn update_workload_configuration(
        &self,
        env: &crate::models::Environment,
    ) -> Result<(), String> {
        self.update_container_configuration(
            env.runtime_id.as_deref().unwrap_or(&env.id),
            env.network_access,
            env.gpu_access,
            env.network_access,
            env.gpu_access,
            env.container_command.as_deref().unwrap_or_default(),
            &env.resource_policy,
        )
        .await
    }
    /// Serializes PC-folder preparation and deletion of one workload. Lock order:
    /// this per-workload lock, then `appliance_operations`, then `workload_shares`.
    pub(super) async fn workload_bind_mutex(&self, id: &str) -> std::sync::Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.workload_binds.lock().await;
        locks.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = locks.get(id).and_then(std::sync::Weak::upgrade) {
            return lock;
        }
        let lock = std::sync::Arc::new(tokio::sync::Mutex::new(()));
        locks.insert(id.to_owned(), std::sync::Arc::downgrade(&lock));
        lock
    }

    /// A locked-down container keeps its PC folder mounts, but they answer nothing.
    pub async fn set_workload_shares_suspended(&self, id: &str, suspended: bool) -> Result<(), String> {
        if let Some(engine) = self.storage_runtime(id)? {
            return Box::pin(engine.set_workload_shares_suspended(id, suspended)).await;
        }
        if let Some((_, servers)) = self.workload_shares.lock().await.get(id) {
            for server in servers {
                server.set_suspended(suspended);
            }
        }
        Ok(())
    }

    pub async fn prepare_workload_binds(&self, id: &str) -> Result<serde_json::Value, String> {
        if let Some(engine) = self.storage_runtime(id)? {
            return Box::pin(engine.prepare_workload_binds(id)).await;
        }
        let options = self.workload_options(id)?;
        let mut value = serde_json::to_value(&options).map_err(|e| e.to_string())?;
        crate::projects::secrets::inject(&mut value, &options.secret_environment)?;
        let bind_lock = self.workload_bind_mutex(id).await;
        let _bind_guard = bind_lock.lock().await;
        if options.binds.is_empty() {
            self.workload_shares.lock().await.remove(id);
            return Ok(value);
        }
        self.container_endpoint(id).await?;
        self.prepare_native_model(id).await?;
        let cuda = self.container_provider(id)? == crate::models::RuntimeProviderKind::YougoriCuda;
        // Reuse live servers but always restore guest mounts after an engine restart.
        let fingerprint = serde_json::to_string(&options.binds).map_err(|e| e.to_string())?;
        // Never hold workload_shares across agent calls: deletion holds the
        // appliance_operations writer before taking it, and agent_post waits for
        // a reader lease. The per-workload lock keeps this entry exclusive.
        let mut servers = match self.workload_shares.lock().await.remove(id) {
            Some((old_key, old)) if old_key == fingerprint => old,
            _ => Vec::new(),
        };
        let result=async {
            for (index,bind) in options.binds.iter().enumerate(){
                let root=std::path::Path::new(&bind.source).canonicalize().map_err(|e|format!("PC volume {}: {e}",bind.source))?;
                shareable_volume(&root,self).map_err(|e|format!("PC volume {}: {e}",bind.source))?;
                if let Err(error)=crate::changes::ensure_folder_baseline(self,id,&root).await { eprintln!("Changes baseline for {id}: {error}"); }
                if servers.len()<=index{servers.push(crate::host_files::HostFolderServer::start(root,bind.read_only).await?)}
                let server=&servers[index];let endpoint=self.workload_folder_endpoint(id,cuda,server).await?;
                let slot=format!("{id}-{index}");
                let _:serde_json::Value=self.agent_post("/v1/workloads/mount",&serde_json::json!({"id":id,"slot":slot,"endpoint":endpoint,"token":server.token,"readOnly":bind.read_only})).await?;
                value["binds"][index]["source"]=slot.into();
            }Ok(value)
        }.await;
        self.workload_shares.lock().await.insert(id.to_owned(), (fingerprint, servers));
        result
    }
    pub fn save_workload_options(&self, id: &str, options: &Options) -> Result<(), String> {
        options.validate()?;
        let root = self.environment_storage_root(id)?.join("workload-options");
        std::fs::create_dir_all(&root).map_err(|e| e.to_string())?;
        let mut file = tempfile::NamedTempFile::new_in(&root).map_err(|e| e.to_string())?;
        serde_json::to_writer(&mut file, options).map_err(|e| e.to_string())?;
        file.as_file().sync_all().map_err(|e| e.to_string())?;
        file.persist(root.join(format!("{id}.json")))
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    pub fn workload_options(&self, id: &str) -> Result<Options, String> {
        let path = self
            .environment_storage_root(id)?
            .join("workload-options")
            .join(format!("{id}.json"));
        if !path.try_exists().map_err(|e| e.to_string())? {
            return Ok(Options::default());
        }
        if std::fs::metadata(&path).map_err(|e| e.to_string())?.len() > 256 * 1024 {
            return Err("Invalid workload metadata".into());
        }
        let options: Options =
            serde_json::from_slice(&std::fs::read(path).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        options.validate()?;
        Ok(options)
    }
}

/// Whether a project may mount this PC folder (canonical) into a container: the dashboard's own
/// rule, so a folder is never a whole drive and never inside or around Yougori's data.
fn shareable_volume(folder: &std::path::Path, runtime: &RuntimeManager) -> Result<(), String> {
    if !folder.is_dir() {
        return Err("Choose a folder for a PC volume".into());
    }
    crate::host_files::ensure_shareable_folder(folder, &crate::host_files::yougori_folders(runtime), false)
}

fn model_cache_names(options: &Options) -> Vec<String> {
    if !options.environment.contains_key("YOUGORI_MODEL")
        || !(options.secret_environment.contains_key("YOUGORI_MODEL_TOKEN") || options.environment.contains_key("YOUGORI_MODEL_TOKEN")) {
        return Vec::new();
    }
    options.volumes.iter().filter(|v| {
        !v.read_only && v.target == "/root/.cache/huggingface"
            && v.source.strip_prefix("model-").and_then(|s| s.strip_suffix("-models"))
                .is_some_and(|id| id.len() == 8 && id.bytes().all(|b| b.is_ascii_hexdigit()))
    }).map(|v| v.source.clone()).collect()
}

#[cfg(test)]
mod model_cache_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn model_deletion_keeps_user_data_and_shared_or_unreadable_peer_caches() {
        let data = tempfile::tempdir().unwrap();
        let runtime = RuntimeManager::new(std::path::Path::new(env!("CARGO_MANIFEST_DIR")), data.path()).unwrap();
        let model: Options = serde_json::from_value(json!({
            "environment":{"YOUGORI_MODEL":"owner/model"}, "secretEnvironment":{"YOUGORI_MODEL_TOKEN":"model-key"},
            "volumes":[{"source":"model-1234abcd-models","target":"/root/.cache/huggingface"}, {"source":"user-data","target":"/data"}],
            "binds":[{"source":"C:/weights","target":"/weights"}]
        })).unwrap();
        runtime.save_workload_options("model", &model).unwrap();
        assert_eq!(runtime.unshared_model_caches("model").unwrap(), ["model-1234abcd-models"]);
        let mut user = model.clone();
        user.secret_environment.clear();
        assert!(model_cache_names(&user).is_empty());
        user.secret_environment = model.secret_environment.clone();
        user.volumes[0].source = "my-own-cache".into();
        assert!(model_cache_names(&user).is_empty());
        let mut peer = Options::default();
        peer.volumes.push(model.volumes[0].clone());
        runtime.save_workload_options("stopped-peer", &peer).unwrap();
        assert!(runtime.unshared_model_caches("model").unwrap().is_empty());
        runtime.save_workload_options("stopped-peer", &Options::default()).unwrap();
        assert_eq!(runtime.unshared_model_caches("model").unwrap().len(), 1);
        std::fs::write(runtime.storage_root().join("workload-options/stopped-peer.json"), b"broken").unwrap();
        assert!(runtime.unshared_model_caches("model").is_err());
    }

    #[test]
    fn project_volumes_never_reach_yougori_data() {
        let home = tempfile::tempdir().unwrap();
        // App data as Yougori lays it out: the runtime inside it, beside its own state.
        let app = home.path().join("app");
        let runtime = RuntimeManager::new(std::path::Path::new(env!("CARGO_MANIFEST_DIR")), &app).unwrap();
        crate::host_files::protect_folder(&app);
        let canonical = |path: std::path::PathBuf| { std::fs::create_dir_all(&path).unwrap(); path.canonicalize().unwrap() };
        for private in ["swarm", "grid", "backup-credentials", "runtime", "runtime/environments", ""] {
            let folder = canonical(app.join(private));
            assert!(shareable_volume(&folder, &runtime).is_err(), "{private} reached a container");
        }
        assert!(shareable_volume(&canonical(home.path().into()), &runtime).is_err(), "a folder holding Yougori's data");
        assert!(shareable_volume(&canonical(home.path().join("project")), &runtime).is_ok());
    }
}
