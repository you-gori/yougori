use super::*;
use std::future::Future;

const CREATION_FAILED: &str = "Environment creation failed: ";
const CLOSED_DURING_CREATION: &str = "Yougori closed before environment creation finished.";
const STOPPED_DURING_CREATION: &str = "Environment creation was stopped before it finished.";

/// A node whose creation never finished: it failed, or was cut short by Ctrl+C, a closed
/// window or Yougori closing. It holds nothing of its own, so it can be deleted and made again.
pub(crate) fn creation_unfinished(environment: &Environment) -> bool {
    environment.status == EnvironmentStatus::Error
        && environment.last_error.as_deref().is_some_and(|error| {
            [CREATION_FAILED, CLOSED_DURING_CREATION, STOPPED_DURING_CREATION].iter().any(|start| error.starts_with(start))
        })
}

/// Marks the node as an error when its creation is dropped part way (a cancelled job aborts
/// the task), so it never spins as Provisioning until Yougori restarts.
struct Unfinished<'a> {
    store: &'a PlatformStore,
    id: &'a str,
    armed: bool,
}

impl Drop for Unfinished<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let _ = self.store.mutate(|state| {
            if let Some(environment) = state.environments.iter_mut().find(|item| item.id == self.id && item.status == EnvironmentStatus::Provisioning) {
                environment.status = EnvironmentStatus::Error;
                environment.last_error = Some(format!("{STOPPED_DURING_CREATION} Delete this incomplete node and create the environment again. Your original images and boot media were not changed."));
            }
            Ok(())
        });
    }
}

/// Persist and announce the real node before downloading images or preparing disks.
/// The async command continues even after its creation form has been closed.
pub(super) async fn create_on_graph(
    request: &CreateEnvironmentRequest,
    policy: ResourcePolicy,
    id: &str,
    store: &PlatformStore,
    provision: impl Future<Output = Result<(Option<String>, String), String>>,
    notify: impl Fn(&PlatformState),
) -> Result<PlatformState, String> {
    let pending = Environment {
        id: id.into(),
        name: request.name.trim().into(),
        kind: request.kind.clone(),
        status: EnvironmentStatus::Provisioning,
        runtime: request.runtime.trim().into(),
        provider: Some(request.provider.clone()),
        runtime_id: Some(id.into()),
        runtime_path: None,
        control_endpoint: None,
        console_endpoint: None,
        container_command: request.provider.is_container().then(|| request.container_command.as_deref().map(str::trim).unwrap_or("sleep 2147483647").to_owned()),
        network_access: (request.provider.is_container() || request.provider == RuntimeProviderKind::Qemu) && request.network_access,
        gpu_access: (request.provider.is_container() || request.kind == EnvironmentKind::FullVm) && request.gpu_access,
        sandbox_policy: None,
        last_error: None,
        description: request.description.trim().into(),
        branch_type: request.branch_type.clone(),
        created_at: now(),
        last_opened_at: None,
        cpu_usage: 0.0,
        memory_usage_gb: 0.0,
        storage_delta_gb: 0.0,
        storage_limit_gb: request.provider.is_container().then(|| request.storage_gb.unwrap_or(20.0)),
        storage_drive: request.storage_drive.clone(),
        network_rx_mbps: 0.0,
        resource_policy: policy,
    };
    let state = store.mutate(|state| {
        if state
            .environments
            .iter()
            .any(|item| item.name.eq_ignore_ascii_case(&pending.name))
        {
            return Err("An environment with this name already exists".into());
        }
        state.environments.insert(0, pending);
        Ok(())
    })?;
    notify(&state);
    let mut unfinished = Unfinished { store, id, armed: true };
    let result = provision.await;
    unfinished.armed = false;
    let finalized = store.mutate(|state| {
        let environment = state.environments.iter_mut().find(|item| item.id == id)
            .ok_or("The environment creation record is missing")?;
        match &result {
            Ok((disk, source)) => {
                environment.runtime_path = disk.clone();
                environment.runtime = source.clone();
                environment.status = EnvironmentStatus::Stopped;
                environment.last_error = None;
            }
            Err(error) => {
                environment.status = EnvironmentStatus::Error;
                environment.last_error = Some(format!("{CREATION_FAILED}{error}\nDelete this node and create the environment again. Your original images and boot media were not changed."));
            }
        }
        Ok(())
    });
    let state = match finalized {
        Ok(state) => state,
        Err(error) => {
            let message = format!("Could not save the environment creation result: {error}. Free disk space, then delete this incomplete node and create it again.");
            // Even if the disk is full, do not leave an endless spinner in memory.
            // The persisted Provisioning state is recovered as an error on restart.
            if let Ok(state) = store.mutate_ephemeral(|state| {
                if let Some(environment) = state.environments.iter_mut().find(|item| item.id == id)
                {
                    environment.status = EnvironmentStatus::Error;
                    environment.last_error = Some(message.clone());
                }
                Ok(())
            }) {
                notify(&state);
            }
            return Err(message);
        }
    };
    notify(&state);
    result.map(|_| state)
}

pub(crate) fn recover_interrupted(state: &mut PlatformState) {
    for environment in &mut state.environments {
        if matches!(environment.kind, EnvironmentKind::Container | EnvironmentKind::MicroVm | EnvironmentKind::FullVm)
            && environment.status == EnvironmentStatus::Provisioning
            && !state.pending_factory_resets.iter().any(|entry| entry.environment.id == environment.id)
        {
            environment.status = EnvironmentStatus::Error;
            environment.last_error = Some(format!("{CLOSED_DURING_CREATION} Delete this incomplete node and create the environment again. Your original images and boot media were not changed."));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn fixture() -> (CreateEnvironmentRequest, ResourcePolicy) {
        let policy: ResourcePolicy = serde_json::from_value(serde_json::json!({
            "cpu":{"min":1,"preferred":2,"max":4,"current":0},
            "memoryGb":{"min":1,"preferred":2,"max":4,"current":0},
            "priority":"normal","dynamic":false
        }))
        .unwrap();
        let request = serde_json::from_value(serde_json::json!({
            "name":"Test VM","kind":"fullVm","runtime":"test.iso","provider":"qemu",
            "description":"VM creation test","resourcePolicy":policy
        }))
        .unwrap();
        (request, policy)
    }

    #[tokio::test]
    async fn vm_creation_persists_and_notifies_before_disk_work_then_updates_same_node() {
        let data = tempfile::tempdir().unwrap();
        let path = data.path().join("state.json");
        let store = PlatformStore::load(path.clone()).unwrap();
        let (request, policy) = fixture();
        let events = Mutex::new(Vec::new());
        let result = create_on_graph(
            &request,
            policy,
            "env-create",
            &store,
            async {
                let pending = PlatformStore::load(path).unwrap().snapshot().unwrap();
                assert_eq!(
                    pending.environments[0].status,
                    EnvironmentStatus::Provisioning
                );
                assert!(pending.environments[0].runtime_path.is_none());
                assert_eq!(events.lock().unwrap().len(), 1);
                // Preserve independent edits while disk preparation is in flight.
                store
                    .mutate(|state| {
                        state.environments[0].description = "Preserved edit".into();
                        Ok(())
                    })
                    .unwrap();
                Ok((Some("managed/system.qcow2".into()), "managed/source.iso".into()))
            },
            |state| {
                events
                    .lock()
                    .unwrap()
                    .push(state.environments[0].status.clone())
            },
        )
        .await
        .unwrap();
        assert_eq!(result.environments.len(), 1);
        let environment = &result.environments[0];
        assert_eq!(environment.id, "env-create");
        assert_eq!(environment.description, "Preserved edit");
        assert_eq!(
            environment.runtime_path.as_deref(),
            Some("managed/system.qcow2")
        );
        assert_eq!(environment.runtime, "managed/source.iso");
        assert_eq!(
            *events.lock().unwrap(),
            vec![EnvironmentStatus::Provisioning, EnvironmentStatus::Stopped]
        );
    }

    #[tokio::test]
    async fn vm_creation_failure_stays_visible_and_duplicate_name_never_starts_work() {
        let data = tempfile::tempdir().unwrap();
        let store = PlatformStore::load(data.path().join("state.json")).unwrap();
        let (request, policy) = fixture();
        let failed = create_on_graph(
            &request,
            policy.clone(),
            "env-failure",
            &store,
            async { Err("Disk is full".into()) },
            |_| {},
        )
        .await;
        assert_eq!(failed.unwrap_err(), "Disk is full");
        let state = store.snapshot().unwrap();
        assert_eq!(state.environments[0].status, EnvironmentStatus::Error);
        assert!(state.environments[0]
            .last_error
            .as_ref()
            .unwrap()
            .contains("Disk is full"));
        assert!(state.environments[0].runtime_path.is_none());
        let duplicate = create_on_graph(
            &request,
            policy,
            "env-duplicate",
            &store,
            async { panic!("Duplicate must not import a disk") },
            |_| {},
        )
        .await;
        assert!(duplicate.unwrap_err().contains("already exists"));
        assert_eq!(store.snapshot().unwrap().environments.len(), 1);
    }

    #[tokio::test]
    async fn environment_creation_tracks_every_provider_through_success_failure_and_interruption() {
        for (kind, provider) in [
            (EnvironmentKind::Container, RuntimeProviderKind::YougoriOci),
            (EnvironmentKind::Container, RuntimeProviderKind::YougoriCuda),
            (EnvironmentKind::MicroVm, RuntimeProviderKind::Qemu),
            (EnvironmentKind::FullVm, RuntimeProviderKind::Qemu),
        ] {
            let data = tempfile::tempdir().unwrap();
            let path = data.path().join("state.json");
            let store = PlatformStore::load(path.clone()).unwrap();
            let (mut request, policy) = fixture();
            request.kind = kind.clone();
            request.provider = provider.clone();
            request.network_access = true;
            request.gpu_access = provider == RuntimeProviderKind::YougoriCuda;
            request.container_command = Some(String::new()); // Preserve image ENTRYPOINT.
            let container = provider.is_container();
            let disk = (!container).then(|| "managed/system.qcow2".to_owned());
            let result = create_on_graph(&request, policy.clone(), "env-ready", &store, async {
                let persisted = PlatformStore::load(path.clone())?.snapshot()?;
                let pending = &persisted.environments[0];
                assert_eq!(pending.id, "env-ready");
                assert_eq!(pending.kind, kind);
                assert_eq!(pending.provider, Some(provider.clone()));
                assert_eq!(pending.status, EnvironmentStatus::Provisioning);
                assert!(pending.network_access);
                assert_eq!(pending.gpu_access, request.gpu_access);
                assert_eq!(pending.container_command, container.then(String::new));
                Ok((disk.clone(), "managed-source".to_owned()))
            }, |_| {}).await.unwrap();
            assert_eq!(result.environments.len(), 1);
            assert_eq!(result.environments[0].id, "env-ready");
            assert_eq!(result.environments[0].runtime_path, disk);
            assert_eq!(result.environments[0].status, EnvironmentStatus::Stopped);

            request.name = "Failed creation".into();
            assert!(create_on_graph(&request, policy.clone(), "env-failed", &store,
                async { Err("Image preparation failed".into()) }, |_| {}).await.is_err());
            let failed = store.snapshot().unwrap();
            assert_eq!(failed.environments[0].status, EnvironmentStatus::Error);
            assert!(failed.environments[0].last_error.as_ref().unwrap().contains("Image preparation failed"));
            assert!(create_on_graph(&request, policy.clone(), "env-duplicate", &store,
                async { panic!("A duplicate must never prepare runtime resources") }, |_| {}).await.is_err());

            request.name = "Interrupted creation".into();
            let task = create_on_graph(&request, policy, "env-interrupted", &store, std::future::pending(), |_| {});
            tokio::pin!(task);
            tokio::select! {
                _ = &mut task => panic!("Preparation must still be in progress"),
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
            let mut recovered = store.snapshot().unwrap();
            recover_interrupted(&mut recovered);
            assert_eq!(recovered.environments[0].status, EnvironmentStatus::Error);
            assert!(recovered.environments[0].last_error.as_ref().unwrap().contains("closed before"));
            assert_eq!(recovered.environments[2].status, EnvironmentStatus::Stopped);
            assert_eq!(recovered.environments.len(), 3);
        }
    }

    #[tokio::test]
    async fn a_creation_stopped_part_way_is_an_error_that_can_be_made_again() {
        let data = tempfile::tempdir().unwrap();
        let store = PlatformStore::load(data.path().join("state.json")).unwrap();
        let (request, policy) = fixture();
        {
            let task = create_on_graph(&request, policy, "env-dropped", &store, std::future::pending(), |_| {});
            tokio::pin!(task);
            tokio::select! {
                _ = &mut task => panic!("Preparation must still be in progress"),
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
            assert_eq!(store.snapshot().unwrap().environments[0].status, EnvironmentStatus::Provisioning);
        }
        let environment = &store.snapshot().unwrap().environments[0];
        assert_eq!(environment.status, EnvironmentStatus::Error);
        assert!(environment.last_error.as_deref().unwrap().starts_with(STOPPED_DURING_CREATION));
        assert!(creation_unfinished(environment));
        let mut failed = environment.clone();
        failed.last_error = Some(format!("{CREATION_FAILED}pull access denied"));
        assert!(creation_unfinished(&failed));
        failed.last_error = Some("The container exited with code 1".into());
        assert!(!creation_unfinished(&failed), "a node that ran and failed later is kept for inspection");
        failed.status = EnvironmentStatus::Stopped;
        failed.last_error = Some(format!("{CREATION_FAILED}old"));
        assert!(!creation_unfinished(&failed));
    }

    #[tokio::test]
    async fn vm_creation_interruption_is_not_mistaken_for_a_ready_vm() {
        let data = tempfile::tempdir().unwrap();
        let store = PlatformStore::load(data.path().join("state.json")).unwrap();
        let (request, policy) = fixture();
        let task = create_on_graph(
            &request,
            policy,
            "env-interrupted",
            &store,
            std::future::pending(),
            |_| {},
        );
        tokio::pin!(task);
        tokio::select! {
            _ = &mut task => panic!("Preparation must still be in progress"),
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
        let mut state = store.snapshot().unwrap();
        recover_interrupted(&mut state);
        assert_eq!(state.environments[0].status, EnvironmentStatus::Error);
        assert!(state.environments[0]
            .last_error
            .as_ref()
            .unwrap()
            .contains("closed before"));
    }

    #[tokio::test]
    async fn vm_creation_save_failure_clears_the_live_spinner() {
        let data = tempfile::tempdir().unwrap();
        let path = data.path().join("state.json");
        let store = PlatformStore::load(path.clone()).unwrap();
        let (request, policy) = fixture();
        let failed = create_on_graph(
            &request,
            policy,
            "env-save-failure",
            &store,
            async {
                // Block only this temporary fixture's final atomic write.
                std::fs::create_dir(path.with_extension("json.tmp")).unwrap();
                Ok((Some("managed/system.qcow2".into()), "managed/source.iso".into()))
            },
            |_| {},
        )
        .await;
        assert!(failed.unwrap_err().contains("Could not save"));
        assert_eq!(
            store.snapshot().unwrap().environments[0].status,
            EnvironmentStatus::Error
        );
        let persisted: PlatformState =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(
            persisted.environments[0].status,
            EnvironmentStatus::Provisioning
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "creates an isolated VM disk using bundled QEMU; never starts a VM or touches user environments"]
    async fn vm_creation_real_disk_keeps_the_announced_node_id() {
        let data = tempfile::tempdir().unwrap();
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let runtime = RuntimeManager::new(&root, data.path()).unwrap();
        let store = PlatformStore::load(data.path().join("state.json")).unwrap();
        let (mut request, policy) = fixture();
        request.runtime = root
            .join("resources/runtime/appliance/appliance-base.qcow2")
            .to_string_lossy()
            .into_owned();
        let result = create_on_graph(
            &request,
            policy,
            "env-test-create",
            &store,
            async {
                assert_eq!(
                    store.snapshot()?.environments[0].status,
                    EnvironmentStatus::Provisioning
                );
                let disk = runtime
                    .provision_vm("env-test-create", &request.runtime)
                    .await?;
                Ok((
                    Some(disk.disk_path.to_string_lossy().into_owned()),
                    disk.source_path.to_string_lossy().into_owned(),
                ))
            },
            |_| {},
        )
        .await
        .unwrap();
        let environment = &result.environments[0];
        assert_eq!(environment.id, "env-test-create");
        assert_eq!(environment.status, EnvironmentStatus::Stopped);
        assert!(PathBuf::from(environment.runtime_path.as_ref().unwrap()).is_file());
        runtime.delete_vm("env-test-create").await.unwrap();
        runtime.shutdown_all().await;
    }
}
