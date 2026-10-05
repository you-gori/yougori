use super::*;

pub(crate) fn ensure_complete(state: &PlatformState, id: &str) -> Result<(), String> {
    if state
        .pending_factory_resets
        .iter()
        .any(|p| p.environment.id == id)
    {
        return Err(
            "Finish the pending Factory reset before modifying or backing up this environment"
                .into(),
        );
    }
    Ok(())
}

pub(crate) fn recover_interrupted(state: &mut PlatformState) {
    for entry in &state.pending_factory_resets {
        if let Some(environment) = state
            .environments
            .iter_mut()
            .find(|e| e.id == entry.environment.id)
        {
            environment.status = EnvironmentStatus::Error;
            environment.last_error = Some("Factory reset was interrupted. Use Factory reset again to finish cleanup safely. External backups and the original image are unchanged.".into());
        }
    }
}

/// Journal entries can only refer to inactive generations, never a live node's disk.
fn validate_cleanup(state: &PlatformState, entry: &FactoryResetCleanup) -> Result<(), String> {
    if state
        .environments
        .iter()
        .any(|e| runtime_id(e) == runtime_id(&entry.environment))
    {
        return Err("Refusing to delete the active environment generation".into());
    }
    if matches!(entry.environment.kind, EnvironmentKind::ComputerBranch | EnvironmentKind::Cloud)
        || provider(&entry.environment) == RuntimeProviderKind::NativeSandbox
    {
        return Err("Factory reset is only supported for containers, MicroVMs and VMs".into());
    }
    Ok(())
}

pub(super) async fn cleanup_pending(
    id: &str,
    store: &PlatformStore,
    runtime: &RuntimeManager,
    backup: &BackupManager,
) -> Result<bool, String> {
    let entries = store
        .snapshot()?
        .pending_factory_resets
        .into_iter()
        .filter(|p| p.environment.id == id)
        .collect::<Vec<_>>();
    let committed = entries.iter().any(|p| p.committed);
    for entry in entries {
        validate_cleanup(&store.snapshot()?, &entry)?;
        for snapshot in &entry.snapshots {
            // Internal VM snapshots disappear with the retired disk. External backups stay.
            if provider(&entry.environment).is_container() {
                runtime
                    .delete_container_snapshot(runtime_id(&entry.environment), &snapshot.id)
                    .await?;
            }
            if let Some(path) = snapshot.artifact_path.as_deref().map(PathBuf::from) {
                if path.exists() {
                    if let Err(error) = runtime.remove_snapshot_artifact(&path).await {
                        backup
                            .delete_restore_artifact(&path)
                            .await
                            .map_err(|e| format!("{error}; {e}"))?;
                    }
                }
            }
        }
        match provider(&entry.environment) {
            RuntimeProviderKind::YougoriOci | RuntimeProviderKind::YougoriCuda => {
                runtime
                    .delete_container(runtime_id(&entry.environment))
                    .await?
            }
            RuntimeProviderKind::Qemu => runtime.delete_vm(runtime_id(&entry.environment)).await?,
            _ => unreachable!(),
        }
        store.mutate(|state| {
            state
                .pending_factory_resets
                .retain(|p| runtime_id(&p.environment) != runtime_id(&entry.environment));
            Ok(())
        })?;
    }
    Ok(committed)
}

fn finish_state(state: &mut PlatformState, id: &str) -> Result<(), String> {
    let environment = state
        .environments
        .iter_mut()
        .find(|e| e.id == id)
        .ok_or("Environment not found")?;
    environment.status = EnvironmentStatus::Stopped;
    environment.last_error = None;
    environment.console_endpoint = None;
    environment.control_endpoint = None;
    environment.last_opened_at = None;
    environment.cpu_usage = 0.0;
    environment.memory_usage_gb = 0.0;
    environment.storage_delta_gb = 0.0;
    environment.network_rx_mbps = 0.0;
    environment.resource_policy.cpu.current = 0.0;
    environment.resource_policy.memory_gb.current = 0.0;
    for connection in &mut state.connections {
        if connection.source_id == id || connection.target_id == id {
            connection.enforcement_status = Some(EnforcementStatus::Pending);
            connection.provider_rule_ids.clear();
            connection.last_error = None;
        }
    }
    Ok(())
}

pub(super) async fn reset(
    id: &str,
    store: &PlatformStore,
    runtime: &RuntimeManager,
    backup: &BackupManager,
) -> Result<PlatformState, String> {
    let environment = store.environment(&id)?;
    if !matches!(
        environment.status,
        EnvironmentStatus::Stopped | EnvironmentStatus::Error
    ) {
        return Err("Shut down this environment before factory reset".into());
    }
    if matches!(environment.kind, EnvironmentKind::ComputerBranch | EnvironmentKind::Cloud)
        || provider(&environment) == RuntimeProviderKind::NativeSandbox
    {
        return Err("Factory reset is only supported for containers, MicroVMs and VMs".into());
    }
    if store
        .snapshot()?
        .backup_runs
        .iter()
        .any(|run| run.environment_id == id && run.status == BackupRunStatus::Running)
    {
        return Err("Wait for the current backup to finish before factory reset".into());
    }
    if cleanup_pending(id, store, runtime, backup).await? {
        // A crash after commit needs deletion only, not a second destructive reset.
        return store.mutate(|state| finish_state(state, id));
    }
    if provider(&environment) == RuntimeProviderKind::Qemu
        && runtime.vm_is_running(runtime_id(&environment)).await?
    {
        return Err("The VM is still running. Shut it down before factory reset".into());
    }
    let mut fresh = environment.clone();
    fresh.runtime_id = Some(format!("reset-{}", Uuid::new_v4()));
    fresh.runtime_path = None;
    store.mutate(|state| {
        state.pending_factory_resets.push(FactoryResetCleanup {
            environment: fresh.clone(),
            snapshots: vec![],
            committed: false,
        });
        let current = state
            .environments
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or("Environment not found")?;
        current.status = EnvironmentStatus::Provisioning;
        current.last_error = None;
        Ok(())
    })?;
    let prepared = async {
        match provider(&environment) {
            RuntimeProviderKind::YougoriOci | RuntimeProviderKind::YougoriCuda => {
                runtime
                    .provision_reset_container(
                        runtime_id(&fresh),
                        runtime_id(&environment),
                        &environment,
                    )
                    .await?
            }
            RuntimeProviderKind::Qemu => {
                let prepared = if environment.kind == EnvironmentKind::MicroVm {
                    runtime
                        .provision_reset_micro_vm(
                            runtime_id(&environment),
                            runtime_id(&fresh),
                            &vm_disk(&environment)?,
                        )
                        .await?
                } else {
                    runtime
                        .provision_reset_full_vm(
                            runtime_id(&environment),
                            runtime_id(&fresh),
                            &environment.runtime,
                            &vm_disk(&environment)?,
                        )
                        .await?
                };
                fresh.runtime_path = Some(prepared.disk_path.to_string_lossy().into_owned());
                if environment.runtime != BUILTIN_MICRO_VM_SOURCE {
                    fresh.runtime = prepared.source_path.to_string_lossy().into_owned();
                }
            }
            _ => unreachable!(),
        }
        Ok::<(), String>(())
    }
    .await;
    if let Err(error) = prepared {
        let cleanup = cleanup_pending(id, store, runtime, backup).await.err();
        let message = format!(
            "Factory reset did not replace your environment: {error}{}",
            cleanup
                .map(|e| format!(". Temporary cleanup needs retry: {e}"))
                .unwrap_or_default()
        );
        store.mutate(|state| {
            let current = state
                .environments
                .iter_mut()
                .find(|e| e.id == id)
                .ok_or("Environment not found")?;
            current.status = EnvironmentStatus::Error;
            current.last_error = Some(message.clone());
            Ok(())
        })?;
        return Err(message);
    }
    // One durable commit switches disk + security identity and journals exactly what can be erased.
    store.mutate(|state| {
        let snapshots = state
            .snapshots
            .iter()
            .filter(|s| s.environment_id == id)
            .cloned()
            .collect();
        state.snapshots.retain(|s| s.environment_id != id);
        state
            .pending_factory_resets
            .retain(|p| p.environment.id != id);
        state.pending_factory_resets.push(FactoryResetCleanup {
            environment: environment.clone(),
            snapshots,
            committed: true,
        });
        let current = state
            .environments
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or("Environment not found")?;
        current.runtime_id = fresh.runtime_id.clone();
        current.runtime_path = fresh.runtime_path.clone();
        current.runtime = fresh.runtime.clone();
        Ok(())
    })?;
    forget_applied_resource_limits(runtime_id(&environment));
    if let Err(error) = cleanup_pending(id, store, runtime, backup).await {
        let message = format!("The fresh image is ready, but old data cleanup is incomplete: {error}. Use Factory reset again to finish cleanup; it will not reset the new disk twice.");
        store.mutate(|state| {
            let current = state
                .environments
                .iter_mut()
                .find(|e| e.id == id)
                .ok_or("Environment not found")?;
            current.status = EnvironmentStatus::Error;
            current.last_error = Some(message.clone());
            Ok(())
        })?;
        return Err(message);
    }
    store.mutate(|state| finish_state(state, id))
}

#[tauri::command]
pub async fn factory_reset_environment(
    environment_id: String,
    confirmation: String,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
    backup: State<'_, BackupManager>,
    workspace: State<'_, crate::workspace::WorkspaceManager>,
) -> Result<PlatformState, String> {
    let lock = environment_network_lock(&environment_id).await;
    let _guard = lock.lock().await;
    let environment = store.environment(&environment_id)?;
    let _resources = environment_container_policy_guard(&runtime, &environment).await?;
    if confirmation != environment.name {
        return Err("Type the environment name exactly to confirm factory reset".into());
    }
    let result = reset(&environment_id, &store, &runtime, &backup).await;
    if let Err(error) = &result {
        // Includes failure to persist the generation switch: keep the journal
        // and expose retry rather than leaving a permanent Provisioning spinner.
        let recover = |state: &mut PlatformState| {
            recover_interrupted(state);
            if let Some(current) = state
                .environments
                .iter_mut()
                .find(|e| e.id == environment_id)
            {
                if current.status == EnvironmentStatus::Provisioning {
                    current.status = EnvironmentStatus::Error;
                    current.last_error = Some(format!("Factory reset could not finish saving its state: {error}. Free disk space if needed, then retry."));
                }
            }
            Ok(())
        };
        if store.mutate(recover).is_err() {
            let _ = store.mutate_ephemeral(recover);
        }
    }
    workspace.cleanup(&store, &runtime).await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(id: &str, kind: &str, provider: &str, source: &str) -> Environment {
        serde_json::from_value(serde_json::json!({
            "id":id,"name":id,"kind":kind,"provider":provider,"runtime":source,
            "status":"stopped","description":"Reset test","createdAt":now(),
            "containerCommand":"sleep 2147483647", "cpuUsage":0,"memoryUsageGb":0,
            "storageDeltaGb":0,"networkRxMbps":0,
            "resourcePolicy":{"cpu":{"min":1,"preferred":1,"max":1,"current":0},
            "memoryGb":{"min":0.5,"preferred":0.5,"max":0.5,"current":0},"priority":"normal","dynamic":false}
        })).unwrap()
    }
    fn state_fixture() -> PlatformState {
        let mut state = PlatformState::empty().unwrap();
        state.environments = vec![
            fixture("one", "container", "yougoriOci", "alpine"),
            fixture("two", "container", "yougoriOci", "alpine"),
        ];
        state
    }
    #[test]
    fn factory_reset_cleanup_refuses_active_generation() {
        let state = state_fixture();
        let mut entry = FactoryResetCleanup {
            environment: state.environments[0].clone(),
            snapshots: vec![],
            committed: true,
        };
        assert!(validate_cleanup(&state, &entry)
            .unwrap_err()
            .contains("active"));
        entry.environment.runtime_id = Some("reset-retired".into());
        entry.environment.kind = EnvironmentKind::Container;
        entry.environment.provider = Some(RuntimeProviderKind::YougoriOci);
        assert!(validate_cleanup(&state, &entry).is_ok());
    }
    #[test]
    fn factory_reset_finish_preserves_settings_and_other_nodes() {
        let mut state = state_fixture();
        let before = state.environments[0].clone();
        let others = serde_json::to_value(&state.environments[1..]).unwrap();
        finish_state(&mut state, &before.id).unwrap();
        let after = &state.environments[0];
        assert_eq!(after.status, EnvironmentStatus::Stopped);
        assert_eq!(after.runtime, before.runtime);
        assert_eq!(after.network_access, before.network_access);
        assert_eq!(
            after.resource_policy.memory_gb.max,
            before.resource_policy.memory_gb.max
        );
        assert_eq!(
            serde_json::to_value(&state.environments[1..]).unwrap(),
            others
        );
    }

    #[tokio::test]
    #[ignore = "boots only disposable MicroVMs and containers to verify actual factory reset and persistence"]
    async fn factory_reset_native_guests_erase_only_target_data() -> Result<(), String> {
        let data = tempfile::tempdir().unwrap();
        let runtime = RuntimeManager::new(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")),
            data.path(),
        )?;
        let store = PlatformStore::load(data.path().join("state.json"))?;
        let backup = BackupManager::new(data.path())?;
        async fn micro_command(
            runtime: &RuntimeManager,
            id: &str,
            command: &str,
        ) -> Result<CommandResult, String> {
            let deadline = Instant::now() + Duration::from_secs(70);
            loop {
                match runtime.execute_micro_vm_command(id, command).await {
                    Ok(result) => return Ok(result),
                    Err(error) if Instant::now() >= deadline => return Err(error),
                    Err(_) => tokio::time::sleep(Duration::from_millis(250)).await,
                }
            }
        }
        let result = async {
            let mut micro = fixture("reset-micro", "microVm", "qemu", BUILTIN_MICRO_VM_SOURCE);
            let vm = runtime.provision_micro_vm(&micro.id, &micro.runtime).await?;
            micro.runtime_path = Some(vm.disk_path.to_string_lossy().into_owned());
            runtime.grow_vm_storage(&micro.id, &vm.disk_path, 8.0).await?;
            store.mutate(|state| { state.environments.push(micro.clone()); Ok(()) })?;
            runtime.start_micro_vm(&micro.id, &vm.disk_path, &vm.source_path, &micro.resource_policy).await?;
            assert_eq!(micro_command(&runtime, &micro.id, "echo saved > /root/reset-marker; sync").await?.exit_code, 0);
            runtime.vm_action(&micro.id, "stop").await?;
            runtime.start_micro_vm(&micro.id, &vm.disk_path, &vm.source_path, &micro.resource_policy).await?;
            assert_eq!(micro_command(&runtime, &micro.id, "cat /root/reset-marker").await?.stdout.trim(), "saved", "ordinary stop/start must persist data without snapshots");
            runtime.vm_action(&micro.id, "stop").await?;
            let state = reset(&micro.id, &store, &runtime, &backup).await?;
            let clean = &state.environments[0];
            assert_ne!(runtime_id(clean), runtime_id(&micro));
            assert!(!vm.disk_path.exists());
            assert_eq!(runtime.vm_storage_allocation(runtime_id(clean), &vm_disk(clean)?).await?.capacity_gb, 8.0);
            runtime.start_micro_vm_with_network(runtime_id(clean), &vm_disk(clean)?, &micro_vm_manifest(clean)?, &clean.resource_policy, clean.network_access).await?;
            assert_eq!(micro_command(&runtime, runtime_id(clean), "test ! -e /root/reset-marker && echo fresh").await?.stdout.trim(), "fresh");
            runtime.vm_action(runtime_id(clean), "stop").await?;
            eprintln!("MicroVM: persistence without snapshots, erased writable files, retained 8 GB capacity verified");

            let image = "quay.io/libpod/alpine:latest";
            let container = fixture("reset-container", "container", "yougoriOci", image);
            let sibling = fixture("reset-sibling", "container", "yougoriOci", image);
            for env in [&container, &sibling] {
                runtime.provision_container(&env.id, image, env.container_command.as_deref().unwrap(), &env.resource_policy, false, false).await?;
                runtime.container_action(&env.id, "start", false).await?;
                assert_eq!(runtime.execute_container_command(&env.id, "echo saved > /root/reset-marker; sync").await?.exit_code, 0);
            }
            runtime.container_action(&container.id, "stop", false).await?;
            let artifact = runtime.create_container_snapshot(&container.id, "reset-snapshot", image, container.container_command.as_deref().unwrap()).await?;
            runtime.import_container_snapshot("reset-snapshot", &artifact.path).await?;
            runtime.restore_container_snapshot(&container.id, "reset-snapshot", image, container.container_command.as_deref().unwrap(), false, false).await?;
            store.mutate(|state| {
                state.environments.extend([container.clone(), sibling.clone()]);
                state.snapshots.push(Snapshot {
                    id: "reset-snapshot".into(), environment_id: container.id.clone(), name: "Before reset".into(), created_at: now(), size_gb: 0.0, delta_gb: 0.0, encrypted: false, status: SnapshotStatus::Ready,
                    provider_snapshot_id: Some(artifact.provider_snapshot_id.clone()), artifact_path: Some(artifact.path.to_string_lossy().into_owned()), artifact_size_bytes: Some(artifact.size_bytes), checksum_sha256: Some(artifact.checksum_sha256.clone()), environment_state: None, connections: None,
                });
                Ok(())
            })?;
            let state = reset(&container.id, &store, &runtime, &backup).await?;
            let clean = state.environments.iter().find(|e| e.id == container.id).unwrap();
            runtime.container_action(runtime_id(clean), "start", false).await?;
            assert_eq!(runtime.execute_container_command(runtime_id(clean), "test ! -e /root/reset-marker && echo fresh").await?.stdout.trim(), "fresh");
            assert_eq!(runtime.execute_container_command(&sibling.id, "cat /root/reset-marker").await?.stdout.trim(), "saved", "running sibling data must be untouched");
            runtime.container_action(runtime_id(clean), "stop", false).await?;
            assert!(state.pending_factory_resets.is_empty());
            assert!(state.snapshots.is_empty());
            assert!(!artifact.path.exists(), "local snapshot data must be erased too");
            eprintln!("Container: original cached image reused, target erased, running sibling untouched");
            Ok(())
        }.await;
        runtime.shutdown_all().await;
        result
    }

    #[tokio::test]
    #[ignore = "uses bundled qemu-img on disposable VM disks; never boots an installer"]
    async fn factory_reset_vm_preserves_installer_and_recovers_commit() -> Result<(), String> {
        let data = tempfile::tempdir().unwrap();
        let runtime = RuntimeManager::new(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")),
            data.path(),
        )?;
        let store = PlatformStore::load(data.path().join("state.json"))?;
        let backup = BackupManager::new(data.path())?;
        let iso = data.path().join("Windows11-fixture.iso");
        std::fs::write(&iso, vec![0_u8; 65536]).map_err(|e| e.to_string())?;
        let vm = runtime
            .provision_vm_with_storage("reset-vm", iso.to_str().unwrap(), Some(12.0))
            .await?;
        let mut env = fixture(
            "reset-vm",
            "fullVm",
            "qemu",
            vm.source_path.to_str().unwrap(),
        );
        env.runtime_path = Some(vm.disk_path.to_string_lossy().into_owned());
        let source_bytes = std::fs::read(&vm.source_path).map_err(|e| e.to_string())?;
        assert!(runtime.vm_security_enabled(&env.id)?);
        let old_profile = std::fs::read(vm.disk_path.parent().unwrap().join("vm-security.json"))
            .map_err(|e| e.to_string())?;
        store.mutate(|state| {
            state.environments.push(env.clone());
            Ok(())
        })?;
        let state = reset(&env.id, &store, &runtime, &backup).await?;
        let fresh = state.environments[0].clone();
        assert!(runtime.vm_security_enabled(runtime_id(&fresh))?);
        let new_profile =
            std::fs::read(vm_disk(&fresh)?.parent().unwrap().join("vm-security.json"))
                .map_err(|e| e.to_string())?;
        assert_ne!(
            old_profile, new_profile,
            "factory reset must create a fresh private TPM identity"
        );
        assert!(!vm.disk_path.exists());
        assert_eq!(fresh.runtime, env.runtime);
        assert_eq!(
            runtime
                .vm_storage_allocation(runtime_id(&fresh), &vm_disk(&fresh)?)
                .await?
                .capacity_gb,
            12.0
        );
        assert_eq!(
            std::fs::read(&vm.source_path).map_err(|e| e.to_string())?,
            source_bytes
        );

        // Simulate restart after the durable switch but before deleting a retired generation.
        let retired = runtime
            .provision_vm("retired-fixture", iso.to_str().unwrap())
            .await?;
        let mut old = env.clone();
        old.runtime_id = Some("retired-fixture".into());
        old.runtime_path = Some(retired.disk_path.to_string_lossy().into_owned());
        store.mutate(|state| {
            state.pending_factory_resets.push(FactoryResetCleanup {
                environment: old,
                snapshots: vec![],
                committed: true,
            });
            recover_interrupted(state);
            Ok(())
        })?;
        let state = reset(&env.id, &store, &runtime, &backup).await?;
        assert_eq!(
            runtime_id(&state.environments[0]),
            runtime_id(&fresh),
            "retry must not create another generation"
        );
        assert!(!retired.disk_path.exists());
        assert!(vm_disk(&fresh)?.exists());
        assert!(state.pending_factory_resets.is_empty());

        // Missing source must not erase the current disk.
        store.mutate(|state| {
            state.environments[0].runtime = "missing-installer.iso".into();
            Ok(())
        })?;
        assert!(reset(&env.id, &store, &runtime, &backup).await.is_err());
        assert!(vm_disk(&fresh)?.exists());
        assert!(store.snapshot()?.pending_factory_resets.is_empty());
        Ok(())
    }
}
