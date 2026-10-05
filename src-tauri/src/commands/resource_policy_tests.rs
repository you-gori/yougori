use super::*;

#[tokio::test]
async fn provider_coordination_is_scoped_to_the_provider_and_original_storage_pool() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let a = container_policy_lock(first.path(), &RuntimeProviderKind::YougoriOci).await;
    let same = container_policy_lock(first.path(), &RuntimeProviderKind::YougoriOci).await;
    let other_provider = container_policy_lock(first.path(), &RuntimeProviderKind::YougoriCuda).await;
    let other_drive = container_policy_lock(second.path(), &RuntimeProviderKind::YougoriOci).await;
    assert!(std::sync::Arc::ptr_eq(&a, &same));
    let _held = a.lock_owned().await;
    assert!(same.try_lock_owned().is_err());
    assert!(other_provider.try_lock_owned().is_ok());
    assert!(other_drive.try_lock_owned().is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "boots a disposable container to verify edited policies against actual cgroups"]
async fn saved_container_resources_reach_cgroups_on_start_and_live_save() -> Result<(), String> {
    let data = tempfile::tempdir().unwrap();
    let runtime = RuntimeManager::new(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")),
        data.path(),
    )?;
    let id = format!("env-resource-{}", Uuid::new_v4().simple());
    let mut env: Environment = serde_json::from_value(serde_json::json!({
        "id":id,"name":"Resource fixture","kind":"container","provider":"yougoriOci","status":"stopped",
        "runtime":"quay.io/libpod/alpine:latest","description":"","createdAt":"test","cpuUsage":0,"memoryUsageGb":0,"storageDeltaGb":0,"networkRxMbps":0,
        "resourcePolicy":{"cpu":{"min":0.5,"preferred":0.5,"max":0.5,"current":0},"memoryGb":{"min":0.5,"preferred":0.5,"max":0.5,"current":0},"priority":"normal","dynamic":true}
    })).unwrap();
    let result = async {
        // Reserve the final envelope up front; no active workload needs a restart.
        runtime.ensure_container_capacity(4.0, 8.0).await?;
        runtime.provision_container(&id, &env.runtime, "sleep 2147483647", &env.resource_policy, false, false).await?;
        // Editing a stopped node persists a policy but does not rewrite its OCI spec.
        env.resource_policy.cpu = ResourceRange { min: 3.0, preferred: 4.0, max: 4.0, current: 0.0 };
        env.resource_policy.memory_gb = ResourceRange { min: 5.0, preferred: 6.0, max: 8.0, current: 0.0 };
        let mut state = PlatformState::empty().map_err(|e| e.to_string())?;
        state.environments = vec![env.clone()];
        prepare_container_start(&state, &env, &runtime, None).await?;
        runtime.container_action(&id, "start", false).await?;
        let first = runtime.execute_container_command(&id, "cat /sys/fs/cgroup/cpu.max /sys/fs/cgroup/memory.max").await?;
        if first.exit_code != 0 || !first.stdout.contains("400000 100000\n6442450944") {
            return Err(format!("Saved 4 CPU / 6 GiB policy was not applied at start: {}", first.stdout));
        }
        // A stale cache must not prevent Save from repairing a running container.
        runtime.update_container_resources(&id, 0.5, 0.5).await?;
        record_applied_resource_limits(&id, 4.0, 6.0);
        env.status = EnvironmentStatus::Running;
        env.resource_policy.cpu.current = 4.0;
        env.resource_policy.memory_gb.current = 6.0;
        state.environments = vec![env.clone()];
        prepare_container_start(&state, &env, &runtime, None).await?;
        let repaired = runtime.execute_container_command(&id, "cat /sys/fs/cgroup/cpu.max /sys/fs/cgroup/memory.max").await?;
        if repaired.exit_code != 0 || !repaired.stdout.contains("400000 100000\n6442450944") {
            return Err(format!("Live save trusted stale applied limits: {}", repaired.stdout));
        }
        // A subsequent live edit must keep the existing process and guest data.
        let before = runtime.execute_container_command(&id, "printf keep-me > /root/resource-marker; cat /proc/1/stat").await?;
        env.resource_policy.cpu.preferred = 3.5;
        env.resource_policy.memory_gb.preferred = 5.5;
        state.environments = vec![env.clone()];
        prepare_container_start(&state, &env, &runtime, None).await?;
        let changed = runtime.execute_container_command(&id, "cat /sys/fs/cgroup/cpu.max /sys/fs/cgroup/memory.max /root/resource-marker").await?;
        if changed.exit_code != 0 || !changed.stdout.contains("350000 100000\n5905580032\nkeep-me") {
            return Err(format!("Live changed limits did not reach cgroups: {}", changed.stdout));
        }
        let after = runtime.execute_container_command(&id, "cat /proc/1/stat").await?;
        if before.stdout.split_whitespace().nth(21) != after.stdout.split_whitespace().nth(21) { return Err("Resource save restarted the container process".into()); }
        env.resource_policy.cpu.current = 1.5;
        env.resource_policy.memory_gb.current = 2.5;
        apply_scheduled_resource_limits(&runtime, &env).await?;
        let scheduled = runtime.execute_container_command(&id, "cat /sys/fs/cgroup/cpu.max /sys/fs/cgroup/memory.max /root/resource-marker").await?;
        if scheduled.exit_code != 0 || !scheduled.stdout.contains("150000 100000\n2684354560\nkeep-me") {
            return Err(format!("Scheduled limits did not reach cgroups: {}", scheduled.stdout));
        }
        if resource_update_needed(&id, 1.5, 2.5) { return Err("Applied scheduled limits were not recorded".into()); }
        eprintln!("Saved-on-stop policy, stale-cache repair, live edits and scheduled limits match real cgroups; process and files preserved.");
        Ok(())
    }.await;
    runtime.shutdown_all().await;
    forget_applied_resource_limits(&id);
    result
}
