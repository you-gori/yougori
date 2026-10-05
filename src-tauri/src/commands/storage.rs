use super::*;
use crate::runtime::storage::StorageAllocation;

#[tauri::command]
pub fn get_storage_location(runtime: State<'_, RuntimeManager>) -> String { runtime.storage_root().to_string_lossy().into_owned() }

/// Select before creating/importing environments. Existing data is never moved or
/// silently abandoned; use verified backup/export and restore to change its drive.
#[tauri::command]
pub async fn set_storage_location(path: String, app: AppHandle, store: State<'_, PlatformStore>, runtime: State<'_, RuntimeManager>) -> Result<(), String> {
    let mut _storage_guards = Vec::new();
    for provider in [RuntimeProviderKind::YougoriOci, RuntimeProviderKind::YougoriCuda] {
        _storage_guards.push(container_policy_lock(runtime.storage_root(), &provider).await.lock_owned().await);
    }
    let selected = std::path::PathBuf::from(path);
    if !selected.is_absolute() { return Err("Choose an absolute folder path on your preferred drive".into()); }
    let selected = selected.canonicalize().map_err(|e|format!("Choose an existing folder: {e}"))?;
    if !selected.is_dir() || selected.parent().is_none() { return Err("Choose a dedicated folder, not a drive root".into()); }
    let target = selected.join("runtime");
    let current = runtime.storage_root().canonicalize().map_err(|e|e.to_string())?;
    if target.canonicalize().is_ok_and(|p| p == current) { return Ok(()); }
    if target.exists() { return Err("This folder already contains runtime data. Choose an empty, dedicated folder; existing data will not be overwritten.".into()); }
    if selected.starts_with(&current) || current.starts_with(&selected) { return Err("Choose a separate folder outside the current runtime".into()); }
    let probe = tempfile::NamedTempFile::new_in(&selected).map_err(|e|format!("This folder is not writable: {e}"))?;
    drop(probe);
    let disks = sysinfo::Disks::new_with_refreshed_list();
    if crate::runtime::storage::runtime_disk(&disks, &selected).is_some_and(|d| d.available_space() < 2 * 1024 * 1024 * 1024) { return Err("The selected drive needs at least 2 GB free before creating environments".into()); }
    store.mutate(|state| {
        if !state.environments.is_empty() || !state.snapshots.is_empty() || state.backup_runs.iter().any(|r|r.status == BackupRunStatus::Running) {
            return Err("Export your existing environments, then remove them before switching storage. Restore the exports after restarting. Yougori will not move or discard existing disks automatically.".into());
        }
        state.settings.data_directory = selected.to_string_lossy().into_owned();
        Ok(())
    })?;
    runtime.shutdown_all().await;
    crate::restart_engine(&app)
}

#[tauri::command]
pub async fn reclaim_storage(store: State<'_, PlatformStore>, runtime: State<'_, RuntimeManager>) -> Result<EnvironmentDeletionResult, String> {
    let mut cleanup = StorageCleanupResult::default();
    for provider in [RuntimeProviderKind::YougoriOci, RuntimeProviderKind::YougoriCuda] {
        let mut _pool_guards = Vec::new();
        for root in runtime.storage_pool_roots() {
            _pool_guards.push(container_policy_lock(&root, &provider).await.lock_owned().await);
        }
        match runtime.reclaim_container_storage(&provider).await {
            Ok(result) => {
                cleanup.reclaimed_disk_bytes = cleanup.reclaimed_disk_bytes.saturating_add(result.reclaimed_disk_bytes);
                cleanup.warnings.extend(result.warnings);
                cleanup.notes.extend(result.notes);
            }
            Err(error) => cleanup.warnings.push(format!("{} storage: {error}", if provider == RuntimeProviderKind::YougoriCuda { "GPU" } else { "Standard container" })),
        }
    }
    let current = store.snapshot()?;
    match runtime.garbage_collect_vm_bases(&referenced_vm_sources(&current)).await {
        Ok(bytes) => cleanup.reclaimed_cache_bytes = bytes,
        Err(error) => cleanup.warnings.push(format!("Unused VM images were kept: {error}")),
    }
    cleanup.notes.sort();
    cleanup.notes.dedup();
    if let Some(sampler) = HOST_SAMPLER.get() {
        let mut sampler = sampler.lock().unwrap_or_else(|p| p.into_inner());
        sampler.disks.refresh(true);
        sampler.last_disk_refresh = Instant::now();
    }
    let state = store.mutate_ephemeral(|state| {
        state.host = collect_host_metrics(&state.host, runtime.storage_root());
        Ok(())
    })?;
    Ok(EnvironmentDeletionResult { state, storage_cleanup: cleanup })
}

#[tauri::command]
pub async fn get_storage_allocation(environment_id: Option<String>, new_vm: Option<bool>, storage_drive: Option<String>, store: State<'_, PlatformStore>, runtime: State<'_, RuntimeManager>) -> Result<StorageAllocation, String> {
    let _ = new_vm;
    let Some(id) = environment_id else { return runtime.new_storage_on_drive(storage_drive.as_deref()); };
    let environment = store.environment(&id)?;
    match provider(&environment) {
        RuntimeProviderKind::YougoriOci | RuntimeProviderKind::YougoriCuda => runtime.container_storage_allocation(runtime_id(&environment)).await,
        RuntimeProviderKind::Qemu => runtime.vm_storage_allocation(runtime_id(&environment), &vm_disk(&environment)?).await,
        _ => Err("Storage allocation is not available for this environment.".into()),
    }
}

#[tauri::command]
pub async fn expand_environment_storage(environment_id: String, capacity_gb: f64, store: State<'_, PlatformStore>, runtime: State<'_, RuntimeManager>) -> Result<StorageAllocation, String> {
    crate::runtime::storage::storage_bytes(capacity_gb)?;
    let network_lock = environment_network_lock(&environment_id).await;
    let _environment_guard = network_lock.lock().await;
    let state = store.snapshot()?;
    let environment = state.environments.iter().find(|e| e.id == environment_id).ok_or("Environment not found")?;
    let _serial = environment_container_policy_guard(&runtime, environment).await?;
    match provider(environment) {
        RuntimeProviderKind::YougoriOci | RuntimeProviderKind::YougoriCuda => {
            let allocation = runtime.set_container_storage(runtime_id(environment), capacity_gb).await?;
            store.mutate(|state| {
                let item = state.environments.iter_mut().find(|e| e.id == environment_id).ok_or("Environment not found")?;
                item.storage_limit_gb = Some(allocation.capacity_gb);
                Ok(())
            })?;
            Ok(allocation)
        },
        RuntimeProviderKind::Qemu if environment.kind != EnvironmentKind::ComputerBranch => {
            if environment.status != EnvironmentStatus::Stopped { return Err("Stop the environment before expanding storage.".into()); }
            runtime.grow_vm_storage(runtime_id(environment), &vm_disk(environment)?, capacity_gb).await
        },
        _ => Err("Storage expansion is not available for this environment.".into()),
    }
}
