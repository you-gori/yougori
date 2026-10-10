mod backup;
mod automation;
mod local_backup;
mod environment_download;
mod commands;
mod instance_lock;
mod host_files;
mod file_import;
mod temporary_storage;
mod host_terminal;
#[cfg(all(target_os = "windows", not(feature = "engine-only")))]
mod node_context_menu;
mod workspace;
mod guest_apps;
mod guest_execution;
mod guest_keyboard;
mod models;
mod runtime;
mod scheduler;
mod lifecycle;
mod shutdown;
#[cfg(all(desktop, not(feature = "engine-only")))]
mod tray;
mod peer_sharing;
mod remote_access;
mod isolated_cli;
mod cloud_deployment;
mod cloud_options;
mod neocloud;
mod duplication;
mod projects;
mod changes;
mod releases;
mod model_runner;
mod market;
mod swarm;
mod model_registry;
mod file_export;
mod ignore_rules;
mod vault;
mod vault_gateway;
mod vault_setup;
#[cfg(target_os = "windows")]
mod vault_notifications;
mod store;
#[cfg(all(test, target_os = "windows", not(feature = "engine-only")))]
mod window_smoke_tests;

use crate::store::PlatformStore;
use std::collections::HashSet;
use tauri::{Emitter, Manager};

fn migrate_legacy_app_data(current: &std::path::Path) -> std::io::Result<()> {
    let Some(parent) = current.parent() else {
        return Err(std::io::Error::other("Cannot locate the Yougori data parent folder"));
    };
    let previous = parent.join("com.opendock.desktop");
    if current.join("platform-state.json").exists() || !previous.join("platform-state.json").exists() {
        return Ok(());
    }
    let previous_metadata = std::fs::symlink_metadata(&previous)?;
    if !previous_metadata.is_dir() || previous_metadata.file_type().is_symlink() {
        return Err(std::io::Error::other("Previous Yougori data is not a regular folder; no data was moved."));
    }
    if current.exists() {
        let current_metadata = std::fs::symlink_metadata(current)?;
        if !current_metadata.is_dir() || current_metadata.file_type().is_symlink() {
            return Err(std::io::Error::other("New Yougori data location is not a regular folder; no data was moved."));
        }
        if std::fs::read_dir(current)?.next().is_some() {
            return Err(std::io::Error::other(
                "Both old and new Yougori data folders contain files. No data was moved; resolve the conflict before opening the app.",
            ));
        }
        std::fs::remove_dir(current)?;
    }
    std::fs::rename(previous, current).map_err(|error| {
        std::io::Error::new(error.kind(), format!(
            "Could not move existing Yougori data to its new folder: {error}. Existing data was left in place."
        ))
    })
}

fn relocated_app_storage(previous_storage: &std::path::Path, current_app_data: &std::path::Path) -> Option<std::path::PathBuf> {
    let previous_app_data = current_app_data.parent()?.join("com.opendock.desktop");
    let relative = previous_storage.strip_prefix(&previous_app_data).ok()?;
    let relocated = current_app_data.join(relative);
    (!previous_app_data.exists() && relocated.exists()).then_some(relocated)
}

#[cfg(test)]
mod app_data_migration_tests {
    use super::{migrate_legacy_app_data, relocated_app_storage};

    #[test]
    fn moves_existing_data_without_replacing_a_newer_state() {
        let root = tempfile::tempdir().unwrap();
        let previous = root.path().join("com.opendock.desktop");
        let current = root.path().join("com.yougori.desktop");
        std::fs::create_dir_all(&previous).unwrap();
        std::fs::write(previous.join("platform-state.json"), "old-state").unwrap();
        migrate_legacy_app_data(&current).unwrap();
        assert_eq!(std::fs::read_to_string(current.join("platform-state.json")).unwrap(), "old-state");
        assert!(!previous.exists());
        std::fs::create_dir_all(&previous).unwrap();
        std::fs::write(previous.join("platform-state.json"), "stale-state").unwrap();
        std::fs::write(current.join("platform-state.json"), "new-state").unwrap();
        migrate_legacy_app_data(&current).unwrap();
        assert_eq!(std::fs::read_to_string(current.join("platform-state.json")).unwrap(), "new-state");
    }

    #[test]
    fn refuses_to_merge_two_populated_data_folders() {
        let root = tempfile::tempdir().unwrap();
        let previous = root.path().join("com.opendock.desktop");
        let current = root.path().join("com.yougori.desktop");
        std::fs::create_dir_all(&previous).unwrap();
        std::fs::create_dir_all(&current).unwrap();
        std::fs::write(previous.join("platform-state.json"), "old-state").unwrap();
        std::fs::write(current.join("other-user-file"), "keep").unwrap();
        assert!(migrate_legacy_app_data(&current).is_err());
        assert_eq!(std::fs::read_to_string(previous.join("platform-state.json")).unwrap(), "old-state");
        assert_eq!(std::fs::read_to_string(current.join("other-user-file")).unwrap(), "keep");
    }

    #[test]
    fn remaps_saved_runtime_path_only_after_its_data_was_moved() {
        let root = tempfile::tempdir().unwrap();
        let previous = root.path().join("com.opendock.desktop");
        let current = root.path().join("com.yougori.desktop");
        std::fs::create_dir_all(current.join("runtime")).unwrap();
        assert_eq!(relocated_app_storage(&previous.join("runtime"), &current), Some(current.join("runtime")));
        std::fs::create_dir_all(previous.join("runtime")).unwrap();
        assert!(relocated_app_storage(&previous.join("runtime"), &current).is_none());
    }
}

/// The desktop app runs the engine inside the WebView runtime. The standalone engine
/// (`engine-only` feature, built by ../engine as `yougori-engine`) uses Tauri's windowless
/// runtime: no WebView, windows or tray, so it needs no display.
#[cfg(not(feature = "engine-only"))]
pub(crate) type Rt = tauri::Wry;
#[cfg(feature = "engine-only")]
pub(crate) type Rt = tauri::test::MockRuntime;
pub(crate) type AppHandle = tauri::AppHandle<Rt>;
pub(crate) type WebviewWindow = tauri::WebviewWindow<Rt>;
pub(crate) const ENGINE_ONLY: bool = cfg!(feature = "engine-only");

/// Bundled resources (runtime, vault broker, CLI). The standalone engine keeps them beside its
/// executable on every system, unlike the app bundles' platform-specific resource folders.
pub(crate) fn resource_dir(app: &AppHandle) -> Result<std::path::PathBuf, String> {
    if ENGINE_ONLY {
        let beside = std::env::current_exe().ok().and_then(|exe| exe.parent().map(std::path::Path::to_path_buf));
        if let Some(directory) = beside.filter(|directory| directory.join("runtime").is_dir()) {
            return Ok(directory);
        }
    }
    app.path().resource_dir().map_err(|error| error.to_string())
}

/// Windows exist only in the desktop app.
pub(crate) fn require_windows(what: &str) -> Result<(), String> {
    if ENGINE_ONLY {
        return Err(format!("{what} needs the Yougori app; this computer runs the engine without it. Install or open the app with `yougori app show`."));
    }
    Ok(())
}

struct ShutdownState {
    id: String,
    stopped: std::sync::atomic::AtomicBool,
    exit: std::sync::atomic::AtomicU8,
}

impl Default for ShutdownState {
    fn default() -> Self {
        Self { id: uuid::Uuid::new_v4().to_string(), stopped: Default::default(), exit: Default::default() }
    }
}

pub(crate) fn shutdown_run_id(app: &AppHandle) -> String {
    shutdown_state(app).id.clone()
}

fn shutdown_state(app: &AppHandle) -> std::sync::Arc<ShutdownState> {
    if let Some(state) = app.try_state::<std::sync::Arc<ShutdownState>>() {
        return state.inner().clone();
    }
    // StateManager admits only one value of this type, including concurrent
    // first callers. Read back the admitted value instead of a losing candidate.
    app.manage(std::sync::Arc::new(ShutdownState::default()));
    app.state::<std::sync::Arc<ShutdownState>>().inner().clone()
}

#[cfg(test)]
mod shutdown_state_tests {
    use super::*;
    use std::sync::{atomic::Ordering, Arc};

    #[test]
    fn cleanup_and_exit_of_one_instance_do_not_disable_another() {
        let first = Arc::new(ShutdownState::default());
        let first_window = first.clone();
        let second = Arc::new(ShutdownState::default());
        assert_ne!(first.id, second.id);
        assert!(!first.stopped.swap(true, Ordering::SeqCst));
        assert!(first_window.stopped.swap(true, Ordering::SeqCst));
        first.exit.store(2, Ordering::Release);
        assert!(!second.stopped.swap(true, Ordering::SeqCst));
        assert_eq!(second.exit.load(Ordering::Acquire), 0);
        assert_eq!(first_window.exit.load(Ordering::Acquire), 2);
    }
}

/// Stops guests, terminals and the vault once for this app instance.
fn shutdown_engine(app_handle: &AppHandle) {
    if shutdown_state(app_handle).stopped.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    let report=tauri::async_runtime::block_on(shutdown::run(app_handle));
    if report["requiresReconciliation"] == true { eprintln!("Yougori shutdown reached a cleanup deadline; the recorded outcome requires startup reconciliation."); }
}

// The shutdown above can wait for guest power-down and disk flushes. Keep it off
// the window event loop so Windows can continue to service the app while it quits.

fn shutdown_before_exit(app_handle: &AppHandle, api: &tauri::ExitRequestApi, code: Option<i32>) {
    use std::sync::atomic::Ordering;
    let state = shutdown_state(app_handle);

    // Tauri does not allow a restart request to be cancelled. Preserve its
    // existing cleanup path; ordinary close/quit requests use the worker below.
    if code == Some(tauri::RESTART_EXIT_CODE) {
        shutdown_engine(app_handle);
        return;
    }
    if state.exit.load(Ordering::Acquire) == 2 {
        return;
    }
    api.prevent_exit();
    if state.exit
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    let app = app_handle.clone();
    let exit_code = code.unwrap_or(0);
    std::thread::spawn(move || {
        shutdown_engine(&app);
        state.exit.store(2, Ordering::Release);
        app.exit(exit_code);
    });
}

fn request_main_window_close(app_handle: &AppHandle) {
    if shutdown_state(app_handle).exit.load(std::sync::atomic::Ordering::Acquire) != 0 {
        return;
    }
    let app = app_handle.clone();
    tauri::async_runtime::spawn(async move {
        // A state update can be persisting to disk when the close button is
        // pressed. Do not wait for the store mutex on the window event loop.
        let store_app = app.clone();
        let needs_confirmation = tokio::task::spawn_blocking(move || {
            store_app.state::<PlatformStore>().snapshot()
                .map(|state| state.environments.iter().any(|environment| matches!(
                    environment.status,
                    models::EnvironmentStatus::Running
                        | models::EnvironmentStatus::Paused
                        | models::EnvironmentStatus::Provisioning
                )))
                .unwrap_or(true)
        }).await.unwrap_or(true);
        if needs_confirmation {
            let _ = app.emit_to("main", "app-close-requested", ());
        } else {
            // Closing Desktop quits the whole app, even with other windows open.
            // Explicit exit also bypasses the CLI engine's headless keepalive.
            exit_engine(&app, 0);
        }
    });
}

/// Quits the engine. Desktop exit requests run teardown on a worker; the windowless runtime
/// has no exit request, so the standalone engine tears down on its own thread and ends.
pub(crate) fn exit_engine(app: &AppHandle, code: i32) {
    #[cfg(not(feature = "engine-only"))]
    app.exit(code);
    #[cfg(feature = "engine-only")]
    {
        let app = app.clone();
        std::thread::spawn(move || {
            shutdown_engine(&app);
            std::process::exit(code);
        });
    }
}

/// Restarts the engine process (for example after moving its storage).
pub(crate) fn restart_engine(app: &AppHandle) -> Result<(), String> {
    #[cfg(not(feature = "engine-only"))]
    app.restart();
    #[cfg(feature = "engine-only")]
    {
        let app = app.clone();
        std::thread::spawn(move || {
            shutdown_engine(&app);
            tauri::process::restart(&app.env());
        });
        Ok(())
    }
}

/// A second launch while another engine holds the lock. The desktop app asks the running engine
/// for its dashboard; a standalone engine hands over when nothing runs, then this launch continues.
fn second_launch(headless: bool, error: String) -> Option<instance_lock::InstanceLock> {
    if headless {
        eprintln!("{error}");
        return None;
    }
    let shown = tauri::async_runtime::block_on(yougori_cli::client::call(
        &yougori_cli::client::request("app_show", serde_json::json!({})),
    ));
    match shown {
        Ok(result) if result["handover"] == true => {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
            while std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(500));
                if let Ok(lock) = instance_lock::InstanceLock::acquire() {
                    return Some(lock);
                }
            }
            launch_error("The background Yougori engine did not stop in time. Try again, or run `yougori app quit`.");
            None
        }
        Ok(_) => None,
        Err(message) => {
            launch_error(&message);
            None
        }
    }
}

fn launch_error(message: &str) {
    eprintln!("{message}");
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONINFORMATION, MB_OK};
        let wide = |text: &str| text.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
        let (text, title) = (wide(message), wide("Yougori"));
        // SAFETY: both strings are NUL-terminated UTF-16 buffers that outlive the call.
        unsafe { MessageBoxW(std::ptr::null_mut(), text.as_ptr(), title.as_ptr(), MB_OK | MB_ICONINFORMATION) };
    }
}

/// Guest provisioning nests deep async state machines; unoptimised builds overflow tokio's
/// default 2 MiB worker stacks. The runtime lives for the whole process.
fn install_async_runtime() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(16 * 1024 * 1024)
        .build()
        .expect("start the Yougori async runtime");
    tauri::async_runtime::set(runtime.handle().clone());
    std::mem::forget(runtime);
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    install_async_runtime();
    let headless = ENGINE_ONLY || std::env::args().any(|argument| argument == "--headless");
    // Acquire before constructing WebView/Tauri state so a duplicate launch exits
    // immediately without paying startup cost or turning a setup error into a panic.
    let instance_lock = match instance_lock::InstanceLock::acquire() {
        Ok(lock) => lock,
        Err(error) => match second_launch(headless, error) {
            Some(lock) => lock,
            None => return,
        },
    };
    let mut context = tauri::generate_context!();
    if headless {
        for window in &mut context.config_mut().app.windows { window.create = false; }
    }
    #[cfg(feature = "engine-only")]
    let builder = tauri::test::mock_builder();
    #[cfg(not(feature = "engine-only"))]
    let builder = tauri::Builder::default()
        // Do not expose an unpainted WebView during native setup.
        .on_page_load(|webview, payload| {
            if webview.label() == "main"
                && matches!(payload.event(), tauri::webview::PageLoadEvent::Finished)
            {
                #[cfg(target_os = "windows")]
                node_context_menu::install(webview);
                let _ = webview.window().show();
            }
        });
    let builder = builder
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init());
    #[cfg(target_os = "windows")]
    let builder = builder.plugin(tauri_plugin_notification::init());
    let app = builder
        .setup(move |app| {
            let app_directory = app.path().app_data_dir()?;
            migrate_legacy_app_data(&app_directory)?;
            let resource_directory = resource_dir(app.handle()).map_err(std::io::Error::other)?;
            let store = PlatformStore::load(app_directory.join("platform-state.json"))
                .map_err(std::io::Error::other)?;
            let configured_storage = store.snapshot().map_err(std::io::Error::other)?.settings.data_directory;
            let configured_storage = if configured_storage.is_empty() {
                configured_storage
            } else if let Some(relocated) = relocated_app_storage(std::path::Path::new(&configured_storage), &app_directory) {
                let relocated = relocated.to_string_lossy().into_owned();
                store.mutate(|state| { state.settings.data_directory = relocated.clone(); Ok(()) })
                    .map_err(std::io::Error::other)?;
                relocated
            } else {
                configured_storage
            };
            let storage_directory = if configured_storage.is_empty() { app_directory.clone() } else { std::path::PathBuf::from(configured_storage) };
            if !storage_directory.is_absolute() { return Err(std::io::Error::other("Environment storage must be an absolute folder path").into()); }
            let runtime = runtime::RuntimeManager::new(&resource_directory, &storage_directory)
                .map_err(std::io::Error::other)?;
            tauri::async_runtime::block_on(runtime.cleanup_orphan_branch_boot_disks())
                .map_err(std::io::Error::other)?;
            let backup =
                backup::BackupManager::new(&app_directory).map_err(std::io::Error::other)?;
            let mut state = store.snapshot().map_err(std::io::Error::other)?;
            runtime.restore_container_routes(&state).map_err(std::io::Error::other)?;
            // A durable state intent brackets every disk replacement. If the process
            // stopped before the restored state committed, reactivate the old disk;
            // if state committed first, finish deleting the retained rollback disk.
            let restore_intents = state
                .pending_vm_restores
                .iter()
                .cloned()
                .collect::<HashSet<_>>();
            let mut restore_candidates = restore_intents.clone();
            restore_candidates.extend(
                state
                    .environments
                    .iter()
                    .filter(|environment| {
                        environment.provider == Some(models::RuntimeProviderKind::Qemu)
                    })
                    .map(|environment| {
                        environment
                            .runtime_id
                            .clone()
                            .unwrap_or_else(|| environment.id.clone())
                    }),
            );
            for environment_id in restore_candidates {
                if !runtime
                    .has_pending_vm_backup_install(&environment_id)
                    .map_err(std::io::Error::other)?
                {
                    continue;
                }
                if restore_intents.contains(&environment_id) {
                    tauri::async_runtime::block_on(
                        runtime.rollback_vm_backup_install(&environment_id),
                    )
                    .map_err(std::io::Error::other)?;
                } else {
                    tauri::async_runtime::block_on(
                        runtime.finalize_vm_backup_install(&environment_id),
                    )
                    .map_err(std::io::Error::other)?;
                }
            }
            state.pending_vm_restores.clear();
            // A fresh install has no OCI state to protect, so creating/checking the appliance
            // disk can wait until the first container operation. Existing OCI environments
            // still get the compatibility check before their persisted status is restored.
            let has_oci_environments = state.environments.iter().any(|environment| {
                environment.provider == Some(models::RuntimeProviderKind::YougoriOci)
            });
            let (appliance_reset, appliance_error) = if has_oci_environments {
                match tauri::async_runtime::block_on(runtime.prepare_appliance_overlay()) {
                    Ok(reset) => (reset, None),
                    // Keep the UI available so users can see the error and recover/delete.
                    // Preparation leaves the disk untouched when an external runtime owns it.
                    Err(error) => (false, Some(error)),
                }
            } else {
                (false, None)
            };
            state.host = commands::collect_host_metrics(&state.host, runtime.storage_root());
            state.host.storage_saved_gb = 0.0;
            state.providers = runtime.provider_statuses();
            if appliance_reset {
                for environment in &mut state.environments {
                    if environment.provider == Some(models::RuntimeProviderKind::YougoriOci) {
                        environment.status = models::EnvironmentStatus::Error;
                        environment.last_error = Some(
                            "The previous OCI runtime disk was archived after an appliance upgrade or filesystem failure. Recreate this container; its archived runtime disk remains available for recovery."
                                .into(),
                        );
                    }
                }
            }
            let startup_recovery_candidates=state.environments.iter().filter(|environment| matches!(environment.status,models::EnvironmentStatus::Running | models::EnvironmentStatus::Paused | models::EnvironmentStatus::Provisioning)).map(|environment|environment.id.clone()).collect();
            commands::vm_creation::recover_interrupted(&mut state);
            commands::factory_reset::recover_interrupted(&mut state);
            for (id,deployment) in &mut state.cloud_deployments {
                if matches!(deployment.state.as_str(),"Creating"|"Deleting") {
                    deployment.state="Needs inspection".into();
                    deployment.last_error=Some("Yougori exited during a cloud operation. Inspect the deployment before retrying; resources may already exist.".into());
                    if let Some(environment)=state.environments.iter_mut().find(|e|&e.id==id){environment.status=models::EnvironmentStatus::Error;environment.last_error=deployment.last_error.clone();}
                }
            }
            for environment in &mut state.environments {
                if environment.provider == Some(models::RuntimeProviderKind::YougoriOci) {
                    if let Some(error) = &appliance_error {
                        environment.status = models::EnvironmentStatus::Error;
                        environment.last_error = Some(error.clone());
                    }
                }
                if matches!(
                    environment.status,
                    models::EnvironmentStatus::Running
                        | models::EnvironmentStatus::Paused
                        | models::EnvironmentStatus::Provisioning
                ) {
                    environment.status = models::EnvironmentStatus::Stopped;
                    environment.cpu_usage = 0.0;
                    environment.memory_usage_gb = 0.0;
                    environment.network_rx_mbps = 0.0;
                    environment.resource_policy.cpu.current = 0.0;
                    environment.resource_policy.memory_gb.current = 0.0;
                    environment.control_endpoint = None;
                    environment.console_endpoint = None;
                }
            }
            for connection in &mut state.connections {
                connection.enforcement_status = Some(models::EnforcementStatus::Pending);
                connection.provider_rule_ids.clear();
            }
            for run in &mut state.backup_runs {
                if run.status == models::BackupRunStatus::Running {
                    run.status = models::BackupRunStatus::Failed;
                    run.completed_at = Some(chrono::Utc::now().to_rfc3339());
                    run.last_error = Some("Yougori closed before this backup completed".into());
                }
            }
            store.replace(state).map_err(std::io::Error::other)?;
            app.manage(store);
            app.manage(peer_sharing::Sharing::default());
            app.manage(remote_access::RemoteAccess::new(app_directory.clone()).map_err(std::io::Error::other)?);
            app.manage(runtime);
            app.manage(backup);
            app.manage(instance_lock);
            app.manage(workspace::WorkspaceManager::new(&storage_directory));
            app.manage(environment_download::Downloads::new(&storage_directory));
            app.manage(host_terminal::HostTerminalManager::default());
            app.manage(market::Market::default());
            app.manage(swarm::Swarm::default());
            // Native system installers cannot provision every user's home.
            // Set up the shared skill for the user who actually runs this app
            // or engine. Development checkouts do not change installed skills.
            #[cfg(not(debug_assertions))]
            {
                let skill_app = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    if let Err(error) = host_terminal::setup_access(&skill_app).await {
                        eprintln!("Automatic Yougori skill setup could not finish: {error}");
                    }
                });
            }
            app.manage(vault_gateway::GatewayState::default());
            app.manage(vault_setup::SetupState::default());
            #[cfg(target_os = "windows")]
            vault_notifications::start(app.handle());
            automation::start(app.handle(), headless).map_err(std::io::Error::other)?;
            #[cfg(all(desktop, not(feature = "engine-only")))]
            if !headless { tray::install(app.handle())?; }
            app.manage(lifecycle::StartupRecoveryCandidates(startup_recovery_candidates));
            lifecycle::start(app.handle());
            automation::start_storage_maintenance(app.handle());
            peer_sharing::start_refresh(app.handle());
            remote_access::start_cleanup(app.handle());
            environment_download::start_cleanup(app.handle());
            neocloud::runpod::resume(app.handle());
            market::start(app.handle());
            model_runner::optimizer::start(app.handle());
            let workspace_app = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let shutdown=automation::shutdown_signal(&workspace_app);
                let mut ticks = 0u8;
                loop {
                    tokio::select! { _=shutdown.cancelled()=>break, _=tokio::time::sleep(std::time::Duration::from_secs(2))=>{} }
                    let workspace=workspace_app.state::<workspace::WorkspaceManager>();
                    let store=workspace_app.state::<PlatformStore>();
                    let runtime=workspace_app.state::<runtime::RuntimeManager>();
                    tokio::select! { _=shutdown.cancelled()=>break, _=workspace.cleanup(&store,&runtime)=>{} }
                    ticks = (ticks + 1) % 6;
                    if ticks == 0 { automation::headless_tick(&workspace_app).await; }
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            environment_download::start_environment_download,
            environment_download::list_environment_downloads,
            environment_download::keep_environment_downloads_alive,
            environment_download::stop_environment_download,
            releases::check_release_update,
            releases::remind_release_update_later,
            releases::open_release_downloads,
            vault::vault_status,
            vault::vault_control,
            vault::vault_add_items,
            vault::vault_export_plugin,
            vault_setup::vault_bootstrap,
            vault_setup::vault_create,
            vault_setup::vault_connection,
            model_runner::run_model,
            model_runner::run_neocloud_model,
            model_runner::model_api,
            model_runner::model_chat,
            model_runner::model_chat_stream,
            model_runner::model_chat_cancel,
            model_runner::model_api_status,
            model_runner::optimizer::model_optimizer,
            model_runner::model_usage,
            market::market_status,
            swarm::swarm_dispatch,
            model_registry::model_registry_request,
            model_registry::model_registry_connect,
            model_registry::model_registry_pause,
            model_registry::model_registry_upload,
            model_registry::model_registry_download,
            market::confidential_network_chat,
            market::market_sign_in,
            market::market_sign_out,
            market::market_share_model,
            market::market_unshare_model,
            file_export::copy_files_from_environment,
            file_export::copy_files_between_environments,
            file_export::list_volumes,
            file_export::remove_volume,
            cloud_options::cloud_options,
            model_runner::model_chat_history,
            model_runner::save_model_chat_history,
            model_runner::model_status,
            changes::environment_changes,
            projects::inspect_project,
            projects::discover_projects,
            projects::import_compose,
            projects::project_action,
            projects::run_workload,
            host_terminal::get_host_terminal_info,
            host_terminal::validate_edit_app_folder,
            host_terminal::set_up_agent_access,
            host_terminal::host_terminal_action,
            commands::get_platform_state,
            commands::cloud::scan_cloud_host,
            commands::cloud::test_cloud_connection,
            commands::cloud::add_cloud_environment,
            commands::cloud::get_cloud_connection,
            commands::connection_skills::get_connection_skills,
            commands::connection_skills::install::install_environment_skills,
            commands::open_environment_window,
            commands::close_environment_window,
            commands::reset_platform_state,
            commands::create_environment,
            commands::set_environment_status,
            commands::delete_environment,
            commands::recover_container_runtime,
            commands::recover_vm_runtime,
            commands::update_resource_policy,
            commands::rename_environment,
            commands::startup::update_container_startup_command,
            commands::storage::get_storage_allocation,
            commands::storage::get_storage_location,
            commands::storage::set_storage_location,
            commands::storage::reclaim_storage,
            commands::storage::expand_environment_storage,
            commands::factory_reset::factory_reset_environment,
            commands::update_container_network,
            commands::update_environment_gpu,
            runtime::gpu::get_shared_gpu_settings,
            runtime::cuda::get_cuda_runtime_status,
            runtime::cuda::install_cuda_runtime,
            runtime::cuda::verify_environment_cuda,
            runtime::gpu::set_shared_gpu_selection,
            commands::create_connection,
            commands::set_connection_active,
            commands::delete_connection,
            commands::create_snapshot,
            commands::delete_snapshot,
            commands::restore_snapshot,
            commands::add_backup_destination,
            commands::delete_backup_destination,
            commands::run_backup,
            commands::restore_backup,
            commands::update_settings,
            lifecycle::finish_app_close,
            remote_access::create_remote_share,
            remote_access::start_remote_tunnel,
            remote_access::stop_remote_tunnel,
            remote_access::list_remote_shares,
            remote_access::update_remote_share,
            remote_access::remove_remote_share,
            remote_access::client::connect_remote_share,
            remote_access::client::reconnect_remote_share,
            remote_access::client::remote_share_request,
            remote_access::client::download_remote_folder,
            peer_sharing::create_environment_share,
            peer_sharing::list_environment_shares,
            peer_sharing::revoke_environment_share,
            peer_sharing::import_environment_share,
            cloud_deployment::cloud_authenticate,
            cloud_deployment::deploy_cloud_environment,
            cloud_deployment::cloud_deployment_action,
            cloud_deployment::delete_cloud_deployment,
            neocloud::neocloud_providers,
            neocloud::install::neocloud_install,
            neocloud::accounts::neocloud_account,
            neocloud::accounts::neocloud_authenticate,
            neocloud::accounts::neocloud_forget_account,
            neocloud::catalog::neocloud_catalog,
            neocloud::neocloud_discover,
            neocloud::neocloud_prices,
            neocloud::neocloud_plan,
            neocloud::create_neocloud_environment,
            neocloud::neocloud_action,
            neocloud::neocloud_recover_id,
            neocloud::runpod::runpod_status,
            neocloud::runpod::runpod_connect,
            neocloud::runpod::runpod_disconnect,
            neocloud::runpod::runpod_catalog,
            neocloud::runpod::runpod_gpu_offers,
            neocloud::runpod::runpod_template,
            neocloud::runpod::runpod_search_templates,
            neocloud::runpod::runpod_hub,
            neocloud::runpod::runpod_hub_repo,
            neocloud::runpod::runpod_create_pod,
            neocloud::runpod::runpod_links,
            neocloud::runpod::runpod_logs,
            neocloud::runpod::runpod_create_endpoint,
            neocloud::runpod::runpod_endpoint_run,
            neocloud::runpod::runpod_action,
            neocloud::runpod::runpod_resources,
            neocloud::runpod::runpod_attach,
            neocloud::runpod::runpod_volume,
            neocloud::runpod::runpod_registry,
            isolated_cli::open_isolated_cli,
            isolated_cli::grant_isolated_cli_environment,
            commands::cloud::configure_cloud_environment,
            commands::refresh_host_metrics,
            local_backup::export_local_backup,
            local_backup::import_local_backup,
            local_backup::duplicate_local_environment,
            duplication::duplicate_environment,
            duplication::inspect_duplication_source,
            duplication::cleanup_environment_duplication,
            commands::get_guest_session,
            commands::execute_environment_command,
            guest_execution::execute_guest_job,
            guest_execution::guest_execution_output,
            guest_execution::cancel_guest_execution,
            guest_execution::release_guest_execution,
            file_import::cancel_file_transfer,
            lifecycle::patch_settings,
            lifecycle::get_settings_snapshot,
            lifecycle::get_startup_report,
            lifecycle::recover_environment_runtime_report,
            projects::deployment_status,
            projects::secrets::set_deployment_secret,
            projects::secrets::delete_deployment_secret,
            model_runner::preflight::model_preflight,
            model_runner::preflight::model_support_task,
            model_runner::huggingface::model_huggingface_status,
            projects::readiness::get_environment_health_check,
            projects::readiness::set_environment_health_check,
            workspace::publication_preflight,
            workspace::host_share_credentials,
            workspace::get_environment_log_window,
            commands::execute_connected_command,
            commands::list_environment_folders,
            commands::request_connected_files,
            commands::workloads::get_environment_logs,
            commands::workloads::manage_oci_images,
            commands::read_environment_console,
            workspace::terminal_action,
            workspace::installers::prepare_terminal_installer,
            guest_apps::micro_vm_apps,
            guest_apps::open_micro_vm_app_window,
            workspace::list_environment_services,
            workspace::get_manual_service_ports,
            workspace::set_manual_service_port,
            workspace::publish_environment_service,
            workspace::cloudflare::saved_cloudflare_account,
            workspace::cloudflare::forget_cloudflare_account,
            workspace::cloudflare::save_cloudflare_preset,
            workspace::cloudflare::copy_saved_cloudflare_to_preset,
            workspace::cloudflare::forget_cloudflare_preset,
            workspace::cloudflare::update_saved_domain,
            workspace::cloudflare::list_saved_domains,
            workspace::cloudflare::start_saved_domain_tunnel,
            workspace::cloudflare::stop_saved_domain_tunnel,
            workspace::cloudflare::import_saved_domains,
            workspace::unpublish_environment_service,
            workspace::attach_host_folder,
            file_import::copy_files_to_environment,
            file_import::list_imported_drives,
            file_import::set_imported_drive_attached,
            workspace::detach_host_folder,
            workspace::list_environment_windows,
            workspace::focus_environment_window,
            workspace::title_environment_window,
            workspace::open_workspace_url,
            workspace::open_service_window,
            guest_keyboard::set_guest_keyboard_capture,
        ])
        .build(context)
        .expect("error while building Yougori");
    app.run(|app_handle, event| {
        if let tauri::RunEvent::WindowEvent { label, event: tauri::WindowEvent::CloseRequested { api, .. }, .. } = &event {
            if label == "main" {
                api.prevent_close();
                request_main_window_close(app_handle);
            }
        }
        if let tauri::RunEvent::ExitRequested { code, api, .. } = &event {
            if code.is_none() && app_handle.state::<std::sync::Arc<automation::Control>>().headless {
                api.prevent_exit();
                return;
            }
            shutdown_before_exit(app_handle, api, *code);
            return;
        }
        if let tauri::RunEvent::WindowEvent { label, event: tauri::WindowEvent::Focused(false) | tauri::WindowEvent::Destroyed, .. } = &event {
            guest_keyboard::release_window(label);
        }
        if let tauri::RunEvent::WindowEvent { label, event: tauri::WindowEvent::Destroyed, .. } = &event {
            let app = app_handle.clone();
            let label = label.clone();
            tauri::async_runtime::spawn(async move {
                let host_app=app.clone();let owner=label.clone();
                let _=tokio::task::spawn_blocking(move ||host_app.state::<host_terminal::HostTerminalManager>().close_owner(&owner)).await;
                app.state::<workspace::WorkspaceManager>().close_window(&label, &app.state::<PlatformStore>(), &app.state::<runtime::RuntimeManager>()).await;
            });
        }
        // A forced exit or restart can skip the cancellable request. Keep this
        // fallback; a normal close has already completed cleanup on its worker.
        if matches!(event, tauri::RunEvent::Exit) {
            shutdown_engine(app_handle);
        }
    });
}
