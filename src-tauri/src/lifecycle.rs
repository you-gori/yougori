use crate::{commands, models::{AppSettings, EnvironmentStatus, ThemePreference}, runtime::RuntimeManager, store::PlatformStore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::{BTreeMap, BTreeSet}, sync::OnceLock};
use tauri::{Manager, State};
use crate::AppHandle;

#[path = "lifecycle/startup_registration.rs"]
mod startup_registration;

static SETTINGS_OPERATIONS: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

#[derive(Default)]
pub struct StartupControl {
    cancelled: std::sync::atomic::AtomicBool,
    notify: tokio::sync::Notify,
}

/// Captured before setup reconciles persisted statuses to Stopped. Keeping this
/// intent separately prevents unselected abandoned providers from being missed.
pub struct StartupRecoveryCandidates(pub Vec<String>);

impl StartupControl {
    async fn cancelled(&self) {
        use std::sync::atomic::Ordering;
        loop {
            let notified = self.notify.notified();
            if self.cancelled.load(Ordering::Acquire) { return; }
            notified.await;
        }
    }
}

/// Startup is scoped to this app instance, never a process-global flag. Cancels
/// pending probes/streams and prevents later stages from creating publications.
pub fn cancel_startup(app: &AppHandle) {
    use std::sync::atomic::Ordering;
    if let Some(control) = app.try_state::<StartupControl>() {
        control.cancelled.store(true, Ordering::Release);
        control.notify.notify_waiters();
    }
    if let Some(store) = app.try_state::<PlatformStore>() {
        let _ = store.mutate(|state| {
            if let Some(report) = &mut state.startup_report {
                if report.status == "running" {
                    report.status = "interrupted".into();
                    report.completed_at = Some(chrono::Utc::now().to_rfc3339());
                    for environment in report.environments.iter_mut().filter(|environment| environment.status == "pending") {
                        environment.status = "interrupted".into();
                        environment.error = Some("Shutdown interrupted startup before this stage was verified".into());
                        environment.recovery_action = Some("Restart Yougori to reconcile its verified provider and saved deployment".into());
                    }
                }
            }
            Ok(())
        });
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartupEnvironmentReport {
    pub environment_id: String,
    pub provider: crate::models::RuntimeProviderKind,
    pub storage_root: Option<String>,
    pub stage: String,
    pub status: String,
    pub recovery: Option<crate::runtime::recovery::RecoveryReport>,
    pub readiness: Option<Value>,
    pub error: Option<String>,
    pub recovery_action: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartupReport {
    pub started_at: String,
    pub completed_at: Option<String>,
    pub status: String,
    pub trigger: String,
    pub starts_before_sign_in: bool,
    #[serde(default)]
    pub service_registration: Option<Value>,
    pub environments: Vec<StartupEnvironmentReport>,
}

/// Diagnostics are persisted, so strip URLs (which may carry bearer secrets)
/// and bound their size. Credentials and request bodies never enter the report.
pub(crate) fn safe_diagnostic(error: &str) -> String {
    let mut mask_next = false;
    error.split_whitespace().map(|word| {
        let lower = word.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '=').to_ascii_lowercase();
        let inline = lower.split_once(['=', ':']).is_some_and(|(_, value)| !value.is_empty());
        // Quoted JSON keys (`"access_token":"…"`) keep their quotes until trimmed here.
        let key = lower.split(['=', ':']).next().unwrap_or_default().trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_');
        let sensitive = ["bearer", "password", "secret", "token", "authorization", "api_key", "apikey", "access_token", "refresh_token", "client_secret", "private_key"].contains(&key);
        let replacement = if mask_next || word.contains("://") || (sensitive && inline) { "[credential redacted]" } else { word };
        mask_next = sensitive && !inline;
        replacement
    }).collect::<Vec<_>>().join(" ").chars().take(1000).collect()
}

#[tauri::command]
pub async fn get_settings_snapshot(store: State<'_, PlatformStore>) -> Result<Value, String> {
    let state = store.snapshot()?;
    let registration = startup_registration_snapshot(state.settings.clone()).await;
    Ok(json!({"settings":state.settings,"revision":state.settings_revision,"startupTrigger":"signIn","startsBeforeSignIn":false,"serviceRegistration":registration}))
}

async fn startup_registration_snapshot(settings:AppSettings) -> Value {
    tokio::task::spawn_blocking(move||startup_registration::describe(&settings)).await.unwrap_or_else(|_|json!({"status":"unverified","trigger":"signIn","startsBeforeSignIn":false,"recoveryAction":"Read automatic-startup registration again; its operating-system status could not be verified"}))
}
async fn change_startup_registration(enabled:bool,headless:bool) -> Result<(),String> {
    tokio::task::spawn_blocking(move||set_launch_at_startup(enabled,headless)).await.map_err(|_|"YOUGORI_OPERATION_INTERRUPTED: startup registration worker stopped unexpectedly; inspect startup settings before retrying".to_string())?
}

pub(crate) fn patched_settings(previous: &AppSettings, patch: &Value) -> Result<(AppSettings, Value), String> {
    let object = patch.as_object().ok_or("Settings patch must be an object")?;
    if serde_json::to_vec(patch).map_err(|e| e.to_string())?.len() > 16 * 1024 { return Err("Settings patch exceeds 16 KiB".into()); }
    let mut value = serde_json::to_value(previous).map_err(|e| e.to_string())?;
    let settings = value.as_object_mut().ok_or("Settings serialization failed")?;
    let mut changed = serde_json::Map::new();
    for (name, replacement) in object {
        let old = settings.get(name).ok_or_else(|| format!("Unknown settings field: {name}"))?;
        if old != replacement { changed.insert(name.clone(), replacement.clone()); }
        settings.insert(name.clone(), replacement.clone());
    }
    let next = serde_json::from_value(value).map_err(|e| format!("Invalid settings patch: {e}"))?;
    Ok((next, Value::Object(changed)))
}

pub(crate) async fn save_settings(settings: AppSettings, expected_revision: u64, store: &PlatformStore) -> Result<crate::models::PlatformState, String> {
    save_settings_registering(settings, expected_revision, store, false).await
}

/// `register_again`: the caller asked for sign-in startup explicitly, so a missing or stale
/// registration is written again even though the setting itself did not change.
async fn save_settings_registering(settings: AppSettings, expected_revision: u64, store: &PlatformStore, register_again: bool) -> Result<crate::models::PlatformState, String> {
    let _guard = SETTINGS_OPERATIONS.get_or_init(|| tokio::sync::Mutex::new(())).lock().await;
    let previous = store.snapshot()?;
    validate_settings_limits(&settings, &previous.settings)?;
    validate(&settings, store)?;
    if previous.settings_revision != expected_revision { return Err(format!("[YOUGORI_SETTINGS_REVISION_CONFLICT] Expected settings revision {expected_revision}, current revision {}. Read settings and retry the intended patch.", previous.settings_revision)); }
    let startup_changed = settings.launch_at_startup != previous.settings.launch_at_startup || settings.startup_headless != previous.settings.startup_headless
        || (register_again && settings.launch_at_startup);
    if startup_changed { change_startup_registration(settings.launch_at_startup, settings.startup_headless).await?; }
    let committed = store.mutate(|state| {
        if state.settings_revision != expected_revision { return Err("[YOUGORI_SETTINGS_REVISION_CONFLICT] Settings changed before commit; read settings and retry".into()); }
        if settings.auto_start_environment_ids.iter().any(|id| !state.environments.iter().any(|environment| &environment.id == id)) { return Err("Automatic startup environment was removed before settings commit".into()); }
        state.settings = settings;
        crate::scheduler::schedule(state);
        Ok(())
    });
    if committed.is_err() && startup_changed { let _ = change_startup_registration(previous.settings.launch_at_startup, previous.settings.startup_headless).await; }
    committed
}

fn validate_settings_limits(settings: &AppSettings, previous: &AppSettings) -> Result<(), String> {
    if settings.snapshot_retention == 0 || settings.snapshot_retention > 365 { return Err("Snapshot retention must be between 1 and 365".into()); }
    if settings.data_directory != previous.data_directory { return Err("Use Storage settings to choose a location and restart the engine".into()); }
    if settings.bandwidth_limit_mbps > 100_000 { return Err("Backup bandwidth must be 0 (unlimited) or at most 100,000 Mbps".into()); }
    settings.security_monitoring.validate()
}

#[tauri::command]
pub async fn patch_settings(patch: Value, expected_revision: u64, store: State<'_, PlatformStore>, runtime: State<'_, RuntimeManager>, backup: State<'_, crate::backup::BackupManager>) -> Result<Value, String> {
    let previous = store.snapshot()?;
    if let Some(policies) = patch.get("securityMonitoring") {
        crate::security::monitor::check_fields(policies)?;
    }
    let (settings, changed) = patched_settings(&previous.settings, &patch)?;
    // Turning sign-in startup on again is the repair the startup report asks for.
    let register_again = patch.get("launchAtStartup") == Some(&Value::Bool(true));
    let next = save_settings_registering(settings, expected_revision, &store, register_again).await?;
    crate::security::settings_changed(&previous.settings.security_monitoring, &next.settings.security_monitoring);
    let mut warnings = Vec::new();
    if changed.get("snapshotRetention").is_some() {
        if let Err(error) = commands::enforce_snapshot_retention(&store, &runtime, &backup).await { warnings.push(safe_diagnostic(&error)); }
    }
    let registration = startup_registration_snapshot(next.settings.clone()).await;
    Ok(json!({"revision":next.settings_revision,"changed":changed,"applied":true,"warnings":warnings,"startupTrigger":"signIn","startsBeforeSignIn":false,"serviceRegistration":registration}))
}

#[tauri::command]
pub fn get_startup_report(store: State<'_, PlatformStore>) -> Result<Option<StartupReport>, String> { Ok(store.snapshot()?.startup_report) }

#[tauri::command]
pub async fn recover_environment_runtime_report(environment_id: String, confirmed: bool, store: State<'_, PlatformStore>, runtime: State<'_, RuntimeManager>) -> Result<crate::runtime::recovery::RecoveryReport, String> {
    if !confirmed { return Err("Confirm stopping only the verified abandoned runtime first".into()); }
    let lock = commands::environment_network_lock(&environment_id).await;
    let _environment_guard = lock.lock().await;
    let state = store.snapshot()?;
    let environment = state.environments.iter().find(|environment| environment.id == environment_id).ok_or("Environment not found")?;
    if environment.status == EnvironmentStatus::Provisioning { return Err("Environment creation is still in progress".into()); }
    let _pool_guard = commands::environment_container_policy_guard(&runtime, environment).await?;
    let mut report = runtime.recover_environment_report(environment).await?;
    if report.ownership_released {
        let provider = commands::provider(environment);
        let root = runtime.environment_storage_root(environment.runtime_id.as_deref().unwrap_or(&environment.id))?;
        let affected: BTreeSet<_> = state.environments.iter().filter(|other| {
            if provider.is_container() {
                commands::provider(other) == provider && runtime.environment_storage_root(other.runtime_id.as_deref().unwrap_or(&other.id)).is_ok_and(|other_root| other_root == root)
            } else { other.id == environment_id }
        }).map(|environment| environment.id.clone()).collect();
        if let Err(error) = store.mutate(|state| {
            for environment in state.environments.iter_mut().filter(|environment| affected.contains(&environment.id)) {
                environment.status = EnvironmentStatus::Stopped;
                environment.console_endpoint = None;
                environment.control_endpoint = None;
                environment.cpu_usage = 0.0;
                environment.memory_usage_gb = 0.0;
                environment.last_error = report.error.clone();
            }
            crate::scheduler::schedule(state);
            Ok(())
        }) {
            report.status = "recoveredNeedsReconciliation".into();
            report.ready_to_start = false;
            report.error = Some(safe_diagnostic(&error));
            report.recovery_action = Some("Restore writable platform-state storage, then reconcile recovery before starting".into());
        }
    }
    Ok(report)
}

pub fn validate(settings: &AppSettings, store: &PlatformStore) -> Result<(), String> {
    if matches!(settings.theme, ThemePreference::Custom) && settings.custom_theme_colors.is_none() {
        return Err("Choose four colors for the custom theme".into());
    }
    if let Some(colors) = &settings.custom_theme_colors {
        for value in [&colors.background, &colors.surface, &colors.accent, &colors.detail] {
            if value.len() != 7 || !value.starts_with('#') || !value.as_bytes()[1..].iter().all(u8::is_ascii_hexdigit) {
                return Err("Custom theme colors must be six-digit hex values such as #315B8C".into());
            }
        }
    }
    let state = store.snapshot()?;
    if settings.auto_start_environment_ids.len() > state.environments.len() || settings.auto_start_environment_ids.iter().any(|id| !state.environments.iter().any(|e| &e.id == id)) {
        return Err("Automatic startup must reference existing environments".into());
    }
    Ok(())
}

/// `headless` starts the engine without the dashboard (for CLI-first use).
pub fn set_launch_at_startup(enabled: bool, headless: bool) -> Result<(), String> {
    let executable = std::env::current_exe().map_err(|e|e.to_string())?;
    #[cfg(target_os = "windows")]
    let flag = if headless { " --headless --startup-sign-in" } else { " --startup-sign-in" };
    #[cfg(target_os="windows")]
    {
        use std::os::windows::process::CommandExt;
        let reg = std::path::PathBuf::from(std::env::var_os("SystemRoot").ok_or("Windows system directory unavailable")?).join("System32/reg.exe");
        let mut command = std::process::Command::new(reg);
        command.creation_flags(0x08000000);
        command.args([if enabled {"add"} else {"delete"}, "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "/v", "Yougori", "/f"]);
        if enabled { command.args(["/t", "REG_SZ", "/d"]).arg(format!("\"{}\"{flag}", executable.display())); }
        let result = startup_registration::bounded_output(&mut command)?;
        if !result.status.success() {
            // Deleting an already absent value is idempotent; other registry errors
            // remain visible rather than claiming startup configuration succeeded.
            let absent = startup_registration::read_windows_registration()?.is_none();
            if enabled || !absent { return Err(format!("Could not update automatic launch: {}",safe_diagnostic(&String::from_utf8_lossy(&result.stderr)))); }
        }
        let installed = startup_registration::read_windows_registration()?;
        let expected = enabled.then(||format!("\"{}\"{flag}",executable.display()));
        if installed != expected {return Err("YOUGORI_OPERATION_INTERRUPTED: Windows sign-in registration did not match its requested postcondition; inspect OS startup registration before retrying".into());}
    }
    #[cfg(target_os="linux")]
    {
        startup_registration::configure_linux(&executable, enabled, headless)?;
    }
    #[cfg(target_os="macos")]
    {
        let root=std::path::PathBuf::from(std::env::var_os("HOME").ok_or("User directory unavailable")?).join("Library/LaunchAgents");
        std::fs::create_dir_all(&root).map_err(|e|e.to_string())?;
        let path=root.join("app.yougori.startup.plist");
        if enabled { let exe=executable.to_string_lossy().replace('&',"&amp;").replace('<',"&lt;").replace('>',"&gt;"); std::fs::write(path,format!("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>Label</key><string>app.yougori.startup</string><key>ProgramArguments</key><array><string>{exe}</string>{}<string>--startup-sign-in</string></array><key>RunAtLoad</key><true/></dict></plist>", if headless {"<string>--headless</string>"} else {""})).map_err(|e|e.to_string())?; } else if path.exists(){ std::fs::remove_file(path).map_err(|e|e.to_string())?; }
    }
    Ok(())
}

/// Recover each relevant provider/storage pool before starting any workloads.
/// Shared pools are reconciled once, and no unrelated drive is targeted.
async fn reclaim_abandoned_runtimes(app: &AppHandle) -> BTreeMap<String, Result<crate::runtime::recovery::RecoveryReport, String>> {
    let store = app.state::<PlatformStore>();
    let runtime = app.state::<RuntimeManager>();
    let Ok(state) = store.snapshot() else { return BTreeMap::new() };
    let stale: BTreeSet<_> = app.try_state::<StartupRecoveryCandidates>().map(|candidates| candidates.0.iter().cloned().collect()).unwrap_or_default();
    let mut pools: BTreeMap<String, Result<crate::runtime::recovery::RecoveryReport, String>> = BTreeMap::new();
    let mut results = BTreeMap::new();
    for environment in state.environments.iter().filter(|environment|
        !crate::peer_sharing::is_shared(environment) &&
        (state.settings.auto_start_environment_ids.contains(&environment.id) ||
         stale.contains(&environment.id) ||
         matches!(environment.status, EnvironmentStatus::Running | EnvironmentStatus::Provisioning | EnvironmentStatus::Paused))) {
        let provider = commands::provider(environment);
        if !provider.is_container() && provider != crate::models::RuntimeProviderKind::Qemu { continue; }
        let id = environment.runtime_id.as_deref().unwrap_or(&environment.id);
        let root = match runtime.environment_storage_root(id) {
            Ok(root) => root,
            Err(error) => { results.insert(environment.id.clone(), Err(safe_diagnostic(&error))); continue; }
        };
        let pool = format!("{}:{provider:?}:{}", root.display(), if provider.is_container() { "shared" } else { id });
        let mut result = if let Some(result) = pools.get(&pool) { result.clone() }
            else {
                let lock = commands::environment_network_lock(&environment.id).await;
                let _environment_guard = lock.lock().await;
                let _pool_guard = match commands::environment_container_policy_guard(&runtime, environment).await {
                    Ok(guard) => guard,
                    Err(error) => { results.insert(environment.id.clone(), Err(safe_diagnostic(&error))); continue; }
                };
                let mut result = runtime.recover_environment_report(environment).await;
                if let Ok(report) = &mut result {
                    if report.ownership_released {
                        let affected: BTreeSet<_> = state.environments.iter().filter(|other| {
                            if provider.is_container() {
                                commands::provider(other) == provider && runtime.environment_storage_root(other.runtime_id.as_deref().unwrap_or(&other.id)).is_ok_and(|other_root| other_root == root)
                            } else { other.id == environment.id }
                        }).map(|environment| environment.id.clone()).collect();
                        if let Err(error) = store.mutate(|state| {
                            for environment in state.environments.iter_mut().filter(|environment| affected.contains(&environment.id)) {
                                environment.status = EnvironmentStatus::Stopped;
                                environment.console_endpoint = None;
                                environment.control_endpoint = None;
                                environment.cpu_usage = 0.0;
                                environment.memory_usage_gb = 0.0;
                                environment.last_error = report.error.clone();
                            }
                            crate::scheduler::schedule(state);
                            Ok(())
                        }) {
                            report.ready_to_start = false;
                            report.status = "recoveredNeedsReconciliation".into();
                            report.error = Some(safe_diagnostic(&error));
                            report.recovery_action = Some("Restore writable platform state and retry verified recovery".into());
                        }
                    }
                }
                pools.insert(pool, result.clone());
                result
            };
        if let Ok(report) = &mut result {
            report.environment_id = environment.id.clone();
        }
        results.insert(environment.id.clone(), result);
    }
    results
}

/// The report only describes startup progress. A failed save (for example an antivirus
/// sharing violation on the state file) is retried once, then logged, and must never
/// stop the remaining environments from starting.
fn save_startup_report(store: &PlatformStore, report: &StartupReport) {
    let save = || store.mutate(|state| { state.startup_report = Some(report.clone()); Ok(()) }).map(|_| ());
    if let Err(error) = save().or_else(|_| { std::thread::sleep(std::time::Duration::from_millis(250)); save() }) {
        eprintln!("Startup progress could not be recorded: {}", safe_diagnostic(&error));
    }
}

fn complete_startup_report(report: &mut StartupReport) {
    report.completed_at = Some(chrono::Utc::now().to_rfc3339());
    let registration_failed = report.service_registration.as_ref().and_then(|registration| registration["status"].as_str()).is_some_and(|status| matches!(status, "unsupported" | "missing" | "stale" | "unverified"));
    report.status = if registration_failed { "failed" }
        else if report.environments.iter().all(|item| item.status == "ready") { "succeeded" }
        else if report.environments.iter().all(|item| matches!(item.status.as_str(), "ready" | "runningUnverified")) { "startedUnverified" }
        else { "failed" }.into();
}

fn readiness_outcome(readiness: &Value) -> &'static str {
    if readiness.get("ready").and_then(Value::as_bool) != Some(true) { "failed" }
    else if readiness.get("applicationVerified").and_then(Value::as_bool) == Some(true) { "ready" }
    else { "runningUnverified" }
}

async fn wait_for_readiness<F, Fut>(mut check: F, limit: std::time::Duration, retry_delay: std::time::Duration) -> Result<Value, String>
where F: FnMut() -> Fut, Fut: std::future::Future<Output = Result<Value, String>> {
    let deadline = tokio::time::Instant::now() + limit;
    let mut attempts = 0;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() { return Err("Automatic startup readiness deadline expired; inspect the failed application or public probe".into()); }
        attempts += 1;
        let mut readiness = tokio::time::timeout(remaining, check()).await
            .map_err(|_| "Automatic startup readiness deadline expired; no healthy outcome was claimed")??;
        readiness["attempts"] = json!(attempts);
        if readiness["ready"] == true || readiness["retryable"] != true { return Ok(readiness); }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining <= retry_delay {
            readiness["startupDeadlineReached"] = json!(true);
            return Ok(readiness);
        }
        tokio::time::sleep(retry_delay).await;
    }
}

async fn automatic_startup(app: &AppHandle) -> Result<(), String> {
    let store = app.state::<PlatformStore>();
    let runtime = app.state::<RuntimeManager>();
    let workspace = app.state::<crate::workspace::WorkspaceManager>();
    let initial = store.snapshot()?;
    let ids: BTreeSet<_> = initial.settings.auto_start_environment_ids.iter().cloned().collect();
    let mut report = StartupReport {
        started_at: chrono::Utc::now().to_rfc3339(), completed_at: None, status: "running".into(),
        trigger: if std::env::args().any(|argument| argument == "--startup-sign-in") { "signIn" } else { "engineLaunch" }.into(), starts_before_sign_in: false, service_registration: None,
        environments: initial.environments.iter().filter(|environment| ids.contains(&environment.id)).map(|environment| StartupEnvironmentReport {
            environment_id: environment.id.clone(), provider: commands::provider(environment),
            storage_root: runtime.environment_storage_root(environment.runtime_id.as_deref().unwrap_or(&environment.id)).ok().map(|root|root.display().to_string()),
            stage: "recovery".into(), status: "pending".into(), recovery: None, readiness: None, error: None, recovery_action: None,
        }).collect(),
    };
    save_startup_report(&store, &report);
    let startup_settings = initial.settings.clone();
    report.service_registration = Some(tokio::task::spawn_blocking(move || startup_registration::describe(&startup_settings)).await.map_err(|error| error.to_string())?);
    save_startup_report(&store, &report);
    let recoveries = reclaim_abandoned_runtimes(app).await;
    for index in 0..report.environments.len() {
        let id = report.environments[index].environment_id.clone();
        if let Some(recovered) = recoveries.get(&id) {
            match recovered {
                Ok(recovery) => {
                    report.environments[index].recovery = Some(recovery.clone());
                    if !recovery.ready_to_start {
                        report.environments[index].status = "failed".into();
                        report.environments[index].error = recovery.error.clone();
                        report.environments[index].recovery_action = recovery.recovery_action.clone();
                        save_startup_report(&store, &report);
                        continue;
                    }
                }
                Err(error) => {
                    report.environments[index].status = "failed".into();
                    report.environments[index].error = Some(safe_diagnostic(error));
                    report.environments[index].recovery_action = Some("Reconnect the original storage and retry the verified provider recovery".into());
                    save_startup_report(&store, &report);
                    continue;
                }
            }
        }
        report.environments[index].stage = "reconciliation".into();
        save_startup_report(&store, &report);
        if let Err(error) = crate::projects::restore_interrupted_staging(&id, &store, &runtime).await {
            report.environments[index].status = "failed".into();
            report.environments[index].error = Some(safe_diagnostic(&error));
            report.environments[index].recovery_action = Some("Reconcile the saved deployment configuration on its original provider before retrying startup. Its interrupted staging marker was preserved.".into());
            save_startup_report(&store, &report);
            continue;
        }
        report.environments[index].stage = "starting".into();
        save_startup_report(&store, &report);
        if let Err(error) = commands::set_environment_status(id.clone(), EnvironmentStatus::Running, store.clone(), runtime.clone()).await {
            report.environments[index].status = "failed".into();
            report.environments[index].error = Some(safe_diagnostic(&error));
            report.environments[index].recovery_action = Some("Inspect the saved startup command and provider checks, then retry Start".into());
            let _ = store.mutate(|state| { if let Some(environment) = state.environments.iter_mut().find(|environment| environment.id == id) { environment.last_error = Some(format!("Automatic startup failed: {}", safe_diagnostic(&error))); } Ok(()) });
            save_startup_report(&store, &report);
            continue;
        }
        report.environments[index].stage = "publication".into();
        save_startup_report(&store, &report);
        if let Err(error) = crate::workspace::restore_environment_publications(&id, &store, &runtime, &workspace).await {
            report.environments[index].status = "failed".into();
            report.environments[index].error = Some(safe_diagnostic(&error));
            report.environments[index].recovery_action = Some("Inspect the saved publication and listener conflict, then retry its connection".into());
            save_startup_report(&store, &report);
            continue;
        }
        report.environments[index].stage = "readiness".into();
        save_startup_report(&store, &report);
        match wait_for_readiness(
            || crate::projects::readiness::environment_readiness(&id, None, &store, &runtime, &workspace),
            std::time::Duration::from_secs(120), std::time::Duration::from_secs(2),
        ).await {
            Ok(readiness) => {
                let outcome = readiness_outcome(&readiness);
                report.environments[index].status = outcome.into();
                report.environments[index].recovery_action = match outcome {
                    "ready" => None,
                    "runningUnverified" => Some("Configure an application health check to verify the API; only its runtime has been checked".into()),
                    _ => Some("Inspect application and public readiness stages, repair the failed probe, then verify again".into()),
                };
                report.environments[index].readiness = Some(readiness);
            }
            Err(error) => {
                report.environments[index].status = "failed".into();
                report.environments[index].error = Some(safe_diagnostic(&error));
                report.environments[index].recovery_action = Some("Inspect application logs and publication status, then verify readiness again".into());
            }
        }
        save_startup_report(&store, &report);
    }
    complete_startup_report(&mut report);
    save_startup_report(&store, &report);
    Ok(())
}

pub fn start(app: &AppHandle) {
    if app.try_state::<StartupControl>().is_none() { app.manage(StartupControl::default()); }
    let app=app.clone();
    let startup=app.clone();
    tauri::async_runtime::spawn(async move {
        let control = startup.state::<StartupControl>();
        tokio::select! {
            biased;
            _ = control.cancelled() => { cancel_startup(&startup); }
            result = automatic_startup(&startup) => {
                if let Err(error) = result { eprintln!("Native automatic startup report: {}", safe_diagnostic(&error)); }
            }
        }
    });
    std::thread::spawn(move || {
        #[cfg(unix)] let mut inhibitor:Option<std::process::Child>=None;
        let mut previous=false;
        loop {
            let awake=app.state::<PlatformStore>().snapshot().is_ok_and(|s|s.settings.keep_awake && s.environments.iter().any(|e|matches!(e.status,EnvironmentStatus::Running|EnvironmentStatus::Provisioning)));
            if awake != previous {
                #[cfg(target_os="windows")]
                unsafe { use windows_sys::Win32::System::Power::{SetThreadExecutionState,ES_CONTINUOUS,ES_SYSTEM_REQUIRED}; SetThreadExecutionState(ES_CONTINUOUS | if awake {ES_SYSTEM_REQUIRED}else{0}); }
                #[cfg(unix)] {
                    if let Some(mut child)=inhibitor.take(){let _=child.kill();let _=child.wait();}
                    if awake {
                        #[cfg(target_os="linux")] let mut command={let mut c=std::process::Command::new("systemd-inhibit");c.args(["--what=sleep","--mode=block","--why=Yougori environments are running","/bin/sh","-c","while kill -0 \"$1\" 2>/dev/null; do sleep 2; done","yougori-inhibit",&std::process::id().to_string()]);c};
                        #[cfg(target_os="macos")] let mut command={let mut c=std::process::Command::new("/usr/bin/caffeinate");c.args(["-i","-w",&std::process::id().to_string()]);c};
                        inhibitor=command.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().ok();
                    }
                }
                previous=awake;
            }
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
    });
}

#[tauri::command]
pub async fn finish_app_close(keep_running: bool, app: AppHandle, store: State<'_,PlatformStore>, runtime: State<'_,RuntimeManager>) -> Result<(),String> {
    if keep_running {
        crate::require_windows("Closing the dashboard")?;
        let main = app.get_webview_window("main").ok_or("Dashboard window not found")?;
        // Keep the engine and its sessions alive. Destroying windows would also
        // close their terminals; exiting would stop workloads and publications.
        // Hide the dashboard last so any failure can still be shown there.
        for (label, window) in app.webview_windows() {
            if label != "main" {
                crate::guest_keyboard::release_window(&label);
                window.hide().map_err(|error| format!("Close {label} window: {error}"))?;
            }
        }
        main.hide().map_err(|error| format!("Close dashboard window: {error}"))?;
        return Ok(());
    }
    cancel_startup(&app);
    let _ = crate::automation::prepare_shutdown(&app, std::time::Duration::from_secs(10)).await;
    // Rented NeoCloud GPUs, in the grid or under Swarm workers, are billed by the hour: quitting
    // stops them before anything else.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(30), futures_util::future::join(crate::grid_neocloud::stop_on_quit(&app), crate::swarm::rented::stop_on_quit(&app))).await;
    let environments=store.snapshot()?.environments;
    let stop = async {
        for e in environments.into_iter().filter(|e|!crate::peer_sharing::is_shared(e)&&matches!(e.status,EnvironmentStatus::Running|EnvironmentStatus::Paused)) {
            if let Err(error) = commands::set_environment_status(e.id,EnvironmentStatus::Stopped,store.clone(),runtime.clone()).await {
                eprintln!("Quit environment stop needs reconciliation: {}", safe_diagnostic(&error));
            }
        }
    };
    let _ = tokio::time::timeout(std::time::Duration::from_secs(15), stop).await;
    // Stop the host CLI before scheduling app exit. In particular, an active
    // coding-agent process must release its conversation when the UI quits.
    let terminal_app = app.clone();
    let terminals = tokio::task::spawn_blocking(move || terminal_app.state::<crate::host_terminal::HostTerminalManager>().shutdown());
    if !tokio::time::timeout(std::time::Duration::from_secs(5), terminals).await.is_ok_and(|result| result.is_ok()) {
        eprintln!("Host terminal cleanup did not finish before quit; bounded engine shutdown will record reconciliation needs");
    }
    tauri::async_runtime::spawn(async move { tokio::time::sleep(std::time::Duration::from_millis(200)).await;crate::exit_engine(&app, 0); });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn startup_cannot_reference_unknown_environments(){let dir=tempfile::tempdir().unwrap();let store=PlatformStore::load(dir.path().join("state.json")).unwrap();let mut settings=store.snapshot().unwrap().settings;settings.auto_start_environment_ids=vec!["missing".into()];assert!(validate(&settings,&store).is_err());}

    #[test]
    fn custom_theme_requires_safe_complete_hex_colors() {
        let dir = tempfile::tempdir().unwrap();
        let store = PlatformStore::load(dir.path().join("state.json")).unwrap();
        let mut settings = store.snapshot().unwrap().settings;
        settings.theme = ThemePreference::Custom;
        assert!(validate(&settings, &store).is_err());
        settings.custom_theme_colors = Some(crate::models::CustomThemeColors {
            background: "#F5EBDD".into(), surface: "#D8C4AD".into(),
            accent: "#315B8C".into(), detail: "#413333".into(),
        });
        assert!(validate(&settings, &store).is_ok());
        settings.custom_theme_colors.as_mut().unwrap().accent = "red; background: black".into();
        assert!(validate(&settings, &store).is_err());
    }

    #[tokio::test]
    async fn narrow_settings_patch_rejects_stale_writers_and_preserves_unrelated_fields() {
        let directory = tempfile::tempdir().unwrap();
        let store = PlatformStore::load(directory.path().join("state.json")).unwrap();
        let initial = store.snapshot().unwrap();
        let (first, changed) = patched_settings(&initial.settings, &json!({"keepAwake":true})).unwrap();
        assert_eq!(changed, json!({"keepAwake":true}));
        let committed = save_settings(first, initial.settings_revision, &store).await.unwrap();
        assert_eq!(committed.settings_revision, initial.settings_revision + 1);
        assert_eq!(committed.settings.theme, initial.settings.theme);
        let (stale, _) = patched_settings(&initial.settings, &json!({"snapshotRetention":42})).unwrap();
        let error = save_settings(stale, initial.settings_revision, &store).await.unwrap_err();
        assert!(error.contains("REVISION_CONFLICT"));
        assert!(store.snapshot().unwrap().settings.keep_awake);
        assert_eq!(store.snapshot().unwrap().settings.snapshot_retention, initial.settings.snapshot_retention);
        assert!(patched_settings(&initial.settings, &json!({"unknown":true})).is_err());
        assert!(patched_settings(&initial.settings, &json!({"keepAwake":"true"})).is_err());
        let (no_op, changed) = patched_settings(&committed.settings, &json!({"keepAwake":true})).unwrap();
        assert_eq!(changed, json!({}));
        assert_eq!(save_settings(no_op, committed.settings_revision, &store).await.unwrap().settings_revision, committed.settings_revision);
    }

    #[test]
    fn startup_never_claims_success_for_a_failed_or_interrupted_stage() {
        let mut report = StartupReport { started_at:"start".into(), completed_at:None, status:"running".into(), trigger:"engineLaunch".into(), starts_before_sign_in:false, service_registration:None, environments:vec![StartupEnvironmentReport { environment_id:"test".into(), provider:crate::models::RuntimeProviderKind::YougoriCuda, storage_root:Some("D:/verified/runtime".into()), stage:"recovery".into(), status:"failed".into(), recovery:None, readiness:None, error:Some("Another live owner".into()), recovery_action:Some("Close its owner normally".into()) }] };
        complete_startup_report(&mut report);
        assert_eq!(report.status, "failed");
        assert!(report.completed_at.is_some());
        report.environments[0].status = "ready".into();
        complete_startup_report(&mut report);
        assert_eq!(report.status, "succeeded");
        assert!(!report.starts_before_sign_in);
        report.environments[0].status = readiness_outcome(&json!({"ready":true,"level":"runtime","applicationVerified":false})).into();
        complete_startup_report(&mut report);
        assert_eq!(report.status, "startedUnverified");
        assert_eq!(report.environments[0].status, "runningUnverified");
        assert_eq!(readiness_outcome(&json!({"ready":true,"applicationVerified":true,"verifiedPublicly":true})), "ready");
        report.environments[0].status = "ready".into();
        report.service_registration = Some(json!({"status":"unsupported","recoveryAction":"Enable the user service manager"}));
        complete_startup_report(&mut report);
        assert_eq!(report.status, "failed", "healthy now does not prove sign-in launch is configured");
    }

    #[test]
    fn persisted_diagnostics_strip_credential_urls_and_are_bounded() {
        let value = safe_diagnostic("Failed https://user:pass@host/private?token=bearer-secret recovery");
        assert!(!value.contains("bearer-secret"));
        assert!(!value.contains("user:pass"));
        assert!(safe_diagnostic(&"x".repeat(10000)).len() <= 1000);
        assert!(!safe_diagnostic("Authorization: Bearer sensitive-token password=private").contains("sensitive-token"));
        assert!(!safe_diagnostic("Authorization: Bearer sensitive-token password=private").contains("private"));
        assert_eq!(safe_diagnostic("token:private api_key=hidden Authorization:credential"), "[credential redacted] [credential redacted] [credential redacted]");
        for leaked in [
            r#"refresh failed {"access_token":"leak-1","expires_in":3600}"#,
            r#"refresh failed {"access_token": "leak-1", "expires_in": 3600}"#,
            r#"refresh failed {'client_secret':'leak-1'}"#,
            r#"refresh failed "password"="leak-1""#,
            "refresh failed access_token:leak-1",
            "refresh failed access_token: leak-1",
            r#"refresh failed {"token":"leak-1"}"#,
        ] {
            let value = safe_diagnostic(leaked);
            assert!(!value.contains("leak-1"), "{leaked} -> {value}");
            assert!(value.starts_with("refresh failed "), "{value}");
        }
        assert_eq!(safe_diagnostic(r#"{"status":"stale"}"#), r#"{"status":"stale"}"#);
    }

    #[tokio::test]
    async fn startup_cancellation_is_scoped_and_wakes_pending_readiness() {
        let first = std::sync::Arc::new(StartupControl::default());
        let second = StartupControl::default();
        let pending = { let first = first.clone(); tokio::spawn(async move { first.cancelled().await }) };
        tokio::task::yield_now().await;
        first.cancelled.store(true, std::sync::atomic::Ordering::Release);
        first.notify.notify_waiters();
        tokio::time::timeout(std::time::Duration::from_secs(1), pending).await.unwrap().unwrap();
        assert!(!second.cancelled.load(std::sync::atomic::Ordering::Acquire));
    }

    #[tokio::test]
    async fn automatic_startup_waits_for_warming_apps_but_never_claims_a_timed_out_probe_ready() {
        let mut attempts = 0;
        let ready = wait_for_readiness(|| {
            attempts += 1;
            let result = if attempts == 3 { json!({"ready":true,"verifiedPublicly":true,"retryable":false}) }
                else { json!({"ready":false,"verifiedPublicly":false,"retryable":true,"httpStatus":530}) };
            std::future::ready(Ok(result))
        }, std::time::Duration::from_millis(100), std::time::Duration::from_millis(1)).await.unwrap();
        assert_eq!(ready["attempts"], 3);
        assert_eq!(ready["verifiedPublicly"], true);
        let stopped = wait_for_readiness(|| std::future::ready(Ok(json!({"ready":false,"retryable":true,"httpStatus":530}))), std::time::Duration::from_millis(5), std::time::Duration::from_millis(10)).await.unwrap();
        assert_eq!(stopped["ready"], false);
        assert_eq!(stopped["startupDeadlineReached"], true);
        let mut attempts = 0;
        let missing = wait_for_readiness(|| { attempts += 1; std::future::ready(Ok(json!({"ready":false,"retryable":false,"missingProbe":true}))) }, std::time::Duration::from_secs(60), std::time::Duration::from_secs(2)).await.unwrap();
        assert_eq!(attempts, 1);
        assert_eq!(missing["ready"], false);
    }
}
