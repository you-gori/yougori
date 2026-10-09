//! Same-user local automation with resource-scoped work and independent control.
pub(crate) mod dispatch;
pub(crate) mod context;
mod transport;
mod coordinator;
mod journal;
mod queue;
use crate::{AppHandle, runtime::RuntimeManager, store::PlatformStore};
use yougori_cli::wire::{self, Request, Response};
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};
#[cfg(test)] use std::time::Instant;
use tauri::Manager;
use tokio::io::{AsyncRead, AsyncWrite};
pub use queue::Control;
#[cfg(test)] use queue::Job;
#[cfg(test)] use std::collections::VecDeque;
const HISTORY: usize = 256;
const RESULT_BUDGET: usize = 64 * 1024 * 1024;
const RESULT_LIMIT: usize = 8 * 1024 * 1024;
const CLIENT_LIMIT: usize = 64;

pub(crate) fn is_shutting_down(app: &AppHandle) -> bool {
    app.try_state::<Arc<Control>>().is_some_and(|control| control.quiescing.load(std::sync::atomic::Ordering::Acquire))
}
pub(crate) fn shutdown_signal(app:&AppHandle)->tokio_util::sync::CancellationToken {
    app.try_state::<Arc<Control>>().map(|control|control.shutdown.clone()).unwrap_or_default()
}
pub(crate) async fn prepare_shutdown(app: &AppHandle, timeout: Duration) -> Value {
    crate::file_import::cancel_all_transfers();
    match app.try_state::<Arc<Control>>() {
        Some(control) => control.prepare_shutdown(timeout).await,
        None => json!({"acceptingWork":false,"drained":true,"remainingJobs":[]}),
    }
}

/// Housekeeping uses the normal job queue so shutdown drains disk operations
/// and errors remain inspectable. No workload is stopped to make space.
pub(crate) fn start_storage_maintenance(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let shutdown = shutdown_signal(&app);
        let mut delay = Duration::from_secs(30);
        loop {
            tokio::select! { _ = shutdown.cancelled() => break, _ = tokio::time::sleep(delay) => {} }
            delay = Duration::from_secs(15 * 60);
            let cleanup_app = app.clone();
            let result = tokio::task::spawn_blocking(move || cleanup_app.state::<RuntimeManager>().clean_temporary_storage()).await;
            if let Ok(result) = result {
                if result.reclaimed_cache_bytes > 0 { eprintln!("Recovered {} bytes of abandoned transfer staging", result.reclaimed_cache_bytes); }
                for warning in result.warnings { eprintln!("Storage maintenance: {}", crate::lifecycle::safe_diagnostic(&warning)); }
            }
            if is_shutting_down(&app) { break; }
            let Ok(state) = app.state::<PlatformStore>().snapshot() else { continue };
            if !storage_maintenance_idle(&state) || !app.state::<RuntimeManager>().has_pending_storage_reclaim() { continue; }
            let control = app.state::<Arc<Control>>();
            if control.jobs.lock().await.iter().any(|job| matches!(job.status, "queued" | "running")) { continue; }
            let response = control.handle(app.clone(), Request {
                version: wire::VERSION, method: "reclaim_storage".into(), params: json!({}), confirmed: true, dry_run: false,
            }).await;
            if !response.ok { eprintln!("Storage maintenance could not queue cleanup: {}", crate::lifecycle::safe_diagnostic(response.error.as_deref().unwrap_or("unknown error"))); }
        }
    });
}

fn storage_maintenance_idle(state: &crate::models::PlatformState) -> bool {
    use crate::models::EnvironmentStatus;
    !state.startup_report.as_ref().is_some_and(|report| report.status == "running")
        && !state.environments.iter().any(|environment| crate::commands::provider(environment).is_container()
            && matches!(environment.status, EnvironmentStatus::Running | EnvironmentStatus::Paused | EnvironmentStatus::Provisioning))
}

async fn connection(
    mut stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    control: Arc<Control>,
    app: AppHandle,
    _connection: tokio::sync::OwnedSemaphorePermit,
) {
    let response = match tokio::time::timeout(
        Duration::from_secs(5),
        wire::read_frame(&mut stream, wire::MAX_REQUEST),
    )
    .await
    {
        Ok(Ok(bytes)) => match serde_json::from_slice::<Request>(&bytes) {
            Ok(request) => {
                if request.method == "terminal_stream" {
                    crate::workspace::terminal_stream::serve_local(stream, app, request).await;
                    return;
                }
                let lane=if queue::is_control_method(&request.method){&control.control_clients}else{&control.regular_clients};
                match lane.clone().try_acquire_owned() {
                    Ok(_client)=>control.handle(app,request).await,
                    Err(_)=>Response::failure_with_details("This control lane is busy; cancel queued jobs or retry shortly",yougori_cli::wire::ErrorDetails{code:"control_lane_busy".into(),affected_resource:None,retryable:true,outcome:"not_submitted".into()})
                }
            },
            Err(_) => Response::failure("Malformed Yougori control request"),
        },
        _ => return,
    };
    if let Ok(bytes) = serde_json::to_vec(&response) {
        let _ = tokio::time::timeout(
            Duration::from_secs(5),
            wire::write_frame(&mut stream, &bytes, wire::MAX_RESPONSE),
        )
        .await;
        // A Windows pipe handle must outlive the client's response read; closing
        // a buffered server immediately can discard unread reply bytes.
        let mut ack = [0u8];
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            tokio::io::AsyncReadExt::read(&mut stream, &mut ack),
        )
        .await;
    }
}

pub fn start(app: &AppHandle, headless: bool) -> Result<(), String> {
    let endpoint = wire::endpoint().map_err(|e| e.to_string())?;
    start_at(app, headless, endpoint)
}
fn start_at(app: &AppHandle, headless: bool, endpoint: String) -> Result<(), String> {
    let control = Arc::new(Control::new(endpoint.clone(), headless, &app.state::<PlatformStore>()));
    // Creation runs inside the already-owned Tokio runtime; failing to reserve
    // the endpoint aborts startup instead of exposing an unprotected fallback.
    let listener = tauri::async_runtime::block_on(async { transport::bind(&endpoint, true) })
        .map_err(|e| format!("Cannot reserve the same-user CLI endpoint: {e}"))?;
    app.manage(control.clone());
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        #[cfg(windows)]
        {
            let mut listener = listener;
            loop {
                if listener.connect().await.is_err() {
                    break;
                }
                // Keep a replacement instance alive before dropping a client,
                // preventing another process from taking over the pipe name.
                let next = match transport::bind(&endpoint, false) {
                    Ok(next) => next,
                    Err(error) => {
                        eprintln!("CLI listener stopped: {error}");
                        break;
                    }
                };
                let stream = std::mem::replace(&mut listener, next);
                if let Ok(permit) = control.clients.clone().try_acquire_owned() {
                    let control = control.clone();
                    let app = app.clone();
                    tokio::spawn(async move {
                        connection(stream, control, app, permit).await;
                    });
                }
            }
        }
        #[cfg(unix)]
        {
            while let Ok((stream, _)) = listener.accept().await {
                if let Ok(permit) = control.clients.clone().try_acquire_owned() {
                    let control = control.clone();
                    let app = app.clone();
                    tokio::spawn(async move {
                        connection(stream, control, app, permit).await;
                    });
                }
            }
        }
    });
    Ok(())
}

/// A hidden dashboard throttles React metric polling. Keep resource scheduling
/// alive for background workloads without booting stopped runtimes to poll them.
pub async fn headless_tick(app: &AppHandle) {
    if is_shutting_down(app) {return;}
    if !app.state::<Arc<Control>>().headless
        && app.get_webview_window("main").is_some_and(|window| window.is_visible().unwrap_or(true)) {
        return;
    }
    if !app.state::<PlatformStore>().snapshot().is_ok_and(|state| {
        state
            .environments
            .iter()
            .any(|env| env.status == crate::models::EnvironmentStatus::Running)
    }) {
        return;
    }
    let _ = crate::commands::refresh_host_metrics(
        app.state::<PlatformStore>(),
        app.state::<RuntimeManager>(),
    )
    .await;
}

#[cfg(test)]
mod tests;
