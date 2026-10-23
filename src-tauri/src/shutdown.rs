//! Shutdown has its own bounded path, outside ordinary operation coordination.
use crate::{store::PlatformStore, AppHandle};
use serde_json::{json, Value};
use std::{
    future::Future,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use tauri::Manager;

/// Set when the standalone engine steps aside for the desktop app, which takes over at once.
static HANDING_OVER: AtomicBool = AtomicBool::new(false);

/// The standalone engine is stepping aside for the desktop app: its rented GPUs keep running for
/// the engine that takes over, rather than being stopped as on a quit.
pub(crate) fn hand_over() {
    HANDING_OVER.store(true, Ordering::Release);
}

async fn stage(
    name: &str,
    seconds: u64,
    deadline: tokio::time::Instant,
    work: impl Future<Output = ()>,
) -> Value {
    let available = deadline
        .saturating_duration_since(tokio::time::Instant::now())
        .min(Duration::from_secs(seconds));
    let finished = tokio::time::timeout(available, work).await.is_ok();
    json!({"stage":name,"status":if finished{"complete"}else{"deadline_exceeded"},"requiresReconciliation":!finished})
}
/// Rented NeoCloud GPUs bill by the hour, so they are stopped before any other cleanup, on every
/// way out: the close button with nothing else running, `yougori app quit` and a forced exit come
/// here without the quit dialog, whose own stop is only a first pass. A stop that does not finish
/// stays written down and is finished at the next start.
async fn rented_gpus(handing_over: bool, deadline: tokio::time::Instant, stop: impl Future<Output = ()>) -> Value {
    if handing_over {
        return json!({"stage":"rented_gpus","status":"skipped","reason":"The desktop app took over and keeps them running","requiresReconciliation":false});
    }
    stage("rented_gpus", 30, deadline, stop).await
}
pub(crate) async fn run(app: &AppHandle) -> Value {
    crate::security::record(crate::security::Event::new("engine.stopping").via("engine"));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(50);
    crate::lifecycle::cancel_startup(app);
    crate::file_import::cancel_all_transfers();
    crate::guest_execution::cancel_all_jobs();
    let control = crate::automation::prepare_shutdown(app, Duration::from_secs(10)).await;
    let mut stages = vec![
        json!({"stage":"cancel_and_drain_operations","status":if control["drained"]==true{"complete"}else{"deadline_exceeded"},"requiresReconciliation":control["drained"]!=true}),
    ];
    let rented = async {
        futures_util::future::join(
            crate::grid_neocloud::stop_on_quit(app),
            crate::swarm::rented::stop_on_quit(app),
        )
        .await;
    };
    stages.push(rented_gpus(HANDING_OVER.load(Ordering::Acquire), deadline, rented).await);
    let terminals = app.clone();
    stages.push(
        stage("host_terminals", 3, deadline, async move {
            let _ = tokio::task::spawn_blocking(move || {
                terminals
                    .state::<crate::host_terminal::HostTerminalManager>()
                    .shutdown()
            })
            .await;
        })
        .await,
    );
    stages.push(stage("vault", 3, deadline, crate::vault_setup::shutdown(app)).await);
    stages.push(
        stage(
            "download_links",
            4,
            deadline,
            app.state::<crate::environment_download::Downloads>()
                .shutdown(),
        )
        .await,
    );
    let runtime = app.state::<crate::runtime::RuntimeManager>();
    if let Ok(platform) = app.state::<crate::store::PlatformStore>().snapshot() {
        crate::security::sync_runtime_containment(&platform);
    }
    stages.push(
        stage(
            "publications_and_sessions",
            8,
            deadline,
            app.state::<crate::workspace::WorkspaceManager>()
                .shutdown(&runtime),
        )
        .await,
    );
    let available = deadline
        .saturating_duration_since(tokio::time::Instant::now())
        .min(Duration::from_secs(20));
    let runtime_stage = match tokio::time::timeout(available, runtime.shutdown_all_report()).await {
        Ok(mut details) => {
            if let Some(outcomes) = details["outcomes"].as_array_mut() {
                let total = outcomes.len();
                outcomes.truncate(64);
                for outcome in outcomes {
                    if let Some(error) = outcome["error"].as_str() {
                        outcome["error"] = json!(crate::lifecycle::safe_diagnostic(error));
                    }
                }
                details["outcomeCount"] = json!(total);
                details["outcomesTruncated"] = json!(total > 64);
            }
            json!({"stage":"owned_runtimes","status":if details["complete"]==true{"complete"}else{"failed"},"requiresReconciliation":details["complete"]!=true,"details":details})
        }
        Err(_) => {
            json!({"stage":"owned_runtimes","status":"deadline_exceeded","requiresReconciliation":true,"postconditionVerified":false})
        }
    };
    stages.push(runtime_stage);
    let remaining=control["remainingJobs"].as_array().map(|jobs|jobs.iter().map(|job|json!({"jobId":job["jobId"],"method":job["method"],"status":job["status"]})).collect::<Vec<_>>()).unwrap_or_default();
    let report = json!({"shutdownRunId":crate::shutdown_run_id(app),"completedAt":chrono::Utc::now().to_rfc3339(),"deadlineSeconds":50,"stages":stages,"remainingJobs":remaining,"requiresReconciliation":stages.iter().any(|stage|stage["requiresReconciliation"]==true),"recoveryAction":"Inspect interrupted jobs and the next startup recovery report before retrying effects with an unknown outcome"});
    let path = app
        .state::<PlatformStore>()
        .data_folder("operations")
        .join("shutdown.json");
    let saved = report.clone();
    let save = tokio::task::spawn_blocking(move || -> Result<(), String> {
        let parent = path.parent().ok_or("Shutdown report directory missing")?;
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        let mut file = tempfile::NamedTempFile::new_in(parent).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|e| e.to_string())?;
        }
        serde_json::to_writer(&mut file, &saved).map_err(|e| e.to_string())?;
        file.as_file().sync_all().map_err(|e| e.to_string())?;
        file.persist(path).map_err(|e| e.error.to_string())?;
        Ok(())
    });
    if !matches!(
        tokio::time::timeout(Duration::from_secs(2), save).await,
        Ok(Ok(Ok(())))
    ) {
        eprintln!("Shutdown report could not be flushed before its deadline; reconcile runtime ownership on next startup.");
    }
    crate::security::flush();
    report
}
pub(crate) fn latest(store: &PlatformStore) -> Option<Value> {
    let path = store.data_folder("operations").join("shutdown.json");
    let metadata = std::fs::symlink_metadata(&path).ok()?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 65536 {
        return None;
    }
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn a_stuck_cleanup_stage_expires_without_blocking_the_next_stage() {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(30);
        let stuck = stage("stalled_transfer", 10, deadline, std::future::pending()).await;
        assert_eq!(stuck["status"], "deadline_exceeded");
        let next = stage(
            "flush_other_state",
            1,
            tokio::time::Instant::now() + Duration::from_secs(1),
            async {},
        )
        .await;
        assert_eq!(next["status"], "complete");
    }

    #[tokio::test]
    async fn every_quit_stops_rented_gpus_and_only_a_hand_over_keeps_them() {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(50);
        let stopped = AtomicBool::new(false);
        let stop = || async { stopped.store(true, Ordering::SeqCst) };
        let quit = rented_gpus(false, deadline, stop()).await;
        assert!(stopped.swap(false, Ordering::SeqCst), "a quit sends the stops");
        assert_eq!((quit["stage"].as_str(), quit["status"].as_str(), quit["requiresReconciliation"].as_bool()), (Some("rented_gpus"), Some("complete"), Some(false)));
        let handed = rented_gpus(true, deadline, stop()).await;
        assert!(!stopped.load(Ordering::SeqCst), "the engine taking over keeps them running");
        assert_eq!((handed["status"].as_str(), handed["requiresReconciliation"].as_bool()), (Some("skipped"), Some(false)));
        // NeoCloud not answering cannot hold the quit past the stage's share; the start after finishes it.
        let soon = tokio::time::Instant::now() + Duration::from_millis(30);
        let hung = rented_gpus(false, soon, std::future::pending()).await;
        assert_eq!((hung["status"].as_str(), hung["requiresReconciliation"].as_bool()), (Some("deadline_exceeded"), Some(true)));
    }
}
