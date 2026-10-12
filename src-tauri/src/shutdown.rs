//! Shutdown has its own bounded path, outside ordinary operation coordination.
use crate::{store::PlatformStore, AppHandle};
use serde_json::{json, Value};
use std::{future::Future, time::Duration};
use tauri::Manager;

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
}
