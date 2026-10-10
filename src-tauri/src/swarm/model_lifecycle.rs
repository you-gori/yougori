//! Residency is separate from worker deletion. These operations only touch a
//! tagged Swarm model and preserve its verified files and persistent cache.
use super::{Swarm, Worker};
use crate::{
    models::{Environment, EnvironmentKind, EnvironmentStatus, PlatformState, RuntimeProviderKind},
    runtime::RuntimeManager,
    store::PlatformStore,
    AppHandle,
};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    sync::{Mutex as StdMutex, OnceLock},
    time::Duration,
};
use tauri::Manager;
use tokio_util::sync::CancellationToken;
use yougori_cli::workload::Options;

const OWNER: &str = "YOUGORI_SWARM_MODEL_OWNER";
static CLEANUP_TASKS: OnceLock<StdMutex<BTreeSet<String>>> = OnceLock::new();

fn same_files(encoded: Option<&String>, expected: &Value) -> bool {
    let Some(actual) = encoded.and_then(|value| serde_json::from_str::<Value>(value).ok()) else {
        return false;
    };
    let (Some(actual), Some(expected)) = (actual.as_array(), expected.as_array()) else {
        return false;
    };
    let mut actual = actual.clone();
    let mut expected = expected.clone();
    actual.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    expected.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    actual == expected && !actual.is_empty()
}

fn reusable_model(
    environment: &Environment,
    options: &Options,
    worker: &Worker,
    preflight: &Value,
) -> bool {
    let cpu = worker.resources["cpu"].as_f64().unwrap_or(4.) - 2.;
    let memory = worker.resources["memoryGb"].as_f64().unwrap_or(8.) - 4.;
    let same = |a: f64, b: f64| a.is_finite() && b.is_finite() && (a - b).abs() < 0.000001;
    let range_matches = |range: &crate::models::ResourceRange, allocation: f64| {
        [range.min, range.preferred, range.max]
            .iter()
            .all(|value| same(*value, allocation))
    };
    local_model(environment, options, worker)
        && ownership_valid(options, worker)
        && matches!(
            environment.status,
            EnvironmentStatus::Running | EnvironmentStatus::Stopped | EnvironmentStatus::Error
        )
        && (environment.provider == Some(RuntimeProviderKind::YougoriOci)) == (worker.gpu == "cpu")
        && environment.gpu_access == (worker.gpu != "cpu")
        && (options
            .environment
            .get("YOUGORI_MODEL_CPU")
            .map(String::as_str)
            == Some("1"))
            == (worker.gpu == "cpu")
        && options
            .environment
            .get("YOUGORI_MODEL_AGENT_API")
            .map(String::as_str)
            == Some("1")
        && options
            .environment
            .get("YOUGORI_MODEL_FORMAT")
            .map(String::as_str)
            == Some("gguf")
        && preflight["revision"].as_str().is_some_and(|revision| {
            revision.len() == 40
                && revision.bytes().all(|byte| byte.is_ascii_hexdigit())
                && options
                    .environment
                    .get("YOUGORI_MODEL_REVISION")
                    .map(String::as_str)
                    == Some(revision)
        })
        && preflight["quant"].as_str().is_some_and(|quant| {
            worker.quant.as_deref() == Some(quant)
                && options
                    .environment
                    .get("YOUGORI_MODEL_QUANT")
                    .map(String::as_str)
                    == Some(quant)
        })
        && same_files(
            options.environment.get("YOUGORI_MODEL_FILES"),
            &preflight["files"],
        )
        && options
            .secret_environment
            .get("YOUGORI_MODEL_TOKEN")
            .is_some_and(|reference| !reference.is_empty())
        && range_matches(&environment.resource_policy.cpu, cpu)
        && range_matches(&environment.resource_policy.memory_gb, memory)
        && worker.resources["storageDrive"]
            .as_str()
            .is_none_or(|drive| {
                environment
                    .storage_drive
                    .as_deref()
                    .is_some_and(|selected| {
                        selected
                            .trim_end_matches(['\\', '/'])
                            .eq_ignore_ascii_case(drive.trim_end_matches(['\\', '/']))
                    })
            })
        && worker.resources["storageGb"].as_f64().is_none_or(|quota| {
            environment
                .storage_limit_gb
                .is_some_and(|capacity| capacity >= quota)
        })
}

/// The retained environment, rather than a live worker row, owns the verified
/// cache. Stopped/deleted workers therefore do not force a duplicate download.
pub(crate) async fn find_reusable_model(
    app: &AppHandle,
    worker: &Worker,
    preflight: &Value,
) -> Result<Option<String>, String> {
    let rows = app
        .state::<Swarm>()
        .inner
        .lock()
        .await
        .rows
        .values()
        .cloned()
        .collect::<Vec<_>>();
    let state = app.state::<PlatformStore>().snapshot()?;
    let runtime = app.state::<RuntimeManager>();
    let mut candidates = Vec::new();
    for environment in &state.environments {
        let Ok(options) = runtime.workload_options(runtime_id(environment)) else {
            continue;
        };
        if reusable_model(environment, &options, worker, preflight)
            && !external_connections(&state, &rows, &environment.id)
        {
            candidates.push(environment);
        }
    }
    candidates.sort_by(|a, b| {
        (a.status != EnvironmentStatus::Running)
            .cmp(&(b.status != EnvironmentStatus::Running))
            .then_with(|| a.id.cmp(&b.id))
    });
    for environment in candidates {
        if !external_use(app, &environment.id).await? {
            return Ok(Some(environment.id.clone()));
        }
    }
    Ok(None)
}

fn runtime_id(environment: &Environment) -> &str {
    environment.runtime_id.as_deref().unwrap_or(&environment.id)
}

fn local_model(environment: &Environment, options: &Options, worker: &Worker) -> bool {
    environment.kind == EnvironmentKind::Container
        && matches!(
            environment.provider,
            Some(RuntimeProviderKind::YougoriOci | RuntimeProviderKind::YougoriCuda)
        )
        && options
            .environment
            .get("YOUGORI_MODEL")
            .is_some_and(|model| model == &worker.model)
        && !environment.runtime.starts_with("shared://")
        && !environment.runtime.starts_with("cloud://")
}

fn ownership_valid(options: &Options, worker: &Worker) -> bool {
    options
        .environment
        .get(OWNER)
        .is_some_and(|owner| owner.starts_with("worker-") && super::identifier(owner))
        && options
            .environment
            .get("YOUGORI_MODEL")
            .is_some_and(|model| model == &worker.model)
}

fn references<'a>(rows: &'a [Worker], worker: &Worker) -> Vec<&'a Worker> {
    rows.iter()
        .filter(|other| {
            other.model_environment_id == worker.model_environment_id
                && other.model_environment_id.is_some()
                && !matches!(other.state.as_str(), "stopped" | "failed")
        })
        .collect()
}

fn may_stop(rows: &[Worker], worker: &Worker, options: &Options) -> bool {
    ownership_valid(options, worker)
        && cleanup_current(rows.iter().find(|other| other.id == worker.id), worker)
        && !references(rows, worker)
            .iter()
            .any(|other| other.id != worker.id)
}

fn cleanup_current(current: Option<&Worker>, target: &Worker) -> bool {
    current.is_none_or(|current| {
        current.model_environment_id != target.model_environment_id
            || matches!(current.state.as_str(), "stopped" | "failed")
            || current.state == "paused" && current.server_id.is_none()
    })
}

/// A cancelled generation may still be winding down when Stop returns. Retry
/// only this unused tagged model, and stop retrying when it is reused or the
/// engine shuts down. Neither this task nor stop_if_unused deletes any cache.
pub(crate) fn schedule_unused_cleanup(app: &AppHandle, worker: &Worker) {
    let Some(model) = worker.model_environment_id.as_deref() else {
        return;
    };
    let key = format!("{}:{}:{model}", worker.id, worker.generation);
    if !CLEANUP_TASKS
        .get_or_init(Default::default)
        .lock()
        .map(|mut pending| pending.insert(key.clone()))
        .unwrap_or(false)
    {
        return;
    }
    struct CleanupGuard(String);
    impl Drop for CleanupGuard {
        fn drop(&mut self) {
            if let Ok(mut pending) = CLEANUP_TASKS.get_or_init(Default::default).lock() {
                pending.remove(&self.0);
            }
        }
    }
    let app = app.clone();
    let worker = worker.clone();
    tauri::async_runtime::spawn(async move {
        let _guard = CleanupGuard(key);
        let shutdown = crate::automation::shutdown_signal(&app);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(150);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = tokio::time::sleep_until(deadline) => break,
                _ = tokio::time::sleep(Duration::from_secs(2)) => {},
            }
            let eligible = tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = tokio::time::sleep_until(deadline) => break,
                result = async {
                    let manager = app.state::<Swarm>();
                    let inner = manager.inner.lock().await;
                    cleanup_current(inner.rows.get(&worker.id), &worker)
                } => result,
            };
            if !eligible {
                break;
            }
            let result = tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = tokio::time::sleep_until(deadline) => break,
                result = stop_if_unused(&app, &worker) => result,
            };
            if result.is_ok() {
                let Some(model) = worker.model_environment_id.as_deref() else {
                    break;
                };
                if !app
                    .state::<PlatformStore>()
                    .environment(model)
                    .is_ok_and(|env| env.status != EnvironmentStatus::Stopped)
                {
                    break;
                }
            }
        }
    });
}

fn may_release(rows: &[Worker], worker: &Worker, options: &Options) -> bool {
    if !ownership_valid(options, worker) || worker.keep_resident {
        return false;
    }
    let users = references(rows, worker);
    !users.is_empty()
        && users.iter().all(|other| {
            !other.keep_resident
                && matches!(other.state.as_str(), "ready_waiting" | "waiting" | "paused")
        })
}

fn runtime_idle(health: &Value) -> bool {
    let optimizer = &health["optimizer"];
    health["status"] == "ready"
        && optimizer["pinned"] != true
        && optimizer["loading"] != true
        && optimizer["active"].as_u64() == Some(0)
        && optimizer["pending"].as_u64() == Some(0)
}

fn external_connections(state: &PlatformState, rows: &[Worker], model: &str) -> bool {
    let agents = rows
        .iter()
        .filter_map(|worker| worker.environment_id.as_deref())
        .collect::<BTreeSet<_>>();
    state
        .saved_environment_services
        .iter()
        .any(|service| service.environment_id == model)
        || state
            .connections
            .iter()
            .filter(|connection| connection.active)
            .any(|connection| {
                if connection.source_id == model {
                    !agents.contains(connection.target_id.as_str())
                } else if connection.target_id == model {
                    !agents.contains(connection.source_id.as_str())
                } else {
                    false
                }
            })
}

/// A live API publication or Neo Grid registration is independent use, even
/// if the Swarm worker that created the model has since stopped.
async fn external_use(app: &AppHandle, model: &str) -> Result<bool, String> {
    if let Some(workspace) = app.try_state::<crate::workspace::WorkspaceManager>() {
        let publications = crate::workspace::publication_metadata(
            model,
            &app.state::<PlatformStore>(),
            &workspace,
        )
        .await?;
        if !publications.is_empty() {
            return Ok(true);
        }
    }
    if app.try_state::<crate::market::Market>().is_some() {
        let status = tokio::time::timeout(
            Duration::from_secs(5),
            crate::market::market_status(app.clone()),
        )
        .await;
        // An unavailable ordinary-use inventory never authorizes eviction.
        let Ok(Ok(status)) = status else {
            return Ok(true);
        };
        if status["shares"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|share| share["environmentId"] == model)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn tag_owned_model(app: &AppHandle, worker: &Worker) -> Result<(), String> {
    if !worker.owned_model {
        return Ok(());
    }
    let id = worker
        .model_environment_id
        .as_deref()
        .ok_or("This worker has no created model environment")?;
    let environment = app.state::<PlatformStore>().environment(id)?;
    let runtime = app.state::<RuntimeManager>();
    let mut options = runtime.workload_options(runtime_id(&environment))?;
    if !local_model(&environment, &options, worker) {
        return Err("The created model does not match this worker's local model ownership".into());
    }
    if options
        .environment
        .get(OWNER)
        .is_some_and(|owner| owner != &worker.id)
    {
        return Err(
            "This model already has another Swarm owner; its metadata was preserved".into(),
        );
    }
    options.environment.insert(OWNER.into(), worker.id.clone());
    runtime.save_workload_options(runtime_id(&environment), &options)
}

/// Creation may finish after Cancel, Stop, or Delete. Persist only its owned
/// model reference in the current journal; never restore an earlier generation.
pub(crate) async fn record_created_model(
    app: &AppHandle,
    worker: &mut Worker,
    cancel: &CancellationToken,
) -> Result<bool, String> {
    tag_owned_model(app, worker)?;
    let manager = app.state::<Swarm>();
    let mut inner = manager.inner.lock().await;
    let (current, continuing) = match inner.rows.get_mut(&worker.id) {
        Some(current) => {
            let continuing = reconcile_created(current, worker, cancel.is_cancelled());
            (current.clone(), continuing)
        }
        None => {
            let mut orphan = worker.clone();
            orphan.state = "stopped".into();
            (orphan, false)
        }
    };
    super::save(app, &inner)?;
    drop(inner);
    if !continuing {
        // Keep the freshly created record for cleanup even when a newer
        // generation selected another model. Its owner tag is authoritative.
        let mut cleanup = worker.clone();
        cleanup.state = "stopped".into();
        stop_if_unused(app, &cleanup).await?;
        schedule_unused_cleanup(app, &cleanup);
        *worker = current;
    }
    Ok(continuing)
}

fn reconcile_created(current: &mut Worker, created: &Worker, cancelled: bool) -> bool {
    if current.model_environment_id.is_some()
        && current.model_environment_id != created.model_environment_id
    {
        return false;
    }
    current.model_environment_id = created.model_environment_id.clone();
    current.owned_model = true;
    current.quant = created.quant.clone();
    !cancelled && current.generation == created.generation && current.state == "preparing"
}

pub(crate) async fn stop_if_unused(app: &AppHandle, worker: &Worker) -> Result<(), String> {
    let Some(id) = worker.model_environment_id.as_deref() else {
        return Ok(());
    };
    let manager = app.state::<Swarm>();
    // Hold the reference registry until the residency change completes. A new
    // acceptance cannot race this decision and have its live model stopped.
    let inner = manager.inner.lock().await;
    let rows = inner.rows.values().cloned().collect::<Vec<_>>();
    let state = app.state::<PlatformStore>().snapshot()?;
    let Some(environment) = state
        .environments
        .iter()
        .find(|environment| environment.id == id)
    else {
        return Ok(());
    };
    let runtime = app.state::<RuntimeManager>();
    let options = runtime.workload_options(runtime_id(environment))?;
    if environment.status == EnvironmentStatus::Stopped
        || !local_model(environment, &options, worker)
        || !may_stop(&rows, worker, &options)
        || external_connections(&state, &rows, id)
        || external_use(app, id).await?
    {
        return Ok(());
    }
    let health = tokio::time::timeout(
        Duration::from_secs(10),
        crate::model_runner::model_status(id.into(), app.clone()),
    )
    .await
    .ok()
    .and_then(Result::ok);
    // A cancelled initial setup can have no HTTP server yet. This exception
    // is limited to our tagged private model before any agent is registered;
    // it stops startup while retaining partial, resumable downloads.
    let initial_setup = worker.server_id.is_none()
        && worker.environment_id.is_none()
        && options
            .environment
            .get("YOUGORI_MODEL_AGENT_API")
            .is_some_and(|v| v == "1");
    if !may_stop_runtime(health.as_ref(), initial_setup) {
        return Ok(());
    }
    crate::model_runner::stop_model(id.into(), app.clone()).await?;
    // stop_model keeps the environment, verified weights and cache. This
    // module intentionally has no delete/prune operation.
    Ok(())
}

fn may_stop_runtime(health: Option<&Value>, initial_setup: bool) -> bool {
    match health {
        Some(health)
            if matches!(health["status"].as_str(), Some("ready" | "idle" | "error"))
                && health["optimizer"]["pinned"] != true
                && health["optimizer"]["loading"] != true
                && health["optimizer"]["active"].as_u64() == Some(0)
                && health["optimizer"]["pending"].as_u64() == Some(0) =>
        {
            true
        }
        Some(health) if initial_setup => {
            health["optimizer"]["pinned"] != true
                && health["optimizer"]["active"].as_u64().unwrap_or(0) == 0
                && matches!(
                    health["status"].as_str(),
                    Some(
                        "installing"
                            | "starting"
                            | "downloading"
                            | "loading"
                            | "queued"
                            | "idle"
                            | "error"
                    )
                )
        }
        None => initial_setup,
        _ => false,
    }
}

pub(crate) async fn release_while_waiting(app: &AppHandle, worker: &Worker) -> Result<(), String> {
    let Some(id) = worker.model_environment_id.as_deref() else {
        return Ok(());
    };
    let manager = app.state::<Swarm>();
    let inner = manager.inner.lock().await;
    let rows = inner.rows.values().cloned().collect::<Vec<_>>();
    let state = app.state::<PlatformStore>().snapshot()?;
    let Some(environment) = state
        .environments
        .iter()
        .find(|environment| environment.id == id)
    else {
        return Ok(());
    };
    let runtime = app.state::<RuntimeManager>();
    let options = runtime.workload_options(runtime_id(environment))?;
    if environment.status == EnvironmentStatus::Stopped
        || !local_model(environment, &options, worker)
        || !may_release(&rows, worker, &options)
        || external_connections(&state, &rows, id)
        || external_use(app, id).await?
    {
        return Ok(());
    }
    let health = tokio::time::timeout(
        Duration::from_secs(10),
        crate::model_runner::model_status(id.into(), app.clone()),
    )
    .await
    .map_err(|_| "Could not confirm idle model residency within ten seconds")??;
    if !runtime_idle(&health) {
        return Ok(());
    }
    if worker.gpu == "cpu" {
        crate::model_runner::stop_model(id.into(), app.clone()).await?;
    } else if health["optimizer"]["supported"] == true && health["optimizer"]["enabled"] == true {
        // This opt-in only changes this tagged model. The runner refuses to
        // unload if an inference/lease/pin appears after our health snapshot.
        crate::model_runner::optimizer::model_optimizer(
            id.into(),
            None,
            None,
            Some(10),
            app.clone(),
        )
        .await?;
        let _ = crate::model_runner::model_request(
            app,
            id,
            "/v1/yougori/optimizer",
            Some(json!({"action":"unload"})),
        )
        .await?;
    }
    Ok(())
}

pub(crate) async fn ensure_ready(
    app: &AppHandle,
    worker: &Worker,
    cancel: &CancellationToken,
) -> Result<(), String> {
    let id = worker
        .model_environment_id
        .as_deref()
        .ok_or("The worker has no selected model environment")?;
    let environment = app.state::<PlatformStore>().environment(id)?;
    let options = app
        .state::<RuntimeManager>()
        .workload_options(runtime_id(&environment))?;
    if !local_model(&environment, &options, worker) || !ownership_valid(&options, worker) {
        return Err(
            "The worker model has no valid local Swarm ownership. Its files were preserved.".into(),
        );
    }
    if cancel.is_cancelled() {
        return Err("Worker model preparation cancelled".into());
    }
    if environment.status != EnvironmentStatus::Running {
        crate::model_runner::start_model(id.into(), app.clone()).await?;
    }
    let lease = format!("swarm-{}", uuid::Uuid::new_v4().simple());
    let result = wait_ready(app, worker, &lease, cancel).await;
    if worker.gpu != "cpu" {
        let _ = tokio::time::timeout(
            Duration::from_secs(5),
            crate::model_runner::model_request(
                app,
                id,
                "/v1/yougori/release",
                Some(json!({"lease":lease})),
            ),
        )
        .await;
    }
    result
}

async fn wait_ready(
    app: &AppHandle,
    worker: &Worker,
    lease: &str,
    cancel: &CancellationToken,
) -> Result<(), String> {
    let id = worker
        .model_environment_id
        .as_deref()
        .ok_or("Missing model environment")?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(300);
    loop {
        let health = tokio::select! {
            _ = cancel.cancelled() => return Err("Worker model preparation cancelled".into()),
            value = tokio::time::timeout(Duration::from_secs(10), crate::model_runner::model_status(id.into(), app.clone())) => value,
        };
        if let Ok(Ok(health)) = health {
            if health["status"] == "ready" {
                if should_clear_idle_timeout(&health) {
                    // A previous waiting preference may have left a ten-second
                    // timer. Active work and private prompts retain this model
                    // until the waiting path explicitly releases it again.
                    crate::model_runner::optimizer::model_optimizer(
                        id.into(),
                        None,
                        None,
                        Some(0),
                        app.clone(),
                    )
                    .await?;
                }
                return Ok(());
            }
            if health["status"] == "error" {
                return Err(health["error"]
                    .as_str()
                    .unwrap_or("The worker model could not load")
                    .to_owned());
            }
            if worker.gpu != "cpu" && health["optimizer"]["enabled"] == true {
                // Prepare queues a renewable 20-second demand lease. Only the
                // existing host scheduler may grant it; never directly evict
                // another GPU model, change a pin, or disable optimization.
                let queued = tokio::select! {
                    _ = cancel.cancelled() => return Err("Worker model preparation cancelled".into()),
                    value = tokio::time::timeout(Duration::from_secs(10), crate::model_runner::model_request(app, id, "/v1/yougori/prepare", Some(json!({"lease":lease})))) => value,
                };
                if let Ok(Err(error)) = queued {
                    return Err(error);
                }
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("The worker model did not become ready within five minutes. Other active or pinned models were preserved; verified model files remain available.".into());
        }
        tokio::select! { _ = cancel.cancelled() => return Err("Worker model preparation cancelled".into()), _ = tokio::time::sleep(Duration::from_secs(2)) => {} }
    }
}

fn should_clear_idle_timeout(health: &Value) -> bool {
    health["optimizer"]["supported"] == true
        && health["optimizer"]["enabled"] == true
        && health["optimizer"]["idleTimeoutSeconds"]
            .as_u64()
            .is_some_and(|seconds| seconds > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn worker(id: &str, state: &str, keep: bool) -> Worker {
        serde_json::from_value(json!({"id":id,"name":"Fixture","model":"owner/model-GGUF","state":state,"stage":"Ready","site":"https://example.test","gpu":"cpu","resources":{"cpu":4,"memoryGb":8},"quotaGb":20,"keepResident":keep,"modelEnvironmentId":"env-model","environmentId":format!("env-agent-{id}")})).unwrap()
    }
    fn options() -> Options {
        serde_json::from_value(json!({"environment":{"YOUGORI_MODEL":"owner/model-GGUF","YOUGORI_SWARM_MODEL_OWNER":"worker-original"}})).unwrap()
    }
    #[test]
    fn last_reference_can_stop_a_tagged_model_after_the_original_owner_leaves() {
        let original = worker("worker-original", "stopped", false);
        let reused = worker("worker-reused", "stopped", false);
        assert!(may_stop(&[original, reused.clone()], &reused, &options()));
        assert!(!may_stop(
            &[worker("worker-original", "running", false), reused.clone()],
            &reused,
            &options()
        ));
    }
    #[test]
    fn waiting_release_requires_all_references_idle_and_all_residency_preferences_off() {
        let requester = worker("worker-a", "ready_waiting", false);
        assert!(may_release(
            &[requester.clone(), worker("worker-b", "paused", false)],
            &requester,
            &options()
        ));
        for other in [
            worker("worker-b", "running", false),
            worker("worker-b", "preparing_bounty", false),
            worker("worker-b", "waiting", true),
        ] {
            assert!(!may_release(
                &[requester.clone(), other],
                &requester,
                &options()
            ));
        }
    }
    #[test]
    fn ordinary_or_mismatched_models_never_gain_residency_authorization() {
        let requester = worker("worker-a", "waiting", false);
        let mut ordinary = options();
        ordinary.environment.remove(OWNER);
        assert!(!may_stop(&[requester.clone()], &requester, &ordinary));
        assert!(!may_release(&[requester.clone()], &requester, &ordinary));
        ordinary
            .environment
            .insert(OWNER.into(), "not-a-worker".into());
        assert!(!ownership_valid(&ordinary, &requester));
        let mut wrong = options();
        wrong
            .environment
            .insert("YOUGORI_MODEL".into(), "another/model".into());
        assert!(!ownership_valid(&wrong, &requester));
    }
    #[test]
    fn active_pending_loading_and_pinned_runners_cannot_be_evicted() {
        let idle = json!({"status":"ready","optimizer":{"active":0,"pending":0,"pinned":false,"loading":false}});
        assert!(runtime_idle(&idle));
        for (key, value) in [
            ("active", json!(1)),
            ("pending", json!(1)),
            ("pinned", json!(true)),
            ("loading", json!(true)),
        ] {
            let mut busy = idle.clone();
            busy["optimizer"][key] = value;
            assert!(!runtime_idle(&busy));
        }
        assert!(!runtime_idle(&json!({"status":"ready"})));
    }
    #[test]
    fn late_creation_reconciles_only_owned_model_fields_without_restoring_state() {
        let mut created = worker("worker-a", "preparing", false);
        created.owned_model = true;
        created.quant = Some("Q4_K_M".into());
        let mut paused = worker("worker-a", "paused", false);
        paused.generation = 2;
        paused.model_environment_id = None;
        paused.stage = "Participant paused".into();
        assert!(!reconcile_created(&mut paused, &created, false));
        assert_eq!(paused.model_environment_id, created.model_environment_id);
        assert!(paused.owned_model);
        assert_eq!(paused.quant.as_deref(), Some("Q4_K_M"));
        assert_eq!(paused.state, "paused");
        assert_eq!(paused.generation, 2);
        assert_eq!(paused.stage, "Participant paused");
        let mut replaced = paused.clone();
        replaced.model_environment_id = Some("env-newer".into());
        assert!(!reconcile_created(&mut replaced, &created, false));
        assert_eq!(replaced.model_environment_id.as_deref(), Some("env-newer"));
    }
    #[test]
    fn cancelled_private_startup_can_stop_without_preempting_ready_active_work() {
        assert!(may_stop_runtime(None, true));
        assert!(!may_stop_runtime(None, false));
        let setup =
            json!({"status":"downloading","optimizer":{"active":0,"pending":1,"pinned":false}});
        assert!(may_stop_runtime(Some(&setup), true));
        assert!(!may_stop_runtime(Some(&setup), false));
        for value in [
            json!({"status":"ready","optimizer":{"active":1,"pending":0}}),
            json!({"status":"downloading","optimizer":{"active":0,"pinned":true}}),
        ] {
            assert!(!may_stop_runtime(Some(&value), true));
        }
    }
    #[test]
    fn deferred_cleanup_cannot_stop_a_resumed_worker_or_a_registered_paused_worker() {
        let stopped = worker("worker-a", "stopped", false);
        assert!(cleanup_current(None, &stopped));
        assert!(cleanup_current(Some(&stopped), &stopped));
        let mut resumed = stopped.clone();
        resumed.generation += 1;
        resumed.state = "running".into();
        assert!(!cleanup_current(Some(&resumed), &stopped));
        resumed.state = "ready_waiting".into();
        assert!(!cleanup_current(Some(&resumed), &stopped));
        resumed.state = "paused".into();
        resumed.server_id = Some("server-worker".into());
        assert!(!cleanup_current(Some(&resumed), &stopped));
        resumed.server_id = None;
        assert!(cleanup_current(Some(&resumed), &stopped));
        resumed.model_environment_id = Some("env-replacement".into());
        resumed.state = "running".into();
        assert!(cleanup_current(Some(&resumed), &stopped));
        assert!(!may_stop(
            &[worker("worker-a", "running", false)],
            &stopped,
            &options()
        ));
    }
    #[test]
    fn retained_cache_reuse_requires_exact_private_model_revision_quant_mode_and_allocation() {
        let mut requester = worker("worker-new", "preparing", true);
        requester.quant = Some("Q4_K_M".into());
        let preflight = json!({"revision":"a".repeat(40),"quant":"Q4_K_M","files":[{"name":"model.gguf","size":123,"sha256":"b".repeat(64)}]});
        let environment: Environment = serde_json::from_value(json!({"id":"env-model","name":"Retained model","kind":"container","provider":"yougoriOci","status":"stopped","runtime":"ubuntu:24.04","description":"Hugging Face model","createdAt":"2026-10-10","cpuUsage":0,"memoryUsageGb":0,"storageDeltaGb":0,"networkRxMbps":0,"storageLimitGb":20,"storageDrive":"D:\\","resourcePolicy":{"cpu":{"min":2,"preferred":2,"max":2,"current":0},"memoryGb":{"min":4,"preferred":4,"max":4,"current":0},"priority":"normal"}})).unwrap();
        let mut selected = options();
        for (name, value) in [
            ("YOUGORI_MODEL_REVISION", "a".repeat(40)),
            ("YOUGORI_MODEL_QUANT", "Q4_K_M".into()),
            ("YOUGORI_MODEL_CPU", "1".into()),
            ("YOUGORI_MODEL_AGENT_API", "1".into()),
            ("YOUGORI_MODEL_FORMAT", "gguf".into()),
            ("YOUGORI_MODEL_FILES", preflight["files"].to_string()),
        ] {
            selected.environment.insert(name.into(), value);
        }
        selected
            .secret_environment
            .insert("YOUGORI_MODEL_TOKEN".into(), "model-api-fixture".into());
        assert!(reusable_model(
            &environment,
            &selected,
            &requester,
            &preflight
        ));
        // No originating worker row is consulted: a retained tagged cache
        // remains eligible after its owner was stopped or deleted.
        for (name, value) in [
            (OWNER, ""),
            (
                "YOUGORI_MODEL_REVISION",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
            ("YOUGORI_MODEL_QUANT", "Q8_0"),
            ("YOUGORI_MODEL_CPU", "0"),
            ("YOUGORI_MODEL_AGENT_API", "0"),
            ("YOUGORI_MODEL_FILES", "[]"),
        ] {
            let mut mismatch = selected.clone();
            mismatch.environment.insert(name.into(), value.into());
            assert!(
                !reusable_model(&environment, &mismatch, &requester, &preflight),
                "{name}"
            );
        }
        let mut changed = environment.clone();
        changed.resource_policy.cpu.max = 3.;
        assert!(!reusable_model(&changed, &selected, &requester, &preflight));
        requester.resources["storageDrive"] = json!("D:");
        assert!(reusable_model(
            &environment,
            &selected,
            &requester,
            &preflight
        ));
        requester.resources["storageDrive"] = json!("C:");
        assert!(!reusable_model(
            &environment,
            &selected,
            &requester,
            &preflight
        ));
    }
    #[test]
    fn resumed_demand_clears_a_prior_idle_timer_without_changing_pin_or_enabled_preferences() {
        let health = json!({"optimizer":{"supported":true,"enabled":true,"pinned":true,"idleTimeoutSeconds":10}});
        assert!(should_clear_idle_timeout(&health));
        for (field, value) in [
            ("idleTimeoutSeconds", json!(0)),
            ("enabled", json!(false)),
            ("supported", json!(false)),
        ] {
            let mut changed = health.clone();
            changed["optimizer"][field] = value;
            assert!(!should_clear_idle_timeout(&changed));
        }
        assert_eq!(health["optimizer"]["pinned"], true);
    }
}
