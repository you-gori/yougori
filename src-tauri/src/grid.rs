//! Closed Neo Grid in the engine. On the admin's computer it runs the hub. On every member
//! computer (the admin's included) it follows the admin's plan: it prepares the assigned model,
//! serves the grid only while the plan's hours and idle rule allow, gives the GPU back when the
//! person returns and checks in with the hub every 30 seconds. The hub's private key, the
//! company password's derived key and the membership token live in the OS credential vault.
use crate::{
    models::{EnvironmentKind, EnvironmentStatus},
    projects::secrets,
    runtime::RuntimeManager,
    security::Event,
    store::PlatformStore,
    AppHandle,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tauri::Manager;
use yougori_grid::{
    activity::Activity,
    hub::{self, Hub, ModelReport, PlanChange},
    member::{self, Assignment, MemberError, Membership, Outcome, WorkerEvent},
    net, password,
    policy::{Decision, IdlePolicy},
};

const HUB_KEY: &str = "yougori-grid-hub-key";
const HUB_PASSWORD: &str = "yougori-grid-hub-password";
const MEMBER_TOKEN: &str = "yougori-grid-member-token";
const TICK: Duration = Duration::from_secs(5);
const REPORT: Duration = Duration::from_secs(30);
const HEALTH: Duration = Duration::from_secs(10);
const CAPABILITY: Duration = Duration::from_secs(30 * 60);
/// A model that could not be prepared is tried again after this long.
const RETRY: Duration = Duration::from_secs(10 * 60);
/// A model environment the grid started is stopped after this long outside the plan's hours.
const PARK: Duration = Duration::from_secs(10 * 60);
/// At most one start of a parked model environment per this long.
const RESTART: Duration = Duration::from_secs(2 * 60);

#[derive(Default)]
pub struct Grid {
    inner: tokio::sync::Mutex<Inner>,
    /// Serializes creating, joining, leaving and deleting.
    admin: tokio::sync::Mutex<()>,
    wake: tokio::sync::Notify,
}

#[derive(Default)]
struct Inner {
    loaded: bool,
    hub: Option<Hub>,
    hub_error: Option<String>,
    member: Option<Saved>,
    membership: Option<Membership>,
    member_error: Option<String>,
    connected: bool,
    reported: Option<Instant>,
    reported_state: Option<String>,
    /// Whether this computer can run models, and its backend; refreshed every 30 minutes.
    capable: Option<(bool, String)>,
    capable_at: Option<Instant>,
    /// User activity is read every tick while serving, else every 15 seconds.
    activity: Option<(Activity, Instant)>,
    work: Work,
}

/// This computer's membership as saved on disk; its token is in the OS vault.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Saved {
    version: u8,
    grid_id: String,
    grid_name: String,
    address: String,
    certificate: String,
    fingerprint: String,
    member_id: String,
    joined_at: i64,
    #[serde(default)]
    assignment: Option<Assignment>,
    /// The model environment serving the assignment.
    #[serde(default)]
    environment_id: Option<String>,
    /// The grid created or started that environment, so it may also stop it.
    #[serde(default)]
    managed: bool,
    /// The grid (or an engine shutdown) stopped the environment, so the grid may start it
    /// again; one the person stopped stays stopped.
    #[serde(default)]
    parked: bool,
}

#[derive(Default)]
struct Work {
    preparing: Option<tauri::async_runtime::JoinHandle<()>>,
    prepare_error: Option<(String, Instant)>,
    worker: Option<Worker>,
    ready: bool,
    /// The model server has handled no request, from anyone, for PARK.
    quiet: bool,
    /// From the last health check: a request is running or waiting, and seconds since the
    /// last request (the grid's own included).
    person_using: Option<(bool, Option<u64>)>,
    health_at: Option<Instant>,
    gpu: Option<String>,
    quant: Option<String>,
    outside_since: Option<Instant>,
    started_at: Option<Instant>,
    state: String,
    reason: String,
}

struct Worker {
    gate: tokio::sync::watch::Sender<bool>,
    task: tauri::async_runtime::JoinHandle<()>,
    environment_id: String,
    stats: Arc<std::sync::Mutex<Stats>>,
}

#[derive(Clone, Default)]
struct Stats {
    busy: bool,
    jobs: u64,
    released: u64,
    failures: u64,
    last_job: Option<Instant>,
    last_error: Option<String>,
}

fn folder(app: &AppHandle) -> PathBuf {
    app.state::<PlatformStore>().data_folder("grid")
}

fn hub_path(app: &AppHandle) -> PathBuf {
    folder(app).join("hub.json")
}

fn member_path(app: &AppHandle) -> PathBuf {
    folder(app).join("member.json")
}

fn persist(app: &AppHandle, saved: &Saved) -> Result<(), String> {
    let path = member_path(app);
    let folder = path.parent().ok_or("Invalid grid folder")?;
    std::fs::create_dir_all(folder).map_err(|error| error.to_string())?;
    let mut file = tempfile::NamedTempFile::new_in(folder).map_err(|error| error.to_string())?;
    std::io::Write::write_all(&mut file, &serde_json::to_vec_pretty(saved).map_err(|error| error.to_string())?).map_err(|error| error.to_string())?;
    file.persist(&path).map_err(|error| error.to_string())?;
    Ok(())
}

/// Joins, refusals and departures at the hub go to the security audit log.
fn events() -> hub::Events {
    Arc::new(|kind: &'static str, detail: Value| crate::security::record(Event::new(kind).object("detail", detail)))
}

fn computer_name(app: &AppHandle) -> String {
    app.state::<PlatformStore>().snapshot().map(|state| state.host.hostname.trim().to_owned()).ok().filter(|name| !name.is_empty()).unwrap_or_else(|| "Computer".into())
}

fn ready(health: &Value) -> bool {
    health["status"] == "ready"
        || health["weightsVerified"] == true && health["optimizer"]["enabled"] == true && matches!(health["status"].as_str(), Some("idle" | "queued" | "freeing_memory" | "loading" | "unloading"))
}

async fn capability(app: &AppHandle) -> (bool, String) {
    match crate::model_runner::model_compute_status(app.clone()).await {
        Ok(value) => (value["cudaSupported"] == true || value["metalSupported"] == true, value["backend"].as_str().unwrap_or("cpu").to_owned()),
        Err(_) => (false, "unknown".into()),
    }
}

async fn ensure_loaded(app: &AppHandle) {
    let grid = app.state::<Grid>();
    let mut inner = grid.inner.lock().await;
    if inner.loaded {
        return;
    }
    inner.loaded = true;
    let path = hub_path(app);
    if path.exists() {
        match (secrets::resolve(HUB_KEY), secrets::resolve(HUB_PASSWORD)) {
            (Ok(key), Ok(password_key)) => match Hub::start(path, &key, &password_key, events()).await {
                Ok(hub) => inner.hub = Some(hub),
                Err(error) => inner.hub_error = Some(error),
            },
            _ => inner.hub_error = Some("The grid hub's keys are missing from the OS credential vault; delete the grid and create it again".into()),
        }
    }
    if let Ok(bytes) = std::fs::read(member_path(app)) {
        match serde_json::from_slice::<Saved>(&bytes) {
            Ok(saved) => {
                let membership = saved
                    .address
                    .parse::<SocketAddr>()
                    .map_err(|error| error.to_string())
                    .and_then(|address| Membership::new(address, &saved.certificate, saved.member_id.clone(), secrets::resolve(MEMBER_TOKEN)?));
                match membership {
                    Ok(membership) => {
                        inner.membership = Some(membership);
                        inner.member = Some(saved);
                    }
                    Err(_) => inner.member_error = Some("This computer's grid membership is incomplete; join again with the company password".into()),
                }
            }
            Err(_) => inner.member_error = Some("This computer's grid membership is damaged; join again with the company password".into()),
        }
    }
}

/// Keeps this computer's grid work in line with the admin's plan while the engine runs.
pub(crate) fn start(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let shutdown = crate::automation::shutdown_signal(&app);
        ensure_loaded(&app).await;
        loop {
            let grid = app.state::<Grid>();
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = grid.wake.notified() => {}
                _ = tokio::time::sleep(TICK) => {}
            }
            tick(&app).await;
        }
        let grid = app.state::<Grid>();
        let mut inner = grid.inner.lock().await;
        stop_worker(&mut inner.work, true);
        if let Some(saved) = inner.member.as_mut().filter(|saved| saved.managed && !saved.parked) {
            saved.parked = true;
            let _ = persist(&app, saved);
        }
        if let Some(hub) = inner.hub.take() {
            hub.flush();
        }
    });
}

/// Closing the gate lets a reply in progress finish; `now` also cancels it.
fn stop_worker(work: &mut Work, now: bool) {
    if let Some(worker) = work.worker.take() {
        if now {
            worker.task.abort();
        }
    }
    work.ready = false;
    work.health_at = None;
}

fn spawn_worker(app: &AppHandle, membership: Membership, model: String, environment_id: String, serve: bool) -> Worker {
    let (gate, receiver) = tokio::sync::watch::channel(serve);
    let stats = Arc::new(std::sync::Mutex::new(Stats::default()));
    let connect = {
        let (app, id) = (app.clone(), environment_id.clone());
        move || {
            let (app, id) = (app.clone(), id.clone());
            async move {
                let (io, api_key) = crate::model_runner::model_socket(&app, &id).await?;
                Ok(member::LocalModel { io: Box::new(io), api_key })
            }
        }
    };
    let events = {
        let stats = stats.clone();
        move |event: WorkerEvent| {
            let mut stats = stats.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            match event {
                WorkerEvent::Started => stats.busy = true,
                WorkerEvent::Finished(outcome) => {
                    stats.busy = false;
                    stats.last_job = Some(Instant::now());
                    match outcome {
                        Outcome::Served { status } if status < 400 => stats.jobs += 1,
                        Outcome::Served { status } => stats.last_error = Some(format!("The local model answered HTTP {status}")),
                        Outcome::Released(reason) => {
                            stats.released += 1;
                            stats.last_error = Some(reason);
                        }
                        Outcome::Cancelled => {}
                        Outcome::Failed(error) => {
                            stats.failures += 1;
                            stats.last_error = Some(error);
                        }
                    }
                }
                WorkerEvent::Removed => stats.last_error = Some(MemberError::Removed.to_string()),
                WorkerEvent::Error(error) => stats.last_error = Some(error),
            }
        }
    };
    let task = tauri::async_runtime::spawn(member::serve(membership, model, receiver, connect, events));
    Worker { gate, task, environment_id, stats }
}

/// An environment that already runs the assigned model, running ones first.
fn find_environment(app: &AppHandle, assignment: &Assignment) -> Option<(String, bool)> {
    let state = app.state::<PlatformStore>().snapshot().ok()?;
    let runtime = app.state::<RuntimeManager>();
    let wanted = yougori_grid::model_key(&assignment.model);
    let mut matches: Vec<(String, bool)> = state
        .environments
        .iter()
        .filter(|environment| environment.kind == EnvironmentKind::Container)
        .filter_map(|environment| {
            let options = runtime.workload_options(environment.runtime_id.as_deref().unwrap_or(&environment.id)).ok()?;
            let model = options.environment.get("YOUGORI_REGISTRY_MODEL").or_else(|| options.environment.get("YOUGORI_MODEL"))?;
            let quant = options.environment.get("YOUGORI_MODEL_QUANT");
            let same = yougori_grid::model_key(model) == wanted
                && assignment.quant.as_ref().is_none_or(|wanted| quant.is_some_and(|quant| quant.eq_ignore_ascii_case(wanted)))
                && options.environment.get("YOUGORI_MODEL_FORMAT").is_none_or(|format| format != "source");
            same.then(|| (environment.id.clone(), environment.status == EnvironmentStatus::Running))
        })
        .collect();
    matches.sort_by_key(|(_, running)| !running);
    matches.into_iter().next()
}

/// Finds, starts or creates the model environment for an assignment.
fn prepare(app: &AppHandle, assignment: Assignment) -> tauri::async_runtime::JoinHandle<()> {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let result: Result<(String, bool), String> = async {
            if let Some((id, running)) = find_environment(&app, &assignment) {
                if running {
                    return Ok((id, false));
                }
                crate::model_runner::start_model(id.clone(), app.clone()).await?;
                return Ok((id, true));
            }
            let created = crate::model_runner::run_model_with_resources(assignment.model.clone(), None, None, assignment.quant.clone(), app.clone()).await?;
            let id = created["id"].as_str().ok_or("The model environment was not created")?.to_owned();
            Ok((id, true))
        }
        .await;
        let grid = app.state::<Grid>();
        let mut guard = grid.inner.lock().await;
        let inner = &mut *guard;
        inner.work.preparing = None;
        // The assignment changed meanwhile: an environment the grid started for it is stopped.
        let Some(saved) = inner.member.as_mut().filter(|saved| saved.assignment.as_ref().is_some_and(|current| current.same_model(&assignment))) else {
            if let Ok((id, true)) = result {
                spawn_power(&app, id, false);
            }
            return;
        };
        match result {
            Ok((id, managed)) => {
                crate::security::record(Event::new("grid.model.prepared").env(&id).text("model", &assignment.model).flag("created", managed));
                saved.environment_id = Some(id);
                saved.managed = managed;
                saved.parked = false;
                let _ = persist(&app, saved);
                inner.work.prepare_error = None;
            }
            Err(error) => inner.work.prepare_error = Some((error, Instant::now())),
        }
        grid.wake.notify_one();
    })
}

/// Gives the GPU back early on a grid-started environment whose optimizer would unload it
/// later anyway, when the grid was the last to use the model: any newer request came from
/// this computer's person, whose model stays loaded. A model kept loaded on purpose
/// (idle timeout 0) is never unloaded.
async fn release_gpu(app: AppHandle, id: String, since_job: Duration) {
    let Ok(health) = crate::model_runner::model_status(id.clone(), app.clone()).await else { return };
    let optimizer = &health["optimizer"];
    let quiet = optimizer["active"].as_u64() == Some(0) && optimizer["pending"].as_u64() == Some(0);
    let last_used_by_grid = optimizer["idleSeconds"].as_u64().is_some_and(|idle| idle + 5 >= since_job.as_secs());
    let unloads_anyway = optimizer["idleTimeoutSeconds"].as_u64().is_some_and(|timeout| timeout > 0);
    if optimizer["enabled"] == true && optimizer["resident"] == true && optimizer["pinned"] != true && unloads_anyway && quiet && last_used_by_grid {
        let _ = crate::model_runner::model_request(&app, &id, "/v1/yougori/optimizer", Some(json!({"action": "unload"}))).await;
    }
}

/// Nobody, the person included, has used the model for PARK. Without a clear answer (the
/// server cannot say, or did not answer) the model counts as in use.
fn quiet(health: Option<&Value>) -> bool {
    health.is_some_and(|health| {
        let optimizer = &health["optimizer"];
        optimizer["supported"] == true
            && optimizer["active"].as_u64() == Some(0)
            && optimizer["pending"].as_u64() == Some(0)
            && optimizer["idleSeconds"].as_u64().is_some_and(|idle| idle >= PARK.as_secs())
    })
}

/// Starts a grid-managed environment, or stops one once nobody has used its model for
/// PARK: a person who is using it keeps it, and it simply stays running.
fn spawn_power(app: &AppHandle, id: String, start: bool) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        if !start {
            let health = tokio::time::timeout(Duration::from_secs(15), crate::model_runner::model_status(id.clone(), app.clone())).await.ok().and_then(Result::ok);
            if !quiet(health.as_ref()) {
                crate::security::record(Event::new("grid.model.kept").env(&id).text("reason", "in use or not answering"));
                return;
            }
        }
        let result = if start { crate::model_runner::start_model(id.clone(), app.clone()).await } else { crate::model_runner::stop_model(id.clone(), app.clone()).await };
        crate::security::record(Event::new(if start { "grid.model.started" } else { "grid.model.stopped" }).env(&id).outcome(&result));
    });
}

/// Brings this computer in line with its assignment and returns what to report to the hub.
async fn follow(app: &AppHandle, membership: &Membership, saved: &Saved, activity: &Activity) -> Vec<ModelReport> {
    let grid = app.state::<Grid>();
    let Some(assignment) = saved.assignment.clone() else {
        let mut inner = grid.inner.lock().await;
        stop_worker(&mut inner.work, false);
        inner.work.state.clear();
        inner.work.reason.clear();
        return Vec::new();
    };
    let report = |state: &str, reason: &str, work: &Work| ModelReport {
        model: assignment.model.clone(),
        state: state.into(),
        reason: reason.into(),
        quant: work.quant.clone().or_else(|| assignment.quant.clone()),
        gpu: work.gpu.clone(),
    };
    // The hub validated the rules; a damaged copy never serves.
    let decision = match assignment.policy() {
        Ok(policy) => policy.decide_at(&chrono::Local::now(), activity),
        Err(_) => Decision::OutsideSchedule,
    };
    let environment = saved.environment_id.as_ref().and_then(|id| app.state::<PlatformStore>().snapshot().ok()?.environments.into_iter().find(|environment| &environment.id == id));
    let Some(environment) = environment else {
        let mut guard = grid.inner.lock().await;
        let inner = &mut *guard;
        stop_worker(&mut inner.work, false);
        // The environment was deleted: prepare the model again.
        if let Some(saved) = inner.member.as_mut().filter(|saved| saved.environment_id.is_some()) {
            saved.environment_id = None;
            saved.managed = false;
            let _ = persist(app, saved);
        }
        let retry = inner.work.prepare_error.as_ref().is_none_or(|(_, at)| at.elapsed() >= RETRY);
        if inner.work.preparing.is_none() && retry {
            inner.work.prepare_error = None;
            inner.work.preparing = Some(prepare(app, assignment.clone()));
        }
        let (state, reason) = match &inner.work.prepare_error {
            Some((error, _)) => ("error", format!("Could not prepare the model: {error}")),
            None => ("preparing", "Preparing the model".into()),
        };
        inner.work.state = state.into();
        inner.work.reason = reason.clone();
        return vec![report(state, &reason, &inner.work)];
    };
    let id = environment.id.clone();
    let running = environment.status == EnvironmentStatus::Running;
    let locked = crate::security::is_contained(&id);
    let health_due = grid.inner.lock().await.work.health_at.is_none_or(|at| at.elapsed() >= HEALTH);
    let health = if running && health_due {
        Some(tokio::time::timeout(Duration::from_secs(15), crate::model_runner::model_status(id.clone(), app.clone())).await.ok().and_then(Result::ok))
    } else {
        None
    };
    let mut guard = grid.inner.lock().await;
    let inner = &mut *guard;
    let work = &mut inner.work;
    if let Some(health) = health {
        work.health_at = Some(Instant::now());
        work.ready = health.as_ref().is_some_and(ready);
        work.quiet = quiet(health.as_ref());
        work.person_using = health.as_ref().map(|health| {
            let optimizer = &health["optimizer"];
            (optimizer["active"].as_u64().unwrap_or(0) > 0 || optimizer["pending"].as_u64().unwrap_or(0) > 0, optimizer["idleSeconds"].as_u64())
        });
        work.gpu = health.as_ref().and_then(|health| health["gpu"].as_str().map(str::to_owned));
        work.quant = health.as_ref().and_then(|health| health["quant"].as_str().map(str::to_owned));
    }
    if !running {
        work.ready = false;
    }
    // The person's own requests to the model count as using the computer, like the keyboard.
    // The grid's own jobs are not the person's: a request newer than the grid's last job is.
    let idle_needed = u64::from(assignment.idle_after_minutes) * 60;
    let grid_last = |idle: u64| work.worker.as_ref().and_then(|worker| worker.stats.lock().ok().and_then(|stats| stats.last_job)).is_some_and(|last| last.elapsed().as_secs() <= idle + HEALTH.as_secs() + 5);
    let person_using = idle_needed > 0
        && work.person_using.is_some_and(|(active, idle)| active || idle.is_some_and(|idle| idle < idle_needed && !grid_last(idle)));
    let serve = running && work.ready && !locked && decision.serves() && !person_using;
    if work.worker.as_ref().is_some_and(|worker| worker.environment_id != id) {
        stop_worker(work, false);
    }
    let worker = work.worker.get_or_insert_with(|| spawn_worker(app, membership.clone(), assignment.model.clone(), id.clone(), serve));
    let was_serving = *worker.gate.borrow();
    worker.gate.send_if_modified(|gate| std::mem::replace(gate, serve) != serve);
    let stats = worker.stats.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone();
    if was_serving && !serve && matches!(decision, Decision::PersonActive { .. }) {
        if let Some(last) = stats.last_job {
            tauri::async_runtime::spawn(release_gpu(app.clone(), id.clone(), last.elapsed()));
        }
    }
    let outside = matches!(decision, Decision::OutsideSchedule);
    if outside {
        work.outside_since.get_or_insert_with(Instant::now);
    } else {
        work.outside_since = None;
    }
    // Parking waits until nobody, the person included, has used the model for PARK.
    let mut park = None;
    if saved.managed && running && !stats.busy && work.quiet && work.outside_since.is_some_and(|since| since.elapsed() >= PARK) {
        work.outside_since = None;
        park = Some(true);
        spawn_power(app, id.clone(), false);
    }
    let failed = environment.status == EnvironmentStatus::Error;
    if saved.managed && !running && !outside && !locked && (saved.parked || failed) && work.started_at.is_none_or(|at| at.elapsed() >= RESTART) {
        work.started_at = Some(Instant::now());
        park = Some(false);
        spawn_power(app, id.clone(), true);
    }
    if let Some(parked) = park {
        if let Some(current) = inner.member.as_mut().filter(|current| current.environment_id.as_deref() == Some(id.as_str())) {
            current.parked = parked;
            let _ = persist(app, current);
        }
    }
    let work = &mut inner.work;
    let (state, reason) = if stats.busy && serve {
        ("busy", "Answering a grid request".to_owned())
    } else if locked {
        ("locked", "This model's environment is locked down on this computer".to_owned())
    } else if serve {
        ("available", decision.reason())
    } else if outside {
        ("outside_schedule", decision.reason())
    } else if !running {
        ("stopped", if saved.managed && (saved.parked || failed) { "Starting the model environment".to_owned() } else if saved.managed { "Stopped by its person; the grid starts it again after Yougori restarts".to_owned() } else { "The model environment is stopped".to_owned() })
    } else if person_using {
        ("person_active", "Someone is using this model on this computer".to_owned())
    } else if !work.ready {
        ("loading", "Loading the model".to_owned())
    } else {
        (decision.state(), decision.reason())
    };
    work.state = state.into();
    work.reason = reason.clone();
    vec![report(state, &reason, work)]
}

/// Applies the admin's current instructions; returns a grid-started environment to stop.
fn apply(app: &AppHandle, inner: &mut Inner, assignment: Option<Assignment>, grid_name: String) -> Option<String> {
    let saved = inner.member.as_mut()?;
    if !grid_name.is_empty() && grid_name != saved.grid_name {
        saved.grid_name = grid_name;
        let _ = persist(app, saved);
    }
    if saved.assignment == assignment {
        return None;
    }
    let same_model = matches!((&saved.assignment, &assignment), (Some(old), Some(new)) if old.same_model(new));
    let mut stop = None;
    if !same_model {
        stop_worker(&mut inner.work, false);
        // A preparation in progress finishes and stops what it started (see `prepare`).
        inner.work.preparing = None;
        inner.work.prepare_error = None;
        if saved.managed {
            stop = saved.environment_id.clone();
        }
        saved.environment_id = None;
        saved.managed = false;
    }
    crate::security::record(Event::new("grid.assignment.changed").text("model", assignment.as_ref().map_or("", |assignment| assignment.model.as_str())));
    saved.assignment = assignment;
    let _ = persist(app, saved);
    stop
}

/// Forgets this computer's membership; returns a grid-started environment to stop.
fn forget(app: &AppHandle, inner: &mut Inner) -> Option<String> {
    stop_worker(&mut inner.work, true);
    inner.work = Work::default();
    inner.membership = None;
    inner.connected = false;
    inner.reported = None;
    inner.reported_state = None;
    let saved = inner.member.take();
    let _ = std::fs::remove_file(member_path(app));
    let _ = secrets::delete_secret(MEMBER_TOKEN);
    saved.filter(|saved| saved.managed).and_then(|saved| saved.environment_id)
}

async fn tick(app: &AppHandle) {
    let grid = app.state::<Grid>();
    let (membership, saved, refresh) = {
        let inner = grid.inner.lock().await;
        let (Some(membership), Some(saved)) = (inner.membership.clone(), inner.member.clone()) else { return };
        (membership, saved, inner.capable_at.is_none_or(|at| at.elapsed() >= CAPABILITY))
    };
    if refresh {
        let found = capability(app).await;
        let mut inner = grid.inner.lock().await;
        inner.capable = Some(found);
        inner.capable_at = Some(Instant::now());
    }
    // Reading activity runs system commands on Linux and macOS: only when there is work to
    // gate, every tick while serving (to notice the person's return) and every 15 s otherwise.
    let activity = if saved.assignment.is_some() {
        let (serving, cached) = {
            let inner = grid.inner.lock().await;
            (inner.work.worker.as_ref().is_some_and(|worker| *worker.gate.borrow()), inner.activity.clone())
        };
        match cached {
            Some((activity, at)) if !serving && at.elapsed() < Duration::from_secs(15) => activity,
            _ => {
                let activity = tokio::task::spawn_blocking(yougori_grid::activity::current).await.unwrap_or_else(|_| Activity::Unknown("User activity could not be read".into()));
                grid.inner.lock().await.activity = Some((activity.clone(), Instant::now()));
                activity
            }
        }
    } else {
        Activity::Nobody
    };
    let reports = follow(app, &membership, &saved, &activity).await;
    let (due, capable) = {
        let inner = grid.inner.lock().await;
        let changed = inner.reported_state.as_deref() != reports.first().map(|report| report.state.as_str());
        (inner.reported.is_none_or(|at| at.elapsed() >= REPORT) || changed, inner.capable.as_ref().is_some_and(|(capable, _)| *capable))
    };
    if !due {
        return;
    }
    let answer = membership.heartbeat(env!("CARGO_PKG_VERSION"), capable, &reports).await;
    let mut guard = grid.inner.lock().await;
    let inner = &mut *guard;
    // Membership changed while the check-in was in flight.
    if inner.member.as_ref().is_none_or(|current| current.member_id != saved.member_id) {
        return;
    }
    inner.reported = Some(Instant::now());
    let stop = match answer {
        Ok(instructions) => {
            inner.connected = true;
            inner.member_error = None;
            inner.reported_state = reports.first().map(|report| report.state.clone());
            apply(app, inner, instructions.assignment, instructions.grid_name)
        }
        Err(MemberError::Removed) => {
            crate::security::record(Event::new("grid.removed").text("grid", &saved.grid_name));
            let stop = forget(app, inner);
            inner.member_error = Some(MemberError::Removed.to_string());
            stop
        }
        Err(MemberError::Failed(error)) => {
            inner.connected = false;
            inner.member_error = Some(error);
            None
        }
    };
    drop(guard);
    if let Some(id) = stop {
        spawn_power(app, id, false);
    }
}

pub(crate) async fn grid_status(app: AppHandle) -> Result<Value, String> {
    ensure_loaded(&app).await;
    let grid = app.state::<Grid>();
    let inner = grid.inner.lock().await;
    let stats = inner.work.worker.as_ref().map(|worker| worker.stats.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone()).unwrap_or_default();
    let member = inner.member.as_ref().map(|saved| {
        json!({
            "gridId": saved.grid_id, "grid": saved.grid_name, "hub": saved.address, "fingerprint": saved.fingerprint,
            "memberId": saved.member_id, "joinedAt": saved.joined_at, "connected": inner.connected, "error": inner.member_error,
            "capable": inner.capable.as_ref().map(|(capable, _)| *capable), "backend": inner.capable.as_ref().map(|(_, backend)| backend.clone()),
            "assignment": saved.assignment,
            "rules": saved.assignment.as_ref().and_then(|assignment| assignment.policy().ok()).map(|policy| policy.describe()),
            "environmentId": saved.environment_id, "managed": saved.managed, "parked": saved.parked,
            "state": inner.work.state, "reason": inner.work.reason,
            "jobs": stats.jobs, "handedBack": stats.released, "failures": stats.failures, "lastError": stats.last_error,
        })
    });
    Ok(json!({
        "hub": inner.hub.as_ref().map(Hub::status),
        "hubError": inner.hub_error,
        "member": member,
        "memberError": if inner.member.is_none() { inner.member_error.clone() } else { None },
    }))
}

fn address(text: &str, port: Option<u16>) -> Result<SocketAddr, String> {
    let ip: IpAddr = text.trim().parse().map_err(|_| "--ip must be an IP address on the company network, such as 10.0.0.5")?;
    Ok(SocketAddr::new(ip, port.unwrap_or(net::DEFAULT_PORT)))
}

async fn derive(secret: String, salt: String) -> Result<String, String> {
    tokio::task::spawn_blocking(move || password::derive(&secret, &salt)).await.map_err(|error| error.to_string())?
}

/// Joins a grid and saves the membership. The caller holds the admin lock.
async fn join_now(app: &AppHandle, company: &str, hub: SocketAddr, secret: &str, name: Option<String>, fingerprint: Option<&str>) -> Result<(), String> {
    let found = capability(app).await;
    let name = name.unwrap_or_else(|| computer_name(app));
    let joined = member::join(company, hub, secret, &name, member::platform(), found.0, fingerprint).await?;
    let saved = Saved {
        version: 1,
        grid_id: joined.grid_id.clone(),
        grid_name: joined.grid_name.clone(),
        address: hub.to_string(),
        certificate: joined.certificate.clone(),
        fingerprint: joined.fingerprint.clone(),
        member_id: joined.membership.member_id.clone(),
        joined_at: yougori_grid::now(),
        assignment: joined.assignment.clone(),
        environment_id: None,
        managed: false,
        parked: false,
    };
    if let Err(error) = secrets::store(MEMBER_TOKEN, &joined.token).and_then(|_| persist(app, &saved)) {
        let _ = joined.membership.leave().await;
        let _ = secrets::delete_secret(MEMBER_TOKEN);
        let _ = std::fs::remove_file(member_path(app));
        return Err(error);
    }
    crate::security::record(Event::new("grid.joined").text("grid", &saved.grid_name).text("hub", &saved.address).text("fingerprint", &saved.fingerprint));
    let grid = app.state::<Grid>();
    let mut inner = grid.inner.lock().await;
    inner.member = Some(saved);
    inner.membership = Some(joined.membership);
    inner.member_error = None;
    inner.connected = true;
    inner.reported = None;
    inner.capable = Some(found);
    inner.capable_at = Some(Instant::now());
    grid.wake.notify_one();
    Ok(())
}

pub(crate) async fn grid_join(company: String, address_text: String, secret: String, port: Option<u16>, name: Option<String>, fingerprint: Option<String>, app: AppHandle) -> Result<Value, String> {
    let grid = app.state::<Grid>();
    let _admin = grid.admin.lock().await;
    ensure_loaded(&app).await;
    if let Some(saved) = grid.inner.lock().await.member.as_ref() {
        return Err(format!("This computer is already in {}'s grid. Leave it first with `yougori grid leave --yes`.", saved.grid_name));
    }
    let hub = address(&address_text, port)?;
    let name = name.map(|name| name.trim().to_owned()).filter(|name| !name.is_empty());
    join_now(&app, &company, hub, &secret, name, fingerprint.as_deref()).await?;
    drop(_admin);
    let mut status = grid_status(app).await?;
    status["message"] = json!(format!(
        "Joined {}'s Closed Neo Grid. Its admin now decides which model this computer runs and when it serves; `yougori grid leave --yes` leaves.",
        status["member"]["grid"].as_str().unwrap_or(&company)
    ));
    Ok(status)
}

pub(crate) async fn grid_create(name: String, address_text: String, secret: String, port: Option<u16>, hostname: Option<String>, app: AppHandle) -> Result<Value, String> {
    let grid = app.state::<Grid>();
    let _admin = grid.admin.lock().await;
    ensure_loaded(&app).await;
    {
        let inner = grid.inner.lock().await;
        if inner.hub.is_some() || hub_path(&app).exists() {
            return Err("This computer already runs a Closed Neo Grid hub; delete it first with `yougori grid delete --yes`".into());
        }
        if let Some(saved) = inner.member.as_ref() {
            return Err(format!("This computer is in {}'s grid; leave it first with `yougori grid leave --yes`", saved.grid_name));
        }
    }
    let hub_address = address(&address_text, port)?;
    if hub_address.ip().is_loopback() || hub_address.ip().is_unspecified() {
        return Err("Use this computer's LAN or VPN address so company computers can reach the hub".into());
    }
    password::validate(&secret)?;
    let salt = password::new_salt();
    let password_key = derive(secret.clone(), salt.clone()).await?;
    let path = hub_path(&app);
    let key = hub::create(&path, &name, hub_address.ip(), hub_address.port(), hostname.as_deref(), &salt)?;
    let started: Result<Hub, String> = async {
        secrets::store(HUB_KEY, &key)?;
        secrets::store(HUB_PASSWORD, &password_key)?;
        Hub::start(path.clone(), &key, &password_key, events()).await
    }
    .await;
    let started = match started {
        Ok(hub) => hub,
        Err(error) => {
            let _ = std::fs::remove_file(&path);
            let _ = secrets::delete_secret(HUB_KEY);
            let _ = secrets::delete_secret(HUB_PASSWORD);
            return Err(error);
        }
    };
    let record = started.record();
    let fingerprint = net::fingerprint(&record.certificate)?;
    {
        let mut inner = grid.inner.lock().await;
        inner.hub = Some(started);
        inner.hub_error = None;
    }
    crate::security::record(Event::new("grid.created").text("name", &record.name).text("address", &hub_address.to_string()).text("fingerprint", &fingerprint));
    // The admin's computer is a member too, so plans can use its GPU.
    let joined = join_now(&app, &record.name, hub_address, &secret, None, Some(&fingerprint)).await;
    drop(_admin);
    let mut status = grid_status(app).await?;
    status["message"] = json!(match joined {
        Ok(()) => format!(
            "{}'s Closed Neo Grid runs on {hub_address}. Company computers join with: yougori {} --neogrid --ip {} — then add a plan with `yougori grid add-plan`.",
            record.name,
            if record.name.contains(char::is_whitespace) { format!("\"{}\"", record.name) } else { record.name.clone() },
            hub_address.ip()
        ),
        Err(error) => format!("The hub runs on {hub_address}, but this computer could not join it: {error}"),
    });
    Ok(status)
}

pub(crate) async fn grid_password(secret: String, app: AppHandle) -> Result<Value, String> {
    let grid = app.state::<Grid>();
    let _admin = grid.admin.lock().await;
    ensure_loaded(&app).await;
    password::validate(&secret)?;
    if grid.inner.lock().await.hub.is_none() {
        return Err("This computer does not run a grid hub".into());
    }
    let salt = password::new_salt();
    let password_key = derive(secret, salt.clone()).await?;
    let previous = secrets::resolve(HUB_PASSWORD).ok();
    secrets::store(HUB_PASSWORD, &password_key)?;
    let changed = match grid.inner.lock().await.hub.as_ref() {
        Some(hub) => hub.set_password(&salt, &password_key),
        None => Err("This computer does not run a grid hub".into()),
    };
    if let Err(error) = changed {
        if let Some(previous) = previous {
            let _ = secrets::store(HUB_PASSWORD, &previous);
        }
        return Err(error);
    }
    crate::security::record(Event::new("grid.password.changed"));
    drop(_admin);
    let mut status = grid_status(app).await?;
    status["message"] = json!("The company password changed. Computers that already joined stay members.");
    Ok(status)
}

pub(crate) async fn grid_delete(app: AppHandle) -> Result<Value, String> {
    let grid = app.state::<Grid>();
    let _admin = grid.admin.lock().await;
    ensure_loaded(&app).await;
    let mut guard = grid.inner.lock().await;
    let inner = &mut *guard;
    let hub = inner.hub.take();
    if hub.is_none() && !hub_path(&app).exists() {
        return Err("This computer does not run a grid hub".into());
    }
    let id = hub.as_ref().map(|hub| hub.record().id).or_else(|| hub::load(&hub_path(&app)).ok().map(|record| record.id));
    drop(hub);
    std::fs::remove_file(hub_path(&app)).map_err(|error| format!("Cannot remove the grid hub's settings: {error}"))?;
    let _ = secrets::delete_secret(HUB_KEY);
    let _ = secrets::delete_secret(HUB_PASSWORD);
    inner.hub_error = None;
    // This computer's own membership ends with the grid.
    let stop = if inner.member.as_ref().is_some_and(|saved| Some(&saved.grid_id) == id.as_ref()) { forget(&app, inner) } else { None };
    drop(guard);
    if let Some(environment) = stop {
        spawn_power(&app, environment, false);
    }
    crate::security::record(Event::new("grid.deleted"));
    Ok(json!({"deleted": true}))
}

pub(crate) async fn grid_leave(app: AppHandle) -> Result<Value, String> {
    let grid = app.state::<Grid>();
    let _admin = grid.admin.lock().await;
    ensure_loaded(&app).await;
    let (membership, name, stop) = {
        let mut guard = grid.inner.lock().await;
        let inner = &mut *guard;
        let Some(name) = inner.member.as_ref().map(|saved| saved.grid_name.clone()) else {
            inner.member_error = None;
            return Err("This computer is not in a grid".into());
        };
        let membership = inner.membership.clone();
        (membership, name, forget(&app, inner))
    };
    if let Some(environment) = stop {
        spawn_power(&app, environment, false);
    }
    // The hub forgets this computer when it can be reached; otherwise the admin can remove it.
    let notified = match membership {
        Some(membership) => membership.leave().await.map_err(|error| error.to_string()),
        None => Err("No membership token".into()),
    };
    crate::security::record(Event::new("grid.left").text("grid", &name).succeeded(notified.is_ok()));
    Ok(json!({"left": true, "grid": name, "hubNotified": notified.is_ok(), "warning": notified.err().map(|error| format!("The hub was not told ({error}); the admin can remove this computer with `yougori grid remove`."))}))
}

async fn with_hub<T>(app: &AppHandle, action: impl FnOnce(&Hub) -> Result<T, String>) -> Result<T, String> {
    ensure_loaded(app).await;
    let grid = app.state::<Grid>();
    let inner = grid.inner.lock().await;
    let hub = inner.hub.as_ref().ok_or("This computer does not run a grid hub. Admins create one with `yougori grid create`.")?;
    action(hub)
}

/// Checks a plan's model on Hugging Face before computers start downloading it.
async fn check_model(model: &str, quant: Option<&str>) -> Result<Option<String>, String> {
    let normalized = crate::model_runner::normalize_model(model)?;
    match crate::model_runner::preflight::preflight_model(normalized.clone(), quant.map(str::to_owned), None).await {
        Ok(compatibility) if compatibility["supported"] == true => Ok(None),
        Ok(compatibility) => Err(format!("{normalized}: {}", compatibility["reason"].as_str().unwrap_or("this model cannot run on Yougori"))),
        Err(error) => Ok(Some(format!("The model could not be checked ({error}); computers report problems when they prepare it."))),
    }
}

pub(crate) async fn grid_plan_add(model: String, percent: u8, schedule: Option<String>, idle_after: Option<u32>, quant: Option<String>, app: AppHandle) -> Result<Value, String> {
    let policy = IdlePolicy::new(idle_after, schedule.as_deref())?;
    let warning = check_model(&model, quant.as_deref()).await?;
    let mut result = with_hub(&app, |hub| hub.add_plan(&model, quant.as_deref(), percent, policy)).await?;
    crate::security::record(Event::new("grid.plan.added").text("model", result["plan"]["model"].as_str().unwrap_or_default()).number("percent", u64::from(percent)));
    result["warning"] = json!(warning);
    app.state::<Grid>().wake.notify_one();
    Ok(result)
}

pub(crate) async fn grid_plan_update(plan_id: String, model: Option<String>, percent: Option<u8>, schedule: Option<String>, idle_after: Option<u32>, quant: Option<String>, app: AppHandle) -> Result<Value, String> {
    let warning = match &model {
        Some(model) => check_model(model, quant.as_deref().filter(|quant| !quant.is_empty())).await?,
        None => None,
    };
    let change = PlanChange { model, quant, percent, idle_after_minutes: idle_after, schedule };
    let mut result = with_hub(&app, |hub| hub.update_plan(&plan_id, change)).await?;
    crate::security::record(Event::new("grid.plan.changed").text("plan", &plan_id));
    result["warning"] = json!(warning);
    Ok(result)
}

pub(crate) async fn grid_plan_remove(plan_id: String, app: AppHandle) -> Result<Value, String> {
    let result = with_hub(&app, |hub| hub.remove_plan(&plan_id)).await?;
    crate::security::record(Event::new("grid.plan.removed").text("plan", &plan_id));
    Ok(result)
}

pub(crate) async fn grid_member_remove(member_id: String, app: AppHandle) -> Result<Value, String> {
    let result = with_hub(&app, |hub| hub.remove_member(&member_id)).await?;
    crate::security::record(Event::new("grid.member.removed").text("memberId", &member_id));
    Ok(result)
}

pub(crate) async fn grid_key_create(name: String, app: AppHandle) -> Result<Value, String> {
    let (mut result, url, certificate) = with_hub(&app, |hub| {
        let status = hub.status();
        Ok((hub.create_key(&name)?, status["url"].clone(), status["certificate"].clone()))
    })
    .await?;
    crate::security::record(Event::new("grid.key.created").text("keyId", result["key"]["id"].as_str().unwrap_or_default()));
    result["baseUrl"] = url;
    result["certificate"] = certificate;
    result["message"] = json!("Shown once. Apps trust the certificate (save it as grid.pem) and call baseUrl with this key.");
    Ok(result)
}

pub(crate) async fn grid_key_revoke(key_id: String, app: AppHandle) -> Result<Value, String> {
    let result = with_hub(&app, |hub| hub.revoke_key(&key_id)).await?;
    crate::security::record(Event::new("grid.key.revoked").text("keyId", &key_id));
    Ok(result)
}
