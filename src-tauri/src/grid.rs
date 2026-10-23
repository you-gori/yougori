//! Closed Neo Grid in the engine. On the admin's computer it runs the hub. On every member
//! computer (the admin's included) it follows the admin's plan: it prepares the assigned model,
//! serves the grid only while the plan's hours and idle rule allow, gives the GPU back when the
//! person returns and checks in with the hub every 30 seconds. The hub's private key, the
//! company password's derived key and the membership token live in the OS credential vault.
//! A hub can also keep a Cloudflare Tunnel open for computers outside the network; the tunnel
//! only relays the grid's own pinned TLS.
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
    harness::{Harness, Strategy},
    hub::{self, Hub, ModelReport, PlanChange, Progress, Target},
    invite::{self, Invite},
    member::{self, Assignment, MemberError, Membership, Outcome, WorkerEvent},
    net::{self, HubAddress},
    password,
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
/// A model the grid no longer needs waits up to DELETE_WAITS x DELETE_WAIT for requests in
/// flight to finish before it is deleted.
const DELETE_WAITS: u32 = 20;
const DELETE_WAIT: Duration = Duration::from_secs(30);
/// At most one start of a parked model environment per this long.
const RESTART: Duration = Duration::from_secs(2 * 60);
/// Waiting for a new grid's tunnel to publish its address before answering without it.
const TUNNEL_START: Duration = Duration::from_secs(60);

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
    /// Set after a failed hub restore: no retry before this time.
    restore_after: Option<Instant>,
    /// Whether the membership read reached an answer that cannot change. Kept apart from
    /// `member_error`, which a vault that was merely not ready yet also sets.
    member_settled: bool,
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
    tunnel: TunnelState,
}

impl Inner {
    /// Forgets this computer's membership state. The last connection error goes with it: once
    /// the computer is out of the grid, a stale "cannot reach the hub" is no longer true. A
    /// caller that has something to say about why membership ended sets it afterwards.
    fn clear_membership(&mut self) {
        self.membership = None;
        self.connected = false;
        self.reported = None;
        self.reported_state = None;
        self.member_error = None;
    }
}

use crate::hub_tunnel::{self, TunnelSetup, TunnelState};

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
    /// The grid created that environment for its model, so it deletes it, with the weights
    /// it downloaded, once this computer no longer runs that model. One the person already had
    /// is only stopped.
    #[serde(default)]
    created: bool,
    /// The grid (or an engine shutdown) stopped the environment, so the grid may start it
    /// again; one the person stopped stays stopped.
    #[serde(default)]
    parked: bool,
    /// The admin scheduled the grid for deletion at this time: until then nothing serves and the
    /// model stays, stopped, so a restore brings it straight back. Saved so a restart keeps it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    paused_until: Option<i64>,
    /// The hub has not answered since this time. A hub that is gone for good never says so, so
    /// after a while this computer's person is asked whether to leave.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    unreachable_since: Option<i64>,
}

#[derive(Default)]
struct Work {
    preparing: Option<tauri::async_runtime::JoinHandle<()>>,
    /// Which preparation `preparing` is: an older one that finishes late must not clear the
    /// handle of a newer one.
    preparing_generation: u64,
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
    /// How far the model has come while it is not ready, from its server's health.
    progress: Option<Progress>,
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

fn tunnel_path(app: &AppHandle) -> PathBuf {
    folder(app).join("tunnel.json")
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

pub(crate) fn computer_name(app: &AppHandle) -> String {
    app.state::<PlatformStore>().snapshot().map(|state| state.host.hostname.trim().to_owned()).ok().filter(|name| !name.is_empty()).unwrap_or_else(|| "Computer".into())
}

/// How far a model that is not ready has come, from its server's health: the download's bytes,
/// the check of the downloaded files, or just the phase.
pub(crate) fn progress(health: &Value) -> Option<Progress> {
    let phase = health["status"].as_str()?;
    let bytes = |section: &Value, done: &str| (section[done].as_u64().unwrap_or(0), section["totalBytes"].as_u64().unwrap_or(0));
    match phase {
        "downloading" => {
            let (done, total) = bytes(&health["download"], "receivedBytes");
            Some(Progress { phase: phase.into(), done, total, rate: health["download"]["bytesPerSecond"].as_f64().unwrap_or(0.0).max(0.0) as u64 })
        }
        "verifying" => {
            let (done, total) = bytes(&health["verification"], "checkedBytes");
            Some(Progress { phase: phase.into(), done, total, rate: 0 })
        }
        "installing" | "loading" | "queued" | "freeing_memory" => Some(Progress { phase: phase.into(), ..Progress::default() }),
        _ => None,
    }
}

/// Progress as one line for the hub's reason field.
pub(crate) fn describe(progress: &Progress) -> String {
    let gb = |bytes: u64| bytes as f64 / 1e9;
    match progress.phase.as_str() {
        "downloading" if progress.total > 0 => format!("Downloading the model: {:.1} of {:.1} GB", gb(progress.done), gb(progress.total)),
        "downloading" => "Downloading the model".into(),
        "verifying" => "Checking the downloaded files".into(),
        "installing" => "Installing the model runtime".into(),
        "queued" | "freeing_memory" => "Waiting for GPU memory".into(),
        _ => "Loading the model".into(),
    }
}

pub(crate) fn ready(health: &Value) -> bool {
    health["status"] == "ready"
        || health["weightsVerified"] == true && health["optimizer"]["enabled"] == true && matches!(health["status"].as_str(), Some("idle" | "queued" | "freeing_memory" | "loading" | "unloading"))
}

pub(crate) async fn capability(app: &AppHandle) -> (bool, String) {
    match crate::model_runner::model_compute_status(app.clone()).await {
        Ok(value) => (value["cudaSupported"] == true || value["metalSupported"] == true, value["backend"].as_str().unwrap_or("cpu").to_owned()),
        Err(_) => (false, "unknown".into()),
    }
}

/// How long after a failed hub restore the next status or action tries it again.
const RESTORE_RETRY: Duration = Duration::from_secs(30);

async fn ensure_loaded(app: &AppHandle) {
    let grid = app.state::<Grid>();
    let mut inner = grid.inner.lock().await;
    if inner.loaded || inner.restore_after.is_some_and(|at| Instant::now() < at) {
        return;
    }
    let path = hub_path(app);
    let mut hub_ready = true;
    if path.exists() && inner.hub.is_none() {
        // A hub that cannot start now (a port still held, the vault asleep) is tried again on a
        // later call rather than given up on for the whole process.
        match secrets::hub_keys(secrets::look_up(HUB_KEY), secrets::look_up(HUB_PASSWORD)) {
            secrets::Keys::Ready(key, password_key) => match Hub::start(path, &key, &password_key, events()).await {
                Ok(hub) => {
                    if let (Some(port), Some(setup)) = (hub.tunnel_address().map(|entry| entry.port()), load_tunnel(app)) {
                        keep_tunnel(app, &mut inner, setup, port);
                    }
                    inner.hub = Some(hub);
                    inner.hub_error = None;
                }
                Err(error) => {
                    inner.hub_error = Some(error);
                    hub_ready = false;
                }
            },
            secrets::Keys::Gone => {
                inner.hub_error = Some("The grid hub's keys are missing from the OS credential vault; delete the grid and create it again".into());
                hub_ready = false;
            }
            // The vault would not answer, which says nothing about whether the keys are there.
            // Telling somebody to delete the grid over this destroys a hub whose keys are intact.
            secrets::Keys::NotYet => {
                inner.hub_error = Some("The grid hub's keys could not be read from the OS credential vault yet, so it has not started. Yougori keeps trying; nothing is changed meanwhile.".into());
                hub_ready = false;
            }
        }
    }
    inner.loaded = hub_ready;
    inner.restore_after = (!hub_ready).then(|| Instant::now() + RESTORE_RETRY);
    // `member_error` used to be the latch, so a vault that was not ready yet set "join again with
    // the company password" and that answer stood for the rest of the run. Only a settled outcome
    // stops the next call looking again.
    if inner.member.is_some() || inner.member_settled {
        return;
    }
    // Not readable is not absent. Reading this wrong says "join again with the company password",
    // and the vault is routinely not ready while a computer is still starting, so only "it is not
    // there" is taken as an answer; anything else is looked at again on the next call.
    let outcome = match std::fs::read(member_path(app)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => secrets::MemberLoad::Absent,
        Err(_) => secrets::MemberLoad::NotYet,
        Ok(bytes) => match serde_json::from_slice::<Saved>(&bytes) {
            Err(_) => secrets::MemberLoad::Damaged,
            Ok(saved) => match secrets::look_up(MEMBER_TOKEN) {
                secrets::Secret::Unavailable => secrets::MemberLoad::NotYet,
                secrets::Secret::Absent => secrets::MemberLoad::Incomplete,
                secrets::Secret::Found(token) => match HubAddress::parse(&saved.address)
                    .and_then(|address| Membership::new(address, &saved.certificate, saved.member_id.clone(), token))
                {
                    Ok(membership) => {
                        inner.membership = Some(membership);
                        inner.member = Some(saved);
                        secrets::MemberLoad::Loaded
                    }
                    Err(_) => secrets::MemberLoad::Incomplete,
                },
            },
        },
    };
    inner.member_error = outcome.message("grid membership", "company password");
    inner.member_settled = outcome.settled();
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
            finish_deleted_hub(&app).await;
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

fn load_tunnel(app: &AppHandle) -> Option<TunnelSetup> {
    hub_tunnel::load(&tunnel_path(app))
}

fn save_tunnel(app: &AppHandle, setup: &TunnelSetup) -> Result<(), String> {
    hub_tunnel::save(&tunnel_path(app), setup)
}

/// Keeps the hub's tunnel connected while the engine runs. The caller holds `inner`.
fn keep_tunnel(app: &AppHandle, inner: &mut Inner, setup: TunnelSetup, port: u16) {
    hub_tunnel::keep(app, &mut inner.tunnel, setup, port);
}

fn stop_tunnel(inner: &mut Inner) {
    inner.tunnel.stop();
}

/// The hub's status, with its tunnel and the invite company computers join with: the tunnel's
/// address when the grid has one, else the hub's LAN address.
fn hub_status(hub: &Hub, tunnel: &TunnelState) -> Value {
    let mut status = hub.status();
    let record = hub.record();
    let reach = match &tunnel.setup {
        Some(_) => tunnel.reach(),
        None => Some(HubAddress::Direct(SocketAddr::new(record.address, hub.address().port()))),
    };
    if let Some(tunnel) = tunnel.status() {
        status["tunnel"] = tunnel;
    }
    if let (Some(address), Ok(fingerprint)) = (reach, net::fingerprint(&record.certificate)) {
        status["invite"] = json!(invite::encode(&Invite { company: record.name.clone(), address, fingerprint }));
    }
    status
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
fn prepare(app: &AppHandle, assignment: Assignment, generation: u64) -> tauri::async_runtime::JoinHandle<()> {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        // (environment, the grid started it, the grid created it)
        let result: Result<(String, bool, bool), String> = async {
            if let Some((id, running)) = find_environment(&app, &assignment) {
                if running {
                    return Ok((id, false, false));
                }
                crate::model_runner::start_model(id.clone(), app.clone()).await?;
                return Ok((id, true, false));
            }
            let created = crate::model_runner::run_model_with_resources(assignment.model.clone(), None, None, assignment.quant.clone(), app.clone()).await?;
            let id = created["id"].as_str().ok_or("The model environment was not created")?.to_owned();
            Ok((id, true, true))
        }
        .await;
        let grid = app.state::<Grid>();
        let mut guard = grid.inner.lock().await;
        let inner = &mut *guard;
        if inner.work.preparing_generation == generation {
            inner.work.preparing = None;
        }
        // The assignment changed meanwhile: what the grid started for it is stopped, and what it
        // created is deleted.
        let Some(saved) = inner.member.as_mut().filter(|saved| saved.assignment.as_ref().is_some_and(|current| current.same_model(&assignment))) else {
            if let Ok((id, true, created)) = result {
                retire(&app, Some(Retire::new(id, created)));
            }
            return;
        };
        match result {
            Ok((id, managed, created)) => {
                crate::security::record(Event::new("grid.model.prepared").env(&id).text("model", &assignment.model).flag("created", created));
                saved.environment_id = Some(id);
                saved.managed = managed;
                saved.created = created;
                saved.parked = false;
                let _ = persist(&app, saved);
                inner.work.prepare_error = None;
            }
            Err(error) => inner.work.prepare_error = Some((error, Instant::now())),
        }
        grid.wake.notify_one();
    })
}

/// After a cancelled preparation: an environment for that model still being provisioned has
/// nobody finishing it, so it is marked failed, where the person can delete it, rather than
/// left looking as if work went on.
fn abandon_preparation(app: &AppHandle, assignment: Assignment) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let Ok(state) = app.state::<PlatformStore>().snapshot() else { return };
        let runtime = app.state::<RuntimeManager>();
        let wanted = yougori_grid::model_key(&assignment.model);
        let half_made: Vec<String> = state
            .environments
            .iter()
            .filter(|environment| environment.kind == EnvironmentKind::Container && environment.status == EnvironmentStatus::Provisioning)
            .filter(|environment| {
                runtime
                    .workload_options(environment.runtime_id.as_deref().unwrap_or(&environment.id))
                    .ok()
                    .and_then(|options| options.environment.get("YOUGORI_REGISTRY_MODEL").or_else(|| options.environment.get("YOUGORI_MODEL")).map(|model| yougori_grid::model_key(model)))
                    .is_some_and(|model| model == wanted)
            })
            .map(|environment| environment.id.clone())
            .collect();
        for id in half_made {
            let result = crate::commands::set_environment_status(id.clone(), EnvironmentStatus::Error, app.state(), app.state()).await;
            crate::security::record(Event::new("grid.model.abandoned").env(&id).text("model", &assignment.model).outcome(&result));
        }
    });
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
/// What becomes of the environment that served a model this computer no longer runs.
enum Retire {
    /// The grid started it from one the person already had, so it is only stopped.
    Stop(String),
    /// The grid created it, so it is deleted with the weights it downloaded.
    Delete(String),
}

impl Retire {
    fn new(id: String, created: bool) -> Self {
        if created { Retire::Delete(id) } else { Retire::Stop(id) }
    }
}

fn retire(app: &AppHandle, retire: Option<Retire>) {
    match retire {
        Some(Retire::Stop(id)) => spawn_power(app, id, false),
        Some(Retire::Delete(id)) => spawn_delete(app, id),
        None => {}
    }
}

/// A request is being answered, or waits, on this model right now.
fn in_flight(health: Option<&Value>) -> bool {
    health.is_some_and(|health| {
        let optimizer = &health["optimizer"];
        optimizer["active"].as_u64().unwrap_or(0) > 0 || optimizer["pending"].as_u64().unwrap_or(0) > 0
    })
}

/// Deletes a model environment the grid created, and with it the weights it downloaded, so a
/// model the computer no longer runs stops taking disk space. Requests in flight finish first;
/// an environment this computer was given again meanwhile is kept.
/// Whether `id` is the environment this computer's current assignment uses.
async fn assigned_now(app: &AppHandle, id: &str) -> bool {
    app.state::<Grid>().inner.lock().await.member.as_ref().is_some_and(|saved| saved.environment_id.as_deref() == Some(id))
}

fn environment_status(app: &AppHandle, id: &str) -> Option<EnvironmentStatus> {
    app.state::<PlatformStore>().snapshot().ok()?.environments.into_iter().find(|environment| environment.id == id).map(|environment| environment.status)
}

fn spawn_delete(app: &AppHandle, id: String) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        // Waits for the model to be free of requests, however long that takes: a model whose
        // health cannot be read while it runs counts as busy, and a long wait is logged rather
        // than given up on, so the weights are not left behind for good.
        let mut attempt: u32 = 0;
        loop {
            let Some(status) = environment_status(&app, &id) else { return };
            if status != EnvironmentStatus::Running {
                break;
            }
            let health = tokio::time::timeout(Duration::from_secs(15), crate::model_runner::model_status(id.clone(), app.clone())).await.ok().and_then(Result::ok);
            if health.is_some() && !in_flight(health.as_ref()) {
                break;
            }
            if assigned_now(&app, &id).await {
                crate::security::record(Event::new("grid.model.kept").env(&id).text("reason", "assigned to this computer again"));
                return;
            }
            attempt += 1;
            if attempt % DELETE_WAITS == 0 {
                crate::security::record(Event::new("grid.model.kept").env(&id).text("reason", if health.is_some() { "still answering requests; deletion waits" } else { "not answering health checks; deletion waits" }));
            }
            tokio::time::sleep(DELETE_WAIT).await;
        }
        if assigned_now(&app, &id).await {
            crate::security::record(Event::new("grid.model.kept").env(&id).text("reason", "assigned to this computer again"));
            return;
        }
        let result: Result<(), String> = async {
            let Some(status) = environment_status(&app, &id) else { return Ok(()) };
            if status != EnvironmentStatus::Stopped {
                crate::commands::set_environment_status(id.clone(), EnvironmentStatus::Stopped, app.state(), app.state()).await?;
            }
            crate::commands::delete_environment(id.clone(), None, app.state(), app.state(), app.state()).await.map(|_| ())
        }
        .await;
        crate::security::record(Event::new("grid.model.deleted").env(&id).outcome(&result));
    });
}

fn spawn_power(app: &AppHandle, id: String, start: bool) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        if !start {
            let health = tokio::time::timeout(Duration::from_secs(15), crate::model_runner::model_status(id.clone(), app.clone())).await.ok().and_then(Result::ok);
            if !quiet(health.as_ref()) {
                crate::security::record(Event::new("grid.model.kept").env(&id).text("reason", "in use or not answering"));
                return;
            }
            // Given back to this computer while the health check ran: it stays running.
            if assigned_now(&app, &id).await {
                crate::security::record(Event::new("grid.model.kept").env(&id).text("reason", "assigned to this computer again"));
                return;
            }
        }
        let result = if start { crate::model_runner::start_model(id.clone(), app.clone()).await } else { crate::model_runner::stop_model(id.clone(), app.clone()).await };
        if start && result.is_ok() {
            // Only a start that went through ends the parked state; a failed one is tried again.
            let grid = app.state::<Grid>();
            let mut inner = grid.inner.lock().await;
            if let Some(saved) = inner.member.as_mut().filter(|saved| saved.environment_id.as_deref() == Some(id.as_str())) {
                saved.parked = false;
                let _ = persist(&app, saved);
            }
        }
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
        progress: work.progress.clone(),
    };
    // The hub validated the rules; a damaged copy never serves.
    let decision = match assignment.policy() {
        Ok(policy) => policy.decide_at(&chrono::Local::now(), activity),
        Err(_) => Decision::OutsideSchedule,
    };
    let environment = saved.environment_id.as_ref().and_then(|id| app.state::<PlatformStore>().snapshot().ok()?.environments.into_iter().find(|environment| &environment.id == id));
    if saved.paused_until.is_some() {
        // The admin scheduled the grid for deletion: serve nothing, and stop a model environment
        // the grid started, keeping it and its weights. A restore starts it again (it is parked).
        let mut guard = grid.inner.lock().await;
        let inner = &mut *guard;
        stop_worker(&mut inner.work, false);
        if let Some(environment) = environment.as_ref().filter(|environment| saved.managed && !saved.parked && environment.status == EnvironmentStatus::Running) {
            spawn_power(app, environment.id.clone(), false);
            if let Some(current) = inner.member.as_mut().filter(|current| current.environment_id.as_deref() == Some(environment.id.as_str())) {
                current.parked = true;
                let _ = persist(app, current);
            }
        }
        let reason = "Paused: the grid's admin scheduled it for deletion; the model stays until then".to_owned();
        inner.work.state = "paused".into();
        inner.work.reason = reason.clone();
        return vec![report("stopped", &reason, &inner.work)];
    }
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
            inner.work.preparing_generation += 1;
            inner.work.preparing = Some(prepare(app, assignment.clone(), inner.work.preparing_generation));
        }
        let (state, reason) = match &inner.work.prepare_error {
            Some((error, _)) => ("error", format!("Could not prepare the model: {error}")),
            None => ("preparing", "Preparing the model".into()),
        };
        inner.work.progress = (state == "preparing").then(|| Progress { phase: "preparing".into(), ..Progress::default() });
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
        work.progress = health.as_ref().filter(|health| !ready(health)).and_then(progress);
    }
    if !running {
        work.ready = false;
        work.progress = None;
    }
    // The person's own requests to the model count as using the computer, like the keyboard.
    // The grid's own jobs are not the person's: a request newer than the grid's last job is.
    let idle_needed = u64::from(assignment.idle_after_minutes) * 60;
    let grid_last = |idle: u64| work.worker.as_ref().and_then(|worker| worker.stats.lock().ok().and_then(|stats| stats.last_job)).is_some_and(|last| last.elapsed().as_secs() <= idle + HEALTH.as_secs() + 5);
    // A request running on the model while the grid's own worker is answering one is the grid's,
    // not the person's.
    let grid_busy = work.worker.as_ref().and_then(|worker| worker.stats.lock().ok().map(|stats| stats.busy || stats.last_job.is_some_and(|last| last.elapsed() <= HEALTH + Duration::from_secs(5)))).unwrap_or(false);
    let person_using = idle_needed > 0
        && work.person_using.is_some_and(|(active, idle)| (active && !grid_busy) || idle.is_some_and(|idle| idle < idle_needed && !grid_last(idle)));
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
        // `parked` is cleared by the start itself once it succeeds (`spawn_power`), so a start
        // that fails before the environment changes state is tried again after RESTART.
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
        ("loading", work.progress.as_ref().map_or_else(|| "Loading the model".to_owned(), describe))
    } else {
        (decision.state(), decision.reason())
    };
    work.state = state.into();
    work.reason = reason.clone();
    vec![report(state, &reason, work)]
}

/// Applies the admin's current instructions; returns a grid-started environment to stop.
fn apply(app: &AppHandle, inner: &mut Inner, assignment: Option<Assignment>, grid_name: String) -> Option<Retire> {
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
        // A download or start in progress for the old model stops here, not when it is done:
        // the task is cancelled, and an environment it left half-made is marked so.
        if let Some(handle) = inner.work.preparing.take() {
            handle.abort();
            inner.work.preparing_generation += 1;
            if let Some(old) = saved.assignment.clone() {
                abandon_preparation(app, old);
            }
        }
        inner.work.prepare_error = None;
        if saved.managed {
            stop = saved.environment_id.clone().map(|id| Retire::new(id, saved.created));
        }
        saved.environment_id = None;
        saved.managed = false;
        saved.created = false;
    }
    crate::security::record(Event::new("grid.assignment.changed").text("model", assignment.as_ref().map_or("", |assignment| assignment.model.as_str())));
    saved.assignment = assignment;
    let _ = persist(app, saved);
    stop
}

/// Forgets this computer's membership; returns what to do with a grid-started environment.
fn forget(app: &AppHandle, inner: &mut Inner) -> Option<Retire> {
    stop_worker(&mut inner.work, true);
    inner.work = Work::default();
    inner.clear_membership();
    let saved = inner.member.take();
    let _ = std::fs::remove_file(member_path(app));
    let _ = secrets::delete_secret(MEMBER_TOKEN);
    saved.filter(|saved| saved.managed).and_then(|saved| saved.environment_id.map(|id| Retire::new(id, saved.created)))
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
            if let Some(current) = inner.member.as_mut().filter(|current| current.unreachable_since.is_some()) {
                current.unreachable_since = None;
                let _ = persist(app, current);
            }
            inner.reported_state = reports.first().map(|report| report.state.clone());
            if let Some(current) = inner.member.as_mut().filter(|current| current.paused_until != instructions.paused_until) {
                crate::security::record(Event::new(if instructions.paused_until.is_some() { "grid.paused" } else { "grid.resumed" }).text("grid", &current.grid_name));
                current.paused_until = instructions.paused_until;
                let _ = persist(app, current);
                grid.wake.notify_one();
            }
            apply(app, inner, instructions.assignment, instructions.grid_name)
        }
        Err(MemberError::Deleted) => {
            // The admin deleted the grid: leave it, and remove the model environment it created.
            crate::security::record(Event::new("grid.deleted.left").text("grid", &saved.grid_name));
            let stop = forget(app, inner);
            let removed = matches!(stop, Some(Retire::Delete(_)));
            inner.member_error = Some(format!("{} deleted this grid. This computer left it{}.", saved.grid_name, if removed { " and removed the model the grid had installed" } else { "" }));
            stop
        }
        Err(MemberError::Removed) => {
            crate::security::record(Event::new("grid.removed").text("grid", &saved.grid_name));
            let stop = forget(app, inner);
            inner.member_error = Some(MemberError::Removed.to_string());
            stop
        }
        // Answered, but in words this build cannot read. The hub is not silent, so the clock
        // that ends in "the hub is gone, leave the grid" must not start: following that advice
        // would unshare every desk on this computer over a hub that is working perfectly.
        Err(MemberError::Unreadable(error)) => {
            inner.connected = false;
            inner.member_error = Some(error);
            // The hub answered, so a clock an earlier failed check-in started stops here too.
            // Not starting one was never enough on its own: a restart for a hub upgrade fails a
            // check-in and starts the clock, and answers this build cannot read then left it
            // running all the way to "leave the grid".
            if let Some(current) = inner.member.as_mut().filter(|current| current.unreachable_since.is_some()) {
                current.unreachable_since = member::silence_clock(true, current.unreachable_since, yougori_grid::now());
                let _ = persist(app, current);
            }
            // Nothing is retired. An answer this build could not read says nothing about what
            // this computer should be running, and retiring on it would delete a grid-created
            // model environment with its weights.
            None
        }
        Err(MemberError::Failed(error)) => {
            inner.connected = false;
            inner.member_error = Some(error);
            if let Some(current) = inner.member.as_mut().filter(|current| current.unreachable_since.is_none()) {
                current.unreachable_since = member::silence_clock(false, current.unreachable_since, yougori_grid::now());
                let _ = persist(app, current);
            }
            None
        }
    };
    drop(guard);
    retire(app, stop);
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
            "environmentId": saved.environment_id, "managed": saved.managed, "parked": saved.parked, "pausedUntil": saved.paused_until,
            "unreachableSince": saved.unreachable_since,
            "state": inner.work.state, "reason": inner.work.reason, "progress": inner.work.progress,
            "jobs": stats.jobs, "handedBack": stats.released, "failures": stats.failures, "lastError": stats.last_error,
        })
    });
    Ok(json!({
        "hub": inner.hub.as_ref().map(|hub| hub_status(hub, &inner.tunnel)),
        "hubError": inner.hub_error,
        "member": member,
        "memberError": if inner.member.is_none() { inner.member_error.clone() } else { None },
    }))
}

/// A hub address from a person: an IP address on the company network, or the grid's
/// `https://` tunnel address.
fn address(text: &str, port: Option<u16>) -> Result<HubAddress, String> {
    let text = text.trim();
    if text.contains("://") {
        return HubAddress::parse(text);
    }
    let ip: IpAddr = text.parse().map_err(|_| "--ip must be an IP address on the company network, such as 10.0.0.5, or the grid's https:// tunnel address")?;
    Ok(HubAddress::Direct(SocketAddr::new(ip, port.unwrap_or(net::DEFAULT_PORT))))
}

async fn derive(secret: String, salt: String) -> Result<String, String> {
    tokio::task::spawn_blocking(move || password::derive(&secret, &salt)).await.map_err(|error| error.to_string())?
}

/// Moves this computer's membership to `address`, the same hub reached another way. The hub must
/// answer there with the pinned certificate and accept this computer's token before anything is
/// saved. The caller holds the admin lock.
async fn readdress(app: &AppHandle, mut saved: Saved, address: HubAddress) -> Result<(), String> {
    let membership = Membership::new(address.clone(), &saved.certificate, saved.member_id.clone(), secrets::resolve(MEMBER_TOKEN)?)?;
    let found = capability(app).await;
    membership.heartbeat(env!("CARGO_PKG_VERSION"), found.0, &[]).await.map_err(|error| error.to_string())?;
    saved.address = address.to_string();
    persist(app, &saved)?;
    crate::security::record(Event::new("grid.readdressed").text("grid", &saved.grid_name).text("hub", &saved.address));
    let grid = app.state::<Grid>();
    let mut inner = grid.inner.lock().await;
    // The worker holds the old address; the next check-in starts one on the new address.
    stop_worker(&mut inner.work, true);
    inner.member = Some(saved);
    inner.membership = Some(membership);
    inner.member_error = None;
    inner.connected = true;
    inner.reported = None;
    grid.wake.notify_one();
    Ok(())
}

/// Joins a grid and saves the membership. The caller holds the admin lock.
async fn join_now(app: &AppHandle, company: &str, hub: HubAddress, secret: &str, name: Option<String>, fingerprint: Option<&str>) -> Result<(), String> {
    let found = capability(app).await;
    let name = name.unwrap_or_else(|| computer_name(app));
    // A tunnel created a moment ago can take a few seconds to answer, so an unreachable tunnel
    // is tried again for a while; a wrong password, company or fingerprint fails at once.
    let deadline = Instant::now() + TUNNEL_START;
    let joined = loop {
        match member::join(company, hub.clone(), secret, &name, member::platform(), found.0, fingerprint).await {
            Err(error) if matches!(hub, HubAddress::Tunnel(_)) && error.starts_with("Cannot reach the grid hub") && Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
            joined => break joined?,
        }
    };
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
        created: false,
        parked: false,
        paused_until: None,
        unreachable_since: None,
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

/// Joins with an `invite` from the admin, which names the company, the hub's address and its
/// fingerprint; or with the company name and the hub's address given separately. An invite for
/// the grid this computer is already in only moves it to the hub's current address, as after a
/// Quick Tunnel restarts; the hub is the same pinned certificate, so no password is needed.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn grid_join(company: Option<String>, address_text: Option<String>, secret: Option<String>, port: Option<u16>, name: Option<String>, fingerprint: Option<String>, invite: Option<String>, app: AppHandle) -> Result<Value, String> {
    let grid = app.state::<Grid>();
    let _admin = grid.admin.lock().await;
    ensure_loaded(&app).await;
    let given = |value: Option<String>| value.map(|value| value.trim().to_owned()).filter(|value| !value.is_empty());
    let invite = given(invite).map(|code| invite::decode(&code)).transpose()?;
    let member = grid.inner.lock().await.member.clone();
    if let Some(saved) = member {
        if let Some(invite) = invite.filter(|invite| net::normalize_fingerprint(&saved.fingerprint).as_deref() == Some(invite.fingerprint.as_str())) {
            readdress(&app, saved, invite.address).await?;
            drop(_admin);
            let mut status = grid_status(app).await?;
            status["message"] = json!(format!("This computer now reaches {}'s grid at {}.", status["member"]["grid"].as_str().unwrap_or(&invite.company), status["member"]["hub"].as_str().unwrap_or_default()));
            return Ok(status);
        }
        return Err(format!("This computer is already in {}'s grid. Leave it first with `yougori grid leave --yes`.", saved.grid_name));
    }
    let secret = secret.filter(|secret| !secret.is_empty()).ok_or("Give the company password")?;
    let (company, hub, fingerprint) = match invite {
        Some(invite) => (invite.company, invite.address, Some(invite.fingerprint)),
        None => {
            let company = given(company).ok_or("Give the company name, or the invite your admin shared")?;
            let text = given(address_text).ok_or("Give the hub's address, or the invite your admin shared")?;
            (company, address(&text, port)?, fingerprint)
        }
    };
    let name = given(name);
    join_now(&app, &company, hub, &secret, name, fingerprint.as_deref()).await?;
    drop(_admin);
    let mut status = grid_status(app).await?;
    status["message"] = json!(format!(
        "Joined {}'s Closed Neo Grid. Its admin now decides which model this computer runs and when it serves; `yougori grid leave --yes` leaves.",
        status["member"]["grid"].as_str().unwrap_or(&company)
    ));
    Ok(status)
}

/// `tunnel` also opens the grid to computers outside the network: `quick` for a temporary
/// trycloudflare.com address, or the name of a saved Cloudflare domain.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn grid_create(name: String, address_text: String, secret: String, port: Option<u16>, hostname: Option<String>, tunnel: Option<String>, app: AppHandle) -> Result<Value, String> {
    let grid = app.state::<Grid>();
    let _admin = grid.admin.lock().await;
    ensure_loaded(&app).await;
    {
        let inner = grid.inner.lock().await;
        if inner.hub.is_some() || hub_path(&app).exists() {
            return Err(if inner.hub.as_ref().is_some_and(|hub| hub.phase() != yougori_grid::hub::Phase::Open) { "This computer's last grid is still being deleted; finish it with `yougori grid delete --when forget --yes`".into() } else { "This computer already runs a Closed Neo Grid hub; delete it first with `yougori grid delete --when now --yes`".into() });
        }
        if let Some(saved) = inner.member.as_ref() {
            return Err(format!("This computer is in {}'s grid; leave it first with `yougori grid leave --yes`", saved.grid_name));
        }
    }
    let hub_address = match address(&address_text, port)? {
        HubAddress::Direct(address) => address,
        HubAddress::Tunnel(_) => return Err("--ip is this computer's LAN or VPN address; a tunnel is chosen separately".into()),
    };
    if hub_address.ip().is_loopback() || hub_address.ip().is_unspecified() {
        return Err("Use this computer's LAN or VPN address so company computers can reach the hub".into());
    }
    let setup = TunnelSetup::parse(tunnel.as_deref());
    // A Quick Tunnel can use any free port; a domain's tunnel already routes to its own.
    let tunnel_port = setup.as_ref().map(|setup| setup.port(&app, hub_address.port(), net::DEFAULT_TUNNEL_PORT)).transpose()?;
    password::validate(&secret)?;
    let salt = password::new_salt();
    let password_key = derive(secret.clone(), salt.clone()).await?;
    let path = hub_path(&app);
    let key = hub::create(&path, &name, hub_address.ip(), hub_address.port(), hostname.as_deref(), tunnel_port, &salt)?;
    let started: Result<Hub, String> = async {
        secrets::store(HUB_KEY, &key)?;
        secrets::store(HUB_PASSWORD, &password_key)?;
        if let Some(setup) = &setup {
            save_tunnel(&app, setup)?;
        }
        Hub::start(path.clone(), &key, &password_key, events()).await
    }
    .await;
    let started = match started {
        Ok(hub) => hub,
        Err(error) => {
            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_file(tunnel_path(&app));
            let _ = secrets::delete_secret(HUB_KEY);
            let _ = secrets::delete_secret(HUB_PASSWORD);
            return Err(error);
        }
    };
    let record = started.record();
    let fingerprint = net::fingerprint(&record.certificate)?;
    let entry = started.tunnel_address().map(|entry| entry.port());
    {
        let mut inner = grid.inner.lock().await;
        if let (Some(setup), Some(port)) = (setup.clone(), entry) {
            keep_tunnel(&app, &mut inner, setup, port);
        }
        inner.hub = Some(started);
        inner.hub_error = None;
    }
    crate::security::record(Event::new("grid.created").text("name", &record.name).text("address", &hub_address.to_string()).text("fingerprint", &fingerprint));
    // The admin's computer is a member too, so plans can use its GPU.
    let joined = join_now(&app, &record.name, HubAddress::Direct(hub_address), &secret, None, Some(&fingerprint)).await;
    // The invite names the tunnel, so wait briefly for it to publish its address.
    let tunnel_note = if setup.is_some() {
        let deadline = Instant::now() + TUNNEL_START;
        loop {
            let (url, error) = {
                let inner = grid.inner.lock().await;
                (inner.tunnel.url(), inner.tunnel.error())
            };
            if let Some(url) = url {
                break format!(" Computers anywhere reach it through {url}.");
            }
            if let Some(error) = error {
                break format!(" Its tunnel did not connect yet ({error}); Yougori keeps trying, and `yougori grid` shows the invite once it is up.");
            }
            if Instant::now() >= deadline {
                break " Its tunnel is still connecting; `yougori grid` shows the invite once it is up.".to_owned();
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    } else {
        String::new()
    };
    drop(_admin);
    let mut status = grid_status(app).await?;
    status["message"] = json!(match joined {
        Ok(()) => format!(
            "{}'s Closed Neo Grid runs on {hub_address}.{tunnel_note} On each company computer, run `yougori join grid` and paste the invite; share the company password separately. Then choose what runs with `yougori grid add-plan`.",
            record.name
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

/// Deletes the grid this computer hosts. `later` (the default) pauses it for three days, during
/// which `grid_restore` brings it back; `now` deletes it at once. Either way the hub keeps
/// answering until every computer has heard, so each leaves and removes the model it got.
/// `forget` stops waiting for computers that are still away and removes the hub right now.
pub(crate) async fn grid_delete(when: Option<String>, app: AppHandle) -> Result<Value, String> {
    let when = when.as_deref().map(str::trim).filter(|when| !when.is_empty()).unwrap_or("later");
    if when == "forget" {
        return forget_hub(app).await;
    }
    let at_once = match when {
        "now" => true,
        "later" => false,
        _ => return Err("--when is later (paused for three days, can be restored), now, or forget".into()),
    };
    ensure_loaded(&app).await;
    let grid = app.state::<Grid>();
    {
        let inner = grid.inner.lock().await;
        let hub = inner.hub.as_ref().ok_or("This computer does not run a grid hub")?;
        hub.close(at_once)?;
    }
    crate::security::record(Event::new("grid.deleting").flag("atOnce", at_once));
    grid.wake.notify_one();
    let mut status = grid_status(app).await?;
    status["message"] = json!(if at_once { "The grid is deleted. Each computer is told when it next checks in; it leaves and removes the model the grid installed." } else { "The grid is paused and will be deleted in three days. Restore it before then to bring everything back." });
    Ok(status)
}

/// Takes back a deletion while the grid is still paused.
pub(crate) async fn grid_restore(app: AppHandle) -> Result<Value, String> {
    ensure_loaded(&app).await;
    let grid = app.state::<Grid>();
    {
        let inner = grid.inner.lock().await;
        inner.hub.as_ref().ok_or("This computer does not run a grid hub")?.restore()?;
    }
    crate::security::record(Event::new("grid.restored"));
    grid.wake.notify_one();
    let mut status = grid_status(app).await?;
    status["message"] = json!("The grid is restored. Its computers pick up where they were at their next check-in.");
    Ok(status)
}

/// A deleted grid whose computers have all heard, or that waited long enough, goes for good.
async fn finish_deleted_hub(app: &AppHandle) {
    let finished = app.state::<Grid>().inner.lock().await.hub.as_ref().is_some_and(Hub::finished);
    if finished {
        let _ = forget_hub(app.clone()).await;
    }
}

/// Removes the hub at once: its settings, keys and tunnel, and this computer's own membership.
async fn forget_hub(app: AppHandle) -> Result<Value, String> {
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
    stop_tunnel(inner);
    let _ = std::fs::remove_file(tunnel_path(&app));
    std::fs::remove_file(hub_path(&app)).map_err(|error| format!("Cannot remove the grid hub's settings: {error}"))?;
    let _ = secrets::delete_secret(HUB_KEY);
    let _ = secrets::delete_secret(HUB_PASSWORD);
    inner.hub_error = None;
    // This computer's own membership ends with the grid.
    let stop = if inner.member.as_ref().is_some_and(|saved| Some(&saved.grid_id) == id.as_ref()) { forget(&app, inner) } else { None };
    drop(guard);
    retire(&app, stop);
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
    retire(&app, stop);
    // The hub forgets this computer when it can be reached; otherwise the admin can remove it.
    let notified = match membership {
        Some(membership) => membership.leave().await.map_err(|error| error.to_string()),
        None => Err("No membership token".into()),
    };
    crate::security::record(Event::new("grid.left").text("grid", &name).succeeded(notified.is_ok()));
    Ok(json!({"left": true, "grid": name, "hubNotified": notified.is_ok(), "warning": notified.err().map(|error| format!("The hub was not told ({error}); the admin can remove this computer with `yougori grid remove`."))}))
}

pub(crate) async fn with_hub<T>(app: &AppHandle, action: impl FnOnce(&Hub) -> Result<T, String>) -> Result<T, String> {
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

/// Runs `model` on the `computers` the admin picked, or on `percent` of the computers in
/// `scope`: `all` (the default) or `remaining`, the ones nobody picked.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn grid_plan_add(model: String, percent: Option<u8>, schedule: Option<String>, idle_after: Option<u32>, quant: Option<String>, scope: Option<String>, computers: Option<Vec<String>>, app: AppHandle) -> Result<Value, String> {
    let policy = IdlePolicy::new(idle_after, schedule.as_deref())?;
    let picked = computers.unwrap_or_default();
    let target = if !picked.is_empty() {
        Target::Computers { members: picked }
    } else {
        match scope.as_deref().map(str::trim) {
            None | Some("" | "all") => Target::All,
            Some("remaining") => Target::Remaining,
            Some(_) => return Err("scope must be all or remaining".into()),
        }
    };
    let percent = match (&target, percent) {
        (Target::Computers { .. }, _) => 100,
        (_, Some(percent)) => percent,
        (_, None) => return Err("Give --percent, the share of the computers that run the model, or pick computers".into()),
    };
    let warning = check_model(&model, quant.as_deref()).await?;
    let mut result = with_hub(&app, |hub| hub.add_plan(&model, quant.as_deref(), percent, policy, target)).await?;
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

/// Admin: leaves a computer out of the grid's work, or brings it back. Left out, it gets no
/// model and no work, so it drops the model the grid gave it, a download in progress included.
async fn set_excluded(member_id: String, excluded: bool, app: AppHandle) -> Result<Value, String> {
    let result = with_hub(&app, |hub| hub.set_excluded(&member_id, excluded)).await?;
    crate::security::record(Event::new(if excluded { "grid.member.excluded" } else { "grid.member.included" }).text("memberId", &member_id));
    app.state::<Grid>().wake.notify_one();
    Ok(result)
}

pub(crate) async fn grid_member_exclude(member_id: String, app: AppHandle) -> Result<Value, String> {
    set_excluded(member_id, true, app).await
}

pub(crate) async fn grid_member_include(member_id: String, app: AppHandle) -> Result<Value, String> {
    set_excluded(member_id, false, app).await
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

/// Admin: a team of models that apps call as the model `swarm/NAME`. `tasks` defaults to
/// `computers`, so each computer gets one task (plan) or gives one answer (mixture).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn grid_swarm_add(name: String, strategy: Option<String>, lead: String, workers: Vec<String>, computers: u8, tasks: Option<u8>, rounds: Option<u8>, app: AppHandle) -> Result<Value, String> {
    let strategy = match strategy.as_deref().map(str::trim) {
        None | Some("" | "plan") => Strategy::Plan,
        Some("mixture") => Strategy::Mixture,
        Some(_) => return Err("strategy must be plan or mixture".into()),
    };
    let harness = Harness::new(&name, strategy, &lead, &workers, computers, tasks.unwrap_or(computers), rounds.unwrap_or(1))?;
    let result = with_hub(&app, |hub| hub.add_harness(harness)).await?;
    crate::security::record(Event::new("grid.swarm.added").text("model", result["model"].as_str().unwrap_or_default()).number("computers", u64::from(computers)));
    Ok(result)
}

pub(crate) async fn grid_swarm_remove(harness_id: String, app: AppHandle) -> Result<Value, String> {
    let result = with_hub(&app, |hub| hub.remove_harness(&harness_id)).await?;
    crate::security::record(Event::new("grid.swarm.removed").text("model", result["model"].as_str().unwrap_or_default()));
    Ok(result)
}

/// Admin: runs a harness once on `prompt`; the answer comes with which computer did each part.
pub(crate) async fn grid_swarm_run(harness: String, prompt: String, app: AppHandle) -> Result<Value, String> {
    if prompt.trim().is_empty() {
        return Err("Give the prompt to run".into());
    }
    // The run can take minutes, so it must not hold the grid's lock.
    let swarm = with_hub(&app, |hub| Ok(hub.swarm())).await?;
    swarm.run(&harness, &[json!({"role": "user", "content": prompt})]).await
}

/// This computer's address on its local network or VPN, to suggest as a hub's address.
pub(crate) fn suggested_address() -> Option<String> {
    // Connecting a UDP socket only chooses the outgoing route; nothing is sent.
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("192.0.2.1:80").ok()?;
    Some(socket.local_addr().ok()?.ip()).filter(|ip| net::private(*ip)).map(|ip| ip.to_string())
}

/// The grid as the dashboard drives it. These reach the same functions as the CLI's pipe, and
/// only from the main window: an environment's window must never host, join or remove a grid.
pub(crate) mod commands {
    use super::*;
    use crate::WebviewWindow;

    fn main_window(window: &WebviewWindow) -> Result<(), String> {
        if window.label() == "main" { Ok(()) } else { Err("Closed Neo Grid is managed from the main Yougori window".into()) }
    }

    #[tauri::command]
    pub async fn grid_status(app: AppHandle, window: WebviewWindow) -> Result<Value, String> {
        main_window(&window)?;
        super::grid_status(app).await
    }

    #[tauri::command]
    pub fn grid_suggested_address(window: WebviewWindow) -> Result<Option<String>, String> {
        main_window(&window)?;
        Ok(super::suggested_address())
    }

    /// `tunnel` is `quick` for a temporary public link, or absent for this network only.
    #[tauri::command]
    pub async fn grid_create(app: AppHandle, window: WebviewWindow, name: String, address: String, password: String, tunnel: Option<String>) -> Result<Value, String> {
        main_window(&window)?;
        super::grid_create(name, address, password, None, None, tunnel, app).await
    }

    #[tauri::command]
    pub async fn grid_join(app: AppHandle, window: WebviewWindow, invite: String, password: Option<String>) -> Result<Value, String> {
        main_window(&window)?;
        super::grid_join(None, None, password, None, None, None, Some(invite), app).await
    }

    #[tauri::command]
    pub async fn grid_leave(app: AppHandle, window: WebviewWindow) -> Result<Value, String> {
        main_window(&window)?;
        super::grid_leave(app).await
    }

    #[tauri::command]
    pub async fn grid_delete(app: AppHandle, window: WebviewWindow, when: Option<String>) -> Result<Value, String> {
        main_window(&window)?;
        super::grid_delete(when, app).await
    }

    #[tauri::command]
    pub async fn grid_restore(app: AppHandle, window: WebviewWindow) -> Result<Value, String> {
        main_window(&window)?;
        super::grid_restore(app).await
    }

    /// `computers` picks computers by ID; otherwise `percent` of `scope` (`all` or `remaining`).
    #[tauri::command]
    pub async fn grid_plan_add(app: AppHandle, window: WebviewWindow, model: String, percent: Option<u8>, quant: Option<String>, scope: Option<String>, computers: Option<Vec<String>>) -> Result<Value, String> {
        main_window(&window)?;
        super::grid_plan_add(model, percent, None, None, quant, scope, computers, app).await
    }

    #[tauri::command]
    pub async fn grid_plan_remove(app: AppHandle, window: WebviewWindow, plan_id: String) -> Result<Value, String> {
        main_window(&window)?;
        super::grid_plan_remove(plan_id, app).await
    }

    #[tauri::command]
    pub async fn grid_member_remove(app: AppHandle, window: WebviewWindow, member_id: String) -> Result<Value, String> {
        main_window(&window)?;
        super::grid_member_remove(member_id, app).await
    }

    #[tauri::command]
    pub async fn grid_member_exclude(app: AppHandle, window: WebviewWindow, member_id: String) -> Result<Value, String> {
        main_window(&window)?;
        super::grid_member_exclude(member_id, app).await
    }

    #[tauri::command]
    pub async fn grid_member_include(app: AppHandle, window: WebviewWindow, member_id: String) -> Result<Value, String> {
        main_window(&window)?;
        super::grid_member_include(member_id, app).await
    }

    #[tauri::command]
    #[allow(clippy::too_many_arguments)]
    pub async fn grid_swarm_add(app: AppHandle, window: WebviewWindow, name: String, strategy: Option<String>, lead: String, workers: Vec<String>, computers: u8, tasks: Option<u8>, rounds: Option<u8>) -> Result<Value, String> {
        main_window(&window)?;
        super::grid_swarm_add(name, strategy, lead, workers, computers, tasks, rounds, app).await
    }

    #[tauri::command]
    pub async fn grid_swarm_remove(app: AppHandle, window: WebviewWindow, harness_id: String) -> Result<Value, String> {
        main_window(&window)?;
        super::grid_swarm_remove(harness_id, app).await
    }

    #[tauri::command]
    pub async fn grid_swarm_run(app: AppHandle, window: WebviewWindow, harness: String, prompt: String) -> Result<Value, String> {
        main_window(&window)?;
        super::grid_swarm_run(harness, prompt, app).await
    }
}

#[cfg(test)]
mod membership_tests {
    use super::*;

    #[test]
    fn leaving_a_grid_takes_the_last_connection_error_with_it() {
        let mut inner = Inner { connected: true, member_error: Some("Cannot reach the grid hub through https://old.trycloudflare.com".into()), reported_state: Some("available".into()), ..Inner::default() };
        inner.clear_membership();
        // Status shows member_error once the membership is gone, so a stale one would look
        // like the computer still cannot reach a hub it has left.
        assert_eq!(inner.member_error, None);
        assert!(!inner.connected && inner.reported_state.is_none() && inner.membership.is_none());
    }

    #[test]
    fn being_removed_by_the_admin_still_says_so() {
        let mut inner = Inner { member_error: Some("something older".into()), ..Inner::default() };
        inner.clear_membership();
        // The removal path sets its message after forgetting, so it survives.
        inner.member_error = Some(MemberError::Removed.to_string());
        assert!(inner.member_error.as_deref().is_some_and(|error| !error.is_empty()));
    }
}

#[cfg(test)]
mod progress_tests {
    use super::*;

    #[test]
    fn a_download_reports_its_bytes_and_the_check_after_it_reports_its_own() {
        let downloading = json!({"status": "downloading", "download": {"receivedBytes": 3_200_000_000u64, "totalBytes": 16_000_000_000u64, "bytesPerSecond": 45_500_000.7}});
        let found = progress(&downloading).unwrap();
        assert_eq!(found, Progress { phase: "downloading".into(), done: 3_200_000_000, total: 16_000_000_000, rate: 45_500_000 });
        assert_eq!(describe(&found), "Downloading the model: 3.2 of 16.0 GB");
        let verifying = json!({"status": "verifying", "verification": {"checkedBytes": 5, "totalBytes": 10}});
        assert_eq!(progress(&verifying).unwrap(), Progress { phase: "verifying".into(), done: 5, total: 10, rate: 0 });
        assert_eq!(progress(&json!({"status": "installing"})).unwrap().phase, "installing");
        assert_eq!(progress(&json!({"status": "ready"})), None);
        assert_eq!(progress(&json!({"status": "downloading"})).unwrap(), Progress { phase: "downloading".into(), ..Progress::default() }, "no byte counts yet");
        assert_eq!(describe(&Progress { phase: "downloading".into(), ..Progress::default() }), "Downloading the model");
    }
}

#[cfg(test)]
mod retire_tests {
    use super::*;

    #[test]
    fn only_an_environment_the_grid_created_is_deleted() {
        assert!(matches!(Retire::new("env-a".into(), true), Retire::Delete(id) if id == "env-a"));
        assert!(matches!(Retire::new("env-b".into(), false), Retire::Stop(id) if id == "env-b"), "a model the person already had is only stopped");
    }

    #[test]
    fn a_membership_saved_before_creation_was_recorded_deletes_nothing() {
        let saved: Saved = serde_json::from_value(json!({
            "version": 1, "gridId": "g", "gridName": "Acme", "address": "10.0.0.5:7460", "certificate": "", "fingerprint": "",
            "memberId": "m", "joinedAt": 0, "environmentId": "env-old", "managed": true, "parked": false,
        }))
        .unwrap();
        assert!(saved.managed && !saved.created, "an upgrade must not delete an environment it cannot prove the grid made");
    }

    #[test]
    fn requests_in_flight_hold_back_a_deletion() {
        assert!(!in_flight(None), "a stopped or silent model has nothing in flight");
        assert!(!in_flight(Some(&json!({"optimizer": {"active": 0, "pending": 0}}))));
        assert!(in_flight(Some(&json!({"optimizer": {"active": 1, "pending": 0}}))));
        assert!(in_flight(Some(&json!({"optimizer": {"active": 0, "pending": 2}}))));
    }
}

#[cfg(test)]
mod tunnel_tests {
    use super::*;

    const PASSWORD: &str = "correct horse battery staple";

    #[cfg(windows)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "opens a real temporary no-account Cloudflare tunnel to a disposable grid hub and joins it through Cloudflare; requires Internet"]
    async fn a_member_joins_a_disposable_hub_through_a_real_quick_tunnel() {
        let root = PathBuf::from(std::env::var_os("APPDATA").unwrap()).join("com.yougori.desktop");
        let executable = crate::workspace::cloudflared(&root).await.unwrap();
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("hub.json");
        let salt = password::new_salt();
        let password_key = password::derive(PASSWORD, &salt).unwrap();
        let key = hub::create(&path, "Acme", "127.0.0.1".parse().unwrap(), 0, None, Some(0), &salt).unwrap();
        let hub = Hub::start(path, &key, &password_key, Arc::new(|_: &'static str, _: Value| {})).await.unwrap();
        let entry = hub.tunnel_address().expect("the hub opens its tunnel entry").port();
        let mut tunnel = crate::workspace::cloudflare::start(&executable, folder.path(), entry, None).await.expect("the Quick Tunnel connects");
        let address = HubAddress::parse(&tunnel.url).unwrap();
        eprintln!("Quick Tunnel: {address}");
        let outcome = async {
            // A Quick Tunnel created a moment ago can take a little while to answer everywhere.
            let deadline = Instant::now() + Duration::from_secs(120);
            let joined = loop {
                match member::join("Acme", address.clone(), PASSWORD, "Remote office", "windows", true, None).await {
                    Ok(joined) => break joined,
                    Err(error) if Instant::now() < deadline => {
                        eprintln!("not reachable yet: {error}");
                        tokio::time::sleep(Duration::from_secs(3)).await;
                    }
                    Err(error) => return Err(format!("joining through the tunnel failed: {error}")),
                }
            };
            assert_eq!(joined.fingerprint, net::fingerprint(&hub.record().certificate).unwrap(), "the member pinned the hub itself, not Cloudflare");
            // A saved membership reconnects through Cloudflare, and the hub's 25-second wait for
            // work survives the trip: nothing is sent while it waits.
            let membership = Membership::new(address.clone(), &joined.certificate, joined.membership.member_id.clone(), joined.token.clone()).unwrap();
            membership.heartbeat("test", true, &[]).await.map_err(|error| format!("check-in through the tunnel failed: {error}"))?;
            let started = Instant::now();
            let job = membership.next_job(&["Acme/Chat".into()]).await.map_err(|error| format!("waiting for work through the tunnel failed: {error}"))?;
            assert!(job.is_none() && started.elapsed() >= Duration::from_secs(20), "the long wait completed through Cloudflare");
            // A wrong password through Cloudflare is refused like on the network.
            let refused = member::join("Acme", address.clone(), "wrong password!", "Stranger", "windows", true, None).await.err().unwrap_or_default();
            assert!(refused.contains("password is wrong"), "{refused}");
            Ok::<_, String>(())
        }
        .await;
        let _ = tunnel.child.kill().await;
        outcome.unwrap();
    }
}
