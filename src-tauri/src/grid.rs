//! Closed Neo Grid in the engine. On the admin's computer it runs the hub. On every member
//! computer (the admin's included) it follows the admin's plan: it prepares the assigned model,
//! serves the grid only while the plan's hours and idle rule allow, gives the GPU back when the
//! person returns and checks in with the hub every 30 seconds. The hub's private key, the
//! company password's derived key and the membership token live in the OS credential vault.
//! A hub can also keep a Cloudflare Tunnel open for computers outside the network; the tunnel
//! only relays the grid's own pinned TLS.
//!
//! One computer may hold several Neo Grids: hubs it runs and grids it joined, each an instance
//! with its own record, keys, ports, worker and check-in (see `instances`). The grid it had
//! before instances existed is `default` and keeps every old file, key name and port. A command
//! names its grid with `gridId`; without one it acts on the only grid there is, and with several
//! it says which ones there are rather than guess.
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
    collections::{BTreeMap, BTreeSet},
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

pub(crate) mod instances;
use instances::DEFAULT;

/// Vault names of the `default` instance's keys; other instances add `-<instance>`.
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

const NO_HUB: &str = "This computer does not run a grid hub";
const NO_HUB_ADMIN: &str = "This computer does not run a grid hub. Admins create one with `yougori grid create`.";
const NOT_IN_GRID: &str = "This computer is not in a grid";

#[derive(Default)]
pub struct Grid {
    inner: tokio::sync::Mutex<Inner>,
    /// Serializes creating, joining, leaving and deleting, across every instance.
    admin: tokio::sync::Mutex<()>,
    wake: tokio::sync::Notify,
}

/// The Neo Grids on this computer by instance key (`default`, `i-…`), and what is known about
/// the computer itself, which every grid shares.
#[derive(Default)]
struct Inner {
    slots: BTreeMap<String, Slot>,
    /// Whether this computer can run models, and its backend; refreshed every 30 minutes.
    capable: Option<(bool, String)>,
    capable_at: Option<Instant>,
    /// User activity is read every tick while serving, else every 15 seconds.
    activity: Option<(Activity, Instant)>,
}

/// One Neo Grid on this computer: the hub it runs for it, its membership in it, or both.
#[derive(Default)]
struct Slot {
    loaded: bool,
    /// Set after a failed hub restore: no retry before this time.
    restore_after: Option<Instant>,
    /// Whether the membership read reached an answer that cannot change. Kept apart from
    /// `member_error`, which a vault that was merely not ready yet also sets.
    member_settled: bool,
    hub: Option<Hub>,
    /// The hub's grid ID and company name, once its record was read; a hub that has not
    /// started is still named by them.
    hub_label: Option<(String, String)>,
    hub_error: Option<String>,
    member: Option<Saved>,
    membership: Option<Membership>,
    member_error: Option<String>,
    connected: bool,
    reported: Option<Instant>,
    reported_state: Option<String>,
    work: Work,
    tunnel: TunnelState,
}

impl Slot {
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

    /// Holds nothing at all: no hub, no membership, and nothing to say about either.
    fn is_empty(&self) -> bool {
        self.hub.is_none() && self.member.is_none() && self.hub_error.is_none() && self.member_error.is_none() && self.hub_label.is_none()
    }
}

use crate::hub_tunnel::{self, TunnelSetup, TunnelState};

/// This computer's membership as saved on disk; its token is in the OS vault.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Saved {
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

fn hub_path(app: &AppHandle, instance: &str) -> PathBuf {
    instances::file(&folder(app), instance, "hub.json")
}

fn member_path(app: &AppHandle, instance: &str) -> PathBuf {
    instances::file(&folder(app), instance, "member.json")
}

fn tunnel_path(app: &AppHandle, instance: &str) -> PathBuf {
    instances::file(&folder(app), instance, "tunnel.json")
}

/// One of an instance's vault names: the old one for `default`.
fn vault(base: &str, instance: &str) -> String {
    instances::vault_name(base, instance)
}

/// The instances whose hub or membership is on disk, read or not.
fn occupied<'a>(app: &AppHandle, keys: impl Iterator<Item = &'a String>) -> BTreeSet<String> {
    keys.filter(|instance| hub_path(app, instance).exists() || member_path(app, instance).exists()).cloned().collect()
}

fn persist(app: &AppHandle, instance: &str, saved: &Saved) -> Result<(), String> {
    let path = member_path(app, instance);
    let folder = path.parent().ok_or("Invalid grid folder")?;
    std::fs::create_dir_all(folder).map_err(|error| error.to_string())?;
    let mut file = tempfile::NamedTempFile::new_in(folder).map_err(|error| error.to_string())?;
    std::io::Write::write_all(&mut file, &serde_json::to_vec_pretty(saved).map_err(|error| error.to_string())?).map_err(|error| error.to_string())?;
    file.persist(&path).map_err(|error| error.to_string())?;
    Ok(())
}

/// Joins, refusals and departures at the hub go to the security audit log, with the instance
/// they happened in.
fn events(instance: &str) -> hub::Events {
    let instance = instance.to_owned();
    Arc::new(move |kind: &'static str, detail: Value| crate::security::record(Event::new(kind).text("instance", &instance).object("detail", detail)))
}

/// An audit event about one instance. The kinds are the ones a single grid always recorded.
fn event(kind: &'static str, instance: &str) -> Event {
    Event::new(kind).text("instance", instance)
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

/// Reads every instance on disk (the legacy files for `default`, plus each `grid/neo/<instance>/`)
/// once each can be read.
async fn ensure_loaded(app: &AppHandle) {
    let grid = app.state::<Grid>();
    let mut inner = grid.inner.lock().await;
    for instance in instances::on_disk(&folder(app)) {
        inner.slots.entry(instance).or_default();
    }
    let keys: Vec<String> = inner.slots.keys().cloned().collect();
    for instance in keys {
        if let Some(slot) = inner.slots.get_mut(&instance) {
            load(app, &instance, slot).await;
        }
    }
}

/// Starts one instance's hub and reads its membership.
async fn load(app: &AppHandle, instance: &str, slot: &mut Slot) {
    if slot.loaded || slot.restore_after.is_some_and(|at| Instant::now() < at) {
        return;
    }
    let path = hub_path(app, instance);
    let mut hub_ready = true;
    if path.exists() && slot.hub.is_none() {
        if slot.hub_label.is_none() {
            slot.hub_label = hub::load(&path).ok().map(|record| (record.id, record.name));
        }
        // A hub that cannot start now (a port still held, the vault asleep) is tried again on a
        // later call rather than given up on for the whole process.
        match secrets::hub_keys(secrets::look_up(&vault(HUB_KEY, instance)), secrets::look_up(&vault(HUB_PASSWORD, instance))) {
            secrets::Keys::Ready(key, password_key) => match Hub::start(path, &key, &password_key, events(instance)).await {
                Ok(hub) => {
                    if let (Some(port), Some(setup)) = (hub.tunnel_address().map(|entry| entry.port()), load_tunnel(app, instance)) {
                        keep_tunnel(app, slot, setup, port);
                    }
                    let record = hub.record();
                    slot.hub_label = Some((record.id, record.name));
                    slot.hub = Some(hub);
                    slot.hub_error = None;
                }
                Err(error) => {
                    slot.hub_error = Some(error);
                    hub_ready = false;
                }
            },
            secrets::Keys::Gone => {
                slot.hub_error = Some("The grid hub's keys are missing from the OS credential vault; delete the grid and create it again".into());
                hub_ready = false;
            }
            // The vault would not answer, which says nothing about whether the keys are there.
            // Telling somebody to delete the grid over this destroys a hub whose keys are intact.
            secrets::Keys::NotYet => {
                slot.hub_error = Some("The grid hub's keys could not be read from the OS credential vault yet, so it has not started. Yougori keeps trying; nothing is changed meanwhile.".into());
                hub_ready = false;
            }
        }
    }
    slot.loaded = hub_ready;
    slot.restore_after = (!hub_ready).then(|| Instant::now() + RESTORE_RETRY);
    // `member_error` used to be the latch, so a vault that was not ready yet set "join again with
    // the company password" and that answer stood for the rest of the run. Only a settled outcome
    // stops the next call looking again.
    if slot.member.is_some() || slot.member_settled {
        return;
    }
    // Not readable is not absent. Reading this wrong says "join again with the company password",
    // and the vault is routinely not ready while a computer is still starting, so only "it is not
    // there" is taken as an answer; anything else is looked at again on the next call.
    let outcome = match std::fs::read(member_path(app, instance)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => secrets::MemberLoad::Absent,
        Err(_) => secrets::MemberLoad::NotYet,
        Ok(bytes) => match serde_json::from_slice::<Saved>(&bytes) {
            Err(_) => secrets::MemberLoad::Damaged,
            Ok(saved) => match secrets::look_up(&vault(MEMBER_TOKEN, instance)) {
                secrets::Secret::Unavailable => secrets::MemberLoad::NotYet,
                secrets::Secret::Absent => secrets::MemberLoad::Incomplete,
                secrets::Secret::Found(token) => match HubAddress::parse(&saved.address)
                    .and_then(|address| Membership::new(address, &saved.certificate, saved.member_id.clone(), token))
                {
                    Ok(membership) => {
                        slot.membership = Some(membership);
                        slot.member = Some(saved);
                        secrets::MemberLoad::Loaded
                    }
                    Err(_) => secrets::MemberLoad::Incomplete,
                },
            },
        },
    };
    slot.member_error = outcome.message("grid membership", "company password");
    slot.member_settled = outcome.settled();
}

/// Keeps this computer's grid work in line with each admin's plan while the engine runs.
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
            tick_all(&app).await;
            finish_deleted_hubs(&app).await;
        }
        let grid = app.state::<Grid>();
        let mut inner = grid.inner.lock().await;
        for (instance, slot) in inner.slots.iter_mut() {
            stop_worker(&mut slot.work, true);
            if let Some(saved) = slot.member.as_mut().filter(|saved| saved.managed && !saved.parked) {
                saved.parked = true;
                let _ = persist(&app, instance, saved);
            }
            if let Some(hub) = slot.hub.take() {
                hub.flush();
            }
        }
    });
}

/// Every membership on this computer checks in on its own, so a hub that is slow to answer never
/// holds up another grid's check-in.
async fn tick_all(app: &AppHandle) {
    let members = checking_in(&app.state::<Grid>().inner.lock().await.slots);
    futures_util::future::join_all(members.iter().map(|instance| tick(app, instance))).await;
}

/// The grids this computer checks in with: every one it holds a membership in.
fn checking_in(slots: &BTreeMap<String, Slot>) -> Vec<String> {
    slots.iter().filter(|(_, slot)| slot.member.is_some() && slot.membership.is_some()).map(|(instance, _)| instance.clone()).collect()
}

fn load_tunnel(app: &AppHandle, instance: &str) -> Option<TunnelSetup> {
    hub_tunnel::load(&tunnel_path(app, instance))
}

fn save_tunnel(app: &AppHandle, instance: &str, setup: &TunnelSetup) -> Result<(), String> {
    hub_tunnel::save(&tunnel_path(app, instance), setup)
}

/// Keeps the hub's tunnel connected while the engine runs. The caller holds the grid's lock.
fn keep_tunnel(app: &AppHandle, slot: &mut Slot, setup: TunnelSetup, port: u16) {
    hub_tunnel::keep(app, &mut slot.tunnel, setup, port);
}

fn stop_tunnel(slot: &mut Slot) {
    slot.tunnel.stop();
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

/// What one grid may do with an environment it found or made: one another grid on this computer
/// already uses is borrowed, never this grid's to stop or delete.
fn borrowed(slots: &BTreeMap<String, Slot>, instance: &str, id: &str, managed: bool, created: bool) -> (bool, bool) {
    if keeper(slots, instance, id).is_some() {
        (false, false)
    } else {
        (managed, created)
    }
}

/// Finds, starts or creates the model environment for an assignment.
fn prepare(app: &AppHandle, instance: &str, assignment: Assignment, generation: u64) -> tauri::async_runtime::JoinHandle<()> {
    let (app, instance) = (app.clone(), instance.to_owned());
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
        let result = result.map(|(id, managed, created)| {
            let (managed, created) = borrowed(&inner.slots, &instance, &id, managed, created);
            (id, managed, created)
        });
        if let Some(slot) = inner.slots.get_mut(&instance) {
            if slot.work.preparing_generation == generation {
                slot.work.preparing = None;
            }
        }
        // The assignment changed meanwhile, or the grid is gone: what the grid started for it is
        // stopped, and what it created is deleted.
        let current = inner.slots.get(&instance).and_then(|slot| slot.member.as_ref()).is_some_and(|saved| saved.assignment.as_ref().is_some_and(|current| current.same_model(&assignment)));
        if !current {
            if let Ok((id, true, created)) = result {
                let stop = hand_over(&app, inner, &instance, Some(Retire::new(id, created)));
                drop(guard);
                retire(&app, &instance, stop);
            }
            return;
        }
        let Some(slot) = inner.slots.get_mut(&instance) else { return };
        match result {
            Ok((id, managed, created)) => {
                crate::security::record(event("grid.model.prepared", &instance).env(&id).text("model", &assignment.model).flag("created", created));
                if let Some(saved) = slot.member.as_mut() {
                    saved.environment_id = Some(id);
                    saved.managed = managed;
                    saved.created = created;
                    saved.parked = false;
                    let _ = persist(&app, &instance, saved);
                }
                slot.work.prepare_error = None;
            }
            Err(error) => slot.work.prepare_error = Some((error, Instant::now())),
        }
        grid.wake.notify_one();
    })
}

/// After a cancelled preparation: an environment for that model still being provisioned has
/// nobody finishing it, so it is marked failed, where the person can delete it, rather than
/// left looking as if work went on. One another grid on this computer is preparing the same
/// model for is left to it.
fn abandon_preparation(app: &AppHandle, instance: &str, assignment: Assignment) {
    let (app, instance) = (app.clone(), instance.to_owned());
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let wanted = yougori_grid::model_key(&assignment.model);
        let elsewhere = app.state::<Grid>().inner.lock().await.slots.iter().any(|(other, slot)| {
            other != &instance && slot.work.preparing.is_some() && slot.member.as_ref().and_then(|saved| saved.assignment.as_ref()).is_some_and(|theirs| yougori_grid::model_key(&theirs.model) == wanted)
        });
        if elsewhere {
            return;
        }
        let Ok(state) = app.state::<PlatformStore>().snapshot() else { return };
        let runtime = app.state::<RuntimeManager>();
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
            crate::security::record(event("grid.model.abandoned", &instance).env(&id).text("model", &assignment.model).outcome(&result));
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

    fn id(&self) -> &str {
        match self {
            Retire::Stop(id) | Retire::Delete(id) => id,
        }
    }
}

fn retire(app: &AppHandle, instance: &str, retire: Option<Retire>) {
    match retire {
        Some(Retire::Stop(id)) => spawn_power(app, instance, id, false),
        Some(Retire::Delete(id)) => spawn_delete(app, instance, id),
        None => {}
    }
}

/// Another grid on this computer, not `from`, whose membership uses environment `id`.
fn keeper(slots: &BTreeMap<String, Slot>, from: &str, id: &str) -> Option<String> {
    slots
        .iter()
        .find(|(instance, slot)| instance.as_str() != from && slot.member.as_ref().is_some_and(|saved| saved.environment_id.as_deref() == Some(id)))
        .map(|(instance, _)| instance.clone())
}

/// One grid retiring an environment another grid on this computer uses never stops or deletes
/// it: that grid takes it over, with the right to delete it once it is done when the environment
/// was made for a grid. Returns what is still to retire, and who took it over.
fn hand_over_in(slots: &mut BTreeMap<String, Slot>, from: &str, retire: Option<Retire>) -> (Option<Retire>, Option<(String, String)>) {
    let Some(retire) = retire else { return (None, None) };
    let Some(other) = keeper(slots, from, retire.id()) else { return (Some(retire), None) };
    let id = retire.id().to_owned();
    if let Some(saved) = slots.get_mut(&other).and_then(|slot| slot.member.as_mut()) {
        saved.managed = true;
        saved.created |= matches!(retire, Retire::Delete(_));
    }
    (None, Some((other, id)))
}

/// `hand_over_in`, with the new keeper's record saved and the hand-over in the audit log.
fn hand_over(app: &AppHandle, inner: &mut Inner, from: &str, retire: Option<Retire>) -> Option<Retire> {
    let (retire, kept) = hand_over_in(&mut inner.slots, from, retire);
    if let Some((other, id)) = kept {
        if let Some(saved) = inner.slots.get(&other).and_then(|slot| slot.member.as_ref()) {
            let _ = persist(app, &other, saved);
        }
        crate::security::record(event("grid.model.kept", from).env(&id).text("reason", "another grid on this computer uses it").text("keptBy", &other));
    }
    retire
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
/// Whether `id` is the environment a current assignment of any grid on this computer uses.
async fn assigned_now(app: &AppHandle, id: &str) -> bool {
    app.state::<Grid>().inner.lock().await.slots.values().any(|slot| slot.member.as_ref().is_some_and(|saved| saved.environment_id.as_deref() == Some(id)))
}

fn environment_status(app: &AppHandle, id: &str) -> Option<EnvironmentStatus> {
    app.state::<PlatformStore>().snapshot().ok()?.environments.into_iter().find(|environment| environment.id == id).map(|environment| environment.status)
}

fn spawn_delete(app: &AppHandle, instance: &str, id: String) {
    let (app, instance) = (app.clone(), instance.to_owned());
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
                crate::security::record(event("grid.model.kept", &instance).env(&id).text("reason", "assigned to this computer again"));
                return;
            }
            attempt += 1;
            if attempt % DELETE_WAITS == 0 {
                crate::security::record(event("grid.model.kept", &instance).env(&id).text("reason", if health.is_some() { "still answering requests; deletion waits" } else { "not answering health checks; deletion waits" }));
            }
            tokio::time::sleep(DELETE_WAIT).await;
        }
        if assigned_now(&app, &id).await {
            crate::security::record(event("grid.model.kept", &instance).env(&id).text("reason", "assigned to this computer again"));
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
        crate::security::record(event("grid.model.deleted", &instance).env(&id).outcome(&result));
    });
}

fn spawn_power(app: &AppHandle, instance: &str, id: String, start: bool) {
    let (app, instance) = (app.clone(), instance.to_owned());
    tauri::async_runtime::spawn(async move {
        if !start {
            let health = tokio::time::timeout(Duration::from_secs(15), crate::model_runner::model_status(id.clone(), app.clone())).await.ok().and_then(Result::ok);
            if !quiet(health.as_ref()) {
                crate::security::record(event("grid.model.kept", &instance).env(&id).text("reason", "in use or not answering"));
                return;
            }
            // Given back to this computer while the health check ran: it stays running.
            if assigned_now(&app, &id).await {
                crate::security::record(event("grid.model.kept", &instance).env(&id).text("reason", "assigned to this computer again"));
                return;
            }
        }
        let result = if start { crate::model_runner::start_model(id.clone(), app.clone()).await } else { crate::model_runner::stop_model(id.clone(), app.clone()).await };
        if start && result.is_ok() {
            // Only a start that went through ends the parked state; a failed one is tried again.
            let grid = app.state::<Grid>();
            let mut inner = grid.inner.lock().await;
            if let Some(saved) = inner.slots.get_mut(&instance).and_then(|slot| slot.member.as_mut()).filter(|saved| saved.environment_id.as_deref() == Some(id.as_str())) {
                saved.parked = false;
                let _ = persist(&app, &instance, saved);
            }
        }
        crate::security::record(event(if start { "grid.model.started" } else { "grid.model.stopped" }, &instance).env(&id).outcome(&result));
    });
}

/// Brings this computer in line with one grid's assignment and returns what to report to its hub.
async fn follow(app: &AppHandle, instance: &str, membership: &Membership, saved: &Saved, activity: &Activity) -> Vec<ModelReport> {
    let grid = app.state::<Grid>();
    let Some(assignment) = saved.assignment.clone() else {
        let mut inner = grid.inner.lock().await;
        if let Some(slot) = inner.slots.get_mut(instance) {
            stop_worker(&mut slot.work, false);
            slot.work.state.clear();
            slot.work.reason.clear();
        }
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
        let Some(slot) = guard.slots.get_mut(instance) else { return Vec::new() };
        stop_worker(&mut slot.work, false);
        if let Some(environment) = environment.as_ref().filter(|environment| saved.managed && !saved.parked && environment.status == EnvironmentStatus::Running) {
            spawn_power(app, instance, environment.id.clone(), false);
            if let Some(current) = slot.member.as_mut().filter(|current| current.environment_id.as_deref() == Some(environment.id.as_str())) {
                current.parked = true;
                let _ = persist(app, instance, current);
            }
        }
        let reason = "Paused: the grid's admin scheduled it for deletion; the model stays until then".to_owned();
        slot.work.state = "paused".into();
        slot.work.reason = reason.clone();
        return vec![report("stopped", &reason, &slot.work)];
    }
    let Some(environment) = environment else {
        let mut guard = grid.inner.lock().await;
        let Some(slot) = guard.slots.get_mut(instance) else { return Vec::new() };
        stop_worker(&mut slot.work, false);
        // The environment was deleted: prepare the model again.
        if let Some(saved) = slot.member.as_mut().filter(|saved| saved.environment_id.is_some()) {
            saved.environment_id = None;
            saved.managed = false;
            let _ = persist(app, instance, saved);
        }
        let retry = slot.work.prepare_error.as_ref().is_none_or(|(_, at)| at.elapsed() >= RETRY);
        if slot.work.preparing.is_none() && retry {
            slot.work.prepare_error = None;
            slot.work.preparing_generation += 1;
            slot.work.preparing = Some(prepare(app, instance, assignment.clone(), slot.work.preparing_generation));
        }
        let (state, reason) = match &slot.work.prepare_error {
            Some((error, _)) => ("error", format!("Could not prepare the model: {error}")),
            None => ("preparing", "Preparing the model".into()),
        };
        slot.work.progress = (state == "preparing").then(|| Progress { phase: "preparing".into(), ..Progress::default() });
        slot.work.state = state.into();
        slot.work.reason = reason.clone();
        return vec![report(state, &reason, &slot.work)];
    };
    let id = environment.id.clone();
    let running = environment.status == EnvironmentStatus::Running;
    let locked = crate::security::is_contained(&id);
    let health_due = grid.inner.lock().await.slots.get(instance).is_some_and(|slot| slot.work.health_at.is_none_or(|at| at.elapsed() >= HEALTH));
    let health = if running && health_due {
        Some(tokio::time::timeout(Duration::from_secs(15), crate::model_runner::model_status(id.clone(), app.clone())).await.ok().and_then(Result::ok))
    } else {
        None
    };
    let mut guard = grid.inner.lock().await;
    let Some(slot) = guard.slots.get_mut(instance) else { return Vec::new() };
    let work = &mut slot.work;
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
        spawn_power(app, instance, id.clone(), false);
    }
    let failed = environment.status == EnvironmentStatus::Error;
    if saved.managed && !running && !outside && !locked && (saved.parked || failed) && work.started_at.is_none_or(|at| at.elapsed() >= RESTART) {
        work.started_at = Some(Instant::now());
        // `parked` is cleared by the start itself once it succeeds (`spawn_power`), so a start
        // that fails before the environment changes state is tried again after RESTART.
        spawn_power(app, instance, id.clone(), true);
    }
    if let Some(parked) = park {
        if let Some(current) = slot.member.as_mut().filter(|current| current.environment_id.as_deref() == Some(id.as_str())) {
            current.parked = parked;
            let _ = persist(app, instance, current);
        }
    }
    let work = &mut slot.work;
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
fn apply(app: &AppHandle, instance: &str, slot: &mut Slot, assignment: Option<Assignment>, grid_name: String) -> Option<Retire> {
    let saved = slot.member.as_mut()?;
    if !grid_name.is_empty() && grid_name != saved.grid_name {
        saved.grid_name = grid_name;
        let _ = persist(app, instance, saved);
    }
    if saved.assignment == assignment {
        return None;
    }
    let same_model = matches!((&saved.assignment, &assignment), (Some(old), Some(new)) if old.same_model(new));
    let mut stop = None;
    if !same_model {
        stop_worker(&mut slot.work, false);
        // A download or start in progress for the old model stops here, not when it is done:
        // the task is cancelled, and an environment it left half-made is marked so.
        if let Some(handle) = slot.work.preparing.take() {
            handle.abort();
            slot.work.preparing_generation += 1;
            if let Some(old) = saved.assignment.clone() {
                abandon_preparation(app, instance, old);
            }
        }
        slot.work.prepare_error = None;
        if saved.managed {
            stop = saved.environment_id.clone().map(|id| Retire::new(id, saved.created));
        }
        saved.environment_id = None;
        saved.managed = false;
        saved.created = false;
    }
    crate::security::record(event("grid.assignment.changed", instance).text("model", assignment.as_ref().map_or("", |assignment| assignment.model.as_str())));
    saved.assignment = assignment;
    let _ = persist(app, instance, saved);
    stop
}

/// Forgets this computer's membership; returns what to do with a grid-started environment.
fn forget(app: &AppHandle, instance: &str, slot: &mut Slot) -> Option<Retire> {
    stop_worker(&mut slot.work, true);
    slot.work = Work::default();
    slot.clear_membership();
    let saved = slot.member.take();
    let _ = std::fs::remove_file(member_path(app, instance));
    let _ = secrets::delete_secret(&vault(MEMBER_TOKEN, instance));
    saved.filter(|saved| saved.managed).and_then(|saved| saved.environment_id.map(|id| Retire::new(id, saved.created)))
}

/// A grid made after `default` that holds nothing any more is dropped, with its empty folder.
fn drop_if_empty(app: &AppHandle, inner: &mut Inner, instance: &str) {
    if instance != DEFAULT && inner.slots.get(instance).is_some_and(Slot::is_empty) {
        inner.slots.remove(instance);
    }
    instances::tidy(&folder(app), instance);
}

async fn tick(app: &AppHandle, instance: &str) {
    let grid = app.state::<Grid>();
    let (membership, saved, refresh) = {
        let inner = grid.inner.lock().await;
        let Some(slot) = inner.slots.get(instance) else { return };
        let (Some(membership), Some(saved)) = (slot.membership.clone(), slot.member.clone()) else { return };
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
    // Every grid on this computer reads the same person, so they share one reading.
    let activity = if saved.assignment.is_some() {
        let (serving, cached) = {
            let inner = grid.inner.lock().await;
            let serving = inner.slots.get(instance).and_then(|slot| slot.work.worker.as_ref()).is_some_and(|worker| *worker.gate.borrow());
            (serving, inner.activity.clone())
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
    let reports = follow(app, instance, &membership, &saved, &activity).await;
    let (due, capable) = {
        let inner = grid.inner.lock().await;
        let Some(slot) = inner.slots.get(instance) else { return };
        let changed = slot.reported_state.as_deref() != reports.first().map(|report| report.state.as_str());
        (slot.reported.is_none_or(|at| at.elapsed() >= REPORT) || changed, inner.capable.as_ref().is_some_and(|(capable, _)| *capable))
    };
    if !due {
        return;
    }
    let answer = membership.heartbeat(env!("CARGO_PKG_VERSION"), capable, &reports).await;
    let mut guard = grid.inner.lock().await;
    let inner = &mut *guard;
    let Some(slot) = inner.slots.get_mut(instance) else { return };
    // Membership changed while the check-in was in flight.
    if slot.member.as_ref().is_none_or(|current| current.member_id != saved.member_id) {
        return;
    }
    slot.reported = Some(Instant::now());
    let left = matches!(answer, Err(MemberError::Deleted | MemberError::Removed));
    let stop = match answer {
        Ok(instructions) => {
            slot.connected = true;
            slot.member_error = None;
            if let Some(current) = slot.member.as_mut().filter(|current| current.unreachable_since.is_some()) {
                current.unreachable_since = None;
                let _ = persist(app, instance, current);
            }
            slot.reported_state = reports.first().map(|report| report.state.clone());
            if let Some(current) = slot.member.as_mut().filter(|current| current.paused_until != instructions.paused_until) {
                crate::security::record(event(if instructions.paused_until.is_some() { "grid.paused" } else { "grid.resumed" }, instance).text("grid", &current.grid_name));
                current.paused_until = instructions.paused_until;
                let _ = persist(app, instance, current);
                grid.wake.notify_one();
            }
            apply(app, instance, slot, instructions.assignment, instructions.grid_name)
        }
        Err(MemberError::Deleted) => {
            // The admin deleted the grid: leave it, and remove the model environment it created.
            crate::security::record(event("grid.deleted.left", instance).text("grid", &saved.grid_name));
            let stop = forget(app, instance, slot);
            let removed = matches!(stop, Some(Retire::Delete(_)));
            slot.member_error = Some(format!("{} deleted this grid. This computer left it{}.", saved.grid_name, if removed { " and removed the model the grid had installed" } else { "" }));
            stop
        }
        Err(MemberError::Removed) => {
            crate::security::record(event("grid.removed", instance).text("grid", &saved.grid_name));
            let stop = forget(app, instance, slot);
            slot.member_error = Some(MemberError::Removed.to_string());
            stop
        }
        // Answered, but in words this build cannot read. The hub is not silent, so the clock
        // that ends in "the hub is gone, leave the grid" must not start: following that advice
        // would unshare every desk on this computer over a hub that is working perfectly.
        Err(MemberError::Unreadable(error)) => {
            slot.connected = false;
            slot.member_error = Some(error);
            // The hub answered, so a clock an earlier failed check-in started stops here too.
            // Not starting one was never enough on its own: a restart for a hub upgrade fails a
            // check-in and starts the clock, and answers this build cannot read then left it
            // running all the way to "leave the grid".
            if let Some(current) = slot.member.as_mut().filter(|current| current.unreachable_since.is_some()) {
                current.unreachable_since = member::silence_clock(true, current.unreachable_since, yougori_grid::now());
                let _ = persist(app, instance, current);
            }
            // Nothing is retired. An answer this build could not read says nothing about what
            // this computer should be running, and retiring on it would delete a grid-created
            // model environment with its weights.
            None
        }
        Err(MemberError::Failed(error)) => {
            slot.connected = false;
            slot.member_error = Some(error);
            if let Some(current) = slot.member.as_mut().filter(|current| current.unreachable_since.is_none()) {
                current.unreachable_since = member::silence_clock(false, current.unreachable_since, yougori_grid::now());
                let _ = persist(app, instance, current);
            }
            None
        }
    };
    let stop = hand_over(app, inner, instance, stop);
    if left {
        drop_if_empty(app, inner, instance);
    }
    drop(guard);
    retire(app, instance, stop);
}

/// A membership as status shows it.
fn member_status(inner: &Inner, slot: &Slot) -> Option<Value> {
    let saved = slot.member.as_ref()?;
    let stats = slot.work.worker.as_ref().map(|worker| worker.stats.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone()).unwrap_or_default();
    Some(json!({
        "gridId": saved.grid_id, "grid": saved.grid_name, "hub": saved.address, "fingerprint": saved.fingerprint,
        "memberId": saved.member_id, "joinedAt": saved.joined_at, "connected": slot.connected, "error": slot.member_error,
        "capable": inner.capable.as_ref().map(|(capable, _)| *capable), "backend": inner.capable.as_ref().map(|(_, backend)| backend.clone()),
        "assignment": saved.assignment,
        "rules": saved.assignment.as_ref().and_then(|assignment| assignment.policy().ok()).map(|policy| policy.describe()),
        "environmentId": saved.environment_id, "managed": saved.managed, "parked": saved.parked, "pausedUntil": saved.paused_until,
        "unreachableSince": saved.unreachable_since,
        "state": slot.work.state, "reason": slot.work.reason, "progress": slot.work.progress,
        "jobs": stats.jobs, "handedBack": stats.released, "failures": stats.failures, "lastError": stats.last_error,
    }))
}

/// The grid the old single-grid fields of status describe: `default` while it holds anything,
/// else the first grid that does.
fn primary(slots: &BTreeMap<String, Slot>) -> String {
    if slots.get(DEFAULT).is_some_and(|slot| !slot.is_empty()) {
        return DEFAULT.into();
    }
    slots.iter().find(|(_, slot)| !slot.is_empty()).map(|(instance, _)| instance.clone()).unwrap_or_else(|| DEFAULT.into())
}

/// The instance an ID names: an instance key, a hub's grid ID or a joined grid's ID.
fn lookup(slots: &BTreeMap<String, Slot>, id: &str) -> Option<String> {
    let id = id.trim();
    if slots.contains_key(id) {
        return Some(id.to_owned());
    }
    slots
        .iter()
        .find(|(_, slot)| slot.hub_label.as_ref().is_some_and(|(grid, _)| grid == id) || slot.member.as_ref().is_some_and(|saved| saved.grid_id == id))
        .map(|(instance, _)| instance.clone())
}

fn unknown(id: &str) -> String {
    format!("No Neo Grid on this computer has the ID {id}. `yougori grid status` lists each one with its ID.")
}

/// Status, in the shape it always had plus the list of every grid: `hub`, `hubError`, `member`
/// and `memberError` describe the grid `grid_id` names, or else `default` (the only grid on most
/// computers); `instance` says which one that is; `hubs` and `members` list every hub this
/// computer runs and every grid it is in, each with its `instance` and `gridId`.
pub(crate) async fn grid_status_in(grid_id: Option<String>, app: AppHandle) -> Result<Value, String> {
    ensure_loaded(&app).await;
    let grid = app.state::<Grid>();
    let inner = grid.inner.lock().await;
    let chosen = match grid_id.as_deref().map(str::trim).filter(|id| !id.is_empty()) {
        Some(id) => lookup(&inner.slots, id).ok_or_else(|| unknown(id))?,
        None => primary(&inner.slots),
    };
    Ok(status_of(&inner, &chosen))
}

/// Status with `chosen` in the single-grid fields.
fn status_of(inner: &Inner, chosen: &str) -> Value {
    let empty = Slot::default();
    let slot = inner.slots.get(chosen).unwrap_or(&empty);
    let mut hubs = Vec::new();
    let mut members = Vec::new();
    for (instance, each) in &inner.slots {
        let grid_id = each.hub_label.as_ref().map(|(id, _)| id.clone());
        if let Some(hub) = &each.hub {
            let mut entry = hub_status(hub, &each.tunnel);
            entry["instance"] = json!(instance);
            entry["gridId"] = json!(grid_id);
            hubs.push(entry);
        } else if let Some(error) = &each.hub_error {
            hubs.push(json!({"instance": instance, "gridId": grid_id, "name": each.hub_label.as_ref().map(|(_, name)| name), "error": error}));
        }
        if let Some(mut entry) = member_status(inner, each) {
            entry["instance"] = json!(instance);
            members.push(entry);
        } else if let Some(error) = &each.member_error {
            members.push(json!({"instance": instance, "gridId": Value::Null, "error": error}));
        }
    }
    json!({
        "hub": slot.hub.as_ref().map(|hub| hub_status(hub, &slot.tunnel)),
        "hubError": slot.hub_error,
        "member": member_status(inner, slot),
        "memberError": if slot.member.is_none() { slot.member_error.clone() } else { None },
        "instance": chosen,
        "hubs": hubs,
        "members": members,
    })
}

/// What a command needs a grid to be.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Role {
    /// This computer runs its hub (or has its hub's record, started or not).
    Hub,
    /// This computer is in it.
    Member,
}

/// One grid a command could be about.
#[derive(Debug)]
struct Candidate {
    instance: String,
    ids: Vec<String>,
    label: String,
}

/// The grids that can answer a command about `role`. `hub_files` are the instances whose hub
/// record is on disk, so a hub that has not started can still be deleted.
fn candidates(slots: &BTreeMap<String, Slot>, role: Role, hub_files: &BTreeSet<String>) -> Vec<Candidate> {
    slots
        .iter()
        .filter_map(|(instance, slot)| match role {
            Role::Hub if slot.hub.is_some() || hub_files.contains(instance) => {
                let (id, name) = slot.hub_label.clone().unwrap_or_else(|| (instance.clone(), "A grid hub that has not started".into()));
                Some(Candidate { instance: instance.clone(), ids: vec![instance.clone(), id.clone()], label: format!("{name} ({id})") })
            }
            Role::Member => slot.member.as_ref().map(|saved| Candidate {
                instance: instance.clone(),
                ids: vec![instance.clone(), saved.grid_id.clone()],
                label: format!("{} ({})", saved.grid_name, saved.grid_id),
            }),
            Role::Hub => None,
        })
        .collect()
}

/// Which grid a command is about: the one `grid_id` names; with none named, the only one there
/// is. With several and none named it refuses, naming them, because guessing would change the
/// wrong grid. `none` is what to say when no grid can answer.
fn choose(found: &[Candidate], known: impl Fn(&str) -> bool, grid_id: Option<&str>, none: &str) -> Result<String, String> {
    match grid_id.map(str::trim).filter(|id| !id.is_empty()) {
        Some(id) => found.iter().find(|candidate| candidate.ids.iter().any(|each| each == id)).map(|candidate| candidate.instance.clone()).ok_or_else(|| if known(id) { none.to_owned() } else { unknown(id) }),
        None => match found {
            [] => Err(none.to_owned()),
            [one] => Ok(one.instance.clone()),
            several => Err(format!(
                "There are {} Neo Grids on this computer: {}. Say which with gridId.",
                several.len(),
                several.iter().map(|candidate| candidate.label.as_str()).collect::<Vec<_>>().join(", ")
            )),
        },
    }
}

/// `choose` over the grids on this computer now. The caller holds the grid's lock.
fn choose_in(app: &AppHandle, inner: &Inner, grid_id: Option<&str>, role: Role, none: &str) -> Result<String, String> {
    let hub_files: BTreeSet<String> = inner.slots.keys().filter(|instance| hub_path(app, instance).exists()).cloned().collect();
    choose(&candidates(&inner.slots, role, &hub_files), |id| lookup(&inner.slots, id).is_some(), grid_id, none)
}

async fn resolve(app: &AppHandle, grid_id: Option<&str>, role: Role, none: &str) -> Result<String, String> {
    let grid = app.state::<Grid>();
    let inner = grid.inner.lock().await;
    choose_in(app, &inner, grid_id, role, none)
}

/// The hub instance a command for rented GPUs is about: the one `grid_id` names, or the only one.
pub(crate) async fn choose_hub(app: &AppHandle, grid_id: Option<&str>) -> Result<String, String> {
    ensure_loaded(app).await;
    resolve(app, grid_id, Role::Hub, "Host a grid on this computer first; rented GPUs join the grid it hosts.").await
}

/// Every hub this computer runs or has a record of: its instance, grid ID and company name.
pub(crate) async fn hub_instances(app: &AppHandle) -> Vec<(String, Option<String>, Option<String>)> {
    ensure_loaded(app).await;
    let grid = app.state::<Grid>();
    let inner = grid.inner.lock().await;
    inner
        .slots
        .iter()
        .filter(|(instance, slot)| slot.hub.is_some() || slot.hub_error.is_some() || hub_path(app, instance).exists())
        .map(|(instance, slot)| (instance.clone(), slot.hub_label.as_ref().map(|(id, _)| id.clone()), slot.hub_label.as_ref().map(|(_, name)| name.clone())))
        .collect()
}

/// One instance's hub as status shows it: `hub` set while it runs, `hubError` when it is set up
/// here but has not started, both null when this computer runs no hub for it.
pub(crate) async fn hub_state(app: &AppHandle, instance: &str) -> Value {
    ensure_loaded(app).await;
    let grid = app.state::<Grid>();
    let inner = grid.inner.lock().await;
    let slot = inner.slots.get(instance);
    json!({
        "hub": slot.and_then(|slot| slot.hub.as_ref()).map(|_| true),
        "hubError": slot.and_then(|slot| slot.hub_error.clone()),
    })
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

/// Where a new hub goes: `default` while it holds nothing (so a computer's first grid keeps the
/// layout every older build reads), otherwise a new instance. `occupied` are the instances whose
/// hub or membership is on disk.
fn hub_target(slots: &BTreeMap<String, Slot>, occupied: &BTreeSet<String>) -> String {
    let default_free = !occupied.contains(DEFAULT) && slots.get(DEFAULT).is_none_or(|slot| slot.hub.is_none() && slot.member.is_none());
    if default_free {
        return DEFAULT.into();
    }
    loop {
        let key = instances::new_key();
        if !slots.contains_key(&key) && !occupied.contains(&key) {
            return key;
        }
    }
}

/// Where a membership in `grid_id` goes, or why this computer may not join it: a grid this
/// computer is already in is refused, whichever instance holds it. `prefer` is the instance of a
/// hub just created here; a hub this computer runs takes its own membership back.
fn member_target(slots: &BTreeMap<String, Slot>, occupied: &BTreeSet<String>, prefer: Option<&str>, grid_id: &str) -> Result<String, String> {
    if let Some(saved) = slots.values().filter_map(|slot| slot.member.as_ref()).find(|saved| saved.grid_id == grid_id) {
        return Err(format!("This computer is already in {}'s grid. Leave it first with `yougori grid leave --yes`.", saved.grid_name));
    }
    if let Some(prefer) = prefer {
        return Ok(prefer.to_owned());
    }
    if let Some((instance, _)) = slots.iter().find(|(_, slot)| slot.member.is_none() && slot.hub_label.as_ref().is_some_and(|(id, _)| id == grid_id)) {
        return Ok(instance.clone());
    }
    Ok(hub_target(slots, occupied))
}

/// How a command for one grid is typed once this computer has several.
fn with_grid(command: &str, grid_id: &str, several: bool) -> String {
    if several {
        format!("`{command} --grid {grid_id}`")
    } else {
        format!("`{command}`")
    }
}

/// Moves this computer's membership to `address`, the same hub reached another way. The hub must
/// answer there with the pinned certificate and accept this computer's token before anything is
/// saved. The caller holds the admin lock.
async fn readdress(app: &AppHandle, instance: &str, mut saved: Saved, address: HubAddress) -> Result<(), String> {
    let membership = Membership::new(address.clone(), &saved.certificate, saved.member_id.clone(), secrets::resolve(&vault(MEMBER_TOKEN, instance))?)?;
    let found = capability(app).await;
    membership.heartbeat(env!("CARGO_PKG_VERSION"), found.0, &[]).await.map_err(|error| error.to_string())?;
    saved.address = address.to_string();
    persist(app, instance, &saved)?;
    crate::security::record(event("grid.readdressed", instance).text("grid", &saved.grid_name).text("hub", &saved.address));
    let grid = app.state::<Grid>();
    let mut inner = grid.inner.lock().await;
    let slot = inner.slots.entry(instance.to_owned()).or_default();
    // The worker holds the old address; the next check-in starts one on the new address.
    stop_worker(&mut slot.work, true);
    slot.member = Some(saved);
    slot.membership = Some(membership);
    slot.member_error = None;
    slot.connected = true;
    slot.reported = None;
    grid.wake.notify_one();
    Ok(())
}

/// Joins a grid and saves the membership in the instance it belongs in; returns that instance.
/// The caller holds the admin lock.
async fn join_now(app: &AppHandle, prefer: Option<&str>, company: &str, hub: HubAddress, secret: &str, name: Option<String>, fingerprint: Option<&str>) -> Result<String, String> {
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
    let grid = app.state::<Grid>();
    let (instance, fresh) = {
        let mut inner = grid.inner.lock().await;
        let occupied = occupied(app, inner.slots.keys());
        match member_target(&inner.slots, &occupied, prefer, &joined.grid_id) {
            Ok(instance) => {
                let fresh = !inner.slots.contains_key(&instance);
                let slot = inner.slots.entry(instance.clone()).or_default();
                // Claimed before anything is written, so a status read meanwhile does not load
                // this membership a second time.
                slot.loaded |= fresh;
                slot.member_settled = true;
                (instance, fresh)
            }
            Err(error) => {
                drop(inner);
                let _ = joined.membership.leave().await;
                return Err(error);
            }
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
    let token = vault(MEMBER_TOKEN, &instance);
    if let Err(error) = secrets::store(&token, &joined.token).and_then(|_| persist(app, &instance, &saved)) {
        let _ = joined.membership.leave().await;
        let _ = secrets::delete_secret(&token);
        let _ = std::fs::remove_file(member_path(app, &instance));
        let mut inner = grid.inner.lock().await;
        if fresh {
            drop_if_empty(app, &mut inner, &instance);
        }
        return Err(error);
    }
    crate::security::record(event("grid.joined", &instance).text("grid", &saved.grid_name).text("hub", &saved.address).text("fingerprint", &saved.fingerprint));
    let mut inner = grid.inner.lock().await;
    inner.capable = Some(found);
    inner.capable_at = Some(Instant::now());
    let slot = inner.slots.entry(instance.clone()).or_default();
    slot.member = Some(saved);
    slot.membership = Some(joined.membership);
    slot.member_error = None;
    slot.connected = true;
    slot.reported = None;
    grid.wake.notify_one();
    Ok(instance)
}

/// How many grids this computer holds now.
async fn grid_count(app: &AppHandle) -> usize {
    app.state::<Grid>().inner.lock().await.slots.values().filter(|slot| slot.hub.is_some() || slot.member.is_some() || slot.hub_error.is_some()).count()
}

/// Joins with an `invite` from the admin, which names the company, the hub's address and its
/// fingerprint; or with the company name and the hub's address given separately. An invite for
/// a grid this computer is already in only moves it to the hub's current address, as after a
/// Quick Tunnel restarts; the hub is the same pinned certificate, so no password is needed. Any
/// other grid becomes one more on this computer.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn grid_join(company: Option<String>, address_text: Option<String>, secret: Option<String>, port: Option<u16>, name: Option<String>, fingerprint: Option<String>, invite: Option<String>, app: AppHandle) -> Result<Value, String> {
    let grid = app.state::<Grid>();
    let _admin = grid.admin.lock().await;
    ensure_loaded(&app).await;
    let given = |value: Option<String>| value.map(|value| value.trim().to_owned()).filter(|value| !value.is_empty());
    let invite = given(invite).map(|code| invite::decode(&code)).transpose()?;
    let members: Vec<(String, Saved)> = grid.inner.lock().await.slots.iter().filter_map(|(instance, slot)| slot.member.clone().map(|saved| (instance.clone(), saved))).collect();
    if let Some(invite) = &invite {
        if let Some((instance, saved)) = members.iter().find(|(_, saved)| net::normalize_fingerprint(&saved.fingerprint).as_deref() == Some(invite.fingerprint.as_str())) {
            readdress(&app, instance, saved.clone(), invite.address.clone()).await?;
            drop(_admin);
            let mut status = grid_status_in(Some(instance.clone()), app).await?;
            status["message"] = json!(format!("This computer now reaches {}'s grid at {}.", status["member"]["grid"].as_str().unwrap_or(&invite.company), status["member"]["hub"].as_str().unwrap_or_default()));
            return Ok(status);
        }
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
    // A grid this computer is already in, reached at the same address or pinned to the same
    // certificate, is never joined a second time.
    let pinned = fingerprint.as_deref().and_then(net::normalize_fingerprint);
    if let Some((_, saved)) = members.iter().find(|(_, saved)| saved.address == hub.to_string() || pinned.is_some() && net::normalize_fingerprint(&saved.fingerprint) == pinned) {
        return Err(format!("This computer is already in {}'s grid. Leave it first with `yougori grid leave --yes`.", saved.grid_name));
    }
    let name = given(name);
    let instance = join_now(&app, None, &company, hub, &secret, name, fingerprint.as_deref()).await?;
    drop(_admin);
    let several = grid_count(&app).await > 1;
    let mut status = grid_status_in(Some(instance), app).await?;
    let grid_id = status["member"]["gridId"].as_str().unwrap_or_default().to_owned();
    status["message"] = json!(format!(
        "Joined {}'s Closed Neo Grid. Its admin now decides which model this computer runs and when it serves; {} leaves.",
        status["member"]["grid"].as_str().unwrap_or(&company),
        with_grid("yougori grid leave --yes", &grid_id, several)
    ));
    Ok(status)
}

/// Gives back ports allocated for a create when the create ends, however it ends: once the hub's
/// record is written it holds them.
struct Allocated(Vec<u16>);

impl Drop for Allocated {
    fn drop(&mut self) {
        instances::release_ports(&self.0);
    }
}

/// `tunnel` also opens the grid to computers outside the network: `quick` for a temporary
/// trycloudflare.com address, or the name of a saved Cloudflare domain. On a computer that
/// already holds a grid the new one is a grid of its own, on ports picked for it.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn grid_create(name: String, address_text: String, secret: String, port: Option<u16>, hostname: Option<String>, tunnel: Option<String>, app: AppHandle) -> Result<Value, String> {
    let grid = app.state::<Grid>();
    let _admin = grid.admin.lock().await;
    ensure_loaded(&app).await;
    let root = folder(&app);
    let instance = {
        let inner = grid.inner.lock().await;
        let occupied = occupied(&app, inner.slots.keys());
        hub_target(&inner.slots, &occupied)
    };
    let fresh = instance != DEFAULT;
    let mut hub_address = match address(&address_text, port)? {
        HubAddress::Direct(address) => address,
        HubAddress::Tunnel(_) => return Err("--ip is this computer's LAN or VPN address; a tunnel is chosen separately".into()),
    };
    if hub_address.ip().is_loopback() || hub_address.ip().is_unspecified() {
        return Err("Use this computer's LAN or VPN address so company computers can reach the hub".into());
    }
    password::validate(&secret)?;
    let setup = TunnelSetup::parse(tunnel.as_deref());
    let recorded = instances::recorded_ports(&root);
    if fresh && port.is_some_and(|port| instances::FIXED_PORTS.contains(&port)) {
        return Err("Ports 7460 to 7467 belong to Yougori's own grids. Leave the port out and Yougori picks a free one for this grid.".into());
    }
    if fresh && port.is_some_and(|port| recorded.contains(&port)) {
        return Err(format!("Another grid on this computer already uses port {}. Leave the port out and Yougori picks a free one.", hub_address.port()));
    }
    if let Some(TunnelSetup::Domain { domain }) = &setup {
        if instances::tunnel_domains(&root).iter().any(|(_, used)| used.eq_ignore_ascii_case(domain)) {
            return Err(format!("Another grid on this computer already uses the domain {domain} for its tunnel. Choose another saved domain, or a quick link."));
        }
    }
    // A grid after the first takes ports nobody else uses: its own, and a Quick Tunnel's entry.
    let wanted = usize::from(fresh && port.is_none()) + usize::from(fresh && setup == Some(TunnelSetup::Quick));
    let allocated = Allocated(if wanted > 0 { instances::allocate_ports(&root, wanted)? } else { Vec::new() });
    let mut picked = allocated.0.iter().copied();
    if fresh && port.is_none() {
        hub_address.set_port(picked.next().ok_or("No free port was found for the grid")?);
    }
    // A Quick Tunnel can use any free port; a domain's tunnel already routes to its own.
    let tunnel_port = match &setup {
        None => None,
        Some(TunnelSetup::Quick) if fresh => Some(picked.next().ok_or("No free port was found for the grid's tunnel")?),
        Some(setup) => Some(setup.port(&app, hub_address.port(), net::DEFAULT_TUNNEL_PORT)?),
    };
    if let (Some(TunnelSetup::Domain { domain }), Some(route)) = (&setup, tunnel_port) {
        if recorded.contains(&route) {
            return Err(format!("The domain {domain} routes to port {route}, which another grid on this computer uses. Give this grid a domain of its own, or a quick link."));
        }
    }
    let salt = password::new_salt();
    let password_key = derive(secret.clone(), salt.clone()).await?;
    // Claimed before anything is written, so a status read meanwhile does not start this hub too.
    grid.inner.lock().await.slots.entry(instance.clone()).or_default().loaded = true;
    let path = hub_path(&app, &instance);
    let (hub_key, hub_password) = (vault(HUB_KEY, &instance), vault(HUB_PASSWORD, &instance));
    let undo = |app: &AppHandle| {
        let _ = std::fs::remove_file(hub_path(app, &instance));
        let _ = std::fs::remove_file(tunnel_path(app, &instance));
        let _ = secrets::delete_secret(&hub_key);
        let _ = secrets::delete_secret(&hub_password);
    };
    let key = match hub::create(&path, &name, hub_address.ip(), hub_address.port(), hostname.as_deref(), tunnel_port, &salt) {
        Ok(key) => key,
        Err(error) => {
            if fresh {
                drop_if_empty(&app, &mut *grid.inner.lock().await, &instance);
            }
            return Err(error);
        }
    };
    let started: Result<Hub, String> = async {
        secrets::store(&hub_key, &key)?;
        secrets::store(&hub_password, &password_key)?;
        if let Some(setup) = &setup {
            save_tunnel(&app, &instance, setup)?;
        }
        Hub::start(path.clone(), &key, &password_key, events(&instance)).await
    }
    .await;
    let started = match started {
        Ok(hub) => hub,
        Err(error) => {
            undo(&app);
            if fresh {
                drop_if_empty(&app, &mut *grid.inner.lock().await, &instance);
            }
            return Err(error);
        }
    };
    drop(allocated);
    let record = started.record();
    let fingerprint = net::fingerprint(&record.certificate)?;
    let entry = started.tunnel_address().map(|entry| entry.port());
    {
        let mut inner = grid.inner.lock().await;
        let slot = inner.slots.entry(instance.clone()).or_default();
        if let (Some(setup), Some(port)) = (setup.clone(), entry) {
            keep_tunnel(&app, slot, setup, port);
        }
        slot.hub_label = Some((record.id.clone(), record.name.clone()));
        slot.hub = Some(started);
        slot.hub_error = None;
    }
    crate::security::record(event("grid.created", &instance).text("name", &record.name).text("address", &hub_address.to_string()).text("fingerprint", &fingerprint));
    // The admin's computer is a member too, so plans can use its GPU.
    let joined = join_now(&app, Some(&instance), &record.name, HubAddress::Direct(hub_address), &secret, None, Some(&fingerprint)).await;
    // The invite names the tunnel, so wait briefly for it to publish its address.
    let tunnel_note = if setup.is_some() {
        let deadline = Instant::now() + TUNNEL_START;
        loop {
            let (url, error) = {
                let inner = grid.inner.lock().await;
                inner.slots.get(&instance).map(|slot| (slot.tunnel.url(), slot.tunnel.error())).unwrap_or_default()
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
    let several = grid_count(&app).await > 1;
    let mut status = grid_status_in(Some(instance), app).await?;
    let others = if several {
        format!(" This computer now has more than one Neo Grid, so add --grid {} to this grid's commands.", record.id)
    } else {
        String::new()
    };
    status["message"] = json!(match joined {
        Ok(_) => format!(
            "{}'s Closed Neo Grid runs on {hub_address}.{tunnel_note} On each company computer, run `yougori join grid` and paste the invite; share the company password separately. Then choose what runs with {}.{others}",
            record.name,
            with_grid("yougori grid add-plan", &record.id, several)
        ),
        Err(error) => format!("The hub runs on {hub_address}, but this computer could not join it: {error}{others}"),
    });
    Ok(status)
}

pub(crate) async fn grid_password(secret: String, grid_id: Option<String>, app: AppHandle) -> Result<Value, String> {
    let grid = app.state::<Grid>();
    let _admin = grid.admin.lock().await;
    ensure_loaded(&app).await;
    password::validate(&secret)?;
    let instance = resolve(&app, grid_id.as_deref(), Role::Hub, NO_HUB).await?;
    if grid.inner.lock().await.slots.get(&instance).is_none_or(|slot| slot.hub.is_none()) {
        return Err(NO_HUB.into());
    }
    let salt = password::new_salt();
    let password_key = derive(secret, salt.clone()).await?;
    let name = vault(HUB_PASSWORD, &instance);
    let previous = secrets::resolve(&name).ok();
    secrets::store(&name, &password_key)?;
    let changed = match grid.inner.lock().await.slots.get(&instance).and_then(|slot| slot.hub.as_ref()) {
        Some(hub) => hub.set_password(&salt, &password_key),
        None => Err(NO_HUB.into()),
    };
    if let Err(error) = changed {
        if let Some(previous) = previous {
            let _ = secrets::store(&name, &previous);
        }
        return Err(error);
    }
    crate::security::record(event("grid.password.changed", &instance));
    drop(_admin);
    let mut status = grid_status_in(Some(instance), app).await?;
    status["message"] = json!("The company password changed. Computers that already joined stay members.");
    Ok(status)
}

/// Deletes a grid this computer hosts. `later` (the default) pauses it for three days, during
/// which `grid_restore` brings it back; `now` deletes it at once. Either way the hub keeps
/// answering until every computer has heard, so each leaves and removes the model it got.
/// `forget` stops waiting for computers that are still away and removes the hub right now.
pub(crate) async fn grid_delete(when: Option<String>, grid_id: Option<String>, app: AppHandle) -> Result<Value, String> {
    let when = when.as_deref().map(str::trim).filter(|when| !when.is_empty()).unwrap_or("later");
    if when == "forget" {
        return forget_hub(app, grid_id).await;
    }
    let at_once = match when {
        "now" => true,
        "later" => false,
        _ => return Err("--when is later (paused for three days, can be restored), now, or forget".into()),
    };
    ensure_loaded(&app).await;
    let grid = app.state::<Grid>();
    let instance = {
        let inner = grid.inner.lock().await;
        let instance = choose_in(&app, &inner, grid_id.as_deref(), Role::Hub, NO_HUB)?;
        let hub = inner.slots.get(&instance).and_then(|slot| slot.hub.as_ref()).ok_or(NO_HUB)?;
        hub.close(at_once)?;
        instance
    };
    crate::security::record(event("grid.deleting", &instance).flag("atOnce", at_once));
    grid.wake.notify_one();
    let mut status = grid_status_in(Some(instance), app).await?;
    status["message"] = json!(if at_once { "The grid is deleted. Each computer is told when it next checks in; it leaves and removes the model the grid installed." } else { "The grid is paused and will be deleted in three days. Restore it before then to bring everything back." });
    Ok(status)
}

/// Takes back a deletion while the grid is still paused.
pub(crate) async fn grid_restore(grid_id: Option<String>, app: AppHandle) -> Result<Value, String> {
    ensure_loaded(&app).await;
    let grid = app.state::<Grid>();
    let instance = {
        let inner = grid.inner.lock().await;
        let instance = choose_in(&app, &inner, grid_id.as_deref(), Role::Hub, NO_HUB)?;
        inner.slots.get(&instance).and_then(|slot| slot.hub.as_ref()).ok_or(NO_HUB)?.restore()?;
        instance
    };
    crate::security::record(event("grid.restored", &instance));
    grid.wake.notify_one();
    let mut status = grid_status_in(Some(instance), app).await?;
    status["message"] = json!("The grid is restored. Its computers pick up where they were at their next check-in.");
    Ok(status)
}

/// A deleted grid whose computers have all heard, or that waited long enough, goes for good.
async fn finish_deleted_hubs(app: &AppHandle) {
    let finished: Vec<String> = app.state::<Grid>().inner.lock().await.slots.iter().filter(|(_, slot)| slot.hub.as_ref().is_some_and(Hub::finished)).map(|(instance, _)| instance.clone()).collect();
    for instance in finished {
        let _ = forget_hub(app.clone(), Some(instance)).await;
    }
}

/// Removes a hub at once: its settings, keys and tunnel, and this computer's own membership.
async fn forget_hub(app: AppHandle, grid_id: Option<String>) -> Result<Value, String> {
    let grid = app.state::<Grid>();
    let _admin = grid.admin.lock().await;
    ensure_loaded(&app).await;
    let mut guard = grid.inner.lock().await;
    let inner = &mut *guard;
    let instance = choose_in(&app, inner, grid_id.as_deref(), Role::Hub, NO_HUB)?;
    let Some(slot) = inner.slots.get_mut(&instance) else { return Err(NO_HUB.into()) };
    let hub = slot.hub.take();
    if hub.is_none() && !hub_path(&app, &instance).exists() {
        return Err(NO_HUB.into());
    }
    let id = hub.as_ref().map(|hub| hub.record().id).or_else(|| hub::load(&hub_path(&app, &instance)).ok().map(|record| record.id));
    drop(hub);
    stop_tunnel(slot);
    let _ = std::fs::remove_file(tunnel_path(&app, &instance));
    std::fs::remove_file(hub_path(&app, &instance)).map_err(|error| format!("Cannot remove the grid hub's settings: {error}"))?;
    let _ = secrets::delete_secret(&vault(HUB_KEY, &instance));
    let _ = secrets::delete_secret(&vault(HUB_PASSWORD, &instance));
    slot.hub_error = None;
    slot.hub_label = None;
    slot.loaded = true;
    // This computer's own membership ends with the grid.
    let stop = if slot.member.as_ref().is_some_and(|saved| Some(&saved.grid_id) == id.as_ref()) { forget(&app, &instance, slot) } else { None };
    let stop = hand_over(&app, inner, &instance, stop);
    drop_if_empty(&app, inner, &instance);
    drop(guard);
    retire(&app, &instance, stop);
    crate::security::record(event("grid.deleted", &instance));
    Ok(json!({"deleted": true, "gridId": id, "instance": instance}))
}

pub(crate) async fn grid_leave(grid_id: Option<String>, app: AppHandle) -> Result<Value, String> {
    let grid = app.state::<Grid>();
    let _admin = grid.admin.lock().await;
    ensure_loaded(&app).await;
    let (instance, membership, name, left_id, stop) = {
        let mut guard = grid.inner.lock().await;
        let inner = &mut *guard;
        let instance = match choose_in(&app, inner, grid_id.as_deref(), Role::Member, NOT_IN_GRID) {
            Ok(instance) => instance,
            Err(error) => {
                // Asked to leave with no grid to leave: a note about how the last one ended has
                // been read, so it goes.
                if inner.slots.values().all(|slot| slot.member.is_none()) {
                    for slot in inner.slots.values_mut() {
                        slot.member_error = None;
                    }
                }
                return Err(error);
            }
        };
        let Some(slot) = inner.slots.get_mut(&instance) else { return Err(NOT_IN_GRID.into()) };
        let Some((name, left_id)) = slot.member.as_ref().map(|saved| (saved.grid_name.clone(), saved.grid_id.clone())) else {
            slot.member_error = None;
            return Err(NOT_IN_GRID.into());
        };
        let membership = slot.membership.clone();
        let stop = forget(&app, &instance, slot);
        let stop = hand_over(&app, inner, &instance, stop);
        drop_if_empty(&app, inner, &instance);
        (instance, membership, name, left_id, stop)
    };
    retire(&app, &instance, stop);
    // The hub forgets this computer when it can be reached; otherwise the admin can remove it.
    let notified = match membership {
        Some(membership) => membership.leave().await.map_err(|error| error.to_string()),
        None => Err("No membership token".into()),
    };
    crate::security::record(event("grid.left", &instance).text("grid", &name).succeeded(notified.is_ok()));
    Ok(json!({"left": true, "grid": name, "gridId": left_id, "instance": instance, "hubNotified": notified.is_ok(), "warning": notified.err().map(|error| format!("The hub was not told ({error}); the admin can remove this computer with `yougori grid remove`."))}))
}

/// Runs `action` on the hub of the grid `grid_id` names, or of the only one this computer hosts.
pub(crate) async fn with_hub_in<T>(app: &AppHandle, grid_id: Option<&str>, action: impl FnOnce(&Hub) -> Result<T, String>) -> Result<T, String> {
    with_hub_at(app, grid_id, action).await.map(|(_, value)| value)
}

/// `with_hub_in`, with the instance that answered.
async fn with_hub_at<T>(app: &AppHandle, grid_id: Option<&str>, action: impl FnOnce(&Hub) -> Result<T, String>) -> Result<(String, T), String> {
    ensure_loaded(app).await;
    let grid = app.state::<Grid>();
    let inner = grid.inner.lock().await;
    let instance = choose_in(app, &inner, grid_id, Role::Hub, NO_HUB_ADMIN)?;
    let hub = inner.slots.get(&instance).and_then(|slot| slot.hub.as_ref()).ok_or(NO_HUB_ADMIN)?;
    let value = action(hub)?;
    Ok((instance, value))
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
pub(crate) async fn grid_plan_add(model: String, percent: Option<u8>, schedule: Option<String>, idle_after: Option<u32>, quant: Option<String>, scope: Option<String>, computers: Option<Vec<String>>, grid_id: Option<String>, app: AppHandle) -> Result<Value, String> {
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
    // Which grid first: asking several hubs which one is meant comes before checking a model.
    resolve_hub_first(&app, grid_id.as_deref()).await?;
    let warning = check_model(&model, quant.as_deref()).await?;
    let (instance, mut result) = with_hub_at(&app, grid_id.as_deref(), |hub| hub.add_plan(&model, quant.as_deref(), percent, policy, target)).await?;
    crate::security::record(event("grid.plan.added", &instance).text("model", result["plan"]["model"].as_str().unwrap_or_default()).number("percent", u64::from(percent)));
    result["warning"] = json!(warning);
    app.state::<Grid>().wake.notify_one();
    Ok(result)
}

/// Refuses a command for an unclear grid before any slow work is done for it.
async fn resolve_hub_first(app: &AppHandle, grid_id: Option<&str>) -> Result<String, String> {
    ensure_loaded(app).await;
    resolve(app, grid_id, Role::Hub, NO_HUB_ADMIN).await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn grid_plan_update(plan_id: String, model: Option<String>, percent: Option<u8>, schedule: Option<String>, idle_after: Option<u32>, quant: Option<String>, grid_id: Option<String>, app: AppHandle) -> Result<Value, String> {
    resolve_hub_first(&app, grid_id.as_deref()).await?;
    let warning = match &model {
        Some(model) => check_model(model, quant.as_deref().filter(|quant| !quant.is_empty())).await?,
        None => None,
    };
    let change = PlanChange { model, quant, percent, idle_after_minutes: idle_after, schedule };
    let (instance, mut result) = with_hub_at(&app, grid_id.as_deref(), |hub| hub.update_plan(&plan_id, change)).await?;
    crate::security::record(event("grid.plan.changed", &instance).text("plan", &plan_id));
    result["warning"] = json!(warning);
    Ok(result)
}

pub(crate) async fn grid_plan_remove(plan_id: String, grid_id: Option<String>, app: AppHandle) -> Result<Value, String> {
    let (instance, result) = with_hub_at(&app, grid_id.as_deref(), |hub| hub.remove_plan(&plan_id)).await?;
    crate::security::record(event("grid.plan.removed", &instance).text("plan", &plan_id));
    Ok(result)
}

/// Admin: leaves a computer out of the grid's work, or brings it back. Left out, it gets no
/// model and no work, so it drops the model the grid gave it, a download in progress included.
async fn set_excluded(member_id: String, excluded: bool, grid_id: Option<String>, app: AppHandle) -> Result<Value, String> {
    let (instance, result) = with_hub_at(&app, grid_id.as_deref(), |hub| hub.set_excluded(&member_id, excluded)).await?;
    crate::security::record(event(if excluded { "grid.member.excluded" } else { "grid.member.included" }, &instance).text("memberId", &member_id));
    app.state::<Grid>().wake.notify_one();
    Ok(result)
}

pub(crate) async fn grid_member_exclude(member_id: String, grid_id: Option<String>, app: AppHandle) -> Result<Value, String> {
    set_excluded(member_id, true, grid_id, app).await
}

pub(crate) async fn grid_member_include(member_id: String, grid_id: Option<String>, app: AppHandle) -> Result<Value, String> {
    set_excluded(member_id, false, grid_id, app).await
}

pub(crate) async fn grid_member_remove(member_id: String, grid_id: Option<String>, app: AppHandle) -> Result<Value, String> {
    let (instance, result) = with_hub_at(&app, grid_id.as_deref(), |hub| hub.remove_member(&member_id)).await?;
    crate::security::record(event("grid.member.removed", &instance).text("memberId", &member_id));
    Ok(result)
}

pub(crate) async fn grid_key_create(name: String, grid_id: Option<String>, app: AppHandle) -> Result<Value, String> {
    let (instance, (mut result, url, certificate)) = with_hub_at(&app, grid_id.as_deref(), |hub| {
        let status = hub.status();
        Ok((hub.create_key(&name)?, status["url"].clone(), status["certificate"].clone()))
    })
    .await?;
    crate::security::record(event("grid.key.created", &instance).text("keyId", result["key"]["id"].as_str().unwrap_or_default()));
    result["baseUrl"] = url;
    result["certificate"] = certificate;
    result["message"] = json!("Shown once. Apps trust the certificate (save it as grid.pem) and call baseUrl with this key.");
    Ok(result)
}

pub(crate) async fn grid_key_revoke(key_id: String, grid_id: Option<String>, app: AppHandle) -> Result<Value, String> {
    let (instance, result) = with_hub_at(&app, grid_id.as_deref(), |hub| hub.revoke_key(&key_id)).await?;
    crate::security::record(event("grid.key.revoked", &instance).text("keyId", &key_id));
    Ok(result)
}

/// Admin: a team of models that apps call as the model `swarm/NAME`. `tasks` defaults to
/// `computers`, so each computer gets one task (plan) or gives one answer (mixture).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn grid_swarm_add(name: String, strategy: Option<String>, lead: String, workers: Vec<String>, computers: u8, tasks: Option<u8>, rounds: Option<u8>, grid_id: Option<String>, app: AppHandle) -> Result<Value, String> {
    let strategy = match strategy.as_deref().map(str::trim) {
        None | Some("" | "plan") => Strategy::Plan,
        Some("mixture") => Strategy::Mixture,
        Some(_) => return Err("strategy must be plan or mixture".into()),
    };
    let harness = Harness::new(&name, strategy, &lead, &workers, computers, tasks.unwrap_or(computers), rounds.unwrap_or(1))?;
    let (instance, result) = with_hub_at(&app, grid_id.as_deref(), |hub| hub.add_harness(harness)).await?;
    crate::security::record(event("grid.swarm.added", &instance).text("model", result["model"].as_str().unwrap_or_default()).number("computers", u64::from(computers)));
    Ok(result)
}

pub(crate) async fn grid_swarm_remove(harness_id: String, grid_id: Option<String>, app: AppHandle) -> Result<Value, String> {
    let (instance, result) = with_hub_at(&app, grid_id.as_deref(), |hub| hub.remove_harness(&harness_id)).await?;
    crate::security::record(event("grid.swarm.removed", &instance).text("model", result["model"].as_str().unwrap_or_default()));
    Ok(result)
}

/// Admin: runs a harness once on `prompt`; the answer comes with which computer did each part.
pub(crate) async fn grid_swarm_run(harness: String, prompt: String, grid_id: Option<String>, app: AppHandle) -> Result<Value, String> {
    if prompt.trim().is_empty() {
        return Err("Give the prompt to run".into());
    }
    // The run can take minutes, so it must not hold the grid's lock.
    let swarm = with_hub_in(&app, grid_id.as_deref(), |hub| Ok(hub.swarm())).await?;
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
/// `grid_id` is optional everywhere: with one grid on this computer nothing changes.
pub(crate) mod commands {
    use super::*;
    use crate::WebviewWindow;

    fn main_window(window: &WebviewWindow) -> Result<(), String> {
        if window.label() == "main" { Ok(()) } else { Err("Closed Neo Grid is managed from the main Yougori window".into()) }
    }

    #[tauri::command]
    pub async fn grid_status(app: AppHandle, window: WebviewWindow, grid_id: Option<String>) -> Result<Value, String> {
        main_window(&window)?;
        super::grid_status_in(grid_id, app).await
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
    pub async fn grid_leave(app: AppHandle, window: WebviewWindow, grid_id: Option<String>) -> Result<Value, String> {
        main_window(&window)?;
        super::grid_leave(grid_id, app).await
    }

    #[tauri::command]
    pub async fn grid_delete(app: AppHandle, window: WebviewWindow, when: Option<String>, grid_id: Option<String>) -> Result<Value, String> {
        main_window(&window)?;
        super::grid_delete(when, grid_id, app).await
    }

    #[tauri::command]
    pub async fn grid_restore(app: AppHandle, window: WebviewWindow, grid_id: Option<String>) -> Result<Value, String> {
        main_window(&window)?;
        super::grid_restore(grid_id, app).await
    }

    /// `computers` picks computers by ID; otherwise `percent` of `scope` (`all` or `remaining`).
    /// `schedule` and `idle_after` say when it serves, checked by `IdlePolicy::new` exactly as the
    /// command line's `--schedule` and `--idle-after` are; left out, it serves at any time after
    /// the hub's default wait.
    #[tauri::command]
    #[allow(clippy::too_many_arguments)]
    pub async fn grid_plan_add(app: AppHandle, window: WebviewWindow, model: String, percent: Option<u8>, quant: Option<String>, scope: Option<String>, computers: Option<Vec<String>>, schedule: Option<String>, idle_after: Option<u32>, grid_id: Option<String>) -> Result<Value, String> {
        main_window(&window)?;
        super::grid_plan_add(model, percent, schedule, idle_after, quant, scope, computers, grid_id, app).await
    }

    #[tauri::command]
    pub async fn grid_plan_remove(app: AppHandle, window: WebviewWindow, plan_id: String, grid_id: Option<String>) -> Result<Value, String> {
        main_window(&window)?;
        super::grid_plan_remove(plan_id, grid_id, app).await
    }

    #[tauri::command]
    pub async fn grid_member_remove(app: AppHandle, window: WebviewWindow, member_id: String, grid_id: Option<String>) -> Result<Value, String> {
        main_window(&window)?;
        super::grid_member_remove(member_id, grid_id, app).await
    }

    #[tauri::command]
    pub async fn grid_member_exclude(app: AppHandle, window: WebviewWindow, member_id: String, grid_id: Option<String>) -> Result<Value, String> {
        main_window(&window)?;
        super::grid_member_exclude(member_id, grid_id, app).await
    }

    #[tauri::command]
    pub async fn grid_member_include(app: AppHandle, window: WebviewWindow, member_id: String, grid_id: Option<String>) -> Result<Value, String> {
        main_window(&window)?;
        super::grid_member_include(member_id, grid_id, app).await
    }

    #[tauri::command]
    #[allow(clippy::too_many_arguments)]
    pub async fn grid_swarm_add(app: AppHandle, window: WebviewWindow, name: String, strategy: Option<String>, lead: String, workers: Vec<String>, computers: u8, tasks: Option<u8>, rounds: Option<u8>, grid_id: Option<String>) -> Result<Value, String> {
        main_window(&window)?;
        super::grid_swarm_add(name, strategy, lead, workers, computers, tasks, rounds, grid_id, app).await
    }

    #[tauri::command]
    pub async fn grid_swarm_remove(app: AppHandle, window: WebviewWindow, harness_id: String, grid_id: Option<String>) -> Result<Value, String> {
        main_window(&window)?;
        super::grid_swarm_remove(harness_id, grid_id, app).await
    }

    #[tauri::command]
    pub async fn grid_swarm_run(app: AppHandle, window: WebviewWindow, harness: String, prompt: String, grid_id: Option<String>) -> Result<Value, String> {
        main_window(&window)?;
        super::grid_swarm_run(harness, prompt, grid_id, app).await
    }
}

#[cfg(test)]
mod membership_tests {
    use super::*;

    #[test]
    fn leaving_a_grid_takes_the_last_connection_error_with_it() {
        let mut slot = Slot { connected: true, member_error: Some("Cannot reach the grid hub through https://old.trycloudflare.com".into()), reported_state: Some("available".into()), ..Slot::default() };
        slot.clear_membership();
        // Status shows member_error once the membership is gone, so a stale one would look
        // like the computer still cannot reach a hub it has left.
        assert_eq!(slot.member_error, None);
        assert!(!slot.connected && slot.reported_state.is_none() && slot.membership.is_none());
    }

    #[test]
    fn being_removed_by_the_admin_still_says_so() {
        let mut slot = Slot { member_error: Some("something older".into()), ..Slot::default() };
        slot.clear_membership();
        // The removal path sets its message after forgetting, so it survives.
        slot.member_error = Some(MemberError::Removed.to_string());
        assert!(slot.member_error.as_deref().is_some_and(|error| !error.is_empty()));
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
mod instance_tests;

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
