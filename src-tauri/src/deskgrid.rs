//! The Sandbox Grid: a company's own hub for desks, separate from its Closed Neo Grid. One
//! computer runs the desk hub; company computers join it with the sandbox-grid password and
//! report what they have and are using; the admin sets what the grid may take from each, orders
//! desks for people on it (`desks`), and people sign in to open theirs. It has its own record, keys, port and invite (`desk-invite:`), so joining one grid never
//! makes a computer part of the other. Under the hood it is the same hub technology.
//!
//! A computer can hold several Sandbox Grids at once: host one, belong to another, have its
//! person signed in to a third. Each lives in an instance (`desks::instances`), with its own
//! files, vault entries, ports and state here; `default` is the one that existed before, kept
//! exactly where it was. Every command takes an optional `gridId`, and without one acts on the
//! only grid that can answer it, refusing in words when there are several.
use crate::{desks::instances::{self, Joining, Role, Seen, DEFAULT}, hub_tunnel::{self, TunnelSetup, TunnelState}, projects::secrets, security::Event, store::PlatformStore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tauri::Manager;
use crate::{AppHandle, WebviewWindow};
use yougori_grid::{
    activity::Activity,
    desks::{DeskOrder, Share},
    hub::{self, Hub},
    invite::{self, Invite},
    member::{self, MemberError, Membership},
    net::{self, HubAddress},
    password,
};

const HUB_KEY: &str = "yougori-desks-hub-key";
const HUB_PASSWORD: &str = "yougori-desks-hub-password";
const MEMBER_TOKEN: &str = "yougori-desks-member-token";
/// The parking bucket's credentials, on the hub computer only: `{provider, location, accessKey, secretKey}`.
const PARKING: &str = "yougori-desks-parking";
/// A connector's secret, by connection id: `yougori-desks-connection-<id>` holds `{clientSecret}` or `{password}`.
const CONNECTION: &str = "yougori-desks-connection-";
/// The desk hub's port, beside a Closed Neo Grid (7460/7461) and a closed bounty (7462); its
/// Quick Tunnel forwards to the next one. These are the `default` instance's; every other
/// instance is given ports of its own when its hub is made, and keeps them in its hub record.
pub(crate) const PORT: u16 = 7463;
const TUNNEL_PORT: u16 = 7464;
/// Waiting for a new grid's tunnel to publish its address before answering without it.
const TUNNEL_START: Duration = Duration::from_secs(60);
const TICK: Duration = Duration::from_secs(5);
const REPORT: Duration = Duration::from_secs(30);
const CAPABILITY: Duration = Duration::from_secs(30 * 60);

#[derive(Default)]
pub struct DeskGrid {
    /// Every Sandbox Grid on this computer, by instance. Each has its own lock, so one grid's slow
    /// answer never holds up another's.
    slots: std::sync::Mutex<BTreeMap<String, Arc<Slot>>>,
    /// Serializes creating, joining, leaving and deleting, across every instance.
    admin: tokio::sync::Mutex<()>,
    wake: tokio::sync::Notify,
}

#[derive(Default)]
struct Slot {
    inner: tokio::sync::Mutex<Inner>,
}

impl DeskGrid {
    /// Runs the next tick now, for example when a desk finished building.
    pub(crate) fn wake(&self) {
        self.wake.notify_one();
    }

    /// One instance's state, made empty the first time it is asked for.
    fn slot(&self, instance: &str) -> Arc<Slot> {
        let mut slots = self.slots.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        slots.entry(instance.to_owned()).or_default().clone()
    }

    /// Every instance this engine has state for, `default` first and always.
    fn known(&self) -> Vec<String> {
        let mut known: Vec<String> = self.slots.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).keys().cloned().collect();
        if !known.iter().any(|instance| instance == DEFAULT) {
            known.insert(0, DEFAULT.to_owned());
        }
        known.sort_by_key(|instance| instance != DEFAULT);
        known
    }
}

use crate::projects::secrets::MemberLoad;

#[derive(Default)]
struct Inner {
    loaded: bool,
    /// Kept apart from `loaded` so a membership that could not be read yet is read again without
    /// starting the hub a second time.
    member_loaded: bool,
    hub: Option<Hub>,
    hub_error: Option<String>,
    tunnel: TunnelState,
    member: Option<Saved>,
    membership: Option<Membership>,
    member_error: Option<String>,
    connected: bool,
    /// The hub answered in words this build could not read. Kept apart from `connected` because
    /// no desk order will ever arrive while it lasts, so anything waiting for one should stop.
    unreadable: bool,
    reported: Option<Instant>,
    /// The last desk reports sent, so a change checks in at once.
    reported_desks: String,
    /// The hub's current desk orders for this computer.
    orders: Vec<DeskOrder>,
    orders_received: bool,
    /// Bucket credentials the hub sent for a desk being packed or unpacked right now.
    parking: Option<Value>,
    activity: Option<(Activity, Instant)>,
    /// Whether this computer can run GPU work, refreshed every 30 minutes.
    capable: Option<(bool, String)>,
    capable_at: Option<Instant>,
}

/// This computer's place in a sandbox grid, saved on disk; its token is in the OS vault.
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
    /// The admin scheduled the grid for deletion at this time: until then the desks here are
    /// stopped and unshared but kept, so a restore brings them back. Saved so a restart keeps it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    paused_until: Option<i64>,
    /// The hub has not answered since this time. A hub that is gone for good never says so, so
    /// after a while this computer's person is asked whether to leave.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    unreachable_since: Option<i64>,
}

fn grid_folder(app: &AppHandle) -> PathBuf {
    app.state::<PlatformStore>().data_folder("grid")
}

fn folder(app: &AppHandle, instance: &str) -> PathBuf {
    instances::folder(&grid_folder(app), instance)
}

fn hub_path(app: &AppHandle, instance: &str) -> PathBuf {
    folder(app, instance).join(instances::HUB)
}

fn member_path(app: &AppHandle, instance: &str) -> PathBuf {
    folder(app, instance).join(instances::MEMBER)
}

fn tunnel_path(app: &AppHandle, instance: &str) -> PathBuf {
    folder(app, instance).join(instances::TUNNEL)
}

/// An instance's name for one of its OS vault entries.
fn vault(base: &str, instance: &str) -> String {
    instances::vault_name(base, instance)
}

/// How the desks of the grid `grid_id` are tagged on this computer: `None` for `default`, whose
/// desks keep the description they always had.
pub(crate) fn desk_tag_of(instance: &str, grid_id: Option<&str>) -> Option<String> {
    if instance == DEFAULT { None } else { grid_id.map(str::to_owned) }
}

/// The grid an instance's membership file names, read without starting anything.
pub(crate) fn member_grid_id(app: &AppHandle, instance: &str) -> Option<String> {
    let bytes = std::fs::read(member_path(app, instance)).ok()?;
    serde_json::from_slice::<Saved>(&bytes).ok().map(|saved| saved.grid_id)
}

fn events(instance: &str) -> hub::Events {
    let instance = instance.to_owned();
    Arc::new(move |kind: &'static str, detail: Value| crate::security::record(Event::new(kind).text("instance", &instance).object("detail", detail)))
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

async fn derive(secret: String, salt: String) -> Result<String, String> {
    tokio::task::spawn_blocking(move || password::derive(&secret, &salt)).await.map_err(|error| error.to_string())?
}

async fn ensure_loaded(app: &AppHandle, instance: &str) {
    let slot = app.state::<DeskGrid>().slot(instance);
    let mut inner = slot.inner.lock().await;
    if inner.loaded && inner.member_loaded {
        return;
    }
    // The hub starts once. Only the membership below is read again, so a credential vault that
    // was not ready yet cannot start a second hub on the retry.
    if !inner.loaded {
        inner.loaded = true;
        let path = hub_path(app, instance);
        if path.exists() {
            match secrets::hub_keys(secrets::look_up(&vault(HUB_KEY, instance)), secrets::look_up(&vault(HUB_PASSWORD, instance))) {
                secrets::Keys::Ready(key, password_key) => match Hub::start(path, &key, &password_key, events(instance)).await {
                    Ok(hub) => {
                        if let (Some(port), Some(setup)) = (hub.tunnel_address().map(|entry| entry.port()), hub_tunnel::load(&tunnel_path(app, instance))) {
                            hub_tunnel::keep(app, &mut inner.tunnel, setup, port);
                        }
                        hub.set_parking(secrets::resolve(&vault(PARKING, instance)).ok().and_then(|saved| serde_json::from_str(&saved).ok()));
                        for id in hub.connections_with_credentials() {
                            hub.set_connection_credential(&id, secrets::resolve(&vault(&format!("{CONNECTION}{id}"), instance)).ok().and_then(|saved| serde_json::from_str(&saved).ok()));
                        }
                        inner.hub = Some(hub);
                    }
                    Err(error) => inner.hub_error = Some(error),
                },
                secrets::Keys::Gone => inner.hub_error = Some("The sandbox grid's keys are missing from the OS credential vault; delete it and create it again".into()),
                // The vault would not answer. Nothing is decided, so say nothing destructive and
                // let the next call look again rather than latching this for the rest of the run.
                secrets::Keys::NotYet => {
                    inner.hub_error = Some("The sandbox grid's keys could not be read from the OS credential vault yet, so it has not started. Yougori keeps trying; nothing is changed meanwhile.".into());
                    inner.loaded = false;
                }
            }
        }
    }
    if !inner.member_loaded {
        // Not readable is not absent. Reading this wrong says "join again with the password", and
        // joining again orphans every desk this computer hosts, so only "it is not there" is taken
        // as an answer; anything else is looked at again.
        let outcome = match std::fs::read(member_path(app, instance)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => MemberLoad::Absent,
            Err(_) => MemberLoad::NotYet,
            Ok(bytes) => match serde_json::from_slice::<Saved>(&bytes) {
                Err(_) => MemberLoad::Damaged,
                // The OS credential vault is routinely not ready yet when the computer starts
                // Yougori for itself. That is this computer failing to look, not a lost membership.
                Ok(saved) => match secrets::resolve(&vault(MEMBER_TOKEN, instance)) {
                    Err(_) => MemberLoad::NotYet,
                    Ok(token) => match HubAddress::parse(&saved.address)
                        .and_then(|address| Membership::new(address, &saved.certificate, saved.member_id.clone(), token))
                    {
                        Ok(membership) => {
                            inner.membership = Some(membership);
                            inner.member = Some(saved);
                            MemberLoad::Loaded
                        }
                        Err(_) => MemberLoad::Incomplete,
                    },
                },
            },
        };
        inner.member_error = outcome.message("sandbox grid membership", "password");
        inner.member_loaded = outcome.settled();
    }
}

/// Every instance found on disk, loaded: the old layout's `default` and each `grid/desks/i-…`.
async fn load_all(app: &AppHandle) {
    let grid = app.state::<DeskGrid>();
    for instance in instances::on_disk(&grid_folder(app)).into_iter().chain(grid.known()) {
        ensure_loaded(app, &instance).await;
    }
}

/// What every instance holds, for choosing which one a command is about.
pub(crate) async fn census(app: &AppHandle) -> Vec<Seen> {
    load_all(app).await;
    let grid = app.state::<DeskGrid>();
    let mut seen = Vec::new();
    for instance in grid.known() {
        let slot = grid.slot(&instance);
        let (hub, member) = {
            let inner = slot.inner.lock().await;
            let record = inner.hub.as_ref().map(Hub::record).or_else(|| hub_path(app, &instance).exists().then(|| hub::load(&hub_path(app, &instance)).ok()).flatten());
            let hub = match record {
                Some(record) => Some(instances::Grid { fingerprint: net::fingerprint(&record.certificate).ok().and_then(|found| net::normalize_fingerprint(&found)), id: record.id, name: record.name }),
                // Settings that are there but could not be read are still a hub here: deleting it
                // with `--when forget` has to be able to find it.
                None if hub_path(app, &instance).exists() => Some(instances::Grid::default()),
                None => None,
            };
            let member = inner.member.as_ref().map(|saved| instances::Grid { id: saved.grid_id.clone(), name: saved.grid_name.clone(), fingerprint: net::normalize_fingerprint(&saved.fingerprint) });
            (hub, member)
        };
        let login = crate::desks::login_grid(app, &instance).await.map(|(id, name)| instances::Grid { id, name, fingerprint: None });
        seen.push(Seen { instance, hub, member, login });
    }
    seen
}

/// The instance a command acts on: the one `grid_id` names, or the only one holding any of
/// `roles`; `default` when none does, so the command answers as it always has.
pub(crate) async fn pick(app: &AppHandle, grid_id: Option<&str>, roles: &[Role]) -> Result<String, String> {
    let seen = census(app).await;
    instances::choose(&seen, grid_id, roles)
}

/// Forgets this computer's membership.
fn forget(app: &AppHandle, instance: &str, inner: &mut Inner) {
    inner.membership = None;
    inner.member = None;
    inner.connected = false;
    inner.reported = None;
    inner.reported_desks.clear();
    inner.orders.clear();
    inner.orders_received = false;
    inner.member_error = None;
    let _ = std::fs::remove_file(member_path(app, instance));
    let _ = secrets::delete_secret(&vault(MEMBER_TOKEN, instance));
}

/// The hub's status with its tunnel and the invite company computers join with: the tunnel's
/// address when the grid has one, else the hub's LAN address.
fn hub_view(hub: &Hub, tunnel: &TunnelState) -> Value {
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
        status["invite"] = json!(invite::encode_desk(&Invite { company: record.name.clone(), address, fingerprint }));
    }
    status
}

/// Runs `action` with the hub of the grid `grid_id` names, or the only hub on this computer.
pub(crate) async fn with_hub<T>(app: &AppHandle, grid_id: Option<&str>, action: impl FnOnce(&Hub) -> Result<T, String>) -> Result<T, String> {
    let instance = pick(app, grid_id, &[Role::Hub]).await?;
    with_hub_in(app, &instance, action).await
}

/// The same, with the instance already known.
pub(crate) async fn with_hub_in<T>(app: &AppHandle, instance: &str, action: impl FnOnce(&Hub) -> Result<T, String>) -> Result<T, String> {
    ensure_loaded(app, instance).await;
    let slot = app.state::<DeskGrid>().slot(instance);
    let inner = slot.inner.lock().await;
    let hub = inner.hub.as_ref().ok_or("This computer does not run a sandbox grid. Admins create one with `yougori desks create`.")?;
    action(hub)
}

/// One check-in: builds and shares the desks the hub ordered, then reports them and what this
/// computer can host; the hub answers with the current orders.
async fn tick(app: &AppHandle, instance: &str) {
    let grid = app.state::<DeskGrid>();
    let slot = grid.slot(instance);
    let (membership, saved, orders, refresh) = {
        let inner = slot.inner.lock().await;
        let (Some(membership), Some(saved)) = (inner.membership.clone(), inner.member.clone()) else { return };
        (membership, saved, inner.orders.clone(), inner.capable_at.is_none_or(|at| at.elapsed() >= CAPABILITY))
    };
    let tag = desk_tag_of(instance, Some(&saved.grid_id));
    if refresh {
        let found = crate::grid::capability(app).await;
        let mut inner = slot.inner.lock().await;
        inner.capable = Some(found);
        inner.capable_at = Some(Instant::now());
    }
    // Reading activity runs system commands on Linux and macOS: every 15 s is enough.
    let activity = {
        let cached = slot.inner.lock().await.activity.clone();
        match cached {
            Some((activity, at)) if at.elapsed() < Duration::from_secs(15) => activity,
            _ => {
                let activity = tokio::task::spawn_blocking(yougori_grid::activity::current).await.unwrap_or_else(|_| Activity::Unknown("User activity could not be read".into()));
                slot.inner.lock().await.activity = Some((activity.clone(), Instant::now()));
                activity
            }
        }
    };
    let orders_received = slot.inner.lock().await.orders_received;
    let parking = slot.inner.lock().await.parking.clone();
    let reports = if saved.paused_until.is_some() {
        // Paused for deletion: stop and unshare the desks here, keeping them and their data.
        crate::desks::pause(app, instance).await;
        Vec::new()
    } else if orders_received {
        let reports = crate::desks::reconcile(app, instance, &orders, &membership, &saved.grid_id, parking.as_ref()).await;
        // Desks shared here can also be opened from another network, through the hub.
        crate::desks::keep_desk_relays(app, instance, &membership).await;
        reports
    } else {
        Vec::new()
    };
    let summary = serde_json::to_string(&reports.iter().map(|report| (&report.id, &report.state, report.invitation.is_some())).collect::<Vec<_>>()).unwrap_or_default();
    let (due, gpu) = {
        let inner = slot.inner.lock().await;
        (inner.reported.is_none_or(|at| at.elapsed() >= REPORT) || inner.reported_desks != summary, inner.capable.as_ref().is_some_and(|(capable, _)| *capable))
    };
    if !due {
        return;
    }
    let capacity = crate::desks::capacity(app, &activity, gpu);
    let answer = membership.check_in(env!("CARGO_PKG_VERSION"), gpu, &[], Some(&capacity), &reports).await;
    let mut inner = slot.inner.lock().await;
    // Membership changed while the check-in was in flight.
    if inner.member.as_ref().is_none_or(|current| current.member_id != saved.member_id) {
        return;
    }
    inner.reported = Some(Instant::now());
    match answer {
        Ok(instructions) => {
            inner.orders_received = true;
            inner.connected = true;
            inner.member_error = None;
            // An answer this build could read: whatever was wrong before, it is not now.
            inner.unreadable = false;
            if let Some(current) = inner.member.as_mut().filter(|current| current.unreachable_since.is_some()) {
                current.unreachable_since = None;
                let _ = persist(app, instance, current);
            }
            inner.reported_desks = summary;
            if inner.orders != instructions.desks {
                inner.orders = instructions.desks;
                grid.wake.notify_one();
            }
            inner.parking = instructions.parking;
            if let Some(current) = inner.member.as_mut().filter(|current| current.paused_until != instructions.paused_until) {
                crate::security::record(Event::new(if instructions.paused_until.is_some() { "desks.paused" } else { "desks.resumed" }).text("instance", instance).text("grid", &current.grid_name));
                current.paused_until = instructions.paused_until;
                let _ = persist(app, instance, current);
                grid.wake.notify_one();
            }
        }
        Err(MemberError::Deleted) => {
            // The admin deleted the grid: leave it, and delete the desks it put here with their data.
            crate::security::record(Event::new("desks.deleted.left").text("instance", instance).text("grid", &saved.grid_name));
            forget(app, instance, &mut inner);
            inner.member_error = Some(format!("{} deleted this sandbox grid. This computer left it and deleted the desks it hosted.", saved.grid_name));
            drop(inner);
            crate::desks::stop_hosting(app, instance, tag.as_deref(), true).await;
        }
        Err(MemberError::Removed) => {
            crate::security::record(Event::new("desks.removed").text("instance", instance).text("grid", &saved.grid_name));
            forget(app, instance, &mut inner);
            inner.member_error = Some("The sandbox grid's admin removed this computer; join again with the password".into());
            drop(inner);
            crate::desks::stop_hosting(app, instance, tag.as_deref(), false).await;
        }
        // Answered, but in words this build cannot read. The hub is not silent, so the clock
        // that ends in "the hub is gone, leave the grid" must not start: following that advice
        // would unshare every desk on this computer over a hub that is working perfectly.
        Err(MemberError::Unreadable(error)) => {
            inner.connected = false;
            inner.member_error = Some(error);
            inner.unreadable = true;
            // The hub answered, so a clock an earlier failed check-in started stops here as
            // surely as a readable answer stops it. Without this, one restart for a hub upgrade
            // followed by answers this build cannot read still ends in "leave the grid".
            if let Some(current) = inner.member.as_mut().filter(|current| current.unreachable_since.is_some()) {
                current.unreachable_since = member::silence_clock(true, current.unreachable_since, yougori_grid::now());
                let _ = persist(app, instance, current);
            }
        }
        Err(MemberError::Failed(error)) => {
            inner.connected = false;
            inner.member_error = Some(error);
            if let Some(current) = inner.member.as_mut().filter(|current| current.unreachable_since.is_none()) {
                current.unreachable_since = member::silence_clock(false, current.unreachable_since, yougori_grid::now());
                let _ = persist(app, instance, current);
            }
        }
    }
}

/// One pass of the loop for one instance: its check-in, a deletion that has finished, its cloud
/// computers and its connectors' work.
async fn pass(app: &AppHandle, instance: &str) {
    ensure_loaded(app, instance).await;
    tick(app, instance).await;
    finish_deleted_hub(app, instance).await;
    crate::desks::cloud::tick(app, instance).await;
    provisioning_tick(app, instance).await;
}

/// Keeps this computer's desks in line with the hub's orders while the engine runs, for every
/// Sandbox Grid on it. The instances run side by side, so one grid's hub that is slow to answer
/// never holds up another's check-in.
pub(crate) fn start(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let shutdown = crate::automation::shutdown_signal(&app);
        load_all(&app).await;
        loop {
            let grid = app.state::<DeskGrid>();
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = grid.wake.notified() => {}
                _ = tokio::time::sleep(TICK) => {}
            }
            let passes: Vec<_> = grid
                .known()
                .into_iter()
                .map(|instance| {
                    let app = app.clone();
                    tauri::async_runtime::spawn(async move { pass(&app, &instance).await })
                })
                .collect();
            for each in passes {
                let _ = each.await;
            }
        }
        hand_off_before_closing(&app).await;
        let grid = app.state::<DeskGrid>();
        for instance in grid.known() {
            if let Some(hub) = grid.slot(&instance).inner.lock().await.hub.take() {
                hub.flush();
            }
        }
    });
}

/// On the hub computer: whatever the admin asked connectors to do runs here, with the secrets
/// from this computer's vault, and the outcome goes back to the record for the admin to read.
async fn provisioning_tick(app: &AppHandle, instance: &str) {
    let slot = app.state::<DeskGrid>().slot(instance);
    let due = {
        let inner = slot.inner.lock().await;
        let Some(hub) = inner.hub.as_ref().filter(|hub| hub.phase() == hub::Phase::Open) else { return };
        hub.provisioning_due()
    };
    if due.is_empty() {
        return;
    }
    let instance = instance.to_owned();
    tauri::async_runtime::spawn(async move {
        for (id, task) in due {
            let want = task.want.name();
            let outcome = yougori_grid::provisioning::run(&task).await;
            crate::security::record(Event::new("desks.connection.task").text("instance", &instance).text("taskId", &id).text("want", want).text("email", &task.email).outcome(&outcome.as_ref().map(|_| ()).map_err(Clone::clone)));
            let inner = slot.inner.lock().await;
            if let Some(hub) = &inner.hub {
                hub.provisioning_report(&id, outcome);
            }
        }
    });
}

/// Yougori is closing on a computer that hosts desks: it tells each hub so the desks move, and
/// keeps checking in while their data is copied, so nobody's desk is left stranded on a computer
/// that is going away. It waits only as long as `MOVE_WAIT`; a desk still here keeps its data and
/// comes back when this computer does.
async fn hand_off_before_closing(app: &AppHandle) {
    let grid = app.state::<DeskGrid>();
    let mut hosting = Vec::new();
    for instance in grid.known() {
        let member_only = {
            let slot = grid.slot(&instance);
            let inner = slot.inner.lock().await;
            inner.member.is_some() && inner.hub.is_none()
        };
        if member_only && crate::desks::hosts_anything(app, &instance).await {
            hosting.push(instance);
        }
    }
    if hosting.is_empty() {
        return;
    }
    app.state::<crate::desks::DeskHost>().closing.store(true, std::sync::atomic::Ordering::Relaxed);
    crate::security::record(Event::new("desks.closing").text("instance", &hosting.join(",")).text("wait", &format!("{}s", yougori_grid::power::MOVE_WAIT.as_secs())));
    let deadline = Instant::now() + yougori_grid::power::MOVE_WAIT;
    let mut waiting = hosting.clone();
    while Instant::now() < deadline && !waiting.is_empty() {
        let mut still = Vec::new();
        for instance in waiting {
            let slot = grid.slot(&instance);
            // A fresh check-in each time: the hub hands the desks on and this computer packs them.
            slot.inner.lock().await.reported = None;
            tick(app, &instance).await;
            if !crate::desks::moving_anything(app, &instance).await && crate::desks::hosts_anything(app, &instance).await == crate::desks::parked_everything(app, &instance).await {
                continue;
            }
            // Nothing will be packed if the hub's answers cannot be read: no orders arrive, so no
            // desk is ever asked to move. Waiting the full fifteen minutes for that holds the
            // computer open for a quarter of an hour on something that has already been decided.
            if slot.inner.lock().await.unreadable {
                crate::security::record(Event::new("desks.closing_stopped").text("instance", &instance).text("reason", "This computer could not read the hub's answers, so no desk could be handed on"));
                continue;
            }
            still.push(instance);
        }
        waiting = still;
        if waiting.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    let mut handed_on = true;
    for instance in &hosting {
        handed_on &= !crate::desks::moving_anything(app, instance).await;
    }
    crate::security::record(Event::new("desks.closed").text("instance", &hosting.join(",")).flag("handedOn", handed_on));
}

/// What one instance shows in the status.
#[derive(Default)]
struct View {
    instance: String,
    hub: Option<Value>,
    hub_error: Option<String>,
    member: Option<Value>,
    member_error: Option<String>,
    hosting: Value,
    login: Value,
    cloud: Value,
    leftovers: Vec<String>,
}

impl View {
    fn holds_hub(&self) -> bool {
        self.hub.is_some() || self.hub_error.is_some()
    }
    fn holds_member(&self) -> bool {
        self.member.is_some() || self.member_error.is_some()
    }
    fn holds_login(&self) -> bool {
        !self.login.is_null()
    }
    fn hosts(&self) -> bool {
        self.hosting.as_array().is_some_and(|hosting| !hosting.is_empty())
    }
}

async fn view(app: &AppHandle, instance: &str) -> View {
    let slot = app.state::<DeskGrid>().slot(instance);
    let (hub, hub_error, member, member_error) = {
        let inner = slot.inner.lock().await;
        let member = inner.member.as_ref().map(|saved| {
            json!({
                "gridId": saved.grid_id, "grid": saved.grid_name, "hub": saved.address, "fingerprint": saved.fingerprint,
                "memberId": saved.member_id, "joinedAt": saved.joined_at, "connected": inner.connected, "error": inner.member_error, "pausedUntil": saved.paused_until,
                "unreachableSince": saved.unreachable_since,
                "orders": inner.orders.len(),
                "instance": instance,
            })
        });
        let hub = inner.hub.as_ref().map(|hub| {
            let mut shown = hub_view(hub, &inner.tunnel);
            shown["instance"] = json!(instance);
            shown["gridId"] = json!(hub.record().id);
            shown
        });
        let member_error = if inner.member.is_none() { inner.member_error.clone() } else { None };
        (hub, inner.hub_error.clone(), member, member_error)
    };
    let mut login = crate::desks::desk_status(app, instance).await;
    if login.is_object() {
        login["instance"] = json!(instance);
    }
    View {
        instance: instance.to_owned(),
        hub,
        hub_error,
        member,
        member_error,
        hosting: crate::desks::hosting_status(app, instance).await,
        login,
        cloud: crate::desks::cloud::status(app, instance),
        leftovers: crate::desks::bucket_leftovers(instance),
    }
}

/// The status in the shape it has always had, plus every instance.
///
/// `hub`, `member` and `desk` each describe one instance: the one `focus` names, else `default`
/// when it holds one, else the first that does. That is what a reader written for one grid per
/// computer reads, unchanged. `hubs`, `members` and `logins` list every instance's, each entry
/// carrying its `instance` and `gridId`; `errors` lists what any instance could not do.
fn assemble(views: &[View], focus: Option<&str>) -> Value {
    fn chosen<'a>(views: &'a [View], focus: Option<&str>, holds: fn(&View) -> bool) -> Option<&'a View> {
        if let Some(focus) = focus {
            return views.iter().find(|view| view.instance == focus);
        }
        views.iter().find(|view| view.instance == DEFAULT && holds(view)).or_else(|| views.iter().find(|view| holds(view)))
    }
    let default = views.iter().find(|view| view.instance == focus.unwrap_or(DEFAULT));
    let hub = chosen(views, focus, View::holds_hub).or(default);
    let member = chosen(views, focus, View::holds_member).or(default);
    let login = chosen(views, focus, View::holds_login).or(default);
    // The desks this computer hosts belong to the membership shown; with none shown, to the
    // instance that still holds some, so a membership that could not be read hides nothing.
    let hosting = member.filter(|view| view.member.is_some()).or_else(|| chosen(views, focus, View::hosts)).or(default);
    let cloud = default.filter(|view| !view.cloud.is_null()).or_else(|| views.iter().find(|view| !view.cloud.is_null()));
    let mut leftovers: Vec<String> = Vec::new();
    for said in views.iter().flat_map(|view| view.leftovers.iter()) {
        if !leftovers.contains(said) {
            leftovers.push(said.clone());
        }
    }
    let hubs: Vec<Value> = views
        .iter()
        .filter_map(|view| {
            let mut entry = view.hub.clone()?;
            entry["cloudFallback"] = view.cloud.clone();
            Some(entry)
        })
        .collect();
    let members: Vec<Value> = views
        .iter()
        .filter_map(|view| {
            let mut entry = view.member.clone()?;
            entry["hosting"] = view.hosting.clone();
            // The share limit is the computer's own and stays shared; how much of it each grid
            // holds is told per grid.
            entry["sharedDesks"] = json!(view.hosting.as_array().map_or(0, |hosting| hosting.iter().filter(|desk| desk["shared"] == true).count()));
            entry["bucketLeftovers"] = json!(view.leftovers);
            Some(entry)
        })
        .collect();
    let logins: Vec<Value> = views.iter().filter(|view| view.holds_login()).map(|view| view.login.clone()).collect();
    let grid_of = |view: &View| view.hub.as_ref().and_then(|hub| hub["gridId"].as_str()).or_else(|| view.member.as_ref().and_then(|member| member["gridId"].as_str())).map(str::to_owned);
    let mut errors = Vec::new();
    for view in views {
        for (subject, error) in [("hub", &view.hub_error), ("member", &view.member_error)] {
            if let Some(error) = error {
                errors.push(json!({"instance": view.instance, "gridId": grid_of(view), "subject": subject, "error": error}));
            }
        }
    }
    json!({
        // Why no cloud computer is being created, and the ones still running, so a failing or
        // forgotten cloud computer never goes unseen, even after its grid is gone.
        "cloudFallback": cloud.map_or(Value::Null, |view| view.cloud.clone()),
        "hub": hub.and_then(|view| view.hub.clone()),
        "hubError": hub.and_then(|view| view.hub_error.clone()),
        "member": member.and_then(|view| view.member.clone()),
        "memberError": member.and_then(|view| view.member_error.clone()),
        "hosting": hosting.map_or(json!([]), |view| view.hosting.clone()),
        // Copies this computer could not remove from the company's bucket. Shown rather than
        // only recorded: they are a bill nobody asked for and data nobody is tracking, and an
        // audit line is not telling anyone.
        "bucketLeftovers": leftovers,
        "desk": login.map_or(Value::Null, |view| view.login.clone()),
        "hubs": hubs,
        "members": members,
        "logins": logins,
        "errors": errors,
    })
}

pub(crate) async fn desks_status(app: AppHandle, grid_id: Option<String>) -> Result<Value, String> {
    let focus = match grid_id.as_deref().map(str::trim).filter(|wanted| !wanted.is_empty()) {
        Some(wanted) => Some(pick(&app, Some(wanted), instances::ANY).await?),
        None => None,
    };
    status_in(&app, focus.as_deref()).await
}

/// The status, its single-grid fields describing `focus` when given.
async fn status_in(app: &AppHandle, focus: Option<&str>) -> Result<Value, String> {
    load_all(app).await;
    let mut views = Vec::new();
    for instance in app.state::<DeskGrid>().known() {
        views.push(view(app, &instance).await);
    }
    Ok(assemble(&views, focus))
}

/// Moves this computer's membership to `address`, the same hub reached another way (as after a
/// Quick Tunnel restarts). The hub must answer there with the pinned certificate and accept this
/// computer's token before anything is saved. The caller holds the admin lock.
async fn readdress(app: &AppHandle, instance: &str, mut saved: Saved, address: HubAddress) -> Result<(), String> {
    let membership = Membership::new(address.clone(), &saved.certificate, saved.member_id.clone(), secrets::resolve(&vault(MEMBER_TOKEN, instance))?)?;
    membership.check_in(env!("CARGO_PKG_VERSION"), false, &[], None, &[]).await.map_err(|error| error.to_string())?;
    saved.address = address.to_string();
    persist(app, instance, &saved)?;
    crate::security::record(Event::new("desks.readdressed").text("instance", instance).text("grid", &saved.grid_name).text("hub", &saved.address));
    let grid = app.state::<DeskGrid>();
    let slot = grid.slot(instance);
    let mut inner = slot.inner.lock().await;
    inner.member = Some(saved);
    inner.membership = Some(membership);
    inner.member_error = None;
    inner.connected = true;
    inner.reported = None;
    grid.wake.notify_one();
    Ok(())
}

/// Joins a sandbox grid and saves the membership. The caller holds the admin lock.
async fn join_now(app: &AppHandle, instance: &str, company: &str, hub: HubAddress, secret: &str, name: Option<String>, fingerprint: Option<&str>) -> Result<(), String> {
    let found = crate::grid::capability(app).await;
    let name = name.unwrap_or_else(|| crate::grid::computer_name(app));
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
        paused_until: None,
        unreachable_since: None,
    };
    let token_name = vault(MEMBER_TOKEN, instance);
    if let Err(error) = secrets::store(&token_name, &joined.token).and_then(|_| persist(app, instance, &saved)) {
        let _ = joined.membership.leave().await;
        let _ = secrets::delete_secret(&token_name);
        let _ = std::fs::remove_file(member_path(app, instance));
        return Err(error);
    }
    crate::security::record(Event::new("desks.joined").text("instance", instance).text("grid", &saved.grid_name).text("hub", &saved.address).text("fingerprint", &saved.fingerprint));
    let grid = app.state::<DeskGrid>();
    let slot = grid.slot(instance);
    let mut inner = slot.inner.lock().await;
    inner.member = Some(saved);
    inner.membership = Some(joined.membership);
    inner.member_error = None;
    inner.member_loaded = true;
    inner.connected = true;
    inner.reported = None;
    inner.capable = Some(found);
    inner.capable_at = Some(Instant::now());
    grid.wake.notify_one();
    Ok(())
}

/// An instance key no instance on this computer has yet.
fn fresh_instance(app: &AppHandle) -> String {
    let mut taken = instances::on_disk(&grid_folder(app));
    taken.extend(app.state::<DeskGrid>().known());
    instances::new_key(&taken)
}

/// Whether the `default` instance can take a new hub: as before, no hub there, no hub settings
/// there and no membership there.
async fn default_free_for_hub(app: &AppHandle) -> bool {
    let slot = app.state::<DeskGrid>().slot(DEFAULT);
    let inner = slot.inner.lock().await;
    inner.hub.is_none() && !hub_path(app, DEFAULT).exists() && inner.member.is_none()
}

/// The ports a new instance's hub listens on: its own, and its tunnel entry's for a Quick
/// Tunnel, taken from the range every grid on this computer allocates from. A domain's tunnel
/// keeps the port its saved route names, and a domain that already carries another grid's tunnel
/// on this computer is refused rather than shared.
fn ports_for(app: &AppHandle, setup: Option<&TunnelSetup>) -> Result<(u16, Option<u16>, Vec<u16>), String> {
    let grid = grid_folder(app);
    if let Some(TunnelSetup::Domain { domain }) = setup {
        if crate::grid::instances::tunnel_domains(&grid).iter().any(|(_, used)| used.eq_ignore_ascii_case(domain)) {
            return Err(format!("{domain} already carries another grid's tunnel on this computer. Choose another saved domain, or use --tunnel quick."));
        }
    }
    let wanted = if matches!(setup, Some(TunnelSetup::Quick)) { 2 } else { 1 };
    let ports = crate::grid::instances::allocate_ports(&grid, wanted)?;
    let port = *ports.first().ok_or("No free port was found for the sandbox grid")?;
    let tunnel = match setup {
        None => None,
        Some(TunnelSetup::Quick) => Some(*ports.get(1).ok_or("No free port was found for the sandbox grid's tunnel")?),
        Some(domain) => match domain.port(app, port, port) {
            Ok(route) => Some(route),
            Err(error) => {
                crate::grid::instances::release_ports(&ports);
                return Err(error);
            }
        },
    };
    Ok((port, tunnel, ports))
}

/// Admin: hosts a sandbox grid on this computer's LAN or VPN address; this computer joins it too,
/// so it can host desks itself. A computer that already hosts or belongs to a sandbox grid gets a
/// second one beside it, with its own ports and keys.
pub(crate) async fn desks_create(name: String, address_text: String, secret: String, tunnel: Option<String>, app: AppHandle) -> Result<Value, String> {
    let grid = app.state::<DeskGrid>();
    let _admin = grid.admin.lock().await;
    load_all(&app).await;
    let ip: std::net::IpAddr = address_text.trim().parse().map_err(|_| "--ip is this computer's LAN or VPN address, such as 192.168.1.20")?;
    if ip.is_loopback() || ip.is_unspecified() || !net::private(ip) {
        return Err("Use this computer's private LAN or VPN address so company computers can reach the sandbox grid".into());
    }
    let setup = TunnelSetup::parse(tunnel.as_deref());
    let instance = match instances::for_new_hub(default_free_for_hub(&app).await) {
        Some(instance) => instance,
        None => fresh_instance(&app),
    };
    let (port, tunnel_port, allocated) = if instance == DEFAULT {
        (PORT, setup.as_ref().map(|setup| setup.port(&app, PORT, TUNNEL_PORT)).transpose()?, Vec::new())
    } else {
        ports_for(&app, setup.as_ref())?
    };
    let give_back = |allocated: &[u16]| {
        if !allocated.is_empty() {
            crate::grid::instances::release_ports(allocated);
        }
    };
    if let Err(error) = password::validate(&secret) {
        give_back(&allocated);
        return Err(error);
    }
    let salt = password::new_salt();
    let password_key = match derive(secret.clone(), salt.clone()).await {
        Ok(key) => key,
        Err(error) => {
            give_back(&allocated);
            return Err(error);
        }
    };
    let path = hub_path(&app, &instance);
    // Claimed before its settings exist: anything that lists the instances while this runs finds
    // a grid already being started, and never starts its hub a second time beside this one.
    grid.slot(&instance).inner.lock().await.loaded = true;
    let key = match hub::create(&path, &name, ip, port, None, tunnel_port, &salt) {
        Ok(key) => key,
        Err(error) => {
            give_back(&allocated);
            instances::tidy(&grid_folder(&app), &instance);
            return Err(error);
        }
    };
    // This computer runs a sandbox grid again, so the last deletion is no longer the answer for
    // anything. Left behind, it would mark a hub that merely failed to start as deleted.
    let _ = std::fs::remove_file(deleted_path(&app, &instance));
    let (key_name, password_name) = (vault(HUB_KEY, &instance), vault(HUB_PASSWORD, &instance));
    let started: Result<Hub, String> = async {
        secrets::store(&key_name, &key)?;
        secrets::store(&password_name, &password_key)?;
        if let Some(setup) = &setup {
            hub_tunnel::save(&tunnel_path(&app, &instance), setup)?;
        }
        Hub::start(path.clone(), &key, &password_key, events(&instance)).await
    }
    .await;
    let hub = match started {
        Ok(hub) => hub,
        Err(error) => {
            let _ = secrets::delete_secret(&key_name);
            let _ = secrets::delete_secret(&password_name);
            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_file(tunnel_path(&app, &instance));
            give_back(&allocated);
            instances::tidy(&grid_folder(&app), &instance);
            return Err(error);
        }
    };
    let fingerprint = net::fingerprint(&hub.record().certificate)?;
    let direct = HubAddress::Direct(hub.address());
    let slot = grid.slot(&instance);
    {
        let mut inner = slot.inner.lock().await;
        if let (Some(setup), Some(port)) = (setup.clone(), hub.tunnel_address().map(|entry| entry.port())) {
            hub_tunnel::keep(&app, &mut inner.tunnel, setup, port);
        }
        inner.hub = Some(hub);
        inner.hub_error = None;
        inner.loaded = true;
    }
    crate::security::record(Event::new("desks.hosted").text("instance", &instance).text("grid", &name).flag("tunnel", setup.is_some()));
    // With a tunnel, the invite waits for its address so it can be shared straight away; this
    // computer joins over its own LAN address either way.
    if setup.is_some() {
        let deadline = Instant::now() + TUNNEL_START;
        while Instant::now() < deadline {
            let tunnel = &slot.inner.lock().await.tunnel;
            if tunnel.url().is_some() || tunnel.error().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
    let reach = direct;
    // The admin's own computer joins, like any other; a failure here leaves the hub running.
    let joined = join_now(&app, &instance, &name, reach, &secret, None, Some(&fingerprint)).await;
    let mut status = status_in(&app, Some(&instance)).await?;
    status["message"] = json!(match joined {
        Ok(()) => format!("{name}'s sandbox grid is running. Share the invite with the company's computers, and the password separately; then set what the grid may take from each."),
        Err(error) => format!("{name}'s sandbox grid is running, but this computer could not join it: {error}"),
    });
    Ok(status)
}

/// Joins a sandbox grid with the invite the admin shared, committing this computer's idle time.
/// A grid this computer is already in is reached at the invite's address instead; a second grid
/// is joined beside the first.
pub(crate) async fn desks_join(invite_text: String, secret: String, name: Option<String>, grid_id: Option<String>, app: AppHandle) -> Result<Value, String> {
    let grid = app.state::<DeskGrid>();
    let _admin = grid.admin.lock().await;
    let invite = invite::decode_desk(invite_text.trim())?;
    let fingerprint = net::normalize_fingerprint(&invite.fingerprint).unwrap_or_else(|| invite.fingerprint.clone());
    let seen = census(&app).await;
    let target = match grid_id.as_deref().map(str::trim).filter(|wanted| !wanted.is_empty()) {
        None => instances::for_join(&seen, &fingerprint),
        Some(wanted) => {
            let instance = instances::choose(&seen, Some(wanted), instances::ANY)?;
            match instances::for_join(&seen, &fingerprint) {
                Joining::Readdress(already) if already == instance => Joining::Readdress(instance),
                Joining::Readdress(_) => {
                    let name = seen.iter().filter_map(|seen| seen.member.as_ref()).find(|grid| grid.fingerprint.as_deref() == Some(fingerprint.as_str())).map(|grid| grid.name.clone()).unwrap_or_default();
                    return Err(format!("This computer is already in {name}'s sandbox grid under another gridId. Leave it there first with `yougori desks leave --yes`."));
                }
                _ => Joining::Join(instance),
            }
        }
    };
    let instance = match &target {
        Joining::Readdress(instance) => {
            let saved = grid.slot(instance).inner.lock().await.member.clone().ok_or("This computer's membership could not be read; try again")?;
            readdress(&app, instance, saved, invite.address).await?;
            drop(_admin);
            let mut status = status_in(&app, Some(instance)).await?;
            status["message"] = json!(format!("This computer now reaches {}'s sandbox grid at {}.", invite.company, status["member"]["hub"].as_str().unwrap_or_default()));
            return Ok(status);
        }
        Joining::Join(instance) => instance.clone(),
        Joining::New => fresh_instance(&app),
    };
    if let Some(saved) = grid.slot(&instance).inner.lock().await.member.clone() {
        return Err(format!("This computer is already in {}'s sandbox grid. Leave it first with `yougori desks leave --yes`.", saved.grid_name));
    }
    if secret.is_empty() {
        return Err("Give the sandbox grid's password".into());
    }
    let name = name.map(|name| name.trim().to_owned()).filter(|name| !name.is_empty());
    // Anything still hosted here belongs to a membership this computer no longer has. The new
    // membership's orders will not name those desks, and a desk no order names is stopped and
    // deleted with its data — so release them first: they stop being desks and their sandboxes,
    // and everything in them, stay. Reached when a membership could not be read and somebody
    // joined again, which is exactly when the data matters most. Only this instance's desks:
    // another grid's desks on this computer are none of this join's business.
    if crate::desks::hosts_anything(&app, &instance).await {
        let earlier = member_grid_id(&app, &instance);
        crate::desks::stop_hosting(&app, &instance, desk_tag_of(&instance, earlier.as_deref()).as_deref(), false).await;
    }
    if let Err(error) = join_now(&app, &instance, &invite.company, invite.address, &secret, name, Some(&invite.fingerprint)).await {
        if target == Joining::New {
            instances::tidy(&grid_folder(&app), &instance);
        }
        return Err(error);
    }
    drop(_admin);
    let mut status = status_in(&app, Some(&instance)).await?;
    status["message"] = json!(format!("Joined {}'s sandbox grid. This computer hosts desks within the share its admin sets.", invite.company));
    Ok(status)
}

pub(crate) async fn desks_leave(grid_id: Option<String>, app: AppHandle) -> Result<Value, String> {
    let grid = app.state::<DeskGrid>();
    let _admin = grid.admin.lock().await;
    let instance = pick(&app, grid_id.as_deref(), &[Role::Member]).await?;
    let slot = grid.slot(&instance);
    let grid_id = slot.inner.lock().await.member.as_ref().map(|saved| saved.grid_id.clone());
    crate::desks::stop_hosting(&app, &instance, desk_tag_of(&instance, grid_id.as_deref()).as_deref(), false).await;
    let (membership, name) = {
        let mut inner = slot.inner.lock().await;
        let Some(name) = inner.member.as_ref().map(|saved| saved.grid_name.clone()) else {
            inner.member_error = None;
            return Err("This computer is not in a sandbox grid".into());
        };
        let membership = inner.membership.clone();
        forget(&app, &instance, &mut inner);
        (membership, name)
    };
    let notified = match membership {
        Some(membership) => membership.leave().await.map_err(|error| error.to_string()),
        None => Err("No membership token".into()),
    };
    crate::security::record(Event::new("desks.left").text("instance", &instance).text("grid", &name).succeeded(notified.is_ok()));
    instances::tidy(&grid_folder(&app), &instance);
    Ok(json!({"left": true, "grid": name, "gridId": grid_id, "instance": instance, "hubNotified": notified.is_ok(), "warning": notified.err().map(|error| format!("The hub was not told ({error}); the admin can remove this computer with `yougori desks remove`."))}))
}

/// Deletes the sandbox grid this computer hosts. `later` (the default) pauses it for three days,
/// during which `desks_restore` brings it back; `now` deletes it at once. Either way the hub keeps
/// answering until every computer has heard, so each leaves and deletes the desks it hosted.
/// `forget` stops waiting for computers that are still away and removes the hub right now.
pub(crate) async fn desks_delete(when: Option<String>, grid_id: Option<String>, app: AppHandle) -> Result<Value, String> {
    let when = when.as_deref().map(str::trim).filter(|when| !when.is_empty()).unwrap_or("later");
    let at_once = match when {
        "forget" => false,
        "now" => true,
        "later" => false,
        _ => return Err("--when is later (paused for three days, can be restored), now, or forget".into()),
    };
    let instance = pick(&app, grid_id.as_deref(), &[Role::Hub]).await?;
    if when == "forget" {
        return forget_hub(app, &instance).await;
    }
    ensure_loaded(&app, &instance).await;
    let grid = app.state::<DeskGrid>();
    {
        let slot = grid.slot(&instance);
        let inner = slot.inner.lock().await;
        inner.hub.as_ref().ok_or("This computer does not run a sandbox grid")?.close(at_once)?;
    }
    crate::security::record(Event::new("desks.deleting").text("instance", &instance).flag("atOnce", at_once));
    grid.wake();
    let mut status = status_in(&app, Some(&instance)).await?;
    status["message"] = json!(if at_once { "The sandbox grid is deleted. Each computer is told when it next checks in; it leaves and deletes the desks it hosted." } else { "The sandbox grid is paused and will be deleted in three days: desks are stopped but kept. Restore it before then to bring everything back." });
    Ok(status)
}

/// Takes back a deletion while the sandbox grid is still paused.
pub(crate) async fn desks_restore(grid_id: Option<String>, app: AppHandle) -> Result<Value, String> {
    let instance = pick(&app, grid_id.as_deref(), &[Role::Hub]).await?;
    ensure_loaded(&app, &instance).await;
    let grid = app.state::<DeskGrid>();
    {
        let slot = grid.slot(&instance);
        let inner = slot.inner.lock().await;
        inner.hub.as_ref().ok_or("This computer does not run a sandbox grid")?.restore()?;
    }
    crate::security::record(Event::new("desks.restored").text("instance", &instance));
    grid.wake();
    let mut status = status_in(&app, Some(&instance)).await?;
    status["message"] = json!("The sandbox grid is restored. Its computers start and share their desks again at their next check-in.");
    Ok(status)
}

/// A deleted grid whose computers have all heard, or that waited long enough, goes for good.
async fn finish_deleted_hub(app: &AppHandle, instance: &str) {
    let finished = app.state::<DeskGrid>().slot(instance).inner.lock().await.hub.as_ref().is_some_and(Hub::finished);
    if finished {
        let _ = forget_hub(app.clone(), instance).await;
    }
}

/// Removes the hub at once: its settings, keys and tunnel, and this computer's own membership.
async fn forget_hub(app: AppHandle, instance: &str) -> Result<Value, String> {
    let grid = app.state::<DeskGrid>();
    let _admin = grid.admin.lock().await;
    ensure_loaded(&app, instance).await;
    let slot = grid.slot(instance);
    let (own, id) = {
        let mut inner = slot.inner.lock().await;
        let hub = inner.hub.take();
        if hub.is_none() && !hub_path(&app, instance).exists() {
            return Err("This computer does not run a sandbox grid".into());
        }
        let id = hub.as_ref().map(|hub| hub.record().id).or_else(|| hub::load(&hub_path(&app, instance)).ok().map(|record| record.id));
        drop(hub);
        inner.tunnel.stop();
        let _ = std::fs::remove_file(tunnel_path(&app, instance));
        std::fs::remove_file(hub_path(&app, instance)).map_err(|error| format!("Cannot remove the sandbox grid's settings: {error}"))?;
        // Written only once the record has actually gone, so the cloud fallback can tell a grid
        // this computer deleted from one whose record is simply not readable or was moved aside.
        // Without it, retiring the cloud computers rests on a file being missing.
        let _ = std::fs::write(deleted_path(&app, instance), b"");
        let _ = secrets::delete_secret(&vault(HUB_KEY, instance));
        let _ = secrets::delete_secret(&vault(HUB_PASSWORD, instance));
        inner.hub_error = None;
        let own = inner.member.as_ref().is_some_and(|saved| Some(&saved.grid_id) == id.as_ref());
        if own {
            forget(&app, instance, &mut inner);
        }
        (own, id)
    };
    if own {
        crate::desks::stop_hosting(&app, instance, desk_tag_of(instance, id.as_deref()).as_deref(), true).await;
    }
    crate::security::record(Event::new("desks.deleted").text("instance", instance));
    Ok(json!({"deleted": true, "gridId": id, "instance": instance}))
}

/// What the cloud fallback may do now, as this computer's hub stands.
pub(crate) enum CloudSight {
    /// The hub is open. `reach` is how a new computer would reach it, if it can yet.
    Open { fallback: Option<yougori_grid::enterprise::CloudFallback>, needed: Option<String>, reach: Option<HubAddress>, members: Vec<Value> },
    /// Paused for deletion: it may be restored, so nothing it made is removed yet.
    Closing,
    /// Deleted, or removed from this computer: what it made has no grid left to serve.
    Gone,
    /// The hub's settings are here but it is not running: nothing is decided.
    Unknown,
}

/// Where a deletion this computer carried out is written down, beside the hub's own record.
fn deleted_path(app: &AppHandle, instance: &str) -> PathBuf {
    folder(app, instance).join(instances::DELETED)
}

/// What a hub that is not running means for the cloud fallback. [`CloudSight::Gone`] retires every
/// cloud computer and deletes the desks on it with their data, so it is only ever the answer when
/// this computer recorded the deletion itself.
///
/// A record that is merely not there proves nothing: `yougori rollout retire` moves it aside on
/// purpose and keeps it, and a stat that fails reads as absent too. Both used to be read as "the
/// grid was deleted", which threw away desks nobody had deleted. `present` is `None` when this
/// computer could not tell.
fn sight_without_hub(present: Option<bool>, deleted_here: bool) -> CloudSight {
    match (present, deleted_here) {
        (Some(false), true) => CloudSight::Gone,
        _ => CloudSight::Unknown,
    }
}

/// What the cloud fallback needs from the hub of `instance`: the settings, why a computer is
/// needed now (if one is), how the grid is reached from outside, and the computers in it.
pub(crate) async fn cloud_view(app: &AppHandle, instance: &str) -> CloudSight {
    let slot = app.state::<DeskGrid>().slot(instance);
    let inner = slot.inner.lock().await;
    let Some(hub) = inner.hub.as_ref() else {
        let present = match std::fs::metadata(hub_path(app, instance)) {
            Ok(_) => Some(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Some(false),
            // A stat that failed says nothing about whether the grid is there.
            Err(_) => None,
        };
        // `exists()` answers false when the check itself fails, and that is the direction this one
        // has to fail in: a marker we could not read counts as "no deletion was recorded here",
        // which gives Unknown, and Unknown retires nothing. Making a failed check mean "deleted"
        // would retire every cloud computer and delete the desks on it with their data, on the
        // strength of a check that never completed. Leave it reading the unknown as the safe
        // answer, here and for the record above.
        return sight_without_hub(present, deleted_path(app, instance).exists());
    };
    match hub.phase() {
        hub::Phase::Open => {}
        hub::Phase::Paused(_) => return CloudSight::Closing,
        hub::Phase::Gone => return CloudSight::Gone,
    }
    let status = hub.status();
    let fallback = serde_json::from_value(status["enterprise"]["cloudFallback"].clone()).ok();
    let record = hub.record();
    let reach = match &inner.tunnel.setup {
        Some(_) => inner.tunnel.reach(),
        None => Some(HubAddress::Direct(SocketAddr::new(record.address, hub.address().port()))),
    };
    let members = status["members"].as_array().cloned().unwrap_or_default();
    CloudSight::Open { fallback, needed: hub.needs_computer(), reach, members }
}

/// Takes up a membership the hub made ahead of time, on a computer the hub created: the
/// membership JSON (with the token) arrives on stdin, over the SSH session that installed Yougori.
pub(crate) async fn desks_adopt_membership(membership: Value, app: AppHandle) -> Result<Value, String> {
    let grid = app.state::<DeskGrid>();
    let _admin = grid.admin.lock().await;
    let text = |key: &str| membership[key].as_str().map(str::trim).filter(|value| !value.is_empty()).map(str::to_owned).ok_or_else(|| format!("The membership is missing {key}"));
    let (company, address, fingerprint, member_id, token) = (text("company")?, text("address")?, text("fingerprint")?, text("memberId")?, text("memberToken")?);
    let seen = census(&app).await;
    let normalized = net::normalize_fingerprint(&fingerprint).unwrap_or_else(|| fingerprint.clone());
    let instance = match instances::for_adopt(&seen, &normalized, membership["gridId"].as_str())? {
        Some(instance) => instance,
        None => fresh_instance(&app),
    };
    if let Some(saved) = grid.slot(&instance).inner.lock().await.member.as_ref() {
        return Err(format!("This computer is already in {}'s sandbox grid", saved.grid_name));
    }
    let hub = HubAddress::parse(&address)?;
    let joined = member::adopt(&company, hub.clone(), &fingerprint, &member_id, &token).await?;
    let saved = Saved {
        version: 1,
        grid_id: joined.grid_id.clone(),
        grid_name: joined.grid_name.clone(),
        address: hub.to_string(),
        certificate: joined.certificate.clone(),
        fingerprint: joined.fingerprint.clone(),
        member_id: joined.membership.member_id.clone(),
        joined_at: yougori_grid::now(),
        paused_until: None,
        unreachable_since: None,
    };
    let token_name = vault(MEMBER_TOKEN, &instance);
    if let Err(error) = secrets::store(&token_name, &joined.token).and_then(|_| persist(&app, &instance, &saved)) {
        let _ = secrets::delete_secret(&token_name);
        let _ = std::fs::remove_file(member_path(&app, &instance));
        instances::tidy(&grid_folder(&app), &instance);
        return Err(error);
    }
    crate::security::record(Event::new("desks.adopted_membership").text("instance", &instance).text("grid", &saved.grid_name).text("hub", &saved.address));
    let slot = grid.slot(&instance);
    let mut inner = slot.inner.lock().await;
    inner.member = Some(saved);
    inner.membership = Some(joined.membership);
    inner.member_error = None;
    inner.member_loaded = true;
    inner.connected = true;
    inner.reported = None;
    grid.wake.notify_one();
    drop(inner);
    drop(_admin);
    let mut status = status_in(&app, Some(&instance)).await?;
    status["message"] = json!(format!("This computer joined {company}'s sandbox grid as a cloud computer."));
    Ok(status)
}

/// Admin: takes a computer out of the sandbox grid; its desks go back to waiting and are placed
/// again, with their data still on it in case it rejoins.
pub(crate) async fn desks_member_remove(member_id: String, grid_id: Option<String>, app: AppHandle) -> Result<Value, String> {
    let instance = pick(&app, grid_id.as_deref(), &[Role::Hub]).await?;
    let result = with_hub_in(&app, &instance, |hub| hub.enterprise(json!({"action": "computerRemove", "id": member_id}))).await?;
    crate::security::record(Event::new("desks.member.removed").text("instance", &instance).text("memberId", &member_id));
    Ok(result)
}

/// Admin: what the grid may take from a computer. Fields left out keep their current values;
/// `suggested` goes back to the automatic share.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn desks_member_share(member_id: String, cpu: Option<f64>, memory_gb: Option<f64>, disk_gb: Option<f64>, gpu: Option<bool>, idle_only: Option<bool>, suggested: Option<bool>, grid_id: Option<String>, app: AppHandle) -> Result<Value, String> {
    let instance = pick(&app, grid_id.as_deref(), &[Role::Hub]).await?;
    let result = with_hub_in(&app, &instance, |hub| {
        if suggested == Some(true) {
            return hub.set_member_share(&member_id, None);
        }
        let current = hub.member_share(&member_id)?;
        let share = Share::checked(cpu.unwrap_or(current.cpu), memory_gb.unwrap_or(current.memory_gb), disk_gb.unwrap_or(current.disk_gb), gpu.unwrap_or(current.gpu), idle_only.unwrap_or(current.idle_only))?;
        hub.set_member_share(&member_id, Some(share))
    })
    .await?;
    crate::security::record(Event::new("desks.member.share").text("instance", &instance).text("memberId", &member_id).text("share", &result["share"].to_string()));
    Ok(result)
}

pub(crate) async fn desks_manage(mut request: Value, grid_id: Option<String>, app: AppHandle) -> Result<Value, String> {
    let wanted = grid_id.as_deref();
    if request["action"] == "imageImport" {
        let instance = pick(&app, wanted, &[Role::Hub]).await?;
        return crate::desks::media::import(&app, &instance, request).await;
    }
    // The parking bucket: its keys go to this computer's OS vault and the running hub, never
    // into the hub's record or to anyone but a computer moving a desk.
    if request["action"] == "parkingSet" {
        let credentials = json!({"provider": request["provider"], "location": request["location"], "accessKey": request["accessKey"], "secretKey": request["secretKey"]});
        if !credentials["accessKey"].as_str().is_some_and(|key| !key.trim().is_empty()) || !credentials["secretKey"].as_str().is_some_and(|key| !key.trim().is_empty()) {
            return Err("Give the bucket's access key and secret key".into());
        }
        crate::desks::parking::open(&credentials)?;
        if let Some(body) = request.as_object_mut() { body.remove("accessKey"); body.remove("secretKey"); }
        let instance = pick(&app, wanted, &[Role::Hub]).await?;
        ensure_loaded(&app, &instance).await;
        let slot = app.state::<DeskGrid>().slot(&instance);
        let inner = slot.inner.lock().await;
        let hub = inner.hub.as_ref().ok_or("Parking is set up on the computer that hosts the sandbox grid")?;
        let result = hub.enterprise(request)?;
        secrets::store(&vault(PARKING, &instance), &credentials.to_string())?;
        hub.set_parking(Some(credentials));
        crate::security::record(Event::new("desks.parking.set").text("instance", &instance));
        return Ok(result);
    }
    if request["action"] == "parkingClear" {
        let instance = pick(&app, wanted, &[Role::Hub]).await?;
        ensure_loaded(&app, &instance).await;
        let slot = app.state::<DeskGrid>().slot(&instance);
        let inner = slot.inner.lock().await;
        let hub = inner.hub.as_ref().ok_or("Parking is set up on the computer that hosts the sandbox grid")?;
        let result = hub.enterprise(request)?;
        let _ = secrets::delete_secret(&vault(PARKING, &instance));
        hub.set_parking(None);
        crate::security::record(Event::new("desks.parking.cleared").text("instance", &instance));
        return Ok(result);
    }
    // A connector's credential: the identifiers go to the hub's record, the secret to this
    // computer's OS vault and the running hub, never to the record or anyone else.
    if matches!(request["action"].as_str(), Some("connectionAdd" | "connectionCredential")) && request.get("credential").is_some() {
        let instance = pick(&app, wanted, &[Role::Hub]).await?;
        ensure_loaded(&app, &instance).await;
        let slot = app.state::<DeskGrid>().slot(&instance);
        let provider: yougori_grid::enterprise::Provider = match request["action"].as_str() {
            Some("connectionAdd") => serde_json::from_value(request["provider"].clone()).map_err(|_| "Unsupported enterprise provider")?,
            _ => {
                let inner = slot.inner.lock().await;
                let hub = inner.hub.as_ref().ok_or("Credentials are entered on the computer that hosts the sandbox grid")?;
                let id = request["id"].as_str().unwrap_or_default().to_owned();
                hub.status()["enterprise"]["connections"].as_array().into_iter().flatten().find(|c| c["id"] == id).and_then(|c| serde_json::from_value(c["provider"].clone()).ok()).ok_or("No connection with that ID")?
            }
        };
        let credential = request.as_object_mut().and_then(|body| body.remove("credential")).unwrap_or(Value::Null);
        let secret_fields = yougori_grid::enterprise::Connection::secret_fields(provider);
        let mut secret = serde_json::Map::new();
        let mut target = serde_json::Map::new();
        for (key, value) in credential.as_object().cloned().unwrap_or_default() {
            let text = value.as_str().unwrap_or_default().trim().to_owned();
            if secret_fields.contains(&key.as_str()) {
                if !text.is_empty() { secret.insert(key, json!(text)); }
            } else {
                target.insert(key, json!(text));
            }
        }
        if secret.is_empty() {
            return Err(format!("Give the {}", secret_fields.join(" or ")));
        }
        request["target"] = Value::Object(target);
        request["credentialSet"] = json!(true);
        request["set"] = json!(true);
        let inner = slot.inner.lock().await;
        let hub = inner.hub.as_ref().ok_or("Credentials are entered on the computer that hosts the sandbox grid")?;
        let result = hub.enterprise(request)?;
        let id = result["id"].as_str().unwrap_or_default().to_owned();
        let secret = Value::Object(secret);
        secrets::store(&vault(&format!("{CONNECTION}{id}"), &instance), &secret.to_string())?;
        hub.set_connection_credential(&id, Some(secret));
        crate::security::record(Event::new("desks.connection.credential").text("instance", &instance).text("connectionId", &id));
        app.state::<DeskGrid>().wake();
        return Ok(result);
    }
    if matches!(request["action"].as_str(), Some("connectionRemove")) || (request["action"] == "connectionCredential" && request["set"] == false) {
        let instance = pick(&app, wanted, &[Role::Hub, Role::Login]).await?;
        ensure_loaded(&app, &instance).await;
        let slot = app.state::<DeskGrid>().slot(&instance);
        let inner = slot.inner.lock().await;
        let id = request["id"].as_str().unwrap_or_default().to_owned();
        let result = match inner.hub.as_ref() {
            Some(hub) => hub.enterprise(request)?,
            None => crate::desks::management_session(&instance)?.manage(request).await?,
        };
        let _ = secrets::delete_secret(&vault(&format!("{CONNECTION}{id}"), &instance));
        if let Some(hub) = inner.hub.as_ref() { hub.set_connection_credential(&id, None); }
        return Ok(result);
    }
    if matches!(request["action"].as_str(), Some("personAdd" | "personPassword")) {
        let secret = request.as_object_mut().and_then(|o|o.remove("password")).and_then(|v|v.as_str().map(str::to_owned)).ok_or("A password is required")?;
        password::validate(&secret)?;
        let salt = password::new_salt();
        let key = { let salt = salt.clone(); tokio::task::spawn_blocking(move || password::derive(&secret, &salt)).await.map_err(|e|e.to_string())?? };
        request["salt"] = json!(salt); request["key"] = json!(key);
    }
    let instance = pick(&app, wanted, &[Role::Hub, Role::Login]).await?;
    ensure_loaded(&app, &instance).await;
    let grid = app.state::<DeskGrid>();
    { let slot = grid.slot(&instance); let inner = slot.inner.lock().await;
      if let Some(hub) = &inner.hub { let result = hub.enterprise(request); grid.wake(); return result; }
    }
    let session = crate::desks::management_session(&instance)?;
    session.manage(request).await
}

/// App commands, from the main window only.
pub(crate) mod commands {
    use super::*;

    fn main_window(window: &WebviewWindow) -> Result<(), String> {
        if window.label() == "main" { Ok(()) } else { Err("A sandbox grid is managed from the main Yougori window".into()) }
    }

    #[tauri::command]
    pub async fn desks_manage(app: AppHandle, window: WebviewWindow, request: Value, grid_id: Option<String>) -> Result<Value, String> {
        main_window(&window)?;
        super::desks_manage(request, grid_id, app).await
    }

    #[tauri::command]
    pub async fn desks_status(app: AppHandle, window: WebviewWindow, grid_id: Option<String>) -> Result<Value, String> {
        main_window(&window)?;
        super::desks_status(app, grid_id).await
    }

    #[tauri::command]
    pub fn desks_suggested_address(window: WebviewWindow) -> Result<Option<String>, String> {
        main_window(&window)?;
        Ok(crate::bounty::suggested_address())
    }

    #[tauri::command]
    pub async fn desks_create(app: AppHandle, window: WebviewWindow, name: String, address: String, password: String, tunnel: Option<String>) -> Result<Value, String> {
        main_window(&window)?;
        super::desks_create(name, address, password, tunnel, app).await
    }

    #[tauri::command]
    pub async fn desks_join(app: AppHandle, window: WebviewWindow, invite: String, password: String, name: Option<String>, grid_id: Option<String>) -> Result<Value, String> {
        main_window(&window)?;
        super::desks_join(invite, password, name, grid_id, app).await
    }

    #[tauri::command]
    pub async fn desks_leave(app: AppHandle, window: WebviewWindow, grid_id: Option<String>) -> Result<Value, String> {
        main_window(&window)?;
        super::desks_leave(grid_id, app).await
    }

    #[tauri::command]
    pub async fn desks_delete(app: AppHandle, window: WebviewWindow, when: Option<String>, grid_id: Option<String>) -> Result<Value, String> {
        main_window(&window)?;
        super::desks_delete(when, grid_id, app).await
    }

    #[tauri::command]
    pub async fn desks_adopt_membership(app: AppHandle, window: WebviewWindow, membership: Value) -> Result<Value, String> {
        main_window(&window)?;
        super::desks_adopt_membership(membership, app).await
    }

    #[tauri::command]
    pub async fn desks_restore(app: AppHandle, window: WebviewWindow, grid_id: Option<String>) -> Result<Value, String> {
        main_window(&window)?;
        super::desks_restore(grid_id, app).await
    }

    #[tauri::command]
    pub async fn desks_member_remove(app: AppHandle, window: WebviewWindow, member_id: String, grid_id: Option<String>) -> Result<Value, String> {
        main_window(&window)?;
        super::desks_member_remove(member_id, grid_id, app).await
    }

    #[tauri::command]
    #[allow(clippy::too_many_arguments)]
    pub async fn desks_member_share(app: AppHandle, window: WebviewWindow, member_id: String, cpu: Option<f64>, memory_gb: Option<f64>, disk_gb: Option<f64>, gpu: Option<bool>, idle_only: Option<bool>, suggested: Option<bool>, grid_id: Option<String>) -> Result<Value, String> {
        main_window(&window)?;
        super::desks_member_share(member_id, cpu, memory_gb, disk_gb, gpu, idle_only, suggested, grid_id, app).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sandbox_grid_is_only_gone_when_this_computer_deleted_it() {
        let gone = |present, deleted| matches!(sight_without_hub(present, deleted), CloudSight::Gone);

        // The only case that retires cloud computers and deletes the desks on them.
        assert!(gone(Some(false), true), "a deletion this computer recorded, with the record gone");

        // `yougori rollout retire` moves the record aside on purpose and keeps it. The grid was
        // never deleted, and reading the missing file as a deletion threw away people's desks.
        assert!(!gone(Some(false), false), "a record that is merely absent is not a deletion");
        // A stat that failed is this computer not knowing, which is not evidence of anything.
        assert!(!gone(None, false));
        assert!(!gone(None, true), "not even a past deletion decides it while the record cannot be read");
        // The record is right there, so whatever stopped the hub, the grid is not gone.
        assert!(!gone(Some(true), false));
        assert!(!gone(Some(true), true));
    }

    #[tokio::test]
    async fn every_instance_has_state_of_its_own() {
        let grid = DeskGrid::default();
        assert_eq!(grid.known(), vec![DEFAULT.to_owned()], "the old single grid is always there");
        let (one, two) = (grid.slot(DEFAULT), grid.slot("i-0000000b"));
        one.inner.lock().await.member_error = Some("first".into());
        two.inner.lock().await.orders_received = true;
        // Each holds its own: neither sees the other's.
        assert_eq!(grid.slot(DEFAULT).inner.lock().await.member_error.as_deref(), Some("first"));
        assert!(grid.slot("i-0000000b").inner.lock().await.member_error.is_none());
        assert!(!grid.slot(DEFAULT).inner.lock().await.orders_received);
        // Two locks, not one: holding one grid's state never waits on the other's.
        let _held = one.inner.lock().await;
        assert!(two.inner.try_lock().is_ok());
        assert_eq!(grid.known(), vec![DEFAULT.to_owned(), "i-0000000b".to_owned()], "and the loop visits both, default first");
        assert_eq!(desk_tag_of(DEFAULT, Some("grid-a")), None, "default's desks keep their old description");
        assert_eq!(desk_tag_of("i-0000000b", Some("grid-b")).as_deref(), Some("grid-b"));
    }

    fn view(instance: &str, hub: Option<&str>, member: Option<&str>, login: Option<&str>) -> View {
        View {
            instance: instance.into(),
            hub: hub.map(|id| json!({"id": id, "name": format!("Hub {id}"), "instance": instance, "gridId": id})),
            member: member.map(|id| json!({"gridId": id, "grid": format!("Grid {id}"), "instance": instance})),
            login: login.map_or(Value::Null, |id| json!({"gridId": id, "grid": format!("Grid {id}"), "instance": instance})),
            hosting: json!([{"id": format!("desk-of-{instance}"), "shared": true}]),
            cloud: Value::Null,
            ..View::default()
        }
    }

    #[test]
    fn the_status_keeps_its_shape_and_lists_every_instance() {
        // Only the old instance: exactly the fields there always were, describing it.
        let alone = assemble(&[view(DEFAULT, Some("grid-a"), Some("grid-a"), None)], None);
        assert_eq!(alone["hub"]["gridId"], "grid-a");
        assert_eq!(alone["member"]["gridId"], "grid-a");
        assert!(alone["desk"].is_null() && alone["hubError"].is_null() && alone["memberError"].is_null() && alone["cloudFallback"].is_null());
        assert_eq!(alone["hosting"][0]["id"], "desk-of-default");
        for key in ["hub", "hubError", "member", "memberError", "hosting", "bucketLeftovers", "desk", "cloudFallback"] {
            assert!(alone.get(key).is_some(), "{key} is gone from the status");
        }

        // Two hubs, two memberships and two sign-ins on one computer.
        let views = [view(DEFAULT, Some("grid-a"), Some("grid-a"), Some("grid-c")), view("i-0000000b", Some("grid-b"), Some("grid-b"), Some("grid-b"))];
        let both = assemble(&views, None);
        assert_eq!((both["hub"]["gridId"].as_str(), both["member"]["gridId"].as_str(), both["desk"]["gridId"].as_str()), (Some("grid-a"), Some("grid-a"), Some("grid-c")), "the old fields describe default");
        for (list, ids) in [("hubs", ["grid-a", "grid-b"]), ("members", ["grid-a", "grid-b"]), ("logins", ["grid-c", "grid-b"])] {
            let found: Vec<&str> = both[list].as_array().unwrap().iter().map(|entry| entry["gridId"].as_str().unwrap()).collect();
            assert_eq!(found, ids, "{list}");
            let instances: Vec<&str> = both[list].as_array().unwrap().iter().map(|entry| entry["instance"].as_str().unwrap()).collect();
            assert_eq!(instances, [DEFAULT, "i-0000000b"], "{list} entries carry their instance");
        }
        assert_eq!(both["members"][1]["hosting"][0]["id"], "desk-of-i-0000000b", "each membership lists its own desks");
        assert_eq!(both["members"][1]["sharedDesks"], 1);

        // Asked about one: the old fields describe that one.
        let focused = assemble(&views, Some("i-0000000b"));
        assert_eq!((focused["hub"]["gridId"].as_str(), focused["member"]["gridId"].as_str(), focused["desk"]["gridId"].as_str()), (Some("grid-b"), Some("grid-b"), Some("grid-b")));
        assert_eq!(focused["hosting"][0]["id"], "desk-of-i-0000000b");

        // Default empty, one other grid: the old fields describe the only one.
        let only = assemble(&[view(DEFAULT, None, None, None), view("i-0000000b", None, Some("grid-b"), None)], None);
        assert_eq!(only["member"]["gridId"], "grid-b");
        assert!(only["hub"].is_null());
        assert_eq!(only["hosting"][0]["id"], "desk-of-i-0000000b");

        // A membership that could not be read is not hidden behind another grid's.
        let mut unreadable = view(DEFAULT, None, None, None);
        unreadable.member_error = Some("not read yet".into());
        let shown = assemble(&[unreadable, view("i-0000000b", None, Some("grid-b"), None)], None);
        assert_eq!(shown["memberError"], "not read yet");
        assert_eq!(shown["members"][0]["gridId"], "grid-b");
        assert_eq!(shown["errors"][0]["instance"], DEFAULT);
    }
}
