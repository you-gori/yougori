//! The Sandbox Grid: a company's own hub for desks, separate from its Closed Neo Grid. One
//! computer runs the desk hub; company computers join it with the sandbox-grid password and
//! report what they have and are using; the admin sets what the grid may take from each, orders
//! desks for people on it (`desks`), and people sign in to open theirs. It has its own record, keys, port and invite (`desk-invite:`), so joining one grid never
//! makes a computer part of the other. Under the hood it is the same hub technology.
use crate::{hub_tunnel::{self, TunnelSetup, TunnelState}, projects::secrets, security::Event, store::PlatformStore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
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
/// Quick Tunnel forwards to the next one.
pub(crate) const PORT: u16 = 7463;
const TUNNEL_PORT: u16 = 7464;
/// Waiting for a new grid's tunnel to publish its address before answering without it.
const TUNNEL_START: Duration = Duration::from_secs(60);
const TICK: Duration = Duration::from_secs(5);
const REPORT: Duration = Duration::from_secs(30);
const CAPABILITY: Duration = Duration::from_secs(30 * 60);

#[derive(Default)]
pub struct DeskGrid {
    inner: tokio::sync::Mutex<Inner>,
    /// Serializes creating, joining, leaving and deleting.
    admin: tokio::sync::Mutex<()>,
    wake: tokio::sync::Notify,
}

impl DeskGrid {
    /// Runs the next tick now, for example when a desk finished building.
    pub(crate) fn wake(&self) {
        self.wake.notify_one();
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
struct Saved {
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

fn folder(app: &AppHandle) -> PathBuf {
    app.state::<PlatformStore>().data_folder("grid")
}

fn hub_path(app: &AppHandle) -> PathBuf {
    folder(app).join("desks-hub.json")
}

fn member_path(app: &AppHandle) -> PathBuf {
    folder(app).join("desks-member.json")
}

fn tunnel_path(app: &AppHandle) -> PathBuf {
    folder(app).join("desks-tunnel.json")
}

fn events() -> hub::Events {
    Arc::new(|kind: &'static str, detail: Value| crate::security::record(Event::new(kind).object("detail", detail)))
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

async fn derive(secret: String, salt: String) -> Result<String, String> {
    tokio::task::spawn_blocking(move || password::derive(&secret, &salt)).await.map_err(|error| error.to_string())?
}

async fn ensure_loaded(app: &AppHandle) {
    let grid = app.state::<DeskGrid>();
    let mut inner = grid.inner.lock().await;
    if inner.loaded && inner.member_loaded {
        return;
    }
    // The hub starts once. Only the membership below is read again, so a credential vault that
    // was not ready yet cannot start a second hub on the retry.
    if !inner.loaded {
        inner.loaded = true;
        let path = hub_path(app);
        if path.exists() {
            match secrets::hub_keys(secrets::look_up(HUB_KEY), secrets::look_up(HUB_PASSWORD)) {
                secrets::Keys::Ready(key, password_key) => match Hub::start(path, &key, &password_key, events()).await {
                    Ok(hub) => {
                        if let (Some(port), Some(setup)) = (hub.tunnel_address().map(|entry| entry.port()), hub_tunnel::load(&tunnel_path(app))) {
                            hub_tunnel::keep(app, &mut inner.tunnel, setup, port);
                        }
                        hub.set_parking(secrets::resolve(PARKING).ok().and_then(|saved| serde_json::from_str(&saved).ok()));
                        for id in hub.connections_with_credentials() {
                            hub.set_connection_credential(&id, secrets::resolve(&format!("{CONNECTION}{id}")).ok().and_then(|saved| serde_json::from_str(&saved).ok()));
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
        let outcome = match std::fs::read(member_path(app)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => MemberLoad::Absent,
            Err(_) => MemberLoad::NotYet,
            Ok(bytes) => match serde_json::from_slice::<Saved>(&bytes) {
                Err(_) => MemberLoad::Damaged,
                // The OS credential vault is routinely not ready yet when the computer starts
                // Yougori for itself. That is this computer failing to look, not a lost membership.
                Ok(saved) => match secrets::resolve(MEMBER_TOKEN) {
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

/// Forgets this computer's membership.
fn forget(app: &AppHandle, inner: &mut Inner) {
    inner.membership = None;
    inner.member = None;
    inner.connected = false;
    inner.reported = None;
    inner.reported_desks.clear();
    inner.orders.clear();
    inner.orders_received = false;
    inner.member_error = None;
    let _ = std::fs::remove_file(member_path(app));
    let _ = secrets::delete_secret(MEMBER_TOKEN);
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

pub(crate) async fn with_hub<T>(app: &AppHandle, action: impl FnOnce(&Hub) -> Result<T, String>) -> Result<T, String> {
    ensure_loaded(app).await;
    let grid = app.state::<DeskGrid>();
    let inner = grid.inner.lock().await;
    let hub = inner.hub.as_ref().ok_or("This computer does not run a sandbox grid. Admins create one with `yougori desks create`.")?;
    action(hub)
}

/// One check-in: builds and shares the desks the hub ordered, then reports them and what this
/// computer can host; the hub answers with the current orders.
async fn tick(app: &AppHandle) {
    let grid = app.state::<DeskGrid>();
    let (membership, saved, orders, refresh) = {
        let inner = grid.inner.lock().await;
        let (Some(membership), Some(saved)) = (inner.membership.clone(), inner.member.clone()) else { return };
        (membership, saved, inner.orders.clone(), inner.capable_at.is_none_or(|at| at.elapsed() >= CAPABILITY))
    };
    if refresh {
        let found = crate::grid::capability(app).await;
        let mut inner = grid.inner.lock().await;
        inner.capable = Some(found);
        inner.capable_at = Some(Instant::now());
    }
    // Reading activity runs system commands on Linux and macOS: every 15 s is enough.
    let activity = {
        let cached = grid.inner.lock().await.activity.clone();
        match cached {
            Some((activity, at)) if at.elapsed() < Duration::from_secs(15) => activity,
            _ => {
                let activity = tokio::task::spawn_blocking(yougori_grid::activity::current).await.unwrap_or_else(|_| Activity::Unknown("User activity could not be read".into()));
                grid.inner.lock().await.activity = Some((activity.clone(), Instant::now()));
                activity
            }
        }
    };
    let orders_received = grid.inner.lock().await.orders_received;
    let parking = grid.inner.lock().await.parking.clone();
    let reports = if saved.paused_until.is_some() {
        // Paused for deletion: stop and unshare the desks here, keeping them and their data.
        crate::desks::pause(app).await;
        Vec::new()
    } else if orders_received {
        let reports = crate::desks::reconcile(app, &orders, &membership, &saved.grid_id, parking.as_ref()).await;
        // Desks shared here can also be opened from another network, through the hub.
        crate::desks::keep_desk_relays(app, &membership).await;
        reports
    } else {
        Vec::new()
    };
    let summary = serde_json::to_string(&reports.iter().map(|report| (&report.id, &report.state, report.invitation.is_some())).collect::<Vec<_>>()).unwrap_or_default();
    let (due, gpu) = {
        let inner = grid.inner.lock().await;
        (inner.reported.is_none_or(|at| at.elapsed() >= REPORT) || inner.reported_desks != summary, inner.capable.as_ref().is_some_and(|(capable, _)| *capable))
    };
    if !due {
        return;
    }
    let capacity = crate::desks::capacity(app, &activity, gpu);
    let answer = membership.check_in(env!("CARGO_PKG_VERSION"), gpu, &[], Some(&capacity), &reports).await;
    let mut inner = grid.inner.lock().await;
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
                let _ = persist(app, current);
            }
            inner.reported_desks = summary;
            if inner.orders != instructions.desks {
                inner.orders = instructions.desks;
                grid.wake.notify_one();
            }
            inner.parking = instructions.parking;
            if let Some(current) = inner.member.as_mut().filter(|current| current.paused_until != instructions.paused_until) {
                crate::security::record(Event::new(if instructions.paused_until.is_some() { "desks.paused" } else { "desks.resumed" }).text("grid", &current.grid_name));
                current.paused_until = instructions.paused_until;
                let _ = persist(app, current);
                grid.wake.notify_one();
            }
        }
        Err(MemberError::Deleted) => {
            // The admin deleted the grid: leave it, and delete the desks it put here with their data.
            crate::security::record(Event::new("desks.deleted.left").text("grid", &saved.grid_name));
            forget(app, &mut inner);
            inner.member_error = Some(format!("{} deleted this sandbox grid. This computer left it and deleted the desks it hosted.", saved.grid_name));
            drop(inner);
            crate::desks::stop_hosting(app, true).await;
        }
        Err(MemberError::Removed) => {
            crate::security::record(Event::new("desks.removed").text("grid", &saved.grid_name));
            forget(app, &mut inner);
            inner.member_error = Some("The sandbox grid's admin removed this computer; join again with the password".into());
            drop(inner);
            crate::desks::stop_hosting(app, false).await;
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
                let _ = persist(app, current);
            }
        }
        Err(MemberError::Failed(error)) => {
            inner.connected = false;
            inner.member_error = Some(error);
            if let Some(current) = inner.member.as_mut().filter(|current| current.unreachable_since.is_none()) {
                current.unreachable_since = member::silence_clock(false, current.unreachable_since, yougori_grid::now());
                let _ = persist(app, current);
            }
        }
    }
}

/// Keeps this computer's desks in line with the hub's orders while the engine runs.
pub(crate) fn start(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let shutdown = crate::automation::shutdown_signal(&app);
        ensure_loaded(&app).await;
        loop {
            let grid = app.state::<DeskGrid>();
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = grid.wake.notified() => {}
                _ = tokio::time::sleep(TICK) => {}
            }
            tick(&app).await;
            finish_deleted_hub(&app).await;
            crate::desks::cloud::tick(&app).await;
            provisioning_tick(&app).await;
        }
        hand_off_before_closing(&app).await;
        if let Some(hub) = app.state::<DeskGrid>().inner.lock().await.hub.take() {
            hub.flush();
        }
    });
}

/// On the hub computer: whatever the admin asked connectors to do runs here, with the secrets
/// from this computer's vault, and the outcome goes back to the record for the admin to read.
async fn provisioning_tick(app: &AppHandle) {
    let due = {
        let grid = app.state::<DeskGrid>();
        let inner = grid.inner.lock().await;
        let Some(hub) = inner.hub.as_ref().filter(|hub| hub.phase() == hub::Phase::Open) else { return };
        hub.provisioning_due()
    };
    if due.is_empty() {
        return;
    }
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        for (id, task) in due {
            let want = task.want.name();
            let outcome = yougori_grid::provisioning::run(&task).await;
            crate::security::record(Event::new("desks.connection.task").text("taskId", &id).text("want", want).text("email", &task.email).outcome(&outcome.as_ref().map(|_| ()).map_err(Clone::clone)));
            let grid = app.state::<DeskGrid>();
            let inner = grid.inner.lock().await;
            if let Some(hub) = &inner.hub {
                hub.provisioning_report(&id, outcome);
            }
        }
    });
}

/// Yougori is closing on a computer that hosts desks: it tells the hub so the desks move, and
/// keeps checking in while their data is copied, so nobody's desk is left stranded on a computer
/// that is going away. It waits only as long as `MOVE_WAIT`; a desk still here keeps its data and
/// comes back when this computer does.
async fn hand_off_before_closing(app: &AppHandle) {
    let hosting = {
        let grid = app.state::<DeskGrid>();
        let inner = grid.inner.lock().await;
        inner.member.is_some() && inner.hub.is_none()
    };
    if !hosting || !crate::desks::hosts_anything(app).await {
        return;
    }
    app.state::<crate::desks::DeskHost>().closing.store(true, std::sync::atomic::Ordering::Relaxed);
    crate::security::record(Event::new("desks.closing").text("wait", &format!("{}s", yougori_grid::power::MOVE_WAIT.as_secs())));
    let deadline = Instant::now() + yougori_grid::power::MOVE_WAIT;
    while Instant::now() < deadline {
        // A fresh check-in each time: the hub hands the desks on and this computer packs them.
        {
            let grid = app.state::<DeskGrid>();
            grid.inner.lock().await.reported = None;
        }
        tick(app).await;
        if !crate::desks::moving_anything(app).await && crate::desks::hosts_anything(app).await == crate::desks::parked_everything(app).await {
            break;
        }
        // Nothing will be packed if the hub's answers cannot be read: no orders arrive, so no
        // desk is ever asked to move. Waiting the full fifteen minutes for that holds the
        // computer open for a quarter of an hour on something that has already been decided.
        if app.state::<DeskGrid>().inner.lock().await.unreadable {
            crate::security::record(Event::new("desks.closing_stopped").text("reason", "This computer could not read the hub's answers, so no desk could be handed on"));
            break;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    crate::security::record(Event::new("desks.closed").flag("handedOn", !crate::desks::moving_anything(app).await));
}

pub(crate) async fn desks_status(app: AppHandle) -> Result<Value, String> {
    ensure_loaded(&app).await;
    let grid = app.state::<DeskGrid>();
    let inner = grid.inner.lock().await;
    let member = inner.member.as_ref().map(|saved| {
        json!({
            "gridId": saved.grid_id, "grid": saved.grid_name, "hub": saved.address, "fingerprint": saved.fingerprint,
            "memberId": saved.member_id, "joinedAt": saved.joined_at, "connected": inner.connected, "error": inner.member_error, "pausedUntil": saved.paused_until,
            "unreachableSince": saved.unreachable_since,
            "orders": inner.orders.len(),
        })
    });
    let hub = inner.hub.as_ref().map(|hub| hub_view(hub, &inner.tunnel));
    let hub_error = inner.hub_error.clone();
    let member_error = if inner.member.is_none() { inner.member_error.clone() } else { None };
    drop(inner);
    Ok(json!({
        // Why no cloud computer is being created, and the ones still running, so a failing or
        // forgotten cloud computer never goes unseen, even after its grid is gone.
        "cloudFallback": crate::desks::cloud::status(&app),
        "hub": hub,
        "hubError": hub_error,
        "member": member,
        "memberError": member_error,
        "hosting": crate::desks::hosting_status(&app).await,
        // Copies this computer could not remove from the company's bucket. Shown rather than
        // only recorded: they are a bill nobody asked for and data nobody is tracking, and an
        // audit line is not telling anyone.
        "bucketLeftovers": crate::desks::bucket_leftovers(),
        "desk": crate::desks::desk_status(&app).await,
    }))
}

/// Moves this computer's membership to `address`, the same hub reached another way (as after a
/// Quick Tunnel restarts). The hub must answer there with the pinned certificate and accept this
/// computer's token before anything is saved. The caller holds the admin lock.
async fn readdress(app: &AppHandle, mut saved: Saved, address: HubAddress) -> Result<(), String> {
    let membership = Membership::new(address.clone(), &saved.certificate, saved.member_id.clone(), secrets::resolve(MEMBER_TOKEN)?)?;
    membership.check_in(env!("CARGO_PKG_VERSION"), false, &[], None, &[]).await.map_err(|error| error.to_string())?;
    saved.address = address.to_string();
    persist(app, &saved)?;
    crate::security::record(Event::new("desks.readdressed").text("grid", &saved.grid_name).text("hub", &saved.address));
    let grid = app.state::<DeskGrid>();
    let mut inner = grid.inner.lock().await;
    inner.member = Some(saved);
    inner.membership = Some(membership);
    inner.member_error = None;
    inner.connected = true;
    inner.reported = None;
    grid.wake.notify_one();
    Ok(())
}

/// Joins a sandbox grid and saves the membership. The caller holds the admin lock.
async fn join_now(app: &AppHandle, company: &str, hub: HubAddress, secret: &str, name: Option<String>, fingerprint: Option<&str>) -> Result<(), String> {
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
    if let Err(error) = secrets::store(MEMBER_TOKEN, &joined.token).and_then(|_| persist(app, &saved)) {
        let _ = joined.membership.leave().await;
        let _ = secrets::delete_secret(MEMBER_TOKEN);
        let _ = std::fs::remove_file(member_path(app));
        return Err(error);
    }
    crate::security::record(Event::new("desks.joined").text("grid", &saved.grid_name).text("hub", &saved.address).text("fingerprint", &saved.fingerprint));
    let grid = app.state::<DeskGrid>();
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

/// Admin: hosts a sandbox grid on this computer's LAN or VPN address; this computer joins it too,
/// so it can host desks itself.
pub(crate) async fn desks_create(name: String, address_text: String, secret: String, tunnel: Option<String>, app: AppHandle) -> Result<Value, String> {
    let grid = app.state::<DeskGrid>();
    let _admin = grid.admin.lock().await;
    ensure_loaded(&app).await;
    {
        let inner = grid.inner.lock().await;
        if inner.hub.is_some() || hub_path(&app).exists() {
            return Err(if inner.hub.as_ref().is_some_and(|hub| hub.phase() != hub::Phase::Open) { "This computer's last sandbox grid is still being deleted; finish it with `yougori desks delete --when forget --yes`".into() } else { "This computer already runs a sandbox grid; delete it first with `yougori desks delete --when now --yes`".into() });
        }
        if let Some(saved) = inner.member.as_ref() {
            return Err(format!("This computer is in {}'s sandbox grid; leave it first with `yougori desks leave --yes`", saved.grid_name));
        }
    }
    let ip: std::net::IpAddr = address_text.trim().parse().map_err(|_| "--ip is this computer's LAN or VPN address, such as 192.168.1.20")?;
    if ip.is_loopback() || ip.is_unspecified() || !net::private(ip) {
        return Err("Use this computer's private LAN or VPN address so company computers can reach the sandbox grid".into());
    }
    let setup = TunnelSetup::parse(tunnel.as_deref());
    let tunnel_port = setup.as_ref().map(|setup| setup.port(&app, PORT, TUNNEL_PORT)).transpose()?;
    password::validate(&secret)?;
    let salt = password::new_salt();
    let password_key = derive(secret.clone(), salt.clone()).await?;
    let path = hub_path(&app);
    let key = hub::create(&path, &name, ip, PORT, None, tunnel_port, &salt)?;
    // This computer runs a sandbox grid again, so the last deletion is no longer the answer for
    // anything. Left behind, it would mark a hub that merely failed to start as deleted.
    let _ = std::fs::remove_file(deleted_path(&app));
    let started: Result<Hub, String> = async {
        secrets::store(HUB_KEY, &key)?;
        secrets::store(HUB_PASSWORD, &password_key)?;
        if let Some(setup) = &setup {
            hub_tunnel::save(&tunnel_path(&app), setup)?;
        }
        Hub::start(path.clone(), &key, &password_key, events()).await
    }
    .await;
    let hub = match started {
        Ok(hub) => hub,
        Err(error) => {
            let _ = secrets::delete_secret(HUB_KEY);
            let _ = secrets::delete_secret(HUB_PASSWORD);
            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_file(tunnel_path(&app));
            return Err(error);
        }
    };
    let fingerprint = net::fingerprint(&hub.record().certificate)?;
    let direct = HubAddress::Direct(hub.address());
    {
        let mut inner = grid.inner.lock().await;
        if let (Some(setup), Some(port)) = (setup.clone(), hub.tunnel_address().map(|entry| entry.port())) {
            hub_tunnel::keep(&app, &mut inner.tunnel, setup, port);
        }
        inner.hub = Some(hub);
    }
    crate::security::record(Event::new("desks.hosted").text("grid", &name).flag("tunnel", setup.is_some()));
    // With a tunnel, the invite waits for its address so it can be shared straight away; this
    // computer joins over its own LAN address either way.
    if setup.is_some() {
        let deadline = Instant::now() + TUNNEL_START;
        while Instant::now() < deadline {
            let tunnel = &grid.inner.lock().await.tunnel;
            if tunnel.url().is_some() || tunnel.error().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
    let reach = direct;
    // The admin's own computer joins, like any other; a failure here leaves the hub running.
    let joined = join_now(&app, &name, reach, &secret, None, Some(&fingerprint)).await;
    let mut status = desks_status(app.clone()).await?;
    status["message"] = json!(match joined {
        Ok(()) => format!("{name}'s sandbox grid is running. Share the invite with the company's computers, and the password separately; then set what the grid may take from each."),
        Err(error) => format!("{name}'s sandbox grid is running, but this computer could not join it: {error}"),
    });
    Ok(status)
}

/// Joins a sandbox grid with the invite the admin shared, committing this computer's idle time.
pub(crate) async fn desks_join(invite_text: String, secret: String, name: Option<String>, app: AppHandle) -> Result<Value, String> {
    let grid = app.state::<DeskGrid>();
    let _admin = grid.admin.lock().await;
    ensure_loaded(&app).await;
    let invite = invite::decode_desk(invite_text.trim())?;
    let member = grid.inner.lock().await.member.clone();
    if let Some(saved) = member {
        if net::normalize_fingerprint(&saved.fingerprint).as_deref() == Some(invite.fingerprint.as_str()) {
            readdress(&app, saved, invite.address).await?;
            drop(_admin);
            let mut status = desks_status(app).await?;
            status["message"] = json!(format!("This computer now reaches {}'s sandbox grid at {}.", invite.company, status["member"]["hub"].as_str().unwrap_or_default()));
            return Ok(status);
        }
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
    // joined again, which is exactly when the data matters most.
    if crate::desks::hosts_anything(&app).await {
        crate::desks::stop_hosting(&app, false).await;
    }
    join_now(&app, &invite.company, invite.address, &secret, name, Some(&invite.fingerprint)).await?;
    drop(_admin);
    let mut status = desks_status(app.clone()).await?;
    status["message"] = json!(format!("Joined {}'s sandbox grid. This computer hosts desks within the share its admin sets.", invite.company));
    Ok(status)
}

pub(crate) async fn desks_leave(app: AppHandle) -> Result<Value, String> {
    let grid = app.state::<DeskGrid>();
    let _admin = grid.admin.lock().await;
    ensure_loaded(&app).await;
    crate::desks::stop_hosting(&app, false).await;
    let (membership, name) = {
        let mut inner = grid.inner.lock().await;
        let Some(name) = inner.member.as_ref().map(|saved| saved.grid_name.clone()) else {
            inner.member_error = None;
            return Err("This computer is not in a sandbox grid".into());
        };
        let membership = inner.membership.clone();
        forget(&app, &mut inner);
        (membership, name)
    };
    let notified = match membership {
        Some(membership) => membership.leave().await.map_err(|error| error.to_string()),
        None => Err("No membership token".into()),
    };
    crate::security::record(Event::new("desks.left").text("grid", &name).succeeded(notified.is_ok()));
    Ok(json!({"left": true, "grid": name, "hubNotified": notified.is_ok(), "warning": notified.err().map(|error| format!("The hub was not told ({error}); the admin can remove this computer with `yougori desks remove`."))}))
}

/// Deletes the sandbox grid this computer hosts. `later` (the default) pauses it for three days,
/// during which `desks_restore` brings it back; `now` deletes it at once. Either way the hub keeps
/// answering until every computer has heard, so each leaves and deletes the desks it hosted.
/// `forget` stops waiting for computers that are still away and removes the hub right now.
pub(crate) async fn desks_delete(when: Option<String>, app: AppHandle) -> Result<Value, String> {
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
    let grid = app.state::<DeskGrid>();
    {
        let inner = grid.inner.lock().await;
        inner.hub.as_ref().ok_or("This computer does not run a sandbox grid")?.close(at_once)?;
    }
    crate::security::record(Event::new("desks.deleting").flag("atOnce", at_once));
    grid.wake();
    let mut status = desks_status(app).await?;
    status["message"] = json!(if at_once { "The sandbox grid is deleted. Each computer is told when it next checks in; it leaves and deletes the desks it hosted." } else { "The sandbox grid is paused and will be deleted in three days: desks are stopped but kept. Restore it before then to bring everything back." });
    Ok(status)
}

/// Takes back a deletion while the sandbox grid is still paused.
pub(crate) async fn desks_restore(app: AppHandle) -> Result<Value, String> {
    ensure_loaded(&app).await;
    let grid = app.state::<DeskGrid>();
    {
        let inner = grid.inner.lock().await;
        inner.hub.as_ref().ok_or("This computer does not run a sandbox grid")?.restore()?;
    }
    crate::security::record(Event::new("desks.restored"));
    grid.wake();
    let mut status = desks_status(app).await?;
    status["message"] = json!("The sandbox grid is restored. Its computers start and share their desks again at their next check-in.");
    Ok(status)
}

/// A deleted grid whose computers have all heard, or that waited long enough, goes for good.
async fn finish_deleted_hub(app: &AppHandle) {
    let finished = app.state::<DeskGrid>().inner.lock().await.hub.as_ref().is_some_and(Hub::finished);
    if finished {
        let _ = forget_hub(app.clone()).await;
    }
}

/// Removes the hub at once: its settings, keys and tunnel, and this computer's own membership.
async fn forget_hub(app: AppHandle) -> Result<Value, String> {
    let grid = app.state::<DeskGrid>();
    let _admin = grid.admin.lock().await;
    ensure_loaded(&app).await;
    let own = {
        let mut inner = grid.inner.lock().await;
        let hub = inner.hub.take();
        if hub.is_none() && !hub_path(&app).exists() {
            return Err("This computer does not run a sandbox grid".into());
        }
        let id = hub.as_ref().map(|hub| hub.record().id).or_else(|| hub::load(&hub_path(&app)).ok().map(|record| record.id));
        drop(hub);
        inner.tunnel.stop();
        let _ = std::fs::remove_file(tunnel_path(&app));
        std::fs::remove_file(hub_path(&app)).map_err(|error| format!("Cannot remove the sandbox grid's settings: {error}"))?;
        // Written only once the record has actually gone, so the cloud fallback can tell a grid
        // this computer deleted from one whose record is simply not readable or was moved aside.
        // Without it, retiring the cloud computers rests on a file being missing.
        let _ = std::fs::write(deleted_path(&app), b"");
        let _ = secrets::delete_secret(HUB_KEY);
        let _ = secrets::delete_secret(HUB_PASSWORD);
        inner.hub_error = None;
        let own = inner.member.as_ref().is_some_and(|saved| Some(&saved.grid_id) == id.as_ref());
        if own {
            forget(&app, &mut inner);
        }
        own
    };
    if own {
        crate::desks::stop_hosting(&app, true).await;
    }
    crate::security::record(Event::new("desks.deleted"));
    Ok(json!({"deleted": true}))
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
fn deleted_path(app: &AppHandle) -> PathBuf {
    folder(app).join("desks-hub.deleted")
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

/// What the cloud fallback needs from the hub this computer runs: the settings, why a computer is
/// needed now (if one is), how the grid is reached from outside, and the computers in it.
pub(crate) async fn cloud_view(app: &AppHandle, grid: &DeskGrid) -> CloudSight {
    let inner = grid.inner.lock().await;
    let Some(hub) = inner.hub.as_ref() else {
        let present = match std::fs::metadata(hub_path(app)) {
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
        return sight_without_hub(present, deleted_path(app).exists());
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
    ensure_loaded(&app).await;
    if let Some(saved) = grid.inner.lock().await.member.as_ref() {
        return Err(format!("This computer is already in {}'s sandbox grid", saved.grid_name));
    }
    let text = |key: &str| membership[key].as_str().map(str::trim).filter(|value| !value.is_empty()).map(str::to_owned).ok_or_else(|| format!("The membership is missing {key}"));
    let (company, address, fingerprint, member_id, token) = (text("company")?, text("address")?, text("fingerprint")?, text("memberId")?, text("memberToken")?);
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
    if let Err(error) = secrets::store(MEMBER_TOKEN, &joined.token).and_then(|_| persist(&app, &saved)) {
        let _ = secrets::delete_secret(MEMBER_TOKEN);
        let _ = std::fs::remove_file(member_path(&app));
        return Err(error);
    }
    crate::security::record(Event::new("desks.adopted_membership").text("grid", &saved.grid_name).text("hub", &saved.address));
    let mut inner = grid.inner.lock().await;
    inner.member = Some(saved);
    inner.membership = Some(joined.membership);
    inner.member_error = None;
    inner.connected = true;
    inner.reported = None;
    grid.wake.notify_one();
    drop(inner);
    drop(_admin);
    let mut status = desks_status(app).await?;
    status["message"] = json!(format!("This computer joined {company}'s sandbox grid as a cloud computer."));
    Ok(status)
}

/// Admin: takes a computer out of the sandbox grid; its desks go back to waiting and are placed
/// again, with their data still on it in case it rejoins.
pub(crate) async fn desks_member_remove(member_id: String, app: AppHandle) -> Result<Value, String> {
    let result = with_hub(&app, |hub| hub.enterprise(json!({"action": "computerRemove", "id": member_id}))).await?;
    crate::security::record(Event::new("desks.member.removed").text("memberId", &member_id));
    Ok(result)
}

/// Admin: what the grid may take from a computer. Fields left out keep their current values;
/// `suggested` goes back to the automatic share.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn desks_member_share(member_id: String, cpu: Option<f64>, memory_gb: Option<f64>, disk_gb: Option<f64>, gpu: Option<bool>, idle_only: Option<bool>, suggested: Option<bool>, app: AppHandle) -> Result<Value, String> {
    let result = with_hub(&app, |hub| {
        if suggested == Some(true) {
            return hub.set_member_share(&member_id, None);
        }
        let current = hub.member_share(&member_id)?;
        let share = Share::checked(cpu.unwrap_or(current.cpu), memory_gb.unwrap_or(current.memory_gb), disk_gb.unwrap_or(current.disk_gb), gpu.unwrap_or(current.gpu), idle_only.unwrap_or(current.idle_only))?;
        hub.set_member_share(&member_id, Some(share))
    })
    .await?;
    crate::security::record(Event::new("desks.member.share").text("memberId", &member_id).text("share", &result["share"].to_string()));
    Ok(result)
}

pub(crate) async fn desks_manage(mut request: Value, app: AppHandle) -> Result<Value, String> {
    if request["action"]=="imageImport" { return crate::desks::media::import(&app,request).await; }
    // The parking bucket: its keys go to this computer's OS vault and the running hub, never
    // into the hub's record or to anyone but a computer moving a desk.
    if request["action"] == "parkingSet" {
        let credentials = json!({"provider": request["provider"], "location": request["location"], "accessKey": request["accessKey"], "secretKey": request["secretKey"]});
        if !credentials["accessKey"].as_str().is_some_and(|key| !key.trim().is_empty()) || !credentials["secretKey"].as_str().is_some_and(|key| !key.trim().is_empty()) {
            return Err("Give the bucket's access key and secret key".into());
        }
        crate::desks::parking::open(&credentials)?;
        if let Some(body) = request.as_object_mut() { body.remove("accessKey"); body.remove("secretKey"); }
        ensure_loaded(&app).await;
        let grid = app.state::<DeskGrid>();
        let inner = grid.inner.lock().await;
        let hub = inner.hub.as_ref().ok_or("Parking is set up on the computer that hosts the sandbox grid")?;
        let result = hub.enterprise(request)?;
        secrets::store(PARKING, &credentials.to_string())?;
        hub.set_parking(Some(credentials));
        crate::security::record(Event::new("desks.parking.set"));
        return Ok(result);
    }
    if request["action"] == "parkingClear" {
        ensure_loaded(&app).await;
        let grid = app.state::<DeskGrid>();
        let inner = grid.inner.lock().await;
        let hub = inner.hub.as_ref().ok_or("Parking is set up on the computer that hosts the sandbox grid")?;
        let result = hub.enterprise(request)?;
        let _ = secrets::delete_secret(PARKING);
        hub.set_parking(None);
        crate::security::record(Event::new("desks.parking.cleared"));
        return Ok(result);
    }
    // A connector's credential: the identifiers go to the hub's record, the secret to this
    // computer's OS vault and the running hub, never to the record or anyone else.
    if matches!(request["action"].as_str(), Some("connectionAdd" | "connectionCredential")) && request.get("credential").is_some() {
        let provider: yougori_grid::enterprise::Provider = match request["action"].as_str() {
            Some("connectionAdd") => serde_json::from_value(request["provider"].clone()).map_err(|_| "Unsupported enterprise provider")?,
            _ => {
                ensure_loaded(&app).await;
                let grid = app.state::<DeskGrid>();
                let inner = grid.inner.lock().await;
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
        ensure_loaded(&app).await;
        let grid = app.state::<DeskGrid>();
        let inner = grid.inner.lock().await;
        let hub = inner.hub.as_ref().ok_or("Credentials are entered on the computer that hosts the sandbox grid")?;
        let result = hub.enterprise(request)?;
        let id = result["id"].as_str().unwrap_or_default().to_owned();
        let secret = Value::Object(secret);
        secrets::store(&format!("{CONNECTION}{id}"), &secret.to_string())?;
        hub.set_connection_credential(&id, Some(secret));
        crate::security::record(Event::new("desks.connection.credential").text("connectionId", &id));
        grid.wake();
        return Ok(result);
    }
    if matches!(request["action"].as_str(), Some("connectionRemove")) || (request["action"] == "connectionCredential" && request["set"] == false) {
        ensure_loaded(&app).await;
        let grid = app.state::<DeskGrid>();
        let inner = grid.inner.lock().await;
        let id = request["id"].as_str().unwrap_or_default().to_owned();
        let result = match inner.hub.as_ref() {
            Some(hub) => hub.enterprise(request)?,
            None => crate::desks::management_session()?.manage(request).await?,
        };
        let _ = secrets::delete_secret(&format!("{CONNECTION}{id}"));
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
    ensure_loaded(&app).await;
    let grid = app.state::<DeskGrid>();
    { let inner = grid.inner.lock().await;
      if let Some(hub) = &inner.hub { let result = hub.enterprise(request); grid.wake(); return result; }
    }
    let session = crate::desks::management_session()?;
    session.manage(request).await
}

/// App commands, from the main window only.
pub(crate) mod commands {
    use super::*;

    fn main_window(window: &WebviewWindow) -> Result<(), String> {
        if window.label() == "main" { Ok(()) } else { Err("A sandbox grid is managed from the main Yougori window".into()) }
    }

    #[tauri::command]
    pub async fn desks_manage(app: AppHandle, window: WebviewWindow, request: Value) -> Result<Value, String> {
        main_window(&window)?;
        super::desks_manage(request, app).await
    }

    #[tauri::command]
    pub async fn desks_status(app: AppHandle, window: WebviewWindow) -> Result<Value, String> {
        main_window(&window)?;
        super::desks_status(app).await
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
    pub async fn desks_join(app: AppHandle, window: WebviewWindow, invite: String, password: String, name: Option<String>) -> Result<Value, String> {
        main_window(&window)?;
        super::desks_join(invite, password, name, app).await
    }

    #[tauri::command]
    pub async fn desks_leave(app: AppHandle, window: WebviewWindow) -> Result<Value, String> {
        main_window(&window)?;
        super::desks_leave(app).await
    }

    #[tauri::command]
    pub async fn desks_delete(app: AppHandle, window: WebviewWindow, when: Option<String>) -> Result<Value, String> {
        main_window(&window)?;
        super::desks_delete(when, app).await
    }

    #[tauri::command]
    pub async fn desks_adopt_membership(app: AppHandle, window: WebviewWindow, membership: Value) -> Result<Value, String> {
        main_window(&window)?;
        super::desks_adopt_membership(membership, app).await
    }

    #[tauri::command]
    pub async fn desks_restore(app: AppHandle, window: WebviewWindow) -> Result<Value, String> {
        main_window(&window)?;
        super::desks_restore(app).await
    }

    #[tauri::command]
    pub async fn desks_member_remove(app: AppHandle, window: WebviewWindow, member_id: String) -> Result<Value, String> {
        main_window(&window)?;
        super::desks_member_remove(member_id, app).await
    }

    #[tauri::command]
    #[allow(clippy::too_many_arguments)]
    pub async fn desks_member_share(app: AppHandle, window: WebviewWindow, member_id: String, cpu: Option<f64>, memory_gb: Option<f64>, disk_gb: Option<f64>, gpu: Option<bool>, idle_only: Option<bool>, suggested: Option<bool>) -> Result<Value, String> {
        main_window(&window)?;
        super::desks_member_share(member_id, cpu, memory_gb, disk_gb, gpu, idle_only, suggested, app).await
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
}
