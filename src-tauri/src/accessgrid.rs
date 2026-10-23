//! Access Grid on this computer: the company's credential hub when this computer runs it, and
//! this person's sign-in to it either way. The hub keeps credentials sealed with a key in the OS
//! vault and sends requests with them for people's agents (`yougori access mcp`), so agents
//! never hold a value. It has its own record, keys, port (7465) and invite (`access-invite:`),
//! separate from the Neo Grid and the Sandbox Grid.
use crate::{
    hub_tunnel::{self, TunnelSetup, TunnelState},
    projects::secrets,
    security::Event,
    store::PlatformStore,
    AppHandle, WebviewWindow,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashSet,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tauri::Manager;
use yougori_grid::{
    access::{
        backup,
        hub::{self, Hub, Owner, Phase},
        member::{self, CallError, SignedIn},
        seal,
    },
    invite::{self, Invite},
    net::{self, HubAddress},
    password,
};

const HUB_KEY: &str = "yougori-access-hub-key";
const SEAL_KEY: &str = "yougori-access-hub-seal";
/// This computer's device token: it signs the person in again by itself.
const DEVICE_TOKEN: &str = "yougori-access-device";
/// Beside the Neo Grid (7460/7461), a closed bounty (7462) and the Sandbox Grid (7463/7464).
pub(crate) const PORT: u16 = 7465;
const TUNNEL_PORT: u16 = 7466;
const TUNNEL_START: Duration = Duration::from_secs(60);
/// The page asks often; a hub that does not answer quickly is shown as unreachable.
const STATUS_WAIT: Duration = Duration::from_secs(6);
/// How often an approver's computer looks for requests waiting for them.
const WATCH: Duration = Duration::from_secs(15);

#[derive(Default)]
pub struct AccessGrid {
    inner: tokio::sync::Mutex<Inner>,
    /// Serializes creating, deleting, signing in and out.
    admin: tokio::sync::Mutex<()>,
}

#[derive(Default)]
struct Inner {
    loaded: bool,
    hub: Option<Hub>,
    hub_error: Option<String>,
    tunnel: TunnelState,
    member: Option<Saved>,
    /// The current sign-in: its token, when it lapses, and whether it had a second factor.
    session: Option<(String, i64, bool)>,
    /// Why the last call failed, shown until one succeeds.
    member_error: Option<String>,
    /// The hub ended this computer's sign-in (password changed, signed out, removed): nothing is
    /// retried until the person signs in again, so no lockout builds up.
    refused: Option<String>,
    /// Requests an approver here has already been told about.
    told: HashSet<String>,
}

/// This person's sign-in, saved on disk; the device token is in the OS vault.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Saved {
    version: u8,
    access_id: String,
    company: String,
    address: String,
    certificate: String,
    fingerprint: String,
    username: String,
    person_id: String,
    #[serde(default)]
    device_id: String,
    signed_in_at: i64,
}

fn folder(app: &AppHandle) -> PathBuf {
    app.state::<PlatformStore>().data_folder("grid")
}

fn hub_path(app: &AppHandle) -> PathBuf {
    folder(app).join("access-hub.json")
}

fn member_path(app: &AppHandle) -> PathBuf {
    folder(app).join("access-member.json")
}

fn tunnel_path(app: &AppHandle) -> PathBuf {
    folder(app).join("access-tunnel.json")
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

async fn start_hub(app: &AppHandle, inner: &mut Inner) {
    let path = hub_path(app);
    if !path.exists() {
        return;
    }
    match secrets::hub_keys(secrets::look_up(HUB_KEY), secrets::look_up(SEAL_KEY)) {
        secrets::Keys::Ready(key, seal_key) => match Hub::start(path, &key, &seal_key, events()).await {
            Ok(hub) => {
                if let (Some(port), Some(setup)) = (hub.tunnel_address().map(|entry| entry.port()), hub_tunnel::load(&tunnel_path(app))) {
                    hub_tunnel::keep(app, &mut inner.tunnel, setup, port);
                }
                inner.hub = Some(hub);
                inner.hub_error = None;
            }
            Err(error) => inner.hub_error = Some(error),
        },
        secrets::Keys::Gone => inner.hub_error = Some("The Access Grid's keys are missing from the OS credential vault, so its credentials cannot be read. Restore it from a backup, or delete it and create it again.".into()),
        // The vault would not answer. Every credential this grid holds is still there; saying
        // "restore from a backup, or delete it and create it again" over a vault that is merely
        // not ready yet is advice that destroys a company's credential hub.
        secrets::Keys::NotYet => {
            inner.hub_error = Some("The Access Grid's keys could not be read from the OS credential vault yet, so it has not started. Yougori keeps trying; nothing is changed meanwhile.".into());
            inner.loaded = false;
        }
    }
}

async fn ensure_loaded(app: &AppHandle) {
    let grid = app.state::<AccessGrid>();
    let mut inner = grid.inner.lock().await;
    if inner.loaded {
        return;
    }
    inner.loaded = true;
    start_hub(app, &mut inner).await;
    if let Ok(bytes) = std::fs::read(member_path(app)) {
        match serde_json::from_slice::<Saved>(&bytes) {
            Ok(saved) => inner.member = Some(saved),
            Err(_) => inner.member_error = Some("This computer's Access Grid sign-in is damaged; sign in again".into()),
        }
    }
}

/// Forgets this computer's sign-in.
fn forget(app: &AppHandle, inner: &mut Inner) {
    inner.member = None;
    inner.session = None;
    inner.member_error = None;
    inner.refused = None;
    inner.told.clear();
    let _ = std::fs::remove_file(member_path(app));
    let _ = secrets::delete_secret(DEVICE_TOKEN);
}

/// The hub's status with its tunnel and the invite people sign in with: the tunnel's address
/// when it has one, else the hub's LAN address.
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
    if let (Some(address), Phase::Open) = (reach, hub.phase()) {
        status["invite"] = json!(invite::encode_access(&Invite { company: record.company.clone(), address, fingerprint: hub.fingerprint().to_owned() }));
    }
    status
}

/// Saves a fresh sign-in and makes it current. The caller holds the admin lock.
async fn adopt(app: &AppHandle, signed: SignedIn, address: &HubAddress, username: &str) -> Result<(), String> {
    let device = signed.device_token.clone().ok_or("The Access Grid did not let this computer stay signed in")?;
    let saved = Saved {
        version: 2,
        access_id: signed.access_id.clone(),
        company: signed.company.clone(),
        address: address.to_string(),
        certificate: signed.certificate.clone(),
        fingerprint: signed.fingerprint.clone(),
        username: username.to_owned(),
        person_id: signed.person["id"].as_str().unwrap_or_default().to_owned(),
        device_id: signed.device_id.clone().unwrap_or_default(),
        signed_in_at: yougori_grid::now(),
    };
    secrets::store(DEVICE_TOKEN, &device)?;
    if let Err(error) = persist(app, &saved) {
        let _ = secrets::delete_secret(DEVICE_TOKEN);
        return Err(error);
    }
    crate::security::record(Event::new("access.signedin").text("company", &saved.company).text("hub", &saved.address).text("fingerprint", &saved.fingerprint).flag("strong", signed.strong));
    let grid = app.state::<AccessGrid>();
    let mut inner = grid.inner.lock().await;
    inner.member = Some(saved);
    inner.session = Some((signed.token, signed.expires_at, signed.strong));
    inner.member_error = None;
    inner.refused = None;
    Ok(())
}

/// What a refusal or deletion means for this computer's sign-in.
async fn ended(app: &AppHandle, error: &CallError) {
    let grid = app.state::<AccessGrid>();
    let mut inner = grid.inner.lock().await;
    let company = inner.member.as_ref().map(|saved| saved.company.clone()).unwrap_or_default();
    match error {
        CallError::Deleted(_) => {
            crate::security::record(Event::new("access.deleted.left").text("company", &company));
            forget(app, &mut inner);
            inner.member_error = Some(format!("{company} deleted its Access Grid; this computer signed out of it."));
        }
        CallError::Refused { code, .. } if code == "device_ended" => {
            inner.session = None;
            inner.refused = Some(format!("{company}'s Access Grid ended this computer's sign-in: your password changed, two-step was reset, the computer was signed out, or it was not used for 30 days. Sign in again."));
        }
        CallError::Refused { message, .. } | CallError::Failed(message) => inner.member_error = Some(message.clone()),
        CallError::SignedOut => inner.session = None,
    }
}

/// The current sign-in, signing in again with the device token when it lapsed.
async fn session(app: &AppHandle) -> Result<(HubAddress, String, String), String> {
    ensure_loaded(app).await;
    let grid = app.state::<AccessGrid>();
    let (saved, current) = {
        let inner = grid.inner.lock().await;
        if let Some(refused) = &inner.refused {
            return Err(refused.clone());
        }
        let saved = inner.member.clone().ok_or("This computer is not signed in to an Access Grid. Sign in with the invite your admin shared: yougori access signin --invite INVITE --username NAME")?;
        (saved, inner.session.clone())
    };
    let address = HubAddress::parse(&saved.address)?;
    if let Some((token, _, _)) = current.filter(|(_, expires, _)| *expires > yougori_grid::now() + 60) {
        return Ok((address, saved.certificate, token));
    }
    let device = secrets::resolve(DEVICE_TOKEN).map_err(|_| "This computer's Access Grid sign-in is missing from the OS credential vault; sign in again".to_owned())?;
    match member::resume(&address, &saved.certificate, &device, &crate::grid::computer_name(app)).await {
        Ok(signed) => {
            let mut inner = grid.inner.lock().await;
            inner.session = Some((signed.token.clone(), signed.expires_at, signed.strong));
            inner.member_error = None;
            Ok((address, saved.certificate, signed.token))
        }
        Err(error) => {
            let message = error.to_string();
            ended(app, &error).await;
            Err(grid.inner.lock().await.refused.clone().unwrap_or(message))
        }
    }
}

/// One call to the hub as the signed-in person; a lapsed sign-in is renewed once.
async fn call(app: &AppHandle, action: &str, body: Value) -> Result<Value, String> {
    for attempt in 0..2 {
        let (address, certificate, token) = session(app).await?;
        match member::call(&address, &certificate, &token, action, &body).await {
            Ok(value) => {
                app.state::<AccessGrid>().inner.lock().await.member_error = None;
                return Ok(value);
            }
            Err(CallError::SignedOut) if attempt == 0 => app.state::<AccessGrid>().inner.lock().await.session = None,
            Err(error) => {
                let message = error.to_string();
                if matches!(error, CallError::Deleted(_) | CallError::Failed(_)) || matches!(&error, CallError::Refused { code, .. } if code == "paused") {
                    ended(app, &error).await;
                }
                return Err(message);
            }
        }
    }
    Err("The Access Grid ended this sign-in; sign in again".into())
}

/// A request waiting for this approver: tells them once, outside the app when it is not in front.
#[cfg(target_os = "windows")]
fn notify(app: &AppHandle, count: usize) {
    use tauri::UserAttentionType;
    use tauri_plugin_notification::NotificationExt;
    let window = app.get_webview_window("main");
    if window.as_ref().is_some_and(|window| window.is_focused().unwrap_or(false)) {
        return;
    }
    if let Some(window) = window {
        let _ = window.request_user_attention(Some(UserAttentionType::Informational));
    }
    let body = if count == 1 { "An agent is waiting for your approval in Access Grid." } else { "Agents are waiting for your approval in Access Grid." };
    let _ = app.notification().builder().title("Yougori · approval needed").body(body).show();
}

#[cfg(not(target_os = "windows"))]
fn notify(_app: &AppHandle, _count: usize) {}

/// Looks for requests waiting for this approver.
async fn watch(app: &AppHandle) {
    let signed_in = {
        let grid = app.state::<AccessGrid>();
        let inner = grid.inner.lock().await;
        inner.member.is_some() && inner.refused.is_none()
    };
    if !signed_in {
        return;
    }
    let Ok(Ok(me)) = tokio::time::timeout(STATUS_WAIT, call(app, "me", json!({}))).await else { return };
    let permission = me["person"]["permission"].as_str().unwrap_or_default();
    if !matches!(permission, "approver" | "admin") {
        return;
    }
    let username = me["person"]["username"].as_str().unwrap_or_default().to_owned();
    let own_too = me["canApproveOwn"] == true;
    let waiting: Vec<String> = me["overview"]["waiting"].as_array().into_iter().flatten().filter(|request| own_too || request["person"].as_str() != Some(username.as_str())).filter_map(|request| request["id"].as_str().map(str::to_owned)).collect();
    let fresh = {
        let grid = app.state::<AccessGrid>();
        let mut inner = grid.inner.lock().await;
        inner.told.retain(|id| waiting.contains(id));
        let fresh: Vec<String> = waiting.iter().filter(|id| !inner.told.contains(*id)).cloned().collect();
        inner.told.extend(fresh.iter().cloned());
        fresh.len()
    };
    if fresh > 0 {
        notify(app, fresh);
    }
}

/// A deleted hub that has told people long enough is removed from this computer.
async fn finish_deleted_hub(app: &AppHandle) {
    let grid = app.state::<AccessGrid>();
    let done = grid.inner.lock().await.hub.as_ref().is_some_and(Hub::told_enough);
    if done {
        let _admin = grid.admin.lock().await;
        remove_hub(app, &mut *grid.inner.lock().await);
    }
}

fn remove_hub(app: &AppHandle, inner: &mut Inner) {
    let path = hub_path(app);
    inner.tunnel.stop();
    inner.hub = None;
    inner.hub_error = None;
    let activity = hub::activity_path(&path);
    for file in [path, activity.clone(), activity.with_extension("jsonl.1"), tunnel_path(app)] {
        let _ = std::fs::remove_file(file);
    }
    let _ = secrets::delete_secret(HUB_KEY);
    let _ = secrets::delete_secret(SEAL_KEY);
}

pub(crate) fn start(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let shutdown = crate::automation::shutdown_signal(&app);
        ensure_loaded(&app).await;
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = tokio::time::sleep(WATCH) => {}
            }
            watch(&app).await;
            finish_deleted_hub(&app).await;
        }
        let grid = app.state::<AccessGrid>();
        let mut inner = grid.inner.lock().await;
        inner.tunnel.stop();
        inner.hub = None;
    });
}

pub(crate) async fn access_status(app: AppHandle) -> Result<Value, String> {
    ensure_loaded(&app).await;
    let (hub, hub_error, member) = {
        let grid = app.state::<AccessGrid>();
        let inner = grid.inner.lock().await;
        (inner.hub.as_ref().map(|hub| hub_view(hub, &inner.tunnel)), inner.hub_error.clone(), inner.member.clone())
    };
    let me = match &member {
        Some(_) => match tokio::time::timeout(STATUS_WAIT, call(&app, "me", json!({}))).await {
            Ok(Ok(me)) => Some(me),
            Ok(Err(_)) => None,
            Err(_) => {
                app.state::<AccessGrid>().inner.lock().await.member_error = Some("The Access Grid did not answer in time".into());
                None
            }
        },
        None => None,
    };
    let (member, member_error, refused) = {
        let grid = app.state::<AccessGrid>();
        let inner = grid.inner.lock().await;
        (inner.member.clone(), inner.member_error.clone(), inner.refused.clone())
    };
    let member = member.map(|saved| {
        json!({
            "accessId": saved.access_id, "company": saved.company, "hub": saved.address, "fingerprint": saved.fingerprint,
            "username": saved.username, "deviceId": saved.device_id, "signedInAt": saved.signed_in_at, "connected": me.is_some(),
            "error": refused.clone().or(member_error.clone()), "needsSignIn": refused.is_some(),
        })
    });
    Ok(json!({
        "hub": hub,
        "hubError": hub_error,
        "member": member,
        "memberError": if member.is_none() { member_error } else { None },
        "me": me,
        "suggestedAddress": if hub.is_none() { crate::bounty::suggested_address() } else { None },
        "mcp": {"command": "yougori", "args": ["access", "mcp"]},
    }))
}

/// Admin: runs an Access Grid on this computer's LAN or VPN address and signs this computer in
/// as its first admin.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn access_create(company: String, address_text: String, username: String, name: Option<String>, secret: String, tunnel: Option<String>, app: AppHandle) -> Result<Value, String> {
    let grid = app.state::<AccessGrid>();
    let _admin = grid.admin.lock().await;
    ensure_loaded(&app).await;
    {
        let inner = grid.inner.lock().await;
        if inner.hub.is_some() || hub_path(&app).exists() {
            return Err("This computer already runs an Access Grid; delete it first with `yougori access delete --when now --yes`".into());
        }
        if let Some(saved) = &inner.member {
            return Err(format!("This computer is signed in to {}'s Access Grid; sign out first with `yougori access signout --yes`", saved.company));
        }
    }
    let ip: std::net::IpAddr = address_text.trim().parse().map_err(|_| "--ip is this computer's LAN or VPN address, such as 192.168.1.20")?;
    if ip.is_loopback() || ip.is_unspecified() || !net::private(ip) {
        return Err("Use this computer's private LAN or VPN address so company computers can reach the Access Grid".into());
    }
    let username = yougori_grid::access::policy::username(&username)?;
    let setup = TunnelSetup::parse(tunnel.as_deref());
    let tunnel_port = setup.as_ref().map(|setup| setup.port(&app, PORT, TUNNEL_PORT)).transpose()?;
    password::validate(&secret)?;
    let salt = password::new_salt();
    let key = {
        let (secret, salt) = (secret.clone(), salt.clone());
        tokio::task::spawn_blocking(move || password::derive(&secret, &salt)).await.map_err(|error| error.to_string())??
    };
    let path = hub_path(&app);
    let tls_key = hub::create(&path, &company, ip, PORT, tunnel_port, Owner { username: username.clone(), name: name.unwrap_or_default(), salt, key })?;
    let started: Result<Hub, String> = async {
        let seal_key = seal::new_key()?;
        secrets::store(HUB_KEY, &tls_key)?;
        secrets::store(SEAL_KEY, &seal_key)?;
        if let Some(setup) = &setup {
            hub_tunnel::save(&tunnel_path(&app), setup)?;
        }
        Hub::start(path.clone(), &tls_key, &seal_key, events()).await
    }
    .await;
    let hub = match started {
        Ok(hub) => hub,
        Err(error) => {
            let _ = secrets::delete_secret(HUB_KEY);
            let _ = secrets::delete_secret(SEAL_KEY);
            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_file(tunnel_path(&app));
            return Err(error);
        }
    };
    let invite = Invite { company: hub.record().company, address: HubAddress::Direct(hub.address()), fingerprint: hub.fingerprint().to_owned() };
    {
        let mut inner = grid.inner.lock().await;
        if let (Some(setup), Some(port)) = (setup.clone(), hub.tunnel_address().map(|entry| entry.port())) {
            hub_tunnel::keep(&app, &mut inner.tunnel, setup, port);
        }
        inner.hub = Some(hub);
        inner.hub_error = None;
    }
    crate::security::record(Event::new("access.hosted").text("company", &invite.company).flag("tunnel", setup.is_some()));
    if setup.is_some() {
        let deadline = Instant::now() + TUNNEL_START;
        while Instant::now() < deadline {
            // The lock is let go before waiting, so the page's status calls are never held up.
            let settled = {
                let inner = grid.inner.lock().await;
                inner.tunnel.url().is_some() || inner.tunnel.error().is_some()
            };
            if settled {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
    // This computer signs in over its own LAN address, like anyone else.
    let signed = match member::signin(&invite, &username, &secret, None, &crate::grid::computer_name(&app)).await {
        Ok(signed) => adopt(&app, signed, &invite.address, &username).await,
        Err(error) => Err(error),
    };
    drop(_admin);
    let mut status = access_status(app).await?;
    status["message"] = json!(match signed {
        Ok(()) => format!("{}'s Access Grid is running and you are its admin. Add people and credentials, then share the invite; each person signs in with their own password.", invite.company),
        Err(error) => format!("{}'s Access Grid is running, but this computer could not sign in to it: {error}", invite.company),
    });
    Ok(status)
}

/// Admin: deletes this computer's Access Grid. `later` (default) pauses it for three days, when
/// nobody signs in or uses anything and `access_restore` takes it back; `now` wipes its
/// credentials, people and rules at once and tells people's computers so for 30 days; `forget`
/// removes it from this computer without waiting.
pub(crate) async fn access_delete(when: Option<String>, app: AppHandle) -> Result<Value, String> {
    let grid = app.state::<AccessGrid>();
    let _admin = grid.admin.lock().await;
    ensure_loaded(&app).await;
    let mut inner = grid.inner.lock().await;
    if inner.hub.is_none() && !hub_path(&app).exists() {
        return Err("This computer does not run an Access Grid".into());
    }
    let company = inner.hub.as_ref().map(|hub| hub.record().company).unwrap_or_default();
    let fingerprint = inner.hub.as_ref().map(|hub| hub.fingerprint().to_owned());
    let when = when.as_deref().unwrap_or("later");
    deletion_allowed(when, inner.hub.is_some())?;
    let message = match (when, inner.hub.as_ref()) {
        ("later", Some(hub)) => {
            let until = hub.close_later()?;
            let date = chrono::DateTime::from_timestamp(until, 0).map(|at| at.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M").to_string()).unwrap_or_default();
            format!("{company}'s Access Grid is paused and will be deleted on {date}. Nobody signs in or uses its credentials until then; `yougori access restore` takes it back.")
        }
        ("now", Some(hub)) => {
            hub.close_now()?;
            format!("{company}'s Access Grid was deleted with its credentials, people and rules. It keeps telling people's computers for 30 days, then removes itself; `yougori access delete --when forget --yes` removes it at once.")
        }
        ("forget", _) => {
            remove_hub(&app, &mut inner);
            format!("{company}'s Access Grid was removed from this computer with its credentials, people, rules and activity log.")
        }
        (other, _) => return Err(format!("--when is later, now or forget, not {other}")),
    };
    if when != "later" && inner.member.as_ref().is_some_and(|saved| Some(&saved.fingerprint) == fingerprint.as_ref()) {
        forget(&app, &mut inner);
    }
    crate::security::record(Event::new("access.deleted").text("company", &company).text("when", when));
    Ok(json!({"deleted": when != "later", "paused": when == "later", "message": message}))
}

/// Pausing and closing need the hub running; only `forget` may remove a hub that did not
/// start, so a default or mistyped delete never wipes the grid and its keys.
fn deletion_allowed(when: &str, hub_running: bool) -> Result<(), String> {
    match (when, hub_running) {
        ("forget", _) | ("later" | "now", true) => Ok(()),
        ("later" | "now", false) => Err("This computer's Access Grid is not running, so it cannot be paused or closed. Start Yougori again to bring it back, or remove it at once with `yougori access delete --when forget --yes`.".into()),
        (other, _) => Err(format!("--when is later, now or forget, not {other}")),
    }
}

/// Admin: takes back a deletion while the grid is still paused.
pub(crate) async fn access_restore(app: AppHandle) -> Result<Value, String> {
    ensure_loaded(&app).await;
    let grid = app.state::<AccessGrid>();
    let inner = grid.inner.lock().await;
    let hub = inner.hub.as_ref().ok_or("This computer does not run an Access Grid")?;
    hub.restore()?;
    crate::security::record(Event::new("access.restored").text("company", &hub.record().company));
    Ok(json!({"restored": true, "message": "The Access Grid is back; people sign in and use it again."}))
}

/// Signs this person in to the Access Grid the admin's invite names: with their password (and
/// two-step code), or through the company's identity provider (`sso`).
pub(crate) async fn access_signin(invite_text: String, username: Option<String>, secret: Option<String>, code: Option<String>, sso: Option<bool>, app: AppHandle) -> Result<Value, String> {
    let grid = app.state::<AccessGrid>();
    let _admin = grid.admin.lock().await;
    ensure_loaded(&app).await;
    let invite = invite::decode_access(invite_text.trim())?;
    let saved = grid.inner.lock().await.member.clone();
    // The same grid at a new address (a backup restored elsewhere, a new tunnel link): this
    // computer's device token moves it there without a password.
    if let Some(saved) = &saved {
        if net::normalize_fingerprint(&saved.fingerprint).as_deref() == Some(invite.fingerprint.as_str()) && invite.address.to_string() != saved.address {
            if let Ok(device) = secrets::resolve(DEVICE_TOKEN) {
                if let Ok(signed) = member::resume(&invite.address, &saved.certificate, &device, &crate::grid::computer_name(&app)).await {
                    let mut moved = saved.clone();
                    moved.address = invite.address.to_string();
                    persist(&app, &moved)?;
                    let mut inner = grid.inner.lock().await;
                    inner.member = Some(moved);
                    inner.session = Some((signed.token, signed.expires_at, signed.strong));
                    inner.member_error = None;
                    inner.refused = None;
                    drop(inner);
                    drop(_admin);
                    let mut status = access_status(app).await?;
                    status["message"] = json!(format!("This computer now reaches {}'s Access Grid at {}.", invite.company, invite.address));
                    return Ok(status);
                }
            }
        }
    }
    let computer = crate::grid::computer_name(&app);
    let signed = if sso.unwrap_or(false) {
        member::signin_sso(&invite, &computer, |url| crate::workspace::open_workspace_url(url.to_owned())).await?
    } else {
        let username = yougori_grid::access::policy::username(username.as_deref().unwrap_or_default())?;
        let secret = secret.filter(|secret| !secret.is_empty()).ok_or("Give your Access Grid password")?;
        member::signin(&invite, &username, &secret, code.as_deref().filter(|code| !code.trim().is_empty()), &computer).await?
    };
    let username = signed.person["username"].as_str().unwrap_or_default().to_owned();
    if let Some(saved) = &saved {
        let same = net::normalize_fingerprint(&saved.fingerprint).as_deref() == Some(invite.fingerprint.as_str()) && saved.username == username;
        if !same {
            return Err(format!("This computer is signed in to {}'s Access Grid as {}. Sign out first with `yougori access signout --yes`.", saved.company, saved.username));
        }
    }
    let company = signed.company.clone();
    adopt(&app, signed, &invite.address, &username).await?;
    drop(_admin);
    let mut status = access_status(app).await?;
    status["message"] = json!(format!("Signed in to {company}'s Access Grid as {username}. Connect your agents with `yougori access mcp`."));
    Ok(status)
}

/// Signs this person out on this computer and at the hub.
pub(crate) async fn access_signout(app: AppHandle) -> Result<Value, String> {
    let grid = app.state::<AccessGrid>();
    let _admin = grid.admin.lock().await;
    ensure_loaded(&app).await;
    let saved = grid.inner.lock().await.member.clone().ok_or("This computer is not signed in to an Access Grid")?;
    // The hub forgets this computer too, so its device token is useless from now on.
    if !saved.device_id.is_empty() {
        let _ = tokio::time::timeout(STATUS_WAIT, call(&app, "account", json!({"action": "deviceForget", "device": saved.device_id}))).await;
    }
    forget(&app, &mut *grid.inner.lock().await);
    crate::security::record(Event::new("access.signedout").text("company", &saved.company));
    Ok(json!({"signedOut": true, "message": format!("Signed out of {}'s Access Grid. Agents on this computer can no longer use its credentials.", saved.company)}))
}

/// A password in a request becomes a salt and derived key here, so it never leaves this computer.
async fn derive_password(request: &mut Value, field: &str) -> Result<(), String> {
    let Some(secret) = request.as_object_mut().and_then(|object| object.remove(field)).and_then(|value| value.as_str().map(str::to_owned)) else {
        return Err("A password is required".into());
    };
    password::validate(&secret)?;
    let salt = password::new_salt();
    let key = {
        let salt = salt.clone();
        tokio::task::spawn_blocking(move || password::derive(&secret, &salt)).await.map_err(|error| error.to_string())??
    };
    request["salt"] = json!(salt);
    request["key"] = json!(key);
    Ok(())
}

/// Manages the grid: as its owner on the computer that runs it, else as the signed-in person
/// with their permission.
pub(crate) async fn access_manage(mut request: Value, app: AppHandle) -> Result<Value, String> {
    if !request.is_object() {
        return Err("The request must be an object with an action".into());
    }
    if matches!(request["action"].as_str(), Some("personAdd" | "personPassword")) {
        derive_password(&mut request, "password").await?;
    }
    ensure_loaded(&app).await;
    {
        let grid = app.state::<AccessGrid>();
        let inner = grid.inner.lock().await;
        // On the hub's own computer the owner acts directly, unless someone else signed in here:
        // then their own permission applies, and their decisions carry their name.
        if let Some(hub) = inner.hub.as_ref().filter(|hub| hub.phase() == Phase::Open && inner.member.as_ref().is_none_or(|saved| saved.person_id == hub.record().owner)) {
            return hub.manage_as_owner(request);
        }
    }
    call(&app, "manage", request).await
}

/// The signed-in person's own account: two-step sign-in (`twoStepStart`, `twoStepConfirm`
/// {code}, `twoStepOff` {code}), `password` {password, code?}, `signOutOthers`, and
/// `deviceForget` {device}. A new sign-in the hub hands back replaces this computer's.
pub(crate) async fn access_account(mut request: Value, app: AppHandle) -> Result<Value, String> {
    if !request.is_object() {
        return Err("The request must be an object with an action".into());
    }
    if request["action"] == "password" {
        derive_password(&mut request, "password").await?;
    }
    request["computer"] = json!(crate::grid::computer_name(&app));
    let mut answer = call(&app, "account", request).await?;
    if let Some(device) = answer.as_object_mut().and_then(|object| object.remove("deviceToken")).and_then(|value| value.as_str().map(str::to_owned)) {
        secrets::store(DEVICE_TOKEN, &device)?;
        let grid = app.state::<AccessGrid>();
        let mut inner = grid.inner.lock().await;
        if let (Some(token), Some(expires)) = (answer["sessionToken"].as_str(), answer["expiresAt"].as_i64()) {
            inner.session = Some((token.to_owned(), expires, answer["strong"].as_bool().unwrap_or(false)));
        }
        if let Some(saved) = inner.member.as_mut() {
            saved.device_id = answer["deviceId"].as_str().unwrap_or_default().to_owned();
            let _ = persist(&app, saved);
        }
    }
    if let Some(object) = answer.as_object_mut() {
        object.remove("sessionToken");
    }
    Ok(answer)
}

/// An agent's request sent with a company credential. The hub answers with the service's answer
/// (the value hidden), or that an approver decides first, or why it is refused.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn access_use(credential: String, method: Option<String>, url: String, headers: Option<Value>, body: Option<String>, body_base64: Option<String>, agent: Option<String>, app: AppHandle) -> Result<Value, String> {
    let computer = crate::grid::computer_name(&app);
    call(&app, "use", json!({"credential": credential, "method": method.unwrap_or_else(|| "GET".into()), "url": url, "headers": headers, "body": body, "bodyBase64": body_base64, "agent": agent, "computer": computer})).await
}

/// A request's state; a finished answer is handed over once.
pub(crate) async fn access_check(id: String, app: AppHandle) -> Result<Value, String> {
    call(&app, "request", json!({"id": id})).await
}

/// An agent asks to see a credential (a short-lived token for the minting kinds); an approver
/// always decides.
pub(crate) async fn access_reveal(credential: String, reason: Option<String>, agent: Option<String>, app: AppHandle) -> Result<Value, String> {
    let computer = crate::grid::computer_name(&app);
    call(&app, "reveal", json!({"credential": credential, "reason": reason, "agent": agent, "computer": computer})).await
}

/// Admin, on the hub's computer: writes an encrypted backup of the grid (record, activity log
/// and both keys) to `output`, to move it or bring it back after a disk is lost.
pub(crate) async fn access_backup(output: String, passphrase: String, app: AppHandle) -> Result<Value, String> {
    ensure_loaded(&app).await;
    if app.state::<AccessGrid>().inner.lock().await.hub.is_none() {
        return Err("Backups are made on the computer that runs the Access Grid".into());
    }
    let output = PathBuf::from(output.trim());
    if output.as_os_str().is_empty() || output.is_dir() {
        return Err("--output is the backup file to write, such as D:/acme-access.backup".into());
    }
    if output.exists() {
        return Err(format!("{} already exists; choose a new file name", output.display()));
    }
    let (tls_key, seal_key) = (secrets::resolve(HUB_KEY)?, secrets::resolve(SEAL_KEY)?);
    let path = hub_path(&app);
    let bytes = tokio::task::spawn_blocking(move || backup::create(&path, &tls_key, &seal_key, &passphrase)).await.map_err(|error| error.to_string())??;
    std::fs::write(&output, &bytes).map_err(|error| format!("Cannot write {}: {error}", output.display()))?;
    crate::security::record(Event::new("access.backup").path("file", &output.display().to_string()));
    Ok(json!({"file": output.display().to_string(), "bytes": bytes.len(), "message": "Backup written. Keep it and its passphrase apart: together they open every credential the grid keeps."}))
}

/// Admin: brings an Access Grid back from a backup on this computer, at `address`. People's
/// computers keep trusting it; they sign in at the new address with the new invite, and their
/// remembered sign-ins carry over.
pub(crate) async fn access_restore_backup(file: String, passphrase: String, address: String, app: AppHandle) -> Result<Value, String> {
    let grid = app.state::<AccessGrid>();
    let _admin = grid.admin.lock().await;
    ensure_loaded(&app).await;
    if grid.inner.lock().await.hub.is_some() || hub_path(&app).exists() {
        return Err("This computer already runs an Access Grid; delete it first".into());
    }
    let ip: std::net::IpAddr = address.trim().parse().map_err(|_| "--ip is this computer's LAN or VPN address, such as 192.168.1.20")?;
    if ip.is_loopback() || ip.is_unspecified() || !net::private(ip) {
        return Err("Use this computer's private LAN or VPN address".into());
    }
    let bytes = std::fs::read(file.trim()).map_err(|error| format!("Cannot read {file}: {error}"))?;
    let contents = tokio::task::spawn_blocking(move || backup::open(&bytes, &passphrase)).await.map_err(|error| error.to_string())??;
    let path = hub_path(&app);
    let record = hub::install(&path, &contents, Some(ip))?;
    let stored = secrets::store(HUB_KEY, &contents.tls_key).and_then(|_| secrets::store(SEAL_KEY, &contents.seal_key));
    if let Err(error) = stored {
        let _ = std::fs::remove_file(&path);
        return Err(error);
    }
    {
        let mut inner = grid.inner.lock().await;
        start_hub(&app, &mut inner).await;
        if let Some(error) = inner.hub_error.clone() {
            return Err(error);
        }
    }
    crate::security::record(Event::new("access.restored.backup").text("company", &record.company));
    drop(_admin);
    let mut status = access_status(app).await?;
    status["message"] = json!(format!("{}'s Access Grid is running here again. Share the new invite: people's computers move to it without a password.", record.company));
    Ok(status)
}

/// App commands, from the main window only.
pub(crate) mod commands {
    use super::*;

    fn main_window(window: &WebviewWindow) -> Result<(), String> {
        if window.label() == "main" { Ok(()) } else { Err("The Access Grid is managed from the main Yougori window".into()) }
    }

    #[tauri::command]
    pub async fn access_status(app: AppHandle, window: WebviewWindow) -> Result<Value, String> {
        main_window(&window)?;
        super::access_status(app).await
    }

    #[tauri::command]
    #[allow(clippy::too_many_arguments)]
    pub async fn access_create(app: AppHandle, window: WebviewWindow, company: String, address: String, username: String, name: Option<String>, password: String, tunnel: Option<String>) -> Result<Value, String> {
        main_window(&window)?;
        super::access_create(company, address, username, name, password, tunnel, app).await
    }

    #[tauri::command]
    pub async fn access_delete(app: AppHandle, window: WebviewWindow, when: Option<String>) -> Result<Value, String> {
        main_window(&window)?;
        super::access_delete(when, app).await
    }

    #[tauri::command]
    pub async fn access_restore(app: AppHandle, window: WebviewWindow) -> Result<Value, String> {
        main_window(&window)?;
        super::access_restore(app).await
    }

    #[tauri::command]
    #[allow(clippy::too_many_arguments)]
    pub async fn access_signin(app: AppHandle, window: WebviewWindow, invite: String, username: Option<String>, password: Option<String>, code: Option<String>, sso: Option<bool>) -> Result<Value, String> {
        main_window(&window)?;
        super::access_signin(invite, username, password, code, sso, app).await
    }

    #[tauri::command]
    pub async fn access_signout(app: AppHandle, window: WebviewWindow) -> Result<Value, String> {
        main_window(&window)?;
        super::access_signout(app).await
    }

    #[tauri::command]
    pub async fn access_manage(app: AppHandle, window: WebviewWindow, request: Value) -> Result<Value, String> {
        main_window(&window)?;
        super::access_manage(request, app).await
    }

    #[tauri::command]
    pub async fn access_account(app: AppHandle, window: WebviewWindow, request: Value) -> Result<Value, String> {
        main_window(&window)?;
        super::access_account(request, app).await
    }

    #[tauri::command]
    pub async fn access_backup(app: AppHandle, window: WebviewWindow, output: String, passphrase: String) -> Result<Value, String> {
        main_window(&window)?;
        super::access_backup(output, passphrase, app).await
    }

    #[tauri::command]
    pub async fn access_restore_backup(app: AppHandle, window: WebviewWindow, file: String, passphrase: String, address: String) -> Result<Value, String> {
        main_window(&window)?;
        super::access_restore_backup(file, passphrase, address, app).await
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_hub_that_did_not_start_is_never_wiped_by_a_pause_or_close() {
        assert!(super::deletion_allowed("later", false).is_err());
        assert!(super::deletion_allowed("now", false).is_err());
        assert!(super::deletion_allowed("forget", false).is_ok());
        assert!(super::deletion_allowed("later", true).is_ok());
        assert!(super::deletion_allowed("now", true).is_ok());
        assert!(super::deletion_allowed("forget", true).is_ok());
        assert!(super::deletion_allowed("soon", false).unwrap_err().contains("not soon"));
        assert!(super::deletion_allowed("soon", true).is_err());
    }
}
