//! Access Grid on this computer: the company credential hubs this computer runs, and this
//! person's sign-ins to them. A hub keeps credentials sealed with a key in the OS vault and sends
//! requests with them for people's agents (`yougori access mcp`), so agents never hold a value.
//! Access Grid has its own records, keys, ports and invite (`access-invite:`), separate from the
//! Neo Grid and the Sandbox Grid.
//!
//! A computer may run several hubs and be signed in to several grids. Each is an instance
//! (`yougori_grid::access::instances`): the one a computer had first is `default`, with its old
//! files, key names and ports (7465, 7466) untouched; every other one has a key `i-` and eight hex
//! digits, its own folder, `-<key>` key names and ports allocated for it. A hub and the sign-in to
//! that same grid share one instance. Commands name one with `gridId` (the grid's id as status
//! shows it, or the instance key); without it a command acts on the only one there is, and
//! refuses when there are several.
use crate::{
    hub_tunnel::{self, TunnelSetup, TunnelState},
    projects::secrets::{self, Secret},
    security::Event,
    store::PlatformStore,
    AppHandle, WebviewWindow,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashSet},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tauri::Manager;
use yougori_grid::{
    access::{
        backup,
        hub::{self, Hub, Owner, Phase},
        instances::{self, Layout, DEFAULT},
        member::{self, CallError, SignedIn},
        seal,
    },
    invite::{self, Invite},
    net::{self, HubAddress},
    password,
};

const TUNNEL_START: Duration = Duration::from_secs(60);
/// The page asks often; a hub that does not answer quickly is shown as unreachable.
const STATUS_WAIT: Duration = Duration::from_secs(6);
/// How often an approver's computer looks for requests waiting for them.
const WATCH: Duration = Duration::from_secs(15);
/// Messages kept from sign-ins that ended in an instance that is gone now.
const NOTICES: usize = 8;

#[derive(Default)]
pub struct AccessGrid {
    inner: tokio::sync::Mutex<Inner>,
    /// Serializes creating, deleting, signing in and out, on every instance.
    admin: tokio::sync::Mutex<()>,
}

#[derive(Default)]
struct Inner {
    /// Every instance on disk has been read in.
    found: bool,
    /// By instance key. `default` is always here, even when nothing of it exists.
    instances: BTreeMap<String, Instance>,
    /// Why a sign-in in an instance that is gone now ended, shown until the next sign-in.
    notices: Vec<String>,
}

#[derive(Default)]
struct Instance {
    loaded: bool,
    hub: Option<Hub>,
    hub_error: Option<String>,
    /// The hub record's id and company, read even when its keys could not be.
    record: Option<(String, String)>,
    tunnel: TunnelState,
    member: Option<Saved>,
    /// The current sign-in: its token, when it lapses, and whether it had a second factor.
    session: Option<(String, i64, bool)>,
    /// Why the last call failed, shown until one succeeds.
    member_error: Option<String>,
    /// The hub ended this computer's sign-in (password changed, signed out, removed): nothing is
    /// retried until the person signs in again, so no lockout builds up.
    refused: Option<String>,
    /// Requests an approver here has already been told about, for this grid.
    told: HashSet<String>,
}

impl Instance {
    /// The grid's id, as status shows it: the hub's record id, else the sign-in's.
    fn grid_id(&self) -> Option<String> {
        self.record.as_ref().map(|(id, _)| id.clone()).or_else(|| self.member.as_ref().map(|saved| saved.access_id.clone())).filter(|id| !id.is_empty())
    }

    fn company(&self) -> String {
        self.record.as_ref().map(|(_, company)| company.clone()).or_else(|| self.member.as_ref().map(|saved| saved.company.clone())).unwrap_or_default()
    }

    /// The pinned certificate's fingerprint, normalized: the hub's, else the sign-in's.
    fn fingerprint(&self) -> Option<String> {
        self.hub.as_ref().map(|hub| hub.fingerprint().to_owned()).or_else(|| self.member.as_ref().map(|saved| saved.fingerprint.clone())).and_then(|text| net::normalize_fingerprint(&text))
    }

    /// Whether a hub or a sign-in is here, in memory or on disk.
    fn present(&self, layout: &Layout) -> bool {
        self.hub.is_some() || self.member.is_some() || layout.in_use()
    }
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

/// The OS vault, behind a seam so the instance rules can be tested with a fake one.
trait Vault: Sync {
    fn look_up(&self, name: &str) -> Secret;
    fn store(&self, name: &str, value: &str) -> Result<(), String>;
    fn remove(&self, name: &str);
}

struct OsVault;

impl Vault for OsVault {
    fn look_up(&self, name: &str) -> Secret {
        secrets::look_up(name)
    }
    fn store(&self, name: &str, value: &str) -> Result<(), String> {
        secrets::store(name, value)
    }
    fn remove(&self, name: &str) {
        let _ = secrets::delete_secret(name);
    }
}

const OS: OsVault = OsVault;

/// Whether the vault holds `name`. A vault that would not answer stops whatever was about to be
/// written: a name that might be in use is never written over.
fn held(vault: &dyn Vault, name: &str) -> Result<bool, String> {
    match vault.look_up(name) {
        Secret::Found(_) => Ok(true),
        Secret::Absent => Ok(false),
        Secret::Unavailable => Err("The OS credential vault would not answer, so nothing was written and nothing was changed. Try again in a moment.".into()),
    }
}

/// Writes a key that must not exist yet. A key already there is left exactly as it is.
fn store_new(vault: &dyn Vault, name: &str, value: &str) -> Result<(), String> {
    if held(vault, name)? {
        return Err(format!("The OS credential vault already holds a key called {name}. It was left exactly as it is, and nothing was changed."));
    }
    vault.store(name, value)
}

fn resolve(vault: &dyn Vault, name: &str) -> Option<String> {
    match vault.look_up(name) {
        Secret::Found(value) => Some(value),
        _ => None,
    }
}

fn folder(app: &AppHandle) -> PathBuf {
    app.state::<PlatformStore>().data_folder("grid")
}

fn layout(app: &AppHandle, key: &str) -> Layout {
    Layout::new(&folder(app), key).unwrap_or_else(|_| Layout::default_in(&folder(app)))
}

/// The hub's events, each saying which instance it came from.
fn events(instance: &str) -> hub::Events {
    let instance = instance.to_owned();
    Arc::new(move |kind: &'static str, detail: Value| crate::security::record(Event::new(kind).text("instance", &instance).object("detail", detail)))
}

/// An engine event about one instance.
fn event(kind: &'static str, instance: &str) -> Event {
    Event::new(kind).text("instance", instance)
}

fn persist(layout: &Layout, saved: &Saved) -> Result<(), String> {
    let path = layout.member();
    let folder = path.parent().ok_or("Invalid grid folder")?;
    std::fs::create_dir_all(folder).map_err(|error| error.to_string())?;
    let mut file = tempfile::NamedTempFile::new_in(folder).map_err(|error| error.to_string())?;
    std::io::Write::write_all(&mut file, &serde_json::to_vec_pretty(saved).map_err(|error| error.to_string())?).map_err(|error| error.to_string())?;
    file.persist(&path).map_err(|error| error.to_string())?;
    Ok(())
}

/// What starting an instance's hub came to.
enum Opened {
    /// No hub is recorded here.
    Missing,
    Started(Hub),
    Failed(String),
    /// The vault would not answer yet: nothing is decided, and it is tried again.
    NotYet(String),
}

/// Starts the hub recorded in `layout` with that instance's own keys.
async fn open_hub(layout: &Layout, vault: &dyn Vault) -> Opened {
    let path = layout.hub();
    if !path.exists() {
        return Opened::Missing;
    }
    let names = layout.names();
    match secrets::hub_keys(vault.look_up(&names.hub_key), vault.look_up(&names.seal_key)) {
        secrets::Keys::Ready(key, seal_key) => match Hub::start(path, &key, &seal_key, events(layout.key())).await {
            Ok(hub) => Opened::Started(hub),
            Err(error) => Opened::Failed(error),
        },
        secrets::Keys::Gone => Opened::Failed("The Access Grid's keys are missing from the OS credential vault, so its credentials cannot be read. Restore it from a backup, or delete it and create it again.".into()),
        // The vault would not answer. Every credential this grid holds is still there; saying
        // "restore from a backup, or delete it and create it again" over a vault that is merely
        // not ready yet is advice that destroys a company's credential hub.
        secrets::Keys::NotYet => Opened::NotYet("The Access Grid's keys could not be read from the OS credential vault yet, so it has not started. Yougori keeps trying; nothing is changed meanwhile.".into()),
    }
}

/// Reads an instance's sign-in from disk.
fn read_member(layout: &Layout) -> Result<Option<Saved>, String> {
    match std::fs::read(layout.member()) {
        Ok(bytes) => serde_json::from_slice::<Saved>(&bytes).map(Some).map_err(|_| "This computer's Access Grid sign-in is damaged; sign in again".to_owned()),
        Err(_) => Ok(None),
    }
}

/// Reads an instance in from disk without anything the app holds: its hub (started) and its
/// sign-in.
async fn load(layout: &Layout, instance: &mut Instance, vault: &dyn Vault) {
    instance.loaded = true;
    instance.record = hub::load(&layout.hub()).ok().map(|record| (record.id, record.company));
    match open_hub(layout, vault).await {
        Opened::Missing => {}
        Opened::Started(hub) => {
            instance.hub = Some(hub);
            instance.hub_error = None;
        }
        Opened::Failed(error) => instance.hub_error = Some(error),
        Opened::NotYet(error) => {
            instance.hub_error = Some(error);
            instance.loaded = false;
        }
    }
    if instance.member.is_none() {
        match read_member(layout) {
            Ok(saved) => instance.member = saved,
            Err(error) => instance.member_error = Some(error),
        }
    }
}

/// Keeps a started hub's tunnel connected, when it has one.
fn keep_tunnel(app: &AppHandle, layout: &Layout, instance: &mut Instance) {
    let port = instance.hub.as_ref().and_then(|hub| hub.tunnel_address()).map(|entry| entry.port());
    if let (Some(port), Some(setup)) = (port, hub_tunnel::load(&layout.tunnel())) {
        hub_tunnel::keep(app, &mut instance.tunnel, setup, port);
    }
}

/// Reads every instance on disk the first time, and any whose keys could not be read yet.
async fn ensure_loaded(app: &AppHandle) {
    let grid = app.state::<AccessGrid>();
    let root = folder(app);
    let mut inner = grid.inner.lock().await;
    if !inner.found {
        inner.found = true;
        inner.instances.entry(DEFAULT.to_owned()).or_default();
        for key in instances::on_disk(&root) {
            inner.instances.entry(key).or_default();
        }
    }
    let waiting: Vec<String> = inner.instances.iter().filter(|(_, instance)| !instance.loaded).map(|(key, _)| key.clone()).collect();
    for key in waiting {
        let Ok(layout) = Layout::new(&root, &key) else { continue };
        let Some(instance) = inner.instances.get_mut(&key) else { continue };
        load(&layout, instance, &OS).await;
        if instance.hub.is_some() {
            keep_tunnel(app, &layout, instance);
        }
    }
}

/// How one instance is named in a refusal: its company and id.
fn label(key: &str, instance: &Instance) -> String {
    let company = instance.company();
    let id = instance.grid_id().unwrap_or_else(|| key.to_owned());
    match company.is_empty() {
        true => id,
        false => format!("{company} ({id})"),
    }
}

/// The instances with a hub or a sign-in, by key.
fn present<'a>(inner: &'a Inner, root: &Path) -> Vec<(&'a String, &'a Instance)> {
    inner.instances.iter().filter(|(key, instance)| Layout::new(root, key).is_ok_and(|layout| instance.present(&layout))).collect()
}

/// Which instance a command is about. `wanted` is a grid id as status shows it, or an instance
/// key. Without one, the only instance there is; with none at all, the default one, which
/// behaves as it always did; with several, a refusal that names them.
fn choose(inner: &Inner, root: &Path, wanted: Option<&str>) -> Result<String, String> {
    let there = present(inner, root);
    if let Some(wanted) = wanted.map(str::trim).filter(|wanted| !wanted.is_empty()) {
        let matching: Vec<&String> = there
            .iter()
            .filter(|(key, instance)| key.as_str() == wanted || instance.grid_id().as_deref() == Some(wanted) || instance.member.as_ref().is_some_and(|saved| saved.access_id == wanted))
            .map(|(key, _)| *key)
            .collect();
        return match matching.as_slice() {
            [one] => Ok((*one).clone()),
            [] => Err(format!("There is no Access Grid {wanted} on this computer. `yougori access status` lists the ones there are.")),
            many => Err(format!("More than one Access Grid here answers to {wanted}: {}. Name one by its instance.", many.iter().map(|key| key.as_str()).collect::<Vec<_>>().join(", "))),
        };
    }
    match there.as_slice() {
        [] => Ok(DEFAULT.to_owned()),
        [(key, _)] => Ok((*key).clone()),
        many => Err(format!("There are {} Access Grids on this computer: {}. Say which with gridId.", many.len(), many.iter().map(|(key, instance)| label(key, instance)).collect::<Vec<_>>().join(", "))),
    }
}

/// The instance status describes in its old fields: the default one when it is there, else the
/// only one; none when there are several others.
fn described(inner: &Inner, root: &Path) -> Option<String> {
    let there = present(inner, root);
    if there.iter().any(|(key, _)| key.as_str() == DEFAULT) {
        return Some(DEFAULT.to_owned());
    }
    match there.as_slice() {
        [(key, _)] => Some((*key).clone()),
        _ => None,
    }
}

/// Whether the default instance has nothing at all: no hub, no sign-in, and not one of its key
/// names in the vault. Only then does a new hub or sign-in go there, under the old names; keys
/// left behind there might be the only copy of some grid's seal, so they are never written over.
fn default_free(inner: &Inner, root: &Path, vault: &dyn Vault) -> Result<bool, String> {
    let layout = Layout::default_in(root);
    if inner.instances.get(DEFAULT).is_some_and(|instance| instance.present(&layout)) || layout.in_use() {
        return Ok(false);
    }
    for name in layout.names().all() {
        if held(vault, name)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Where a new hub goes: the default instance when it is entirely free, else a new instance whose
/// folder and key names are all unused.
fn slot_for_hub(inner: &Inner, root: &Path, vault: &dyn Vault) -> Result<Layout, String> {
    if default_free(inner, root, vault)? {
        return Ok(Layout::default_in(root));
    }
    instances::fresh(root, |name| held(vault, name))
}

/// Where a sign-in to a grid with `fingerprint` goes, and whether that instance's own device
/// token may be replaced: the instance that already holds that grid (its hub here, or an earlier
/// sign-in), else a free default instance, else a new one.
fn slot_for_member(inner: &Inner, root: &Path, vault: &dyn Vault, fingerprint: &str) -> Result<(Layout, bool), String> {
    for (key, instance) in present(inner, root) {
        if instance.fingerprint().as_deref() == Some(fingerprint) {
            return Ok((Layout::new(root, key)?, true));
        }
    }
    Ok((slot_for_hub(inner, root, vault)?, false))
}

/// The ports a new hub in `layout` opens: the old ones for the default instance, ports allocated
/// for any other (released again by the caller if the hub is not made).
fn hub_ports(layout: &Layout, root: &Path) -> Result<(u16, u16, Vec<u16>), String> {
    if layout.is_default() {
        return Ok((instances::DEFAULT_PORT, instances::DEFAULT_TUNNEL_PORT, Vec::new()));
    }
    let ports = crate::grid::instances::allocate_ports(root, 2)?;
    match ports.as_slice() {
        [port, tunnel] => Ok((*port, *tunnel, ports.clone())),
        _ => {
            crate::grid::instances::release_ports(&ports);
            Err("No free port was left for another Access Grid on this computer. Nothing was changed.".into())
        }
    }
}

/// Makes and starts a new hub in `layout`, with keys stored under that instance's own names and
/// only after the vault says neither exists. Whatever it wrote is taken back if the hub does not
/// start; a key it did not write is never touched.
#[allow(clippy::too_many_arguments)]
async fn found_hub(layout: &Layout, vault: &dyn Vault, company: &str, ip: IpAddr, port: u16, tunnel_port: Option<u16>, owner: Owner, tunnel: Option<&TunnelSetup>) -> Result<Hub, String> {
    let names = layout.names();
    for name in [&names.hub_key, &names.seal_key] {
        if held(vault, name)? {
            return Err(format!("The OS credential vault already holds a key called {name}. It was left exactly as it is, and nothing was changed."));
        }
    }
    let path = layout.hub();
    let tls_key = hub::create(&path, company, ip, port, tunnel_port, owner)?;
    let mut written = Vec::new();
    let started: Result<Hub, String> = async {
        let seal_key = seal::new_key()?;
        store_new(vault, &names.hub_key, &tls_key)?;
        written.push(names.hub_key.clone());
        store_new(vault, &names.seal_key, &seal_key)?;
        written.push(names.seal_key.clone());
        if let Some(setup) = tunnel {
            hub_tunnel::save(&layout.tunnel(), setup)?;
        }
        Hub::start(path.clone(), &tls_key, &seal_key, events(layout.key())).await
    }
    .await;
    started.inspect_err(|_| {
        for name in &written {
            vault.remove(name);
        }
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(layout.tunnel());
        layout.tidy();
    })
}

/// Saves a sign-in in `layout`: the device token under that instance's name, then the record.
/// A new sign-in never writes over a device token already there; `replace` is for this
/// instance's own sign-in, renewed.
fn keep_membership(layout: &Layout, vault: &dyn Vault, saved: &Saved, device: &str, replace: bool) -> Result<(), String> {
    let name = layout.names().device;
    if replace {
        vault.store(&name, device)?;
    } else {
        store_new(vault, &name, device)?;
    }
    persist(layout, saved).inspect_err(|_| vault.remove(&name))
}

/// Forgets an instance's sign-in.
fn forget(layout: &Layout, instance: &mut Instance, vault: &dyn Vault) {
    instance.member = None;
    instance.session = None;
    instance.member_error = None;
    instance.refused = None;
    instance.told.clear();
    let _ = std::fs::remove_file(layout.member());
    vault.remove(&layout.names().device);
}

/// Removes an instance's hub from this computer with its files and its own two keys.
fn remove_hub(layout: &Layout, instance: &mut Instance, vault: &dyn Vault) {
    let path = layout.hub();
    instance.tunnel.stop();
    instance.hub = None;
    instance.hub_error = None;
    instance.record = None;
    let activity = hub::activity_path(&path);
    for file in [path, activity.clone(), activity.with_extension("jsonl.1"), layout.tunnel()] {
        let _ = std::fs::remove_file(file);
    }
    let names = layout.names();
    vault.remove(&names.hub_key);
    vault.remove(&names.seal_key);
}

/// Drops an instance other than the default once nothing of it is left, keeping why its sign-in
/// ended to show once.
fn drop_if_empty(inner: &mut Inner, layout: &Layout) {
    if layout.is_default() {
        return;
    }
    let empty = inner.instances.get(layout.key()).is_none_or(|instance| !instance.present(layout));
    if empty {
        if let Some(message) = inner.instances.remove(layout.key()).and_then(|instance| instance.member_error) {
            inner.notices.push(message);
            let extra = inner.notices.len().saturating_sub(NOTICES);
            inner.notices.drain(..extra);
        }
        layout.tidy();
    }
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

/// How an agent reaches this instance's broker.
fn mcp(layout: &Layout, grid_id: Option<&str>) -> Value {
    match layout.is_default() {
        true => json!({"name": instances::MCP_NAME, "command": "yougori", "args": ["access", "mcp"]}),
        false => json!({"name": layout.mcp_name(), "command": "yougori", "args": ["access", "mcp", "--grid", grid_id.unwrap_or(layout.key())]}),
    }
}

fn member_view(saved: &Saved, connected: bool, error: Option<String>, needs_sign_in: bool) -> Value {
    json!({
        "accessId": saved.access_id, "company": saved.company, "hub": saved.address, "fingerprint": saved.fingerprint,
        "username": saved.username, "deviceId": saved.device_id, "signedInAt": saved.signed_in_at, "connected": connected,
        "error": error, "needsSignIn": needs_sign_in,
    })
}

/// Every hub and every sign-in on this computer, each with its instance and grid id.
fn listing(inner: &Inner, root: &Path) -> (Vec<Value>, Vec<Value>) {
    let (mut hubs, mut members) = (Vec::new(), Vec::new());
    for (key, instance) in present(inner, root) {
        let Ok(layout) = Layout::new(root, key) else { continue };
        let grid_id = instance.grid_id();
        let mut hub = match (&instance.hub, &instance.record) {
            (Some(hub), _) => Some(hub_view(hub, &instance.tunnel)),
            (None, Some((id, company))) => Some(json!({"id": id, "company": company})),
            (None, None) if layout.hub().exists() => Some(json!({})),
            _ => None,
        };
        if let Some(hub) = hub.as_mut() {
            hub["instance"] = json!(key);
            hub["gridId"] = json!(grid_id);
            hub["error"] = json!(instance.hub_error);
            hubs.push(hub.clone());
        }
        match &instance.member {
            Some(saved) => {
                let connected = instance.refused.is_none() && instance.member_error.is_none() && instance.session.as_ref().is_some_and(|(_, expires, _)| *expires > yougori_grid::now());
                let mut view = member_view(saved, connected, instance.refused.clone().or(instance.member_error.clone()), instance.refused.is_some());
                view["instance"] = json!(key);
                view["gridId"] = json!(grid_id);
                view["mcp"] = mcp(&layout, grid_id.as_deref());
                members.push(view);
            }
            None if layout.member().exists() => members.push(json!({"instance": key, "gridId": grid_id, "error": instance.member_error, "needsSignIn": true})),
            None => {}
        }
    }
    (hubs, members)
}

/// Requests in `me` waiting for this approver that they have not been told about yet; marks them
/// told. One instance's `told` never hears about another's requests.
fn fresh_waiting(me: &Value, told: &mut HashSet<String>) -> usize {
    let permission = me["person"]["permission"].as_str().unwrap_or_default();
    if !matches!(permission, "approver" | "admin") {
        return 0;
    }
    let username = me["person"]["username"].as_str().unwrap_or_default();
    let own_too = me["canApproveOwn"] == true;
    let waiting: Vec<String> = me["overview"]["waiting"].as_array().into_iter().flatten().filter(|request| own_too || request["person"].as_str() != Some(username)).filter_map(|request| request["id"].as_str().map(str::to_owned)).collect();
    told.retain(|id| waiting.contains(id));
    let fresh: Vec<String> = waiting.iter().filter(|id| !told.contains(*id)).cloned().collect();
    told.extend(fresh.iter().cloned());
    fresh.len()
}

/// Saves a fresh sign-in in instance `key` and makes it current. The caller holds the admin lock.
async fn adopt(app: &AppHandle, key: &str, signed: SignedIn, address: &HubAddress, username: &str, replace: bool) -> Result<(), String> {
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
    let layout = layout(app, key);
    keep_membership(&layout, &OS, &saved, &device, replace)?;
    crate::security::record(event("access.signedin", key).text("company", &saved.company).text("hub", &saved.address).text("fingerprint", &saved.fingerprint).flag("strong", signed.strong));
    let grid = app.state::<AccessGrid>();
    let mut inner = grid.inner.lock().await;
    inner.notices.clear();
    let instance = inner.instances.entry(key.to_owned()).or_default();
    instance.loaded = true;
    instance.member = Some(saved);
    instance.session = Some((signed.token, signed.expires_at, signed.strong));
    instance.member_error = None;
    instance.refused = None;
    Ok(())
}

/// What a refusal or deletion means for instance `key`'s sign-in.
async fn ended(app: &AppHandle, key: &str, error: &CallError) {
    let grid = app.state::<AccessGrid>();
    let mut inner = grid.inner.lock().await;
    let layout = layout(app, key);
    let Some(instance) = inner.instances.get_mut(key) else { return };
    let company = instance.member.as_ref().map(|saved| saved.company.clone()).unwrap_or_default();
    match error {
        CallError::Deleted(_) => {
            crate::security::record(event("access.deleted.left", key).text("company", &company));
            forget(&layout, instance, &OS);
            instance.member_error = Some(format!("{company} deleted its Access Grid; this computer signed out of it."));
            drop_if_empty(&mut inner, &layout);
        }
        CallError::Refused { code, .. } if code == "device_ended" => {
            instance.session = None;
            instance.refused = Some(format!("{company}'s Access Grid ended this computer's sign-in: your password changed, two-step was reset, the computer was signed out, or it was not used for 30 days. Sign in again."));
        }
        CallError::Refused { message, .. } | CallError::Failed(message) => instance.member_error = Some(message.clone()),
        CallError::SignedOut => instance.session = None,
    }
}

/// Instance `key`'s current sign-in, signing in again with its device token when it lapsed.
async fn session(app: &AppHandle, key: &str) -> Result<(HubAddress, String, String), String> {
    ensure_loaded(app).await;
    let grid = app.state::<AccessGrid>();
    let (saved, current) = {
        let inner = grid.inner.lock().await;
        let instance = inner.instances.get(key);
        if let Some(refused) = instance.and_then(|instance| instance.refused.clone()) {
            return Err(refused);
        }
        let saved = instance.and_then(|instance| instance.member.clone()).ok_or("This computer is not signed in to an Access Grid. Sign in with the invite your admin shared: yougori access signin --invite INVITE --username NAME")?;
        (saved, instance.and_then(|instance| instance.session.clone()))
    };
    let address = HubAddress::parse(&saved.address)?;
    if let Some((token, _, _)) = current.filter(|(_, expires, _)| *expires > yougori_grid::now() + 60) {
        return Ok((address, saved.certificate, token));
    }
    let device = resolve(&OS, &layout(app, key).names().device).ok_or("This computer's Access Grid sign-in is missing from the OS credential vault; sign in again")?;
    match member::resume(&address, &saved.certificate, &device, &crate::grid::computer_name(app)).await {
        Ok(signed) => {
            let mut inner = grid.inner.lock().await;
            if let Some(instance) = inner.instances.get_mut(key) {
                instance.session = Some((signed.token.clone(), signed.expires_at, signed.strong));
                instance.member_error = None;
            }
            Ok((address, saved.certificate, signed.token))
        }
        Err(error) => {
            let message = error.to_string();
            ended(app, key, &error).await;
            Err(grid.inner.lock().await.instances.get(key).and_then(|instance| instance.refused.clone()).unwrap_or(message))
        }
    }
}

/// One call to instance `key`'s hub as the person signed in there; a lapsed sign-in is renewed
/// once. Never another instance's sign-in.
async fn call(app: &AppHandle, key: &str, action: &str, body: Value) -> Result<Value, String> {
    for attempt in 0..2 {
        let (address, certificate, token) = session(app, key).await?;
        match member::call(&address, &certificate, &token, action, &body).await {
            Ok(value) => {
                if let Some(instance) = app.state::<AccessGrid>().inner.lock().await.instances.get_mut(key) {
                    instance.member_error = None;
                }
                return Ok(value);
            }
            Err(CallError::SignedOut) if attempt == 0 => {
                if let Some(instance) = app.state::<AccessGrid>().inner.lock().await.instances.get_mut(key) {
                    instance.session = None;
                }
            }
            Err(error) => {
                let message = error.to_string();
                if matches!(error, CallError::Deleted(_) | CallError::Failed(_)) || matches!(&error, CallError::Refused { code, .. } if code == "paused") {
                    ended(app, key, &error).await;
                }
                return Err(message);
            }
        }
    }
    Err("The Access Grid ended this sign-in; sign in again".into())
}

/// Which instance a command is about (see `choose`).
async fn pick(app: &AppHandle, grid_id: Option<&str>) -> Result<String, String> {
    ensure_loaded(app).await;
    let grid = app.state::<AccessGrid>();
    let inner = grid.inner.lock().await;
    choose(&inner, &folder(app), grid_id)
}

/// A request waiting for this approver: tells them once, outside the app when it is not in front.
#[cfg(target_os = "windows")]
fn notify(app: &AppHandle, count: usize, company: Option<&str>) {
    use tauri::UserAttentionType;
    use tauri_plugin_notification::NotificationExt;
    let window = app.get_webview_window("main");
    if window.as_ref().is_some_and(|window| window.is_focused().unwrap_or(false)) {
        return;
    }
    if let Some(window) = window {
        let _ = window.request_user_attention(Some(UserAttentionType::Informational));
    }
    let place = company.filter(|company| !company.is_empty()).map(|company| format!("{company}'s Access Grid")).unwrap_or_else(|| "Access Grid".into());
    let body = if count == 1 { format!("An agent is waiting for your approval in {place}.") } else { format!("Agents are waiting for your approval in {place}.") };
    let _ = app.notification().builder().title("Yougori · approval needed").body(body).show();
}

#[cfg(not(target_os = "windows"))]
fn notify(_app: &AppHandle, _count: usize, _company: Option<&str>) {}

/// Looks for requests waiting for this approver in instance `key`.
async fn watch(app: &AppHandle, key: &str, several: bool) {
    let signed_in = {
        let grid = app.state::<AccessGrid>();
        let inner = grid.inner.lock().await;
        inner.instances.get(key).is_some_and(|instance| instance.member.is_some() && instance.refused.is_none())
    };
    if !signed_in {
        return;
    }
    let Ok(Ok(me)) = tokio::time::timeout(STATUS_WAIT, call(app, key, "me", json!({}))).await else { return };
    let (fresh, company) = {
        let grid = app.state::<AccessGrid>();
        let mut inner = grid.inner.lock().await;
        let Some(instance) = inner.instances.get_mut(key) else { return };
        (fresh_waiting(&me, &mut instance.told), instance.company())
    };
    if fresh > 0 {
        notify(app, fresh, several.then_some(company.as_str()));
    }
}

/// A deleted hub that has told people long enough is removed from this computer.
async fn finish_deleted_hub(app: &AppHandle, key: &str) {
    let grid = app.state::<AccessGrid>();
    let done = grid.inner.lock().await.instances.get(key).and_then(|instance| instance.hub.as_ref()).is_some_and(Hub::told_enough);
    if done {
        let _admin = grid.admin.lock().await;
        let layout = layout(app, key);
        let mut inner = grid.inner.lock().await;
        if let Some(instance) = inner.instances.get_mut(key) {
            remove_hub(&layout, instance, &OS);
        }
        drop_if_empty(&mut inner, &layout);
    }
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
            // Every instance is looked at: an approver in two grids hears from both.
            ensure_loaded(&app).await;
            let keys: Vec<String> = {
                let grid = app.state::<AccessGrid>();
                let inner = grid.inner.lock().await;
                present(&inner, &folder(&app)).into_iter().map(|(key, _)| key.clone()).collect()
            };
            let several = keys.len() > 1;
            futures_util::future::join_all(keys.iter().map(|key| watch(&app, key, several))).await;
            for key in &keys {
                finish_deleted_hub(&app, key).await;
            }
        }
        let grid = app.state::<AccessGrid>();
        let mut inner = grid.inner.lock().await;
        for instance in inner.instances.values_mut() {
            instance.tunnel.stop();
            instance.hub = None;
        }
    });
}

/// Every Access Grid on this computer. The old fields (`hub`, `member`, `me`…) describe the
/// instance `gridId` names, else the default one, else the only one; `hubs` and `members` list
/// every instance, each with its `instance` and `gridId`.
pub(crate) async fn access_status(grid_id: Option<String>, app: AppHandle) -> Result<Value, String> {
    ensure_loaded(&app).await;
    let root = folder(&app);
    let key = {
        let grid = app.state::<AccessGrid>();
        let inner = grid.inner.lock().await;
        match grid_id.as_deref().map(str::trim).filter(|id| !id.is_empty()) {
            Some(id) => Some(choose(&inner, &root, Some(id))?),
            None => described(&inner, &root),
        }
    };
    let signed_in = match &key {
        Some(key) => app.state::<AccessGrid>().inner.lock().await.instances.get(key).is_some_and(|instance| instance.member.is_some()),
        None => false,
    };
    let me = match (&key, signed_in) {
        (Some(key), true) => match tokio::time::timeout(STATUS_WAIT, call(&app, key, "me", json!({}))).await {
            Ok(Ok(me)) => Some(me),
            Ok(Err(_)) => None,
            Err(_) => {
                if let Some(instance) = app.state::<AccessGrid>().inner.lock().await.instances.get_mut(key) {
                    instance.member_error = Some("The Access Grid did not answer in time".into());
                }
                None
            }
        },
        _ => None,
    };
    let grid = app.state::<AccessGrid>();
    let inner = grid.inner.lock().await;
    let (hubs, members) = listing(&inner, &root);
    let instance = key.as_ref().and_then(|key| inner.instances.get(key));
    let layout = key.as_deref().and_then(|key| Layout::new(&root, key).ok()).unwrap_or_else(|| Layout::default_in(&root));
    let grid_id = instance.and_then(Instance::grid_id);
    let mut hub = instance.and_then(|instance| instance.hub.as_ref().map(|hub| hub_view(hub, &instance.tunnel)));
    let mut member = instance.and_then(|instance| {
        instance.member.as_ref().map(|saved| member_view(saved, me.is_some(), instance.refused.clone().or(instance.member_error.clone()), instance.refused.is_some()))
    });
    for view in [hub.as_mut(), member.as_mut()].into_iter().flatten() {
        view["instance"] = json!(layout.key());
        view["gridId"] = json!(grid_id);
    }
    let member_error = match &member {
        Some(_) => None,
        None => instance.and_then(|instance| instance.member_error.clone()).or_else(|| inner.notices.last().cloned()),
    };
    Ok(json!({
        "hub": hub,
        "hubError": instance.and_then(|instance| instance.hub_error.clone()),
        "member": member,
        "memberError": member_error,
        "me": me,
        "suggestedAddress": if hub.is_none() { crate::bounty::suggested_address() } else { None },
        "mcp": mcp(&layout, grid_id.as_deref()),
        "instance": key,
        "gridId": grid_id,
        "hubs": hubs,
        "members": members,
    }))
}

/// Admin: runs an Access Grid on this computer's LAN or VPN address and signs this computer in
/// as its first admin. The computer's first one keeps the old names and ports; another one gets
/// an instance, keys and ports of its own.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn access_create(company: String, address_text: String, username: String, name: Option<String>, secret: String, tunnel: Option<String>, app: AppHandle) -> Result<Value, String> {
    let grid = app.state::<AccessGrid>();
    let _admin = grid.admin.lock().await;
    ensure_loaded(&app).await;
    let ip: IpAddr = address_text.trim().parse().map_err(|_| "--ip is this computer's LAN or VPN address, such as 192.168.1.20")?;
    if ip.is_loopback() || ip.is_unspecified() || !net::private(ip) {
        return Err("Use this computer's private LAN or VPN address so company computers can reach the Access Grid".into());
    }
    let username = yougori_grid::access::policy::username(&username)?;
    let setup = TunnelSetup::parse(tunnel.as_deref());
    password::validate(&secret)?;
    let root = folder(&app);
    let layout = {
        let inner = grid.inner.lock().await;
        slot_for_hub(&inner, &root, &OS)?
    };
    let key = layout.key().to_owned();
    let (port, tunnel_default, allocated) = hub_ports(&layout, &root)?;
    let release = |error: String| {
        if !allocated.is_empty() {
            crate::grid::instances::release_ports(&allocated);
        }
        error
    };
    let tunnel_port = setup.as_ref().map(|setup| setup.port(&app, port, tunnel_default)).transpose().map_err(release)?;
    let salt = password::new_salt();
    let derived = {
        let (secret, salt) = (secret.clone(), salt.clone());
        tokio::task::spawn_blocking(move || password::derive(&secret, &salt)).await.map_err(|error| error.to_string())?
    };
    let derived = derived.map_err(release)?;
    let owner = Owner { username: username.clone(), name: name.unwrap_or_default(), salt, key: derived };
    let hub = found_hub(&layout, &OS, &company, ip, port, tunnel_port, owner, setup.as_ref()).await.map_err(release)?;
    let invite = Invite { company: hub.record().company, address: HubAddress::Direct(hub.address()), fingerprint: hub.fingerprint().to_owned() };
    {
        let mut inner = grid.inner.lock().await;
        let instance = inner.instances.entry(key.clone()).or_default();
        instance.loaded = true;
        instance.record = Some((hub.record().id, invite.company.clone()));
        if let (Some(setup), Some(port)) = (setup.clone(), hub.tunnel_address().map(|entry| entry.port())) {
            hub_tunnel::keep(&app, &mut instance.tunnel, setup, port);
        }
        instance.hub = Some(hub);
        instance.hub_error = None;
    }
    crate::security::record(event("access.hosted", &key).text("company", &invite.company).flag("tunnel", setup.is_some()));
    if setup.is_some() {
        let deadline = Instant::now() + TUNNEL_START;
        while Instant::now() < deadline {
            // The lock is let go before waiting, so the page's status calls are never held up.
            let settled = {
                let inner = grid.inner.lock().await;
                inner.instances.get(&key).is_none_or(|instance| instance.tunnel.url().is_some() || instance.tunnel.error().is_some())
            };
            if settled {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
    // This computer signs in over its own LAN address, like anyone else.
    let signed = match member::signin(&invite, &username, &secret, None, &crate::grid::computer_name(&app)).await {
        Ok(signed) => adopt(&app, &key, signed, &invite.address, &username, false).await,
        Err(error) => Err(error),
    };
    drop(_admin);
    let mut status = access_status(Some(key), app).await?;
    status["message"] = json!(match signed {
        Ok(()) => format!("{}'s Access Grid is running and you are its admin. Add people and credentials, then share the invite; each person signs in with their own password.", invite.company),
        Err(error) => format!("{}'s Access Grid is running, but this computer could not sign in to it: {error}", invite.company),
    });
    Ok(status)
}

/// Admin: deletes one of this computer's Access Grids. `later` (default) pauses it for three
/// days, when nobody signs in or uses anything and `access_restore` takes it back; `now` wipes
/// its credentials, people and rules at once and tells people's computers so for 30 days;
/// `forget` removes it from this computer without waiting.
pub(crate) async fn access_delete(when: Option<String>, grid_id: Option<String>, app: AppHandle) -> Result<Value, String> {
    let grid = app.state::<AccessGrid>();
    let _admin = grid.admin.lock().await;
    let key = pick(&app, grid_id.as_deref()).await?;
    let layout = layout(&app, &key);
    let mut inner = grid.inner.lock().await;
    let instance = inner.instances.entry(key.clone()).or_default();
    if instance.hub.is_none() && !layout.hub().exists() {
        return Err("This computer does not run an Access Grid".into());
    }
    let company = instance.hub.as_ref().map(|hub| hub.record().company).or_else(|| instance.record.as_ref().map(|(_, company)| company.clone())).unwrap_or_default();
    let fingerprint = instance.hub.as_ref().map(|hub| hub.fingerprint().to_owned());
    let when = when.as_deref().unwrap_or("later");
    deletion_allowed(when, instance.hub.is_some())?;
    let message = match (when, instance.hub.as_ref()) {
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
            remove_hub(&layout, instance, &OS);
            format!("{company}'s Access Grid was removed from this computer with its credentials, people, rules and activity log.")
        }
        (other, _) => return Err(format!("--when is later, now or forget, not {other}")),
    };
    if when != "later" && instance.member.as_ref().is_some_and(|saved| Some(&saved.fingerprint) == fingerprint.as_ref()) {
        forget(&layout, instance, &OS);
    }
    drop_if_empty(&mut inner, &layout);
    crate::security::record(event("access.deleted", &key).text("company", &company).text("when", when));
    Ok(json!({"deleted": when != "later", "paused": when == "later", "message": message, "instance": key}))
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
pub(crate) async fn access_restore(grid_id: Option<String>, app: AppHandle) -> Result<Value, String> {
    let key = pick(&app, grid_id.as_deref()).await?;
    let grid = app.state::<AccessGrid>();
    let inner = grid.inner.lock().await;
    let hub = inner.instances.get(&key).and_then(|instance| instance.hub.as_ref()).ok_or("This computer does not run an Access Grid")?;
    hub.restore()?;
    crate::security::record(event("access.restored", &key).text("company", &hub.record().company));
    Ok(json!({"restored": true, "message": "The Access Grid is back; people sign in and use it again."}))
}

/// Signs this person in to the Access Grid the admin's invite names: with their password (and
/// two-step code), or through the company's identity provider (`sso`). A grid this computer
/// already holds is signed in to again in its own instance; any other gets an instance of its own.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn access_signin(invite_text: String, username: Option<String>, secret: Option<String>, code: Option<String>, sso: Option<bool>, grid_id: Option<String>, app: AppHandle) -> Result<Value, String> {
    let grid = app.state::<AccessGrid>();
    let _admin = grid.admin.lock().await;
    ensure_loaded(&app).await;
    let invite = invite::decode_access(invite_text.trim())?;
    let fingerprint = net::normalize_fingerprint(&invite.fingerprint).unwrap_or_else(|| invite.fingerprint.clone());
    let root = folder(&app);
    // Where this sign-in goes, settled before anything is asked of the hub.
    let (layout, replace) = {
        let inner = grid.inner.lock().await;
        match grid_id.as_deref().map(str::trim).filter(|id| !id.is_empty()) {
            Some(id) => {
                let key = choose(&inner, &root, Some(id))?;
                let theirs = inner.instances.get(&key).and_then(Instance::fingerprint);
                if theirs.is_some_and(|theirs| theirs != fingerprint) {
                    return Err(format!("That invite is for {}'s Access Grid, not the one {id} names. Leave out gridId, or use the invite for {id}.", invite.company));
                }
                (Layout::new(&root, &key)?, true)
            }
            None => slot_for_member(&inner, &root, &OS, &fingerprint)?,
        }
    };
    let key = layout.key().to_owned();
    let saved = grid.inner.lock().await.instances.get(&key).and_then(|instance| instance.member.clone());
    // The same grid at a new address (a backup restored elsewhere, a new tunnel link): this
    // computer's device token moves it there without a password.
    if let Some(saved) = &saved {
        if net::normalize_fingerprint(&saved.fingerprint).as_deref() == Some(fingerprint.as_str()) && invite.address.to_string() != saved.address {
            if let Some(device) = resolve(&OS, &layout.names().device) {
                if let Ok(signed) = member::resume(&invite.address, &saved.certificate, &device, &crate::grid::computer_name(&app)).await {
                    let mut moved = saved.clone();
                    moved.address = invite.address.to_string();
                    persist(&layout, &moved)?;
                    let mut inner = grid.inner.lock().await;
                    let instance = inner.instances.entry(key.clone()).or_default();
                    instance.member = Some(moved);
                    instance.session = Some((signed.token, signed.expires_at, signed.strong));
                    instance.member_error = None;
                    instance.refused = None;
                    drop(inner);
                    drop(_admin);
                    let mut status = access_status(Some(key), app).await?;
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
        let same = net::normalize_fingerprint(&saved.fingerprint).as_deref() == Some(fingerprint.as_str()) && saved.username == username;
        if !same {
            return Err(format!("This computer is signed in to {}'s Access Grid as {}. Sign out first with `yougori access signout --yes`.", saved.company, saved.username));
        }
    }
    let company = signed.company.clone();
    adopt(&app, &key, signed, &invite.address, &username, replace).await?;
    drop(_admin);
    let mut status = access_status(Some(key.clone()), app).await?;
    let connect = match layout.is_default() {
        true => "`yougori access mcp`".to_owned(),
        false => format!("`yougori access mcp --grid {}`", status["gridId"].as_str().unwrap_or(&key)),
    };
    status["message"] = json!(format!("Signed in to {company}'s Access Grid as {username}. Connect your agents with {connect}."));
    Ok(status)
}

/// Signs this person out of one Access Grid on this computer and at its hub.
pub(crate) async fn access_signout(grid_id: Option<String>, app: AppHandle) -> Result<Value, String> {
    let grid = app.state::<AccessGrid>();
    let _admin = grid.admin.lock().await;
    let key = pick(&app, grid_id.as_deref()).await?;
    let saved = grid.inner.lock().await.instances.get(&key).and_then(|instance| instance.member.clone()).ok_or("This computer is not signed in to an Access Grid")?;
    // The hub forgets this computer too, so its device token is useless from now on.
    if !saved.device_id.is_empty() {
        let _ = tokio::time::timeout(STATUS_WAIT, call(&app, &key, "account", json!({"action": "deviceForget", "device": saved.device_id}))).await;
    }
    let layout = layout(&app, &key);
    {
        let mut inner = grid.inner.lock().await;
        if let Some(instance) = inner.instances.get_mut(&key) {
            forget(&layout, instance, &OS);
        }
        drop_if_empty(&mut inner, &layout);
    }
    crate::security::record(event("access.signedout", &key).text("company", &saved.company));
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

/// Manages one grid: as its owner on the computer that runs it, else as the person signed in to
/// that same grid with their permission. Never as anyone signed in to another one.
pub(crate) async fn access_manage(mut request: Value, grid_id: Option<String>, app: AppHandle) -> Result<Value, String> {
    if !request.is_object() {
        return Err("The request must be an object with an action".into());
    }
    let key = pick(&app, grid_id.as_deref()).await?;
    if matches!(request["action"].as_str(), Some("personAdd" | "personPassword")) {
        derive_password(&mut request, "password").await?;
    }
    {
        let grid = app.state::<AccessGrid>();
        let inner = grid.inner.lock().await;
        // On the hub's own computer the owner acts directly, unless someone else signed in here:
        // then their own permission applies, and their decisions carry their name.
        if let Some(instance) = inner.instances.get(&key) {
            if let Some(hub) = instance.hub.as_ref().filter(|hub| hub.phase() == Phase::Open && instance.member.as_ref().is_none_or(|saved| saved.person_id == hub.record().owner)) {
                return hub.manage_as_owner(request);
            }
        }
    }
    call(&app, &key, "manage", request).await
}

/// The signed-in person's own account: two-step sign-in (`twoStepStart`, `twoStepConfirm`
/// {code}, `twoStepOff` {code}), `password` {password, code?}, `signOutOthers`, and
/// `deviceForget` {device}. A new sign-in the hub hands back replaces this instance's own.
pub(crate) async fn access_account(mut request: Value, grid_id: Option<String>, app: AppHandle) -> Result<Value, String> {
    if !request.is_object() {
        return Err("The request must be an object with an action".into());
    }
    let key = pick(&app, grid_id.as_deref()).await?;
    if request["action"] == "password" {
        derive_password(&mut request, "password").await?;
    }
    request["computer"] = json!(crate::grid::computer_name(&app));
    let mut answer = call(&app, &key, "account", request).await?;
    if let Some(device) = answer.as_object_mut().and_then(|object| object.remove("deviceToken")).and_then(|value| value.as_str().map(str::to_owned)) {
        let layout = layout(&app, &key);
        // This instance's own device token, renewed by its own hub.
        OS.store(&layout.names().device, &device)?;
        let grid = app.state::<AccessGrid>();
        let mut inner = grid.inner.lock().await;
        if let Some(instance) = inner.instances.get_mut(&key) {
            if let (Some(token), Some(expires)) = (answer["sessionToken"].as_str(), answer["expiresAt"].as_i64()) {
                instance.session = Some((token.to_owned(), expires, answer["strong"].as_bool().unwrap_or(false)));
            }
            if let Some(saved) = instance.member.as_mut() {
                saved.device_id = answer["deviceId"].as_str().unwrap_or_default().to_owned();
                let _ = persist(&layout, saved);
            }
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
pub(crate) async fn access_use(credential: String, method: Option<String>, url: String, headers: Option<Value>, body: Option<String>, body_base64: Option<String>, agent: Option<String>, grid_id: Option<String>, app: AppHandle) -> Result<Value, String> {
    let key = pick(&app, grid_id.as_deref()).await?;
    let computer = crate::grid::computer_name(&app);
    call(&app, &key, "use", json!({"credential": credential, "method": method.unwrap_or_else(|| "GET".into()), "url": url, "headers": headers, "body": body, "bodyBase64": body_base64, "agent": agent, "computer": computer})).await
}

/// A request's state; a finished answer is handed over once.
pub(crate) async fn access_check(id: String, grid_id: Option<String>, app: AppHandle) -> Result<Value, String> {
    let key = pick(&app, grid_id.as_deref()).await?;
    call(&app, &key, "request", json!({"id": id})).await
}

/// An agent asks to see a credential (a short-lived token for the minting kinds); an approver
/// always decides.
pub(crate) async fn access_reveal(credential: String, reason: Option<String>, agent: Option<String>, grid_id: Option<String>, app: AppHandle) -> Result<Value, String> {
    let key = pick(&app, grid_id.as_deref()).await?;
    let computer = crate::grid::computer_name(&app);
    call(&app, &key, "reveal", json!({"credential": credential, "reason": reason, "agent": agent, "computer": computer})).await
}

/// Admin, on the hub's computer: writes an encrypted backup of one grid (record, activity log
/// and both of its own keys) to `output`, to move it or bring it back after a disk is lost.
pub(crate) async fn access_backup(output: String, passphrase: String, grid_id: Option<String>, app: AppHandle) -> Result<Value, String> {
    let key = pick(&app, grid_id.as_deref()).await?;
    if app.state::<AccessGrid>().inner.lock().await.instances.get(&key).is_none_or(|instance| instance.hub.is_none()) {
        return Err("Backups are made on the computer that runs the Access Grid".into());
    }
    let output = PathBuf::from(output.trim());
    if output.as_os_str().is_empty() || output.is_dir() {
        return Err("--output is the backup file to write, such as D:/acme-access.backup".into());
    }
    if output.exists() {
        return Err(format!("{} already exists; choose a new file name", output.display()));
    }
    let layout = layout(&app, &key);
    let bytes = backup_bytes(&layout, &OS, passphrase).await?;
    std::fs::write(&output, &bytes).map_err(|error| format!("Cannot write {}: {error}", output.display()))?;
    crate::security::record(event("access.backup", &key).path("file", &output.display().to_string()));
    Ok(json!({"file": output.display().to_string(), "bytes": bytes.len(), "message": "Backup written. Keep it and its passphrase apart: together they open every credential the grid keeps."}))
}

/// A backup of the hub in `layout`, with that instance's own keys.
async fn backup_bytes(layout: &Layout, vault: &dyn Vault, passphrase: String) -> Result<Vec<u8>, String> {
    let names = layout.names();
    let missing = || "The Access Grid's keys could not be read from the OS credential vault, so no backup was written".to_owned();
    let (tls_key, seal_key) = (resolve(vault, &names.hub_key).ok_or_else(missing)?, resolve(vault, &names.seal_key).ok_or_else(missing)?);
    let path = layout.hub();
    tokio::task::spawn_blocking(move || backup::create(&path, &tls_key, &seal_key, &passphrase)).await.map_err(|error| error.to_string())?
}

/// Where a backup of the grid `record_id` is restored: the instance `wanted` names, else the one
/// signed in to that grid, else a free default instance, else a new one. Never an instance that
/// has a hub, and never while that grid's hub already runs here.
fn restore_slot(inner: &Inner, root: &Path, vault: &dyn Vault, record_id: &str, fingerprint: Option<&str>, wanted: Option<&str>) -> Result<Layout, String> {
    for (key, instance) in present(inner, root) {
        let layout = Layout::new(root, key)?;
        let runs = instance.hub.is_some() || layout.hub().exists();
        if runs && instance.grid_id().as_deref() == Some(record_id) {
            return Err(format!("This computer already runs {}'s Access Grid; delete it first", instance.company()));
        }
    }
    let target = match wanted.map(str::trim).filter(|wanted| !wanted.is_empty()) {
        Some(wanted) => Some(choose(inner, root, Some(wanted))?),
        None => present(inner, root)
            .into_iter()
            .find(|(_, instance)| instance.hub.is_none() && instance.member.as_ref().is_some_and(|saved| saved.access_id == record_id || net::normalize_fingerprint(&saved.fingerprint).as_deref() == fingerprint))
            .map(|(key, _)| key.clone()),
    };
    let Some(key) = target else { return slot_for_hub(inner, root, vault) };
    let layout = Layout::new(root, &key)?;
    let instance = inner.instances.get(&key);
    if instance.is_some_and(|instance| instance.hub.is_some()) || layout.hub().exists() {
        return Err("That Access Grid already runs a hub here, so the backup was not restored into it. Leave out gridId to restore it beside the grids already here.".into());
    }
    if let (Some(saved), Some(fingerprint)) = (instance.and_then(|instance| instance.member.as_ref()), fingerprint) {
        if net::normalize_fingerprint(&saved.fingerprint).as_deref() != Some(fingerprint) {
            return Err(format!("This backup is not of {}'s Access Grid, which that instance is signed in to. Leave out gridId to restore it beside the grids already here.", saved.company));
        }
    }
    for name in [layout.names().hub_key, layout.names().seal_key] {
        if held(vault, &name)? {
            return Err(format!("The OS credential vault already holds a key called {name}, so the backup was not restored there and nothing was changed. Leave out gridId to restore it beside the grids already here."));
        }
    }
    Ok(layout)
}

/// Puts a backup's grid in `layout`, its keys under that instance's own names (each only if the
/// vault holds no key by that name), taking everything back if a step fails.
fn install_backup(layout: &Layout, vault: &dyn Vault, contents: &backup::Contents, ip: IpAddr, ports: Option<(u16, u16)>) -> Result<hub::Record, String> {
    let path = layout.hub();
    let record = hub::install_with(&path, contents, Some(ip), ports)?;
    let names = layout.names();
    let mut written = Vec::new();
    let mut stored = store_new(vault, &names.hub_key, &contents.tls_key);
    if stored.is_ok() {
        written.push(names.hub_key.as_str());
        stored = store_new(vault, &names.seal_key, &contents.seal_key);
    }
    if let Err(error) = stored {
        for name in written {
            vault.remove(name);
        }
        let activity = hub::activity_path(&path);
        for file in [path, activity] {
            let _ = std::fs::remove_file(file);
        }
        layout.tidy();
        return Err(error);
    }
    Ok(record)
}

/// Admin: brings an Access Grid back from a backup on this computer, at `address`. People's
/// computers keep trusting it; they sign in at the new address with the new invite, and their
/// remembered sign-ins carry over. The backup's keys go only to the instance it is restored into.
pub(crate) async fn access_restore_backup(file: String, passphrase: String, address: String, grid_id: Option<String>, app: AppHandle) -> Result<Value, String> {
    let grid = app.state::<AccessGrid>();
    let _admin = grid.admin.lock().await;
    ensure_loaded(&app).await;
    let ip: IpAddr = address.trim().parse().map_err(|_| "--ip is this computer's LAN or VPN address, such as 192.168.1.20")?;
    if ip.is_loopback() || ip.is_unspecified() || !net::private(ip) {
        return Err("Use this computer's private LAN or VPN address".into());
    }
    let bytes = std::fs::read(file.trim()).map_err(|error| format!("Cannot read {file}: {error}"))?;
    let contents = tokio::task::spawn_blocking(move || backup::open(&bytes, &passphrase)).await.map_err(|error| error.to_string())??;
    let record_id = contents.record["id"].as_str().unwrap_or_default().to_owned();
    let fingerprint = contents.record["certificate"].as_str().and_then(|pem| net::fingerprint(pem).ok()).and_then(|text| net::normalize_fingerprint(&text));
    let root = folder(&app);
    let layout = {
        let inner = grid.inner.lock().await;
        restore_slot(&inner, &root, &OS, &record_id, fingerprint.as_deref(), grid_id.as_deref())?
    };
    let key = layout.key().to_owned();
    // The default instance keeps the ports the grid had; another takes ports given here, since
    // the ones it had may be another grid's on this computer.
    let (ports, allocated) = match layout.is_default() {
        true => (None, Vec::new()),
        false => {
            let (port, tunnel, allocated) = hub_ports(&layout, &root)?;
            (Some((port, tunnel)), allocated)
        }
    };
    let record = install_backup(&layout, &OS, &contents, ip, ports).inspect_err(|_| {
        if !allocated.is_empty() {
            crate::grid::instances::release_ports(&allocated);
        }
    })?;
    {
        let mut inner = grid.inner.lock().await;
        let instance = inner.instances.entry(key.clone()).or_default();
        instance.hub_error = None;
        load(&layout, instance, &OS).await;
        if let Some(error) = instance.hub_error.clone() {
            return Err(error);
        }
        keep_tunnel(&app, &layout, instance);
    }
    crate::security::record(event("access.restored.backup", &key).text("company", &record.company));
    drop(_admin);
    let mut status = access_status(Some(key), app).await?;
    status["message"] = json!(format!("{}'s Access Grid is running here again. Share the new invite: people's computers move to it without a password.", record.company));
    Ok(status)
}

/// App commands, from the main window only. `gridId` is optional everywhere: it names one of the
/// Access Grids on this computer when there are several.
pub(crate) mod commands {
    use super::*;

    fn main_window(window: &WebviewWindow) -> Result<(), String> {
        if window.label() == "main" { Ok(()) } else { Err("The Access Grid is managed from the main Yougori window".into()) }
    }

    #[tauri::command]
    pub async fn access_status(app: AppHandle, window: WebviewWindow, grid_id: Option<String>) -> Result<Value, String> {
        main_window(&window)?;
        super::access_status(grid_id, app).await
    }

    #[tauri::command]
    #[allow(clippy::too_many_arguments)]
    pub async fn access_create(app: AppHandle, window: WebviewWindow, company: String, address: String, username: String, name: Option<String>, password: String, tunnel: Option<String>) -> Result<Value, String> {
        main_window(&window)?;
        super::access_create(company, address, username, name, password, tunnel, app).await
    }

    #[tauri::command]
    pub async fn access_delete(app: AppHandle, window: WebviewWindow, when: Option<String>, grid_id: Option<String>) -> Result<Value, String> {
        main_window(&window)?;
        super::access_delete(when, grid_id, app).await
    }

    #[tauri::command]
    pub async fn access_restore(app: AppHandle, window: WebviewWindow, grid_id: Option<String>) -> Result<Value, String> {
        main_window(&window)?;
        super::access_restore(grid_id, app).await
    }

    #[tauri::command]
    #[allow(clippy::too_many_arguments)]
    pub async fn access_signin(app: AppHandle, window: WebviewWindow, invite: String, username: Option<String>, password: Option<String>, code: Option<String>, sso: Option<bool>, grid_id: Option<String>) -> Result<Value, String> {
        main_window(&window)?;
        super::access_signin(invite, username, password, code, sso, grid_id, app).await
    }

    #[tauri::command]
    pub async fn access_signout(app: AppHandle, window: WebviewWindow, grid_id: Option<String>) -> Result<Value, String> {
        main_window(&window)?;
        super::access_signout(grid_id, app).await
    }

    #[tauri::command]
    pub async fn access_manage(app: AppHandle, window: WebviewWindow, request: Value, grid_id: Option<String>) -> Result<Value, String> {
        main_window(&window)?;
        super::access_manage(request, grid_id, app).await
    }

    #[tauri::command]
    pub async fn access_account(app: AppHandle, window: WebviewWindow, request: Value, grid_id: Option<String>) -> Result<Value, String> {
        main_window(&window)?;
        super::access_account(request, grid_id, app).await
    }

    #[tauri::command]
    pub async fn access_backup(app: AppHandle, window: WebviewWindow, output: String, passphrase: String, grid_id: Option<String>) -> Result<Value, String> {
        main_window(&window)?;
        super::access_backup(output, passphrase, grid_id, app).await
    }

    #[tauri::command]
    pub async fn access_restore_backup(app: AppHandle, window: WebviewWindow, file: String, passphrase: String, address: String, grid_id: Option<String>) -> Result<Value, String> {
        main_window(&window)?;
        super::access_restore_backup(file, passphrase, address, grid_id, app).await
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

#[cfg(test)]
#[path = "accessgrid_tests.rs"]
mod instances_tests;
