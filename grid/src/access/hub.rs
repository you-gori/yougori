//! The Access Grid hub: one trusted company computer keeps the credentials (sealed with a key in
//! its OS vault), the people and the rules. People sign in from their own computers over pinned
//! TLS; their agents ask the hub to send requests with a credential, and the hub sends them
//! itself, so the value never leaves this computer. Requests a rule marks `ask` wait here until
//! an approver decides. Every use, decision and change is written to the activity log.
//!
//! `people` signs people in (password, two-step codes, the company's identity provider) and
//! keeps their remembered computers; `admin` is what admins, approvers and auditors see and
//! change; `requests` sends, waits for approvals and hands answers back.
use super::{
    activity::{self, Entry, Log},
    backup, mint,
    policy::{self, Credential, Permission, Person, Rule, Settings, Sso},
    seal::Sealer,
};
use crate::{
    digest, is_token, label,
    net::{self, Body},
    now, token, tunnel,
};
use hyper::{body::Incoming, header, Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};
use tokio::{net::TcpListener, sync::Semaphore};
use tokio_rustls::TlsAcceptor;

mod admin;
mod people;
mod requests;

/// A sign-in lasts this long; the person's computer signs in again by itself.
pub const SESSION: i64 = 8 * 60 * 60;
/// A request waits this long for an approver.
pub const WAIT: i64 = 15 * 60;
/// Deleting "later" pauses the grid this long; then it is deleted.
pub const PAUSE: i64 = 3 * 24 * 60 * 60;
/// A deleted grid keeps telling people's computers so for this long, then removes itself.
pub const TELL_FOR: i64 = 30 * 24 * 60 * 60;
const MAX_SESSIONS: usize = 4096;
const MAX_CONNECTIONS: usize = 128;
const SMALL: usize = 64 * 1024;
const SWEEP: Duration = Duration::from_secs(15);

pub type Events = Arc<dyn Fn(&'static str, Value) + Send + Sync>;

/// The Access Grid as saved on the hub computer. The TLS key and the sealing key live in the OS
/// vault; credential values and two-step secrets are sealed; people's keys are kept as hashes.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Record {
    pub version: u8,
    pub id: String,
    pub company: String,
    pub address: IpAddr,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel_port: Option<u16>,
    pub certificate: String,
    pub created_at: i64,
    /// The person who created the grid on this computer. They stay an admin.
    pub owner: String,
    #[serde(default)]
    pub people: Vec<Person>,
    #[serde(default)]
    pub credentials: Vec<Credential>,
    #[serde(default)]
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub settings: Settings,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sso: Option<Sso>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closing: Option<Closing>,
}

/// The owner deleted the grid: it is paused until `until`, then deleted (`gone`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Closing {
    pub requested_at: i64,
    pub until: i64,
    #[serde(default)]
    pub gone: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Open,
    /// Nobody signs in or uses anything until the time given; `restore` takes it back.
    Paused(i64),
    /// Deleted: credentials, people and rules are gone; every request is told so.
    Gone,
}

/// The first admin, created with the grid. `key` is derived from their password on this computer.
pub struct Owner {
    pub username: String,
    pub name: String,
    pub salt: String,
    pub key: String,
}

fn new_id(prefix: &str) -> String {
    format!("{prefix}-{}", &token()[..16])
}

fn valid_key(key: &str) -> bool {
    key.len() == 64 && key.bytes().all(|c| c.is_ascii_hexdigit())
}

/// Creates the hub's record; returns the TLS private key for the OS vault.
pub fn create(path: &Path, company: &str, address: IpAddr, port: u16, tunnel_port: Option<u16>, owner: Owner) -> Result<String, String> {
    let company = label(company, "The company name")?;
    if !net::private(address) {
        return Err("The Access Grid needs this computer's private LAN or VPN address, for example 10.0.0.5".into());
    }
    if port < 1024 {
        return Err("Choose a port between 1024 and 65535".into());
    }
    if tunnel_port.is_some_and(|tunnel| tunnel < 1024 || tunnel == port) {
        return Err("Choose a tunnel port between 1024 and 65535, other than the hub's own port".into());
    }
    if path.exists() {
        return Err("This computer already runs an Access Grid".into());
    }
    let username = policy::username(&owner.username)?;
    if !valid_key(&owner.key) {
        return Err("The password key is invalid".into());
    }
    let identity = net::new_identity(address, None)?;
    let person = Person {
        id: new_id("person"),
        name: label(if owner.name.trim().is_empty() { &username } else { &owner.name }, "Your name")?,
        username,
        permission: Permission::Admin,
        teams: Vec::new(),
        salt: owner.salt,
        key_hash: policy::key_hash(&owner.key),
        created_at: now(),
        last_seen_at: None,
        email: None,
        sso_subject: None,
        two_step: None,
        generation: 0,
        devices: Vec::new(),
    };
    let record = Record {
        version: 1,
        id: new_id("access"),
        company,
        address,
        port,
        tunnel_port,
        certificate: identity.certificate,
        created_at: now(),
        owner: person.id.clone(),
        people: vec![person],
        credentials: Vec::new(),
        rules: Vec::new(),
        settings: Settings::default(),
        sso: None,
        closing: None,
    };
    save(path, &record)?;
    Ok(identity.key)
}

pub fn load(path: &Path) -> Result<Record, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("Cannot read the Access Grid's settings: {error}"))?;
    serde_json::from_slice(&bytes).map_err(|_| "The Access Grid's settings are damaged".to_owned())
}

fn save(path: &Path, record: &Record) -> Result<(), String> {
    let folder = path.parent().ok_or("Invalid Access Grid folder")?;
    std::fs::create_dir_all(folder).map_err(|error| error.to_string())?;
    let mut file = tempfile::NamedTempFile::new_in(folder).map_err(|error| error.to_string())?;
    serde_json::to_writer_pretty(&mut file, record).map_err(|error| error.to_string())?;
    file.persist(path).map_err(|error| error.to_string())?;
    Ok(())
}

/// The activity log beside the record.
pub fn activity_path(path: &Path) -> PathBuf {
    path.with_file_name("access-activity.jsonl")
}

/// Puts a backup's record and activity log at `path`, at `address` when it moves to another
/// computer. The keys it holds go to the OS vault, which the caller does.
pub fn install(path: &Path, contents: &backup::Contents, address: Option<IpAddr>) -> Result<Record, String> {
    if path.exists() {
        return Err("This computer already runs an Access Grid; delete it first".into());
    }
    let mut record: Record = serde_json::from_value(contents.record.clone()).map_err(|_| "The backup's record is damaged")?;
    if let Some(address) = address {
        if !net::private(address) {
            return Err("Use this computer's private LAN or VPN address".into());
        }
        record.address = address;
    }
    record.closing = None;
    save(path, &record)?;
    std::fs::write(activity_path(path), &contents.activity).map_err(|error| format!("Cannot write the activity log: {error}"))?;
    Ok(record)
}

/// A signed-in person, as one request sees them.
#[derive(Clone)]
struct Caller {
    person: Person,
    /// Signed in with a second factor.
    strong: bool,
    /// The session's hash, to end it.
    session: String,
    device: Option<String>,
}

struct Session {
    person: String,
    generation: u64,
    expires: i64,
    strong: bool,
    device: Option<String>,
}

#[derive(Default)]
struct SsoCache {
    issuer: String,
    discovery: Option<(Value, Instant)>,
    keys: Option<(Value, Instant)>,
    refreshed: Option<Instant>,
}

struct Live {
    sessions: HashMap<String, Session>,
    /// Wrong sign-ins per address (IPv6 per /64), and per account-from-that-address. The address
    /// count has more room, because an office shares one.
    refused: super::throttle::Throttle<IpAddr>,
    refused_names: super::throttle::Throttle<String>,
    /// The last two-step time step each person signed in with: a code works once.
    used_codes: HashMap<String, i64>,
    requests: HashMap<String, requests::Pending>,
    /// Uses at once under limited allow rules: (rule, person) → times in the last hour.
    usage: HashMap<(String, String), VecDeque<i64>>,
    /// Two-step secrets shown to a person but not yet confirmed with a code.
    two_step: HashMap<String, (String, i64)>,
    /// The identity provider's discovery document and keys.
    sso: SsoCache,
}

impl Default for Live {
    fn default() -> Self {
        Self {
            sessions: HashMap::new(),
            refused: super::throttle::Throttle::with_limit(super::throttle::ADDRESS_LIMIT),
            refused_names: super::throttle::Throttle::default(),
            used_codes: HashMap::new(),
            requests: HashMap::new(),
            usage: HashMap::new(),
            two_step: HashMap::new(),
            sso: SsoCache::default(),
        }
    }
}

struct Shared {
    path: PathBuf,
    bound: SocketAddr,
    tunnel: Option<SocketAddr>,
    fingerprint: String,
    record: Mutex<Record>,
    live: Mutex<Live>,
    sealer: Sealer,
    log: Log,
    mint: mint::Cache,
    events: Events,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A refusal with its HTTP status and a short code the client can act on.
struct Refusal(StatusCode, &'static str, String);

impl Refusal {
    fn bad(message: impl Into<String>) -> Self {
        Refusal(StatusCode::BAD_REQUEST, "invalid_request", message.into())
    }
    fn forbidden(message: impl Into<String>) -> Self {
        Refusal(StatusCode::FORBIDDEN, "refused", message.into())
    }
    fn missing(message: impl Into<String>) -> Self {
        Refusal(StatusCode::NOT_FOUND, "not_found", message.into())
    }
}

impl From<String> for Refusal {
    fn from(message: String) -> Self {
        Refusal::bad(message)
    }
}

/// A running Access Grid hub. Dropping it closes the service and every connection.
pub struct Hub {
    shared: Arc<Shared>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for Hub {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Hub {
    pub async fn start(path: PathBuf, tls_key: &str, seal_key: &str, events: Events) -> Result<Hub, String> {
        let record = load(&path)?;
        let sealer = Sealer::new(seal_key)?;
        let tls = TlsAcceptor::from(net::server_config(&net::Identity { certificate: record.certificate.clone(), key: tls_key.to_owned() })?);
        let fingerprint = net::fingerprint(&record.certificate)?;
        let listener = TcpListener::bind(SocketAddr::new(record.address, record.port))
            .await
            .map_err(|error| format!("Cannot open the Access Grid on {}:{} ({error}). Is this still this computer's address, and is the port free?", record.address, record.port))?;
        let bound = listener.local_addr().map_err(|error| error.to_string())?;
        let tunnel = match record.tunnel_port {
            Some(port) => Some(TcpListener::bind(SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), port)).await.map_err(|error| format!("Cannot open the Access Grid's tunnel entry on 127.0.0.1:{port} ({error})."))?),
            None => None,
        };
        let tunnel_bound = tunnel.as_ref().map(|listener| listener.local_addr()).transpose().map_err(|error| error.to_string())?;
        let log = Log::open(activity_path(&path), activity::chain_key(seal_key));
        let shared = Arc::new(Shared { path, bound, tunnel: tunnel_bound, fingerprint, record: Mutex::new(record), live: Mutex::new(Live::default()), sealer, log, mint: mint::Cache::default(), events });
        let mut tasks = vec![tokio::spawn(serve(shared.clone(), listener, tls.clone())), tokio::spawn(sweep(shared.clone()))];
        if let Some(tunnel) = tunnel {
            tasks.push(tokio::spawn(serve_tunnel(shared.clone(), tunnel, tls)));
        }
        Ok(Hub { shared, tasks })
    }

    pub fn address(&self) -> SocketAddr {
        self.shared.bound
    }

    pub fn tunnel_address(&self) -> Option<SocketAddr> {
        self.shared.tunnel
    }

    pub fn record(&self) -> Record {
        lock(&self.shared.record).clone()
    }

    pub fn fingerprint(&self) -> &str {
        &self.shared.fingerprint
    }

    pub fn phase(&self) -> Phase {
        phase(&lock(&self.shared.record))
    }

    /// The hub at a glance, for the computer that runs it. No values, hashes or keys.
    pub fn status(&self) -> Value {
        let record = lock(&self.shared.record);
        let live = lock(&self.shared.live);
        let owner = record.people.iter().find(|person| person.id == record.owner).map(|person| person.username.clone());
        json!({
            "id": record.id, "company": record.company, "address": record.address.to_string(), "port": self.shared.bound.port(),
            "fingerprint": self.shared.fingerprint, "createdAt": record.created_at, "tunnelPort": self.shared.tunnel.map(|address| address.port()),
            "owner": owner, "people": record.people.len(), "credentials": record.credentials.len(), "rules": record.rules.len(),
            "waiting": live.requests.values().filter(|request| request.waiting()).count(),
            "signedIn": live.sessions.values().filter(|session| session.expires > now()).map(|session| session.person.as_str()).collect::<std::collections::BTreeSet<_>>().len(),
            "closing": record.closing, "sso": record.sso.is_some(), "requireTwoStep": record.settings.require_two_step,
        })
    }

    /// Manages the grid as its owner, for the computer that runs it.
    pub fn manage_as_owner(&self, request: Value) -> Result<Value, String> {
        let owner = {
            let record = lock(&self.shared.record);
            record.people.iter().find(|person| person.id == record.owner).cloned().ok_or("The Access Grid's owner account is missing")?
        };
        let caller = Caller { person: owner, strong: true, session: String::new(), device: None };
        admin::manage(&self.shared, &caller, request).map_err(|Refusal(_, _, message)| message)
    }

    /// Whether an approver must look at something.
    pub fn waiting(&self) -> usize {
        lock(&self.shared.live).requests.values().filter(|request| request.waiting()).count()
    }

    /// Deletes the grid in three days: until then it is paused, and `restore` brings it back.
    pub fn close_later(&self) -> Result<i64, String> {
        // A wiped grid stays wiped: pausing it would let `restore` open an empty grid again. A
        // grid already paused keeps the date it was given.
        match self.phase() {
            Phase::Gone => return Err("This Access Grid was already deleted; its credentials are gone".into()),
            Phase::Paused(until) => return Ok(until),
            Phase::Open => {}
        }
        let until = now() + PAUSE;
        self.set_closing(Some(Closing { requested_at: now(), until, gone: false }))?;
        lock(&self.shared.live).sessions.clear();
        self.shared.log.append(Entry { at: now(), action: "change".into(), outcome: "the grid was scheduled for deletion; paused until then".into(), ..Entry::default() });
        Ok(until)
    }

    /// Deletes the grid now: its credentials, people and rules are wiped at once; it keeps
    /// telling people's computers so until `TELL_FOR` has passed.
    pub fn close_now(&self) -> Result<(), String> {
        wipe(&self.shared)
    }

    /// Takes back a deletion while the grid is still paused.
    pub fn restore(&self) -> Result<(), String> {
        match self.phase() {
            Phase::Paused(_) => {
                self.set_closing(None)?;
                self.shared.log.append(Entry { at: now(), action: "change".into(), outcome: "the deletion was taken back".into(), ..Entry::default() });
                Ok(())
            }
            Phase::Open => Err("This Access Grid is not being deleted".into()),
            Phase::Gone => Err("This Access Grid was already deleted; its credentials are gone".into()),
        }
    }

    /// The deleted grid has told its people's computers for long enough to be removed.
    pub fn told_enough(&self) -> bool {
        lock(&self.shared.record).closing.as_ref().is_some_and(|closing| closing.gone && closing.until + TELL_FOR <= now())
    }

    fn set_closing(&self, closing: Option<Closing>) -> Result<(), String> {
        let mut record = lock(&self.shared.record);
        let mut next = record.clone();
        next.closing = closing;
        save(&self.shared.path, &next)?;
        *record = next;
        Ok(())
    }
}

fn phase(record: &Record) -> Phase {
    match &record.closing {
        None => Phase::Open,
        Some(closing) if closing.gone => Phase::Gone,
        Some(closing) => Phase::Paused(closing.until),
    }
}

/// Deletes everything the grid kept but what it needs to say it is gone.
fn wipe(shared: &Shared) -> Result<(), String> {
    {
        let mut record = lock(&shared.record);
        let mut next = record.clone();
        next.people.clear();
        next.credentials.clear();
        next.rules.clear();
        next.sso = None;
        next.closing = Some(Closing { requested_at: next.closing.as_ref().map_or(now(), |closing| closing.requested_at), until: now(), gone: true });
        save(&shared.path, &next)?;
        *record = next;
    }
    {
        let mut live = lock(&shared.live);
        live.sessions.clear();
        live.requests.clear();
        live.two_step.clear();
        live.usage.clear();
    }
    shared.mint.forget_all();
    shared.log.append(Entry { at: now(), action: "change".into(), outcome: "the grid was deleted with its credentials, people and rules".into(), ..Entry::default() });
    (shared.events)("access.deleted", json!({}));
    Ok(())
}

impl Shared {
    fn log(&self, entry: Entry) {
        self.log.append(entry);
    }

    fn change(&self, actor: &Person, outcome: String) {
        self.log(Entry { at: now(), person: actor.username.clone(), action: "change".into(), outcome, ..Entry::default() });
    }

    fn caller(&self, token: &str) -> Option<Caller> {
        if !is_token(token) {
            return None;
        }
        let hash = digest("access-session", token);
        let (person, generation, strong, device) = {
            let live = lock(&self.live);
            let session = live.sessions.get(&hash).filter(|session| session.expires > now())?;
            (session.person.clone(), session.generation, session.strong, session.device.clone())
        };
        // A changed password, a reset, signing out everywhere or removal ends the session.
        let person = lock(&self.record).people.iter().find(|own| own.id == person && own.generation == generation).cloned()?;
        Some(Caller { person, strong, session: hash, device })
    }

    /// A refusal when the grid wants a second factor this sign-in did not have.
    fn second_factor(&self, caller: &Caller) -> Option<Refusal> {
        (lock(&self.record).settings.require_two_step && !caller.strong).then(|| Refusal(StatusCode::FORBIDDEN, "two_step_required", "Your company requires two-step sign-in. Turn it on for your account in Access Grid (or sign in with your company account), then sign in again.".into()))
    }
}

fn find_person<'a>(record: &'a Record, text: &str) -> Option<&'a Person> {
    let text = text.trim();
    record.people.iter().find(|person| person.id == text || person.username.eq_ignore_ascii_case(text))
}

fn find_credential<'a>(record: &'a Record, text: &str) -> Option<&'a Credential> {
    let text = text.trim();
    record.credentials.iter().find(|credential| credential.id == text).or_else(|| record.credentials.iter().find(|credential| credential.name.eq_ignore_ascii_case(text)))
}

fn text<'a>(body: &'a Value, key: &str) -> Option<&'a str> {
    body.get(key).and_then(Value::as_str)
}

/// A short label from an untrusted caller: printable, single line, at most `max` characters.
fn note(value: Option<&str>, max: usize) -> String {
    value.unwrap_or_default().chars().filter(|c| !c.is_control()).take(max).collect::<String>().trim().to_owned()
}

/// Applies a change to a copy of the record, saves it, then makes it current.
fn change_record<T>(shared: &Shared, change: impl FnOnce(&mut Record) -> Result<T, Refusal>) -> Result<T, Refusal> {
    let mut record = lock(&shared.record);
    let mut next = record.clone();
    let result = change(&mut next)?;
    save(&shared.path, &next)?;
    *record = next;
    Ok(result)
}

async fn sweep(shared: Arc<Shared>) {
    loop {
        tokio::time::sleep(SWEEP).await;
        let at = now();
        let current = phase(&lock(&shared.record));
        if matches!(current, Phase::Paused(until) if until <= at) {
            let _ = wipe(&shared);
        }
        let expired = {
            let mut live = lock(&shared.live);
            live.sessions.retain(|_, session| session.expires > at);
            live.refused.forget_lapsed();
            live.refused_names.forget_lapsed();
            // A code is good for a step either side of now, so older steps cannot come back.
            live.used_codes.retain(|_, step| *step >= at.div_euclid(crate::totp::STEP) - 2);
            live.two_step.retain(|_, (_, until)| *until > at);
            for times in live.usage.values_mut() {
                while times.front().is_some_and(|time| *time <= at - 3600) {
                    times.pop_front();
                }
            }
            live.usage.retain(|_, times| !times.is_empty());
            requests::expire(&mut live, at)
        };
        for entry in expired {
            shared.log(entry);
        }
        // Rules an approval made for a while lapse by themselves, and so do old computers.
        let _ = change_record(&shared, |record| {
            let before = (record.rules.len(), record.people.iter().map(|person| person.devices.len()).sum::<usize>());
            record.rules.retain(|rule| rule.live(at));
            for person in &mut record.people {
                let generation = person.generation;
                person.devices.retain(|device| device.generation == generation && device.last_used_at + policy::DEVICE_LIFETIME > at);
            }
            let after = (record.rules.len(), record.people.iter().map(|person| person.devices.len()).sum::<usize>());
            if before == after {
                return Err(Refusal::bad("nothing lapsed"));
            }
            Ok(())
        });
    }
}

async fn serve(shared: Arc<Shared>, listener: TcpListener, tls: TlsAcceptor) {
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut connections = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((socket, peer)) = accepted else { tokio::time::sleep(Duration::from_millis(100)).await; continue };
                if !net::private(peer.ip()) { continue }
                let Ok(permit) = slots.clone().try_acquire_owned() else { continue };
                let (shared, tls) = (shared.clone(), tls.clone());
                connections.spawn(async move { let _permit = permit; connection(shared, tls, socket, peer.ip()).await; });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

async fn serve_tunnel(shared: Arc<Shared>, listener: TcpListener, tls: TlsAcceptor) {
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut connections = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((socket, from)) = accepted else { tokio::time::sleep(Duration::from_millis(100)).await; continue };
                if !from.ip().is_loopback() { continue }
                let Ok(permit) = slots.clone().try_acquire_owned() else { continue };
                let (shared, tls) = (shared.clone(), tls.clone());
                connections.spawn(async move {
                    let _permit = permit;
                    let Ok((stream, peer)) = tunnel::accept(socket).await else { return };
                    connection(shared, tls, stream, peer).await;
                });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

async fn connection<S>(shared: Arc<Shared>, tls: TlsAcceptor, socket: S, peer: IpAddr)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let Ok(stream) = tls.accept(socket).await else { return };
    let service = hyper::service::service_fn(move |request: Request<Incoming>| {
        let shared = shared.clone();
        async move { Ok::<_, std::convert::Infallible>(route(shared, peer, request).await) }
    });
    let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), service).await;
}

fn json_response(status: StatusCode, value: &Value) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .body(net::full(serde_json::to_vec(value).unwrap_or_default()))
        .expect("response builds")
}

fn error(status: StatusCode, code: &str, message: impl Into<String>) -> Response<Body> {
    json_response(status, &json!({"error": {"code": code, "message": message.into()}}))
}

fn answer(result: Result<Value, Refusal>) -> Response<Body> {
    match result {
        Ok(value) => json_response(StatusCode::OK, &value),
        Err(Refusal(status, code, message)) => error(status, code, message),
    }
}

fn bearer(request: &Request<Incoming>) -> Option<String> {
    request.headers().get(header::AUTHORIZATION)?.to_str().ok()?.strip_prefix("Bearer ").map(str::to_owned)
}

fn throttled(shared: &Shared, peer: IpAddr) -> bool {
    lock(&shared.live).refused.blocked(&super::throttle::network(peer))
}

fn refuse(shared: &Shared, peer: IpAddr) {
    lock(&shared.live).refused.fail(super::throttle::network(peer));
}

/// One account, as guessed at from one address. Keying both together is what stops a stranger
/// locking somebody out of their own grid: to shut Ada out you would have to be guessing from
/// Ada's own address. Unknown names count the same way, so the answer says nothing about who
/// exists.
fn attempt_key(peer: IpAddr, username: &str) -> String {
    format!("{}|{username}", super::throttle::network(peer))
}

fn name_throttled(shared: &Shared, peer: IpAddr, username: &str) -> bool {
    !username.is_empty() && lock(&shared.live).refused_names.blocked(&attempt_key(peer, username))
}

fn refuse_name(shared: &Shared, peer: IpAddr, username: &str) {
    if !username.is_empty() {
        lock(&shared.live).refused_names.fail(attempt_key(peer, username));
    }
}

/// Forgets the wrong sign-ins counted against a person and the address they came from, once they
/// have proved who they are.
fn forgive(shared: &Shared, peer: IpAddr, username: &str) {
    let mut live = lock(&shared.live);
    live.refused.forgive(&super::throttle::network(peer));
    if !username.is_empty() {
        live.refused_names.forgive(&attempt_key(peer, username));
    }
}

/// A refusal by one of the counts above, written to the log. Being kept out belongs in the record
/// as much as getting in does: without it, someone locking a person out leaves no trace at all.
fn rate_limited(shared: &Shared, peer: IpAddr, username: &str, action: &str, what: &str) -> Response<Body> {
    shared.log(Entry {
        at: now(),
        person: username.to_owned(),
        action: action.to_owned(),
        outcome: format!("refused from {peer}: too many wrong sign-ins for {what}"),
        ..Entry::default()
    });
    let said = if what == "this username" {
        "Too many wrong sign-ins for this username; wait 10 minutes"
    } else {
        "Too many wrong passwords from this address; wait 10 minutes"
    };
    error(StatusCode::TOO_MANY_REQUESTS, "rate_limited", said)
}

/// Whether a two-step code for `step` may sign `person` in: only a step after the last one they
/// used, so a code that was seen cannot be used again. Records the step when it may.
fn fresh_code(shared: &Shared, person: &str, step: i64) -> bool {
    let mut live = lock(&shared.live);
    if live.used_codes.get(person).is_some_and(|last| step <= *last) {
        return false;
    }
    live.used_codes.insert(person.to_owned(), step);
    true
}

async fn route(shared: Arc<Shared>, peer: IpAddr, request: Request<Incoming>) -> Response<Body> {
    let path = request.uri().path().to_owned();
    let method = request.method().clone();
    let (current, company) = {
        let record = lock(&shared.record);
        (phase(&record), record.company.clone())
    };
    match current {
        Phase::Gone => return error(StatusCode::GONE, "access_deleted", format!("{company} deleted this Access Grid")),
        Phase::Paused(until) if path != "/access/v1/hello" => {
            let when = chrono::DateTime::from_timestamp(until, 0).map(|at| at.format("%Y-%m-%d %H:%M UTC").to_string()).unwrap_or_default();
            return error(StatusCode::SERVICE_UNAVAILABLE, "paused", format!("This Access Grid is paused: its admin scheduled it for deletion on {when}"));
        }
        _ => {}
    }
    match (method, path.as_str()) {
        (Method::GET, "/access/v1/hello") => {
            let record = lock(&shared.record);
            json_response(StatusCode::OK, &json!({"accessId": record.id, "company": record.company, "sso": record.sso.is_some(), "passwordless": record.sso.as_ref().is_some_and(|sso| sso.passwordless)}))
        }
        (Method::POST, "/access/v1/salt") => people::salt(&shared, peer, request).await,
        (Method::POST, "/access/v1/signin") => people::signin(&shared, peer, request).await,
        (Method::POST, "/access/v1/resume") => people::resume(&shared, peer, request).await,
        (Method::GET, "/access/v1/sso") => people::sso_config(&shared).await,
        (Method::POST, "/access/v1/sso") => people::sso_signin(&shared, peer, request).await,
        (Method::POST, path) if path.starts_with("/access/v1/") => {
            let Some(caller) = shared.caller(&bearer(&request).unwrap_or_default()) else {
                return error(StatusCode::UNAUTHORIZED, "signed_out", "Sign in to the Access Grid again");
            };
            let limit = if path == "/access/v1/use" { requests::LARGE } else { SMALL };
            let body = match net::json_body(request.into_body(), limit).await {
                Ok(body) => body,
                Err(message) => return error(StatusCode::BAD_REQUEST, "invalid_request", message),
            };
            let second = |shared: &Shared| shared.second_factor(&caller);
            answer(match path {
                "/access/v1/me" => Ok(admin::me(&shared, &caller)),
                "/access/v1/account" => people::account(&shared, &caller, body),
                "/access/v1/request" => requests::collect(&shared, &caller.person, text(&body, "id").unwrap_or_default()),
                "/access/v1/signout" => {
                    lock(&shared.live).sessions.remove(&caller.session);
                    Ok(json!({"signedOut": true}))
                }
                _ if second(&shared).is_some() => Err(second(&shared).expect("checked")),
                "/access/v1/use" => requests::use_credential(&shared, &caller.person, body).await,
                "/access/v1/reveal" => requests::reveal(&shared, &caller.person, body),
                "/access/v1/manage" => admin::manage(&shared, &caller, body),
                _ => Err(Refusal::missing("Unknown Access Grid path")),
            })
        }
        _ => error(StatusCode::NOT_FOUND, "not_found", "Unknown path"),
    }
}
