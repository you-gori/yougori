//! A Closed Bounty hub: one computer publishes a source and other computers join to work it.
//!
//! It is the Closed Neo Grid pattern applied to Swarm Mining, and shares its security: the hub
//! holds a pinned certificate, a computer joins with the company password (proved with scrypt and
//! HMAC, never sent) and the hub's fingerprint, and it can be reached on the LAN or through a
//! Cloudflare tunnel. Unlike a grid, the host does not run a model: it publishes a source, each
//! joined computer chooses its own model and works the source, and findings come back to the host.
//!
//! This module is the hub's transport. Running a model against the source happens on the member
//! computer, outside this crate.
use crate::{
    digest, is_token, label, now,
    net::{self, Body},
    password,
    tunnel::{self},
};
use hyper::{body::Incoming, header, Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard,
    },
    time::{Duration, Instant},
};
use tokio::{net::TcpListener, sync::Semaphore};
use tokio_rustls::TlsAcceptor;
#[path = "bounty_coordination.rs"]
mod coordination;

const MAX_MEMBERS: usize = 256;
const MAX_FINDINGS: usize = 2000;
const MAX_CONNECTIONS: usize = 64;
const REQUEST_LIMIT: usize = 64 * 1024;
/// A published source is at most this large across all its files.
pub const MAX_SOURCE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_FILES: usize = 4000;
const ONLINE: Duration = Duration::from_secs(45);

/// A file in the published source: a relative path and its bytes (base64 on the wire).
#[derive(Clone, Serialize, Deserialize)]
pub struct SourceFile {
    pub path: String,
    /// Standard base64 of the file's bytes.
    pub data: String,
}

/// What the host wants worked: a brief for the models, an authorization the worker must accept,
/// and the source files.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bounty {
    pub title: String,
    #[serde(default)]
    pub instructions: String,
    /// What the worker is authorized to do; it accepts this before working.
    #[serde(default)]
    pub authorization: String,
    pub files: Vec<SourceFile>,
    #[serde(default)]
    pub target: crate::bounty_project::Target,
    /// The host lets workers send this bounty's code to a GPU rented from an outside provider, for
    /// their model to read. Off unless the host turned it on; never written while off.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub rented_gpu: bool,
}

impl Bounty {
    pub fn checked(title: &str, instructions: &str, authorization: &str, files: Vec<SourceFile>) -> Result<Bounty, String> {
        let title = label(title, "The bounty title")?;
        // Empty source is allowed here; policy() requires at least one file unless the target is a
        // live URL, which it does not yet know at this point.
        if files.len() > MAX_FILES {
            return Err(format!("A bounty can have at most {MAX_FILES} files"));
        }
        let mut total = 0u64;
        for file in &files {
            if file.path.trim().is_empty() || file.path.contains("..") || file.path.starts_with(['/', '\\']) || file.path.contains(':') {
                return Err(format!("Unsafe file path: {}", file.path));
            }
            total += base64::decoded_len(&file.data) as u64;
        }
        if total > MAX_SOURCE_BYTES {
            return Err(format!("The source is larger than {} MB", MAX_SOURCE_BYTES / (1024 * 1024)));
        }
        crate::bounty_project::snapshot(&files)?;
        Ok(Bounty { title, instructions: instructions.trim().chars().take(8000).collect(), authorization: authorization.trim().chars().take(8000).collect(), files, target: Default::default(), rented_gpu: false })
    }

    fn summary(&self) -> Value {
        json!({"title": self.title, "instructions": self.instructions, "authorization": self.authorization, "target":self.target, "rentedGpu": self.rented_gpu, "files": self.files.len(), "bytes": self.files.iter().map(|file| base64::decoded_len(&file.data) as u64).sum::<u64>()})
    }
}

/// base64 helpers kept together so the wire format is in one place.
mod base64 {
    use ::base64::Engine;
    pub fn decoded_len(data: &str) -> usize {
        ::base64::engine::general_purpose::STANDARD.decode(data).map(|bytes| bytes.len()).unwrap_or(0)
    }
    pub fn valid(data: &str) -> bool {
        ::base64::engine::general_purpose::STANDARD.decode(data).is_ok()
    }
}

/// A finding a worker reported, kept on the host.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub id: String,
    pub member_id: String,
    pub member_name: String,
    pub model: String,
    pub title: String,
    pub detail: String,
    #[serde(default)]
    pub severity: String,
    pub created_at: i64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MemberRecord {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) platform: String,
    token_hash: String,
    pub(crate) joined_at: i64,
    /// The model the member chose to work the bounty with.
    #[serde(default)]
    pub(crate) model: Option<String>,
    #[serde(default)]
    pub(crate) findings: u32,
}

/// The bounty hub as saved on the host computer. Secrets are hashes; the certificate's private
/// key and the password's derived key live in the OS vault.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Record {
    pub version: u8,
    pub id: String,
    pub name: String,
    pub address: IpAddr,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel_port: Option<u16>,
    pub certificate: String,
    pub salt: String,
    pub created_at: i64,
    pub bounty: Bounty,
    // Readable inside this crate so that core::compat::bounty can count a published bounty
    // without starting a host, and so that nothing outside the crate can reach a member's token
    // hash. The same arrangement hub::Record already has for its own members and plans.
    #[serde(default)]
    pub(crate) members: Vec<MemberRecord>,
    #[serde(default)]
    pub(crate) findings: Vec<Finding>,
    #[serde(default, skip_serializing)]
    coordination: coordination::Coordination,
}

#[allow(clippy::too_many_arguments)]
pub fn create(path: &Path, name: &str, address: IpAddr, port: u16, hostname: Option<&str>, tunnel_port: Option<u16>, salt: &str, bounty: Bounty) -> Result<String, String> {
    let name = label(name, "The bounty host name")?;
    if !net::private(address) {
        return Err("The host needs this computer's private LAN or VPN address, for example 10.0.0.5".into());
    }
    if port != 0 && port < 1024 {
        return Err("Choose a port between 1024 and 65535".into());
    }
    if let Some(tunnel) = tunnel_port {
        if tunnel != 0 && (tunnel < 1024 || tunnel == port) {
            return Err("Choose a tunnel port between 1024 and 65535, other than the host's own port".into());
        }
    }
    let hostname = hostname.map(str::trim).filter(|name| !name.is_empty()).map(str::to_ascii_lowercase);
    if hostname.as_deref().is_some_and(|name| !net::valid_hostname(name)) {
        return Err("--hostname must be a DNS name".into());
    }
    if path.exists() {
        return Err("This computer already hosts a closed bounty".into());
    }
    let identity = net::new_identity(address, hostname.as_deref())?;
    let record = Record {
        version: 1,
        id: format!("bounty-{}", &crate::token()[..16]),
        name,
        address,
        port,
        hostname,
        tunnel_port,
        certificate: identity.certificate,
        salt: salt.to_owned(),
        created_at: now(),
        bounty,
        members: Vec::new(),
        findings: Vec::new(),
        coordination: Default::default(),
    };
    save(path, &record)?;
    Ok(identity.key)
}

/// The version of this record that this build writes. The same gate as `hub::VERSION`, and for
/// the same reason: an older build reading a newer record would quietly drop what it does not
/// know on the next save.
pub const VERSION: u8 = 1;

pub fn load(path: &Path) -> Result<Record, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("Cannot read the bounty host's settings: {error}"))?;
    read(&bytes)
}

/// The same, from bytes already in hand, so a record found on a disk can be read without
/// starting a host.
pub fn read(bytes: &[u8]) -> Result<Record, String> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| "The bounty host's settings are damaged".to_owned())?;
    let found = value["version"].as_u64().unwrap_or(0);
    if found > u64::from(VERSION) {
        return Err(format!("This bounty's settings were written by a newer Yougori (version {found}); update Yougori to open them"));
    }
    serde_json::from_value(value).map_err(|_| "The bounty host's settings are damaged".to_owned())
}

fn save(path: &Path, record: &Record) -> Result<(), String> {
    let folder = path.parent().ok_or("Invalid bounty folder")?;
    std::fs::create_dir_all(folder).map_err(|error| error.to_string())?;
    let mut file = tempfile::NamedTempFile::new_in(folder).map_err(|error| error.to_string())?;
    serde_json::to_writer_pretty(&mut file, record).map_err(|error| error.to_string())?;
    file.persist(path).map_err(|error| error.to_string())?;
    Ok(())
}

pub type Events = Arc<dyn Fn(&'static str, Value) + Send + Sync>;

struct Presence {
    seen: Instant,
    address: IpAddr,
    state: String,
    stage: String,
}

struct Live {
    presence: HashMap<String, Presence>,
    /// Wrong join passwords, counted the way both grid hubs count theirs: by address, a public
    /// IPv6 address by its /64, so one machine cannot spread its guesses over the addresses it
    /// holds; and in a table where a flood of new addresses cannot lift a lock already in place.
    refused: crate::access::throttle::Throttle<IpAddr>,
}

impl Default for Live {
    fn default() -> Self {
        // The tighter limit, on purpose, where the two grid hubs give an address the looser
        // `ADDRESS_LIMIT`. There the address count is a backstop behind a cap of ten per account,
        // loose because an office signing in every morning makes ordinary mistakes across many
        // accounts from one address. Joining a bounty has no accounts: one shared password, so
        // the address count is the only brake on guessing it, not the second one. And people join
        // once rather than every day, so ten tries per address (per /64) in ten minutes is plenty
        // for them and stingy for anybody guessing.
        Self { presence: HashMap::new(), refused: crate::access::throttle::Throttle::default() }
    }
}

impl Live {
    /// Whether `peer` has given too many wrong passwords lately.
    fn blocked(&self, peer: IpAddr) -> bool {
        self.refused.blocked(&crate::access::throttle::network(peer))
    }

    /// Counts one wrong password from `peer`.
    fn wrong_password(&mut self, peer: IpAddr) {
        self.refused.fail(crate::access::throttle::network(peer));
    }
}

struct Shared {
    path: PathBuf,
    bound: SocketAddr,
    tunnel: Option<SocketAddr>,
    fingerprint: String,
    password: Mutex<String>,
    record: Mutex<Record>,
    live: Mutex<Live>,
    events: Events,
    dirty: AtomicBool,
    policy: Value,
    source: Value,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A running bounty host. Dropping it closes the service and every connection.
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
    pub async fn start(path: PathBuf, key: &str, password_key: &str, events: Events) -> Result<Hub, String> {
        let mut record = load(&path)?;
        record.coordination = coordination::load(&path)?.unwrap_or(record.coordination);
        let policy = record.bounty.policy(&record.id)?;
        let source = record.bounty.snapshot()?;
        let tls = TlsAcceptor::from(net::server_config(&net::Identity { certificate: record.certificate.clone(), key: key.to_owned() })?);
        let fingerprint = net::fingerprint(&record.certificate)?;
        let listener = TcpListener::bind(SocketAddr::new(record.address, record.port))
            .await
            .map_err(|error| format!("Cannot open the bounty host on {}:{} ({error}).", record.address, record.port))?;
        let bound = listener.local_addr().map_err(|error| error.to_string())?;
        let tunnel = match record.tunnel_port {
            Some(port) => Some(TcpListener::bind(SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), port)).await.map_err(|error| format!("Cannot open the bounty tunnel entry on 127.0.0.1:{port} ({error})."))?),
            None => None,
        };
        let tunnel_bound = tunnel.as_ref().map(|listener| listener.local_addr()).transpose().map_err(|error| error.to_string())?;
        let shared = Arc::new(Shared {
            path,
            bound,
            tunnel: tunnel_bound,
            fingerprint,
            password: Mutex::new(password_key.to_owned()),
            record: Mutex::new(record),
            live: Mutex::new(Live::default()),
            events,
            dirty: AtomicBool::new(false),
            policy,
            source,
        });
        let mut tasks = vec![tokio::spawn(serve(shared.clone(), listener, tls.clone()))];
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

    /// Owner-only enrollment, callable by the host process without distributing its password.
    pub fn local_member(&self, name: &str) -> Result<Member, String> {
        let name = label(name, "Worker name")?;
        let mut record = lock(&self.shared.record);
        if record.members.len() >= MAX_MEMBERS { return Err("This bounty has reached its member limit".into()); }
        let id = format!("member-{}", crate::token());
        let token = crate::token();
        let mut member = Member::restore(crate::net::HubAddress::parse(&self.shared.bound.to_string())?, &record.certificate, id.clone(), token.clone())?;
        member.bounty_title = record.bounty.title.clone();
        record.members.push(MemberRecord { id, name, platform: std::env::consts::OS.into(), token_hash: digest("bounty-member", &token), joined_at: now(), model: None, findings: 0 });
        save(&self.shared.path, &record)?;
        Ok(member)
    }

    /// Whether the saved record has unsent changes (members, findings) to persist.
    pub fn take_dirty(&self) -> bool {
        self.shared.dirty.swap(false, Ordering::Relaxed)
    }

    pub fn status(&self) -> Value {
        let record = lock(&self.shared.record);
        let live = lock(&self.shared.live);
        let online = |member: &str| live.presence.get(member).is_some_and(|presence| presence.seen.elapsed() < ONLINE);
        let members: Vec<Value> = record
            .members
            .iter()
            .map(|member| {
                let presence = live.presence.get(&member.id);
                json!({
                    "id": member.id, "name": member.name, "platform": member.platform, "joinedAt": member.joined_at,
                    "model": member.model, "findings": member.findings, "online": online(&member.id),
                    "state": presence.map(|presence| presence.state.clone()), "stage": presence.map(|presence| presence.stage.clone()),
                    "lastSeenSeconds": presence.map(|presence| presence.seen.elapsed().as_secs()),
                })
            })
            .collect();
        json!({
            "id": record.id, "name": record.name, "address": record.address.to_string(), "port": self.shared.bound.port(),
            "fingerprint": self.shared.fingerprint, "createdAt": record.created_at, "tunnelPort": self.shared.tunnel.map(|address| address.port()),
            "bounty": record.bounty.summary(),
            "computers": {"total": record.members.len(), "online": record.members.iter().filter(|member| online(&member.id)).count(), "working": record.members.iter().filter(|member| online(&member.id) && matches!(live.presence.get(&member.id).map(|presence| presence.state.as_str()), Some("running"))).count()},
            "members": members,
            "findings": record.findings,
            "coordination": record.coordination.public_view(),
        })
    }

    pub fn remove_member(&self, id: &str) -> Result<Value, String> {
        let mut record = lock(&self.shared.record);
        let index = record.members.iter().position(|member| member.id == id).ok_or("No computer with that ID is working this bounty")?;
        let removed = record.members.remove(index);
        save(&self.shared.path, &record)?;
        drop(record);
        lock(&self.shared.live).presence.remove(id);
        Ok(json!({"memberId": removed.id, "name": removed.name, "removed": true}))
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
    // A connection that never finishes its handshake gives its slot back after this.
    let Ok(Ok(stream)) = tokio::time::timeout(Duration::from_secs(10), tls.accept(socket)).await else { return };
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
        .body(net::full(serde_json::to_vec(value).unwrap_or_default()))
        .expect("response builds")
}

fn error(status: StatusCode, code: &str, message: impl Into<String>) -> Response<Body> {
    json_response(status, &json!({"error": {"code": code, "message": message.into()}}))
}

fn bearer(request: &Request<Incoming>) -> Option<String> {
    request.headers().get(header::AUTHORIZATION)?.to_str().ok()?.strip_prefix("Bearer ").map(str::to_owned)
}

fn member_of(shared: &Shared, request: &Request<Incoming>) -> Option<String> {
    let secret = bearer(request).filter(|secret| is_token(secret))?;
    let hash = digest("bounty-member", &secret);
    lock(&shared.record).members.iter().find(|member| member.token_hash == hash).map(|member| member.id.clone())
}

fn throttled(shared: &Shared, peer: IpAddr) -> bool {
    lock(&shared.live).blocked(peer)
}

fn refuse(shared: &Shared, peer: IpAddr) {
    lock(&shared.live).wrong_password(peer);
}

async fn route(shared: Arc<Shared>, peer: IpAddr, request: Request<Incoming>) -> Response<Body> {
    let path = request.uri().path().to_owned();
    match (request.method().clone(), path.as_str()) {
        (Method::GET, "/bounty/v1/hello") => {
            let record = lock(&shared.record);
            json_response(StatusCode::OK, &json!({"bountyId": record.id, "name": record.name, "salt": record.salt, "title": record.bounty.title}))
        }
        (Method::POST, "/bounty/v1/join") => join(&shared, peer, request).await,
        (Method::POST | Method::GET, path) if path.starts_with("/bounty/v1/") => {
            let Some(member) = member_of(&shared, &request) else {
                return error(StatusCode::UNAUTHORIZED, "member_unknown", "This computer has not joined this bounty");
            };
            if path.starts_with("/bounty/v1/agent/") {
                return coordination::route(&shared, &member, request).await;
            }
            match (request.method().clone(), path) {
                (Method::POST, "/bounty/v1/heartbeat") => heartbeat(&shared, &member, peer, request).await,
                (Method::GET, "/bounty/v1/source") => source(&shared),
                (Method::POST, "/bounty/v1/finding") => finding(&shared, &member, request).await,
                (Method::POST, "/bounty/v1/leave") => leave(&shared, &member),
                _ => error(StatusCode::NOT_FOUND, "not_found", "Unknown bounty path"),
            }
        }
        _ => error(StatusCode::NOT_FOUND, "not_found", "Unknown path"),
    }
}

async fn join(shared: &Arc<Shared>, peer: IpAddr, request: Request<Incoming>) -> Response<Body> {
    if throttled(shared, peer) {
        return error(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "Too many wrong passwords from this address; wait 10 minutes");
    }
    let body = match net::json_body(request.into_body(), 4096).await {
        Ok(body) => body,
        Err(message) => return error(StatusCode::BAD_REQUEST, "invalid_request_error", message),
    };
    let nonce = body["nonce"].as_str().filter(|nonce| is_token(nonce)).unwrap_or_default();
    let proof = body["proof"].as_str().unwrap_or_default();
    let key = lock(&shared.password).clone();
    if !password::verify(&key, "member", &shared.fingerprint, nonce, "", proof) {
        refuse(shared, peer);
        (shared.events)("bounty.join.refused", json!({"address": peer.to_string()}));
        return error(StatusCode::FORBIDDEN, "password_wrong", "The bounty name or password is wrong");
    }
    let name = label(body["name"].as_str().unwrap_or_default(), "name").unwrap_or_else(|_| "Computer".into());
    let platform: String = body["platform"].as_str().unwrap_or_default().chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_')).take(32).collect();
    let model = body["model"].as_str().map(|model| model.trim().chars().take(200).collect::<String>()).filter(|model| !model.is_empty());
    let reply = {
        let mut record = lock(&shared.record);
        if record.members.len() >= MAX_MEMBERS {
            return error(StatusCode::CONFLICT, "bounty_full", format!("This bounty already has {MAX_MEMBERS} computers"));
        }
        let member_token = crate::token();
        let id = format!("member-{}", &crate::token()[..12]);
        record.members.push(MemberRecord { id: id.clone(), name: name.clone(), platform, token_hash: digest("bounty-member", &member_token), joined_at: now(), model, findings: 0 });
        if let Err(message) = save(&shared.path, &record) {
            record.members.pop();
            return error(StatusCode::INTERNAL_SERVER_ERROR, "storage", message);
        }
        json!({
            "memberId": id, "memberToken": member_token, "bounty": {"id": record.id, "name": record.name, "title": record.bounty.title},
            "proof": password::prove(&key, "hub", &shared.fingerprint, nonce, &id),
        })
    };
    (shared.events)("bounty.member.joined", json!({"name": name, "address": peer.to_string()}));
    json_response(StatusCode::OK, &reply)
}

async fn heartbeat(shared: &Shared, member: &str, peer: IpAddr, request: Request<Incoming>) -> Response<Body> {
    let body = net::json_body(request.into_body(), REQUEST_LIMIT).await.unwrap_or(Value::Null);
    {
        let mut live = lock(&shared.live);
        let presence = live.presence.entry(member.to_owned()).or_insert_with(|| Presence { seen: Instant::now(), address: peer, state: String::new(), stage: String::new() });
        presence.seen = Instant::now();
        presence.address = peer;
        presence.state = body["state"].as_str().unwrap_or("working").chars().take(32).collect();
        presence.stage = body["stage"].as_str().unwrap_or_default().chars().take(200).collect();
    }
    if let Some(model) = body["model"].as_str().map(|model| model.trim().chars().take(200).collect::<String>()).filter(|model| !model.is_empty()) {
        let mut record = lock(&shared.record);
        if let Some(entry) = record.members.iter_mut().find(|entry| entry.id == member) {
            if entry.model.as_deref() != Some(model.as_str()) {
                entry.model = Some(model);
                shared.dirty.store(true, Ordering::Relaxed);
            }
        }
    }
    let record = lock(&shared.record);
    json_response(StatusCode::OK, &json!({"bountyTitle": record.bounty.title, "stillOpen": true}))
}

/// The published source, for a joined computer to work on.
fn source(shared: &Shared) -> Response<Body> {
    let record = lock(&shared.record);
    json_response(StatusCode::OK, &json!({"title": record.bounty.title, "instructions": record.bounty.instructions, "authorization": record.bounty.authorization, "files": record.bounty.files}))
}

async fn finding(shared: &Shared, member: &str, request: Request<Incoming>) -> Response<Body> {
    let body = match net::json_body(request.into_body(), REQUEST_LIMIT).await {
        Ok(body) => body,
        Err(message) => return error(StatusCode::BAD_REQUEST, "invalid_request_error", message),
    };
    let title = body["title"].as_str().unwrap_or_default().trim();
    if title.is_empty() {
        return error(StatusCode::BAD_REQUEST, "invalid_request_error", "A finding needs a title");
    }
    let event = {
        let mut record = lock(&shared.record);
        let (member_name, model) = match record.members.iter().find(|entry| entry.id == member) {
            Some(entry) => (entry.name.clone(), entry.model.clone().unwrap_or_default()),
            None => return error(StatusCode::UNAUTHORIZED, "member_unknown", "This computer has not joined this bounty"),
        };
        if record.findings.len() >= MAX_FINDINGS {
            return error(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "This bounty already holds the most findings it keeps");
        }
        let finding = Finding {
            id: format!("finding-{}", &crate::token()[..12]),
            member_id: member.to_owned(),
            member_name,
            model,
            title: title.chars().take(200).collect(),
            detail: body["detail"].as_str().unwrap_or_default().chars().take(16000).collect(),
            severity: body["severity"].as_str().unwrap_or("unknown").chars().take(16).collect(),
            created_at: now(),
        };
        let event = json!({"findingId": finding.id, "member": finding.member_name, "title": finding.title});
        record.findings.push(finding);
        if let Some(entry) = record.members.iter_mut().find(|entry| entry.id == member) {
            entry.findings += 1;
        }
        if let Err(message) = save(&shared.path, &record) {
            record.findings.pop();
            return error(StatusCode::INTERNAL_SERVER_ERROR, "storage", message);
        }
        event
    };
    (shared.events)("bounty.finding", event);
    json_response(StatusCode::OK, &json!({"recorded": true}))
}

fn leave(shared: &Shared, member: &str) -> Response<Body> {
    {
        let mut record = lock(&shared.record);
        let before = record.members.len();
        record.members.retain(|entry| entry.id != member);
        if record.members.len() != before {
            let _ = save(&shared.path, &record);
        }
    }
    lock(&shared.live).presence.remove(member);
    json_response(StatusCode::OK, &json!({"left": true}))
}

/// Reads the file bytes of a source received from the hub, checking the paths and base64.
pub fn decode_files(files: &[SourceFile]) -> Result<Vec<SourceFile>, String> {
    if files.len() > MAX_FILES {
        return Err("The source has too many files".into());
    }
    for file in files {
        if file.path.trim().is_empty() || file.path.contains("..") || file.path.starts_with(['/', '\\']) || file.path.contains(':') {
            return Err(format!("Unsafe file path from the host: {}", file.path));
        }
        if !base64::valid(&file.data) {
            return Err(format!("The host sent a file that is not valid base64: {}", file.path));
        }
    }
    Ok(files.to_vec())
}


// ---- The member side: a computer joining a closed bounty to work it. ----

use crate::invite::Invite;
use crate::net::HubAddress;
use http_body_util::{BodyExt, Empty, Full, Limited};
use bytes::Bytes;
use std::sync::Arc as StdArc;
use tokio_rustls::rustls::ClientConfig;

/// This computer's place in a closed bounty it joined.
pub struct Member {
    pub address: HubAddress,
    pub member_id: String,
    pub token: String,
    pub bounty_name: String,
    pub bounty_title: String,
    /// The hub certificate, pinned for every later request.
    pub certificate: String,
    pub fingerprint: String,
    tls: StdArc<ClientConfig>,
}

/// The source a worker downloads from the host to work on.
pub struct Source {
    pub title: String,
    pub instructions: String,
    pub authorization: String,
    pub files: Vec<SourceFile>,
}

async fn talk(address: &HubAddress, tls: &StdArc<ClientConfig>, bearer: Option<&str>, method: &str, path: &str, body: Option<&Value>) -> Result<(StatusCode, Value), String> {
    let mut request = hyper::Request::builder().uri(path).method(method);
    if let Some(bearer) = bearer {
        request = request.header(header::AUTHORIZATION, format!("Bearer {bearer}"));
    }
    let response = match body {
        Some(body) => net::send(address, tls, request.header(header::CONTENT_TYPE, "application/json").body(Full::new(Bytes::from(body.to_string()))).map_err(|error| error.to_string())?, Duration::from_secs(30)).await?,
        None => net::send(address, tls, request.body(Empty::<Bytes>::new()).map_err(|error| error.to_string())?, Duration::from_secs(30)).await?,
    };
    let status = response.status();
    // The headers' deadline does not cover the body: a host that stalls mid-answer is given up on.
    let bytes = tokio::time::timeout(Duration::from_secs(120), Limited::new(response.into_body(), MAX_SOURCE_BYTES as usize * 4 / 3 + 8 * 1024 * 1024).collect())
        .await
        .map_err(|_| "The bounty host's answer did not finish in time")?
        .map_err(|_| "The bounty host's answer was interrupted")?
        .to_bytes();
    Ok((status, if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap_or(Value::Null) }))
}

/// Joins the closed bounty the invite names, with the company password and the chosen model.
pub async fn member_join(invite: &Invite, password: &str, name: &str, platform: &str, model: &str) -> Result<Member, String> {
    if let HubAddress::Direct(direct) = &invite.address {
        if !net::private(direct.ip()) || direct.port() == 0 {
            return Err("The bounty host must be on a private LAN or VPN address, or reached through its tunnel".into());
        }
    }
    let (capture, seen) = net::capturing_config()?;
    let (status, hello) = talk(&invite.address, &capture, None, "GET", "/bounty/v1/hello", None).await?;
    let certificate = seen.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).take().ok_or("The host did not present a certificate")?;
    if status != StatusCode::OK {
        return Err(format!("{} is not a closed bounty host", invite.address));
    }
    let print = net::fingerprint_der(&certificate);
    if print != invite.fingerprint {
        return Err(format!("The host's certificate fingerprint is {print}, not the one in the invite. Do not join; ask whoever shared it."));
    }
    let bounty_name = hello["name"].as_str().unwrap_or_default().to_owned();
    if !bounty_name.trim().eq_ignore_ascii_case(invite.company.trim()) {
        return Err(format!("The host belongs to '{bounty_name}', not '{}'", invite.company));
    }
    let salt = hello["salt"].as_str().filter(|salt| !salt.is_empty() && salt.len() <= 128).ok_or("The host sent an invalid answer")?.to_owned();
    let secret = password.to_owned();
    let key = tokio::task::spawn_blocking(move || password::derive(&secret, &salt)).await.map_err(|error| error.to_string())??;
    let nonce = crate::token();
    let proof = password::prove(&key, "member", &print, &nonce, "");
    let pem = net::certificate_pem(&certificate);
    let tls = net::client_config(&pem)?;
    let body = json!({"nonce": nonce, "proof": proof, "name": name, "platform": platform, "model": model});
    let (status, value) = talk(&invite.address, &tls, None, "POST", "/bounty/v1/join", Some(&body)).await?;
    if status != StatusCode::OK {
        return Err(value["error"]["message"].as_str().unwrap_or("The host refused to let this computer join").to_owned());
    }
    let member_id = value["memberId"].as_str().filter(|id| !id.is_empty() && id.len() <= 64).ok_or("The host sent an invalid answer")?.to_owned();
    if !password::verify(&key, "hub", &print, &nonce, &member_id, value["proof"].as_str().unwrap_or_default()) {
        return Err("The host could not prove it knows the password. Do not trust it.".into());
    }
    let token = value["memberToken"].as_str().filter(|token| is_token(token)).ok_or("The host sent an invalid answer")?.to_owned();
    Ok(Member {
        address: invite.address.clone(),
        member_id,
        token,
        bounty_name,
        bounty_title: value["bounty"]["title"].as_str().unwrap_or_default().to_owned(),
        certificate: pem,
        fingerprint: print,
        tls,
    })
}

impl Member {
    /// Same bounded agent protocol as the public coordinator, carried over the hub's pinned TLS.
    pub async fn agent(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value, String> {
        let suffix = path.strip_prefix("/api/swarm/agent/").ok_or("Invalid private agent operation")?;
        if (suffix.contains("..") || suffix.contains(['#', '%', '\\'])) || suffix.len() > 512 { return Err("Invalid private agent path".into()); }
        let (status, value) = talk(&self.address, &self.tls, Some(&self.token), method, &format!("/bounty/v1/agent/{suffix}"), body).await?;
        if !status.is_success() {
            return Err(format!("SWARM_API:{}:{}: {}", status.as_u16(), value["error"]["code"].as_str().unwrap_or("rejected"), value["error"]["message"].as_str().unwrap_or("Private coordinator rejected the request")));
        }
        Ok(value)
    }
    /// Reconnects a saved membership with only the pinned certificate and its token.
    pub fn restore(address: HubAddress, certificate: &str, member_id: String, token: String) -> Result<Member, String> {
        Ok(Member {
            address,
            member_id,
            token,
            bounty_name: String::new(),
            bounty_title: String::new(),
            fingerprint: net::fingerprint(certificate)?,
            tls: net::client_config(certificate)?,
            certificate: certificate.to_owned(),
        })
    }

    pub async fn source(&self) -> Result<Source, String> {
        let (status, value) = talk(&self.address, &self.tls, Some(&self.token), "GET", "/bounty/v1/source", None).await?;
        if status != StatusCode::OK {
            return Err(value["error"]["message"].as_str().unwrap_or("Could not download the bounty source").to_owned());
        }
        let files: Vec<SourceFile> = serde_json::from_value(value["files"].clone()).map_err(|_| "The host sent an invalid source")?;
        Ok(Source {
            title: value["title"].as_str().unwrap_or_default().to_owned(),
            instructions: value["instructions"].as_str().unwrap_or_default().to_owned(),
            authorization: value["authorization"].as_str().unwrap_or_default().to_owned(),
            files: decode_files(&files)?,
        })
    }

    pub async fn heartbeat(&self, state: &str, stage: &str, model: &str) -> Result<(), String> {
        let (status, value) = talk(&self.address, &self.tls, Some(&self.token), "POST", "/bounty/v1/heartbeat", Some(&json!({"state": state, "stage": stage, "model": model}))).await?;
        if status == StatusCode::UNAUTHORIZED {
            return Err("removed".into());
        }
        if status != StatusCode::OK {
            return Err(value["error"]["message"].as_str().unwrap_or("The host did not accept the check-in").to_owned());
        }
        Ok(())
    }

    pub async fn report(&self, title: &str, detail: &str, severity: &str) -> Result<(), String> {
        let (status, value) = talk(&self.address, &self.tls, Some(&self.token), "POST", "/bounty/v1/finding", Some(&json!({"title": title, "detail": detail, "severity": severity}))).await?;
        if status != StatusCode::OK {
            return Err(value["error"]["message"].as_str().unwrap_or("The host did not accept the finding").to_owned());
        }
        Ok(())
    }

    pub async fn leave(&self) -> Result<(), String> {
        talk(&self.address, &self.tls, Some(&self.token), "POST", "/bounty/v1/leave", Some(&json!({}))).await?;
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str, text: &str) -> SourceFile {
        use ::base64::Engine;
        SourceFile { path: path.into(), data: ::base64::engine::general_purpose::STANDARD.encode(text) }
    }

    #[test]
    fn a_bounty_checks_its_title_files_and_paths() {
        let files = vec![file("src/main.rs", "fn main() {}")];
        let bounty = Bounty::checked("  Review checkout  ", "Look for logic flaws", "You may test checkout.acme.test", files.clone()).unwrap();
        assert_eq!(bounty.title, "Review checkout");
        assert_eq!(bounty.summary()["files"], 1);
        assert!(Bounty::checked("", "", "", files.clone()).is_err(), "a title is required");
        assert!(Bounty::checked("T", "", "", vec![file("../escape", "x")]).is_err(), "no path escapes");
        assert!(Bounty::checked("T", "", "", vec![file("/abs", "x")]).is_err(), "no absolute paths");
        // Empty source passes checked(), but policy() refuses it unless the target is a live URL.
        assert!(Bounty::checked("T", "", "", Vec::new()).unwrap().policy("b").is_err(), "a source review needs a file");
        let mut live = Bounty::checked("T", "", "", Vec::new()).unwrap();
        live.target = serde_json::from_value(json!({"kind":"url","baseUrl":"https://staging.example.com"})).unwrap();
        assert_eq!(live.policy("b").is_ok(), crate::distribution::LIVE_TARGETS, "only the private edition accepts a live URL bounty");
    }

    #[test]
    fn create_refuses_a_public_address_and_round_trips_the_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bounty.json");
        let bounty = Bounty::checked("Review", "", "", vec![file("a.py", "print(1)")]).unwrap();
        assert!(create(&path, "Acme", "8.8.8.8".parse().unwrap(), 0, None, None, "salt", bounty.clone()).unwrap_err().contains("private"));
        let key = create(&path, "Acme", "10.0.0.5".parse().unwrap(), 7470, None, Some(7471), "salt", bounty).unwrap();
        assert!(!key.is_empty());
        let record = load(&path).unwrap();
        assert_eq!((record.name.as_str(), record.port, record.bounty.title.as_str()), ("Acme", 7470, "Review"));
        assert!(create(&path, "Acme", "10.0.0.5".parse().unwrap(), 0, None, None, "salt", Bounty::checked("R", "", "", vec![file("a", "b")]).unwrap()).unwrap_err().contains("already hosts"));
    }

    #[test]
    fn a_source_from_the_host_is_checked_before_it_is_written() {
        let good = vec![file("src/app.py", "x = 1")];
        assert_eq!(decode_files(&good).unwrap().len(), 1);
        assert!(decode_files(&[SourceFile { path: "../etc/passwd".into(), data: good[0].data.clone() }]).is_err());
        assert!(decode_files(&[SourceFile { path: "ok".into(), data: "not base64!!".into() }]).is_err());
    }

    #[test]
    fn older_records_without_the_newer_fields_still_load() {
        let json = json!({"version": 1, "id": "bounty-1", "name": "Acme", "address": "10.0.0.5", "port": 7470, "certificate": "", "salt": "s", "createdAt": 0, "bounty": {"title": "R", "files": []}});
        let record: Record = serde_json::from_value(json).unwrap();
        assert!(record.members.is_empty() && record.findings.is_empty());
        let member: MemberRecord = serde_json::from_value(json!({"id": "m", "name": "PC", "platform": "linux", "tokenHash": "", "joinedAt": 0})).unwrap();
        assert!(member.model.is_none() && member.findings == 0);
    }

    /// PROVES that the shape of the bounty host's record cannot change without somebody noticing:
    /// every field of every type that is serialised into it is named here with no `..`, so
    /// adding, removing or renaming one stops this file compiling. The same half of the freeze the
    /// grid hub has, for the same reason: a new optional field that is skipped when empty
    /// round-trips through the frozen fixture unchanged, and only the compiler can see it.
    ///
    /// DOES NOT PROVE that a change is wrong, only that it was deliberate. Nor does it cover
    /// `coordination`, which is named and left whole: it carries `skip_serializing`, so none of
    /// it is in the record, and its fields belong to the module that keeps it in a file of its
    /// own.
    #[test]
    fn every_field_of_the_bounty_host_record_is_named_here() {
        let record: Record = serde_json::from_value(json!({
            "version": 1, "id": "bounty-1", "name": "Acme", "address": "10.0.0.5", "port": 7470,
            "certificate": "", "salt": "s", "createdAt": 0, "bounty": {"title": "R", "files": []}
        }))
        .unwrap();
        let Record { version, id, name, address, port, hostname, tunnel_port, certificate, salt, created_at, bounty, members, findings, coordination } = record;
        assert_eq!((version, id.as_str(), name.as_str(), port, created_at), (1, "bounty-1", "Acme", 7470, 0));
        assert!(address.is_ipv4() && hostname.is_none() && tunnel_port.is_none() && certificate.is_empty() && salt == "s");
        assert!(members.is_empty() && findings.is_empty());
        // The one field deliberately left whole: `coordination` carries `skip_serializing`, so no
        // byte of it is ever in this record. It is kept in a file of its own and its fields are
        // private to that module, which is why this names it and stops.
        let _ = coordination;

        let Bounty { title, instructions, authorization, files, target, rented_gpu } = bounty;
        assert_eq!((title.as_str(), instructions.as_str(), authorization.as_str(), files.len()), ("R", "", "", 0));
        // A bounty saved before rented GPUs existed does not allow them.
        assert!(!rented_gpu);
        // A bounty with no target at all takes the field's own `Default`, which is empty; the
        // per-field serde defaults are what a target written down gets. Both are named here.
        let crate::bounty_project::Target { kind, setup_command, start_command, test_command, port, health_path, install_network, base_url } = target;
        assert_eq!((kind.as_str(), port, health_path.as_str(), install_network), ("", 0, "", false));
        assert!(setup_command.is_empty() && start_command.is_empty() && test_command.is_empty() && base_url.is_empty());
        let written: crate::bounty_project::Target = serde_json::from_value(json!({})).unwrap();
        assert_eq!((written.kind.as_str(), written.port, written.health_path.as_str()), ("source", 3000, "/"));

        let SourceFile { path, data } = file("src/main.rs", "fn main() {}");
        assert_eq!(path, "src/main.rs");
        assert!(!data.is_empty());

        let member: MemberRecord = serde_json::from_value(json!({"id": "m", "name": "PC", "platform": "linux", "tokenHash": "h", "joinedAt": 1})).unwrap();
        let MemberRecord { id, name, platform, token_hash, joined_at, model, findings } = member;
        assert_eq!((id.as_str(), name.as_str(), platform.as_str(), token_hash.as_str(), joined_at), ("m", "PC", "linux", "h", 1));
        assert!(model.is_none() && findings == 0);

        let found: Finding = serde_json::from_value(json!({"id": "f", "memberId": "m", "memberName": "PC", "model": "x", "title": "t", "detail": "d", "createdAt": 2})).unwrap();
        let Finding { id, member_id, member_name, model, title, detail, severity, created_at } = found;
        assert_eq!((id.as_str(), member_id.as_str(), member_name.as_str(), model.as_str()), ("f", "m", "PC", "x"));
        assert_eq!((title.as_str(), detail.as_str(), severity.as_str(), created_at), ("t", "d", "", 2));
    }

    /// PROVES that a bounty host's record written by a newer build is refused with a sentence
    /// naming the version, rather than read and saved back without what this build never knew.
    ///
    /// DOES NOT PROVE anything about a record already written by a newer build and already saved
    /// over by an older one.
    #[test]
    fn a_bounty_record_from_a_newer_build_is_refused_rather_than_read() {
        let base = json!({"version": 1, "id": "bounty-1", "name": "Acme", "address": "10.0.0.5", "port": 7470, "certificate": "", "salt": "s", "createdAt": 0, "bounty": {"title": "R", "files": []}});
        assert!(read(&serde_json::to_vec(&base).unwrap()).is_ok());
        let mut newer = base.clone();
        newer["version"] = json!(2);
        let Err(refused) = read(&serde_json::to_vec(&newer).unwrap()) else { panic!("a newer record must be refused") };
        assert_eq!(refused, "This bounty's settings were written by a newer Yougori (version 2); update Yougori to open them");
        let mut far = base;
        far["version"] = json!(256);
        let Err(far_refused) = read(&serde_json::to_vec(&far).unwrap()) else { panic!("version 256 must be refused") };
        assert!(far_refused.contains("version 256"), "256 must not narrow to 0: {far_refused}");
    }

    /// PROVES that wrong join passwords are counted the way both grid hubs count theirs.
    ///
    /// This hub kept the old count after the other two moved on: one entry per exact address, so
    /// a machine holding an IPv6 /64 had its guesses at each of 2^64 addresses; and once 1024
    /// addresses were in the table it stopped counting new ones at all, so a flood of addresses
    /// bought unlimited guesses. A tunnel passes on the caller's real address, so both worked from
    /// outside as well.
    #[test]
    fn wrong_join_passwords_count_by_network_and_a_flood_never_lifts_a_lock() {
        use crate::access::throttle::LIMIT;
        use std::net::{Ipv4Addr, Ipv6Addr};
        let mut live = Live::default();
        let in_one_64 = |host: u16| IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, host));
        // Guesses spread over the addresses of one /64 are one machine's guesses.
        for host in 0..LIMIT as u16 {
            live.wrong_password(in_one_64(host));
        }
        assert!(live.blocked(in_one_64(0xffff)), "another address in the same /64 is held back too");
        assert!(!live.blocked(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 3, 0, 0, 0, 1))), "the next /64 is somebody else");
        // A flood of new addresses, well past where this hub used to stop counting.
        for index in 0..2_000u32 {
            live.wrong_password(IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + index)));
        }
        assert!(live.blocked(in_one_64(7)), "the flood did not lift the lock already in place");
        // And an address that arrives after the flood is still counted, up to its own lock.
        let late = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
        for _ in 0..LIMIT {
            assert!(!live.blocked(late));
            live.wrong_password(late);
        }
        assert!(live.blocked(late), "an address after the flood is counted like any other");
        // Each IPv4 address counts on its own: one machine in an office does not lock out the next.
        assert!(!live.blocked(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 8))));
    }
}
