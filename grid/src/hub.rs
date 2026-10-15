//! The hub: one company computer, run by the grid's admin. It keeps the member computers, the
//! admin's plans (which model runs on what share of the computers, in which hours and after how
//! long without input) and the API keys of company apps. It queues the apps' requests, hands
//! each to an idle member computer and relays the member's streamed reply. Prompts pass through
//! memory only and are never stored or logged.
use crate::{
    digest, is_token, label, model_key, model_name,
    net::{self, Body},
    now, password,
    policy::IdlePolicy,
    token,
};
use bytes::Bytes;
use http_body_util::{BodyExt, StreamBody};
use hyper::{
    body::{Frame, Incoming},
    header, Method, Request, Response, StatusCode,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard,
    },
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot, Notify, Semaphore};
use tokio_rustls::TlsAcceptor;

const REQUEST_LIMIT: usize = 64 * 1024;
const RESPONSE_LIMIT: usize = 16 * 1024 * 1024;
const USAGE_LIMIT: usize = 2 * 1024 * 1024;
/// How long a member's request for work waits for a job.
pub const POLL: Duration = Duration::from_secs(25);
/// The longest a member may take to produce a reply.
pub const GENERATION: Duration = Duration::from_secs(30 * 60);
/// How long a request waits in the queue for an idle computer.
const PICKUP: Duration = Duration::from_secs(60);
/// A member confirms each job it receives; an unconfirmed job goes to another computer.
const ACCEPT: Duration = Duration::from_secs(15);
/// After releasing a job, a member is skipped for it this long.
const SKIP: Duration = Duration::from_secs(5);
/// Members report every 30 seconds; one missed report is tolerated.
const ONLINE: Duration = Duration::from_secs(75);
const MAX_QUEUE: usize = 256;
const MAX_PER_KEY: usize = 32;
const MAX_MEMBERS: usize = 1024;
const MAX_KEYS: usize = 256;
const MAX_PLANS: usize = 32;
const MAX_CONNECTIONS: usize = 2048;
const MAX_ATTEMPTS: u8 = 3;
const MAX_MODELS: usize = 8;
pub const KEY_PREFIX: &str = "ygrid_";
/// Model states a member may report.
const STATES: [&str; 10] = ["available", "busy", "person_active", "outside_schedule", "activity_unknown", "preparing", "loading", "stopped", "locked", "error"];

/// The grid as saved on the hub computer. Secrets appear only as hashes; the password's
/// derived key and the certificate's private key live in the OS vault.
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
    pub certificate: String,
    pub salt: String,
    pub created_at: i64,
    #[serde(default)]
    plans: Vec<Plan>,
    #[serde(default)]
    members: Vec<MemberRecord>,
    #[serde(default)]
    keys: Vec<KeyRecord>,
}

/// The admin's decision: run `model` on `percent` of the computers that can run models,
/// serving under `policy`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Plan {
    pub id: String,
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quant: Option<String>,
    pub percent: u8,
    pub policy: IdlePolicy,
    pub created_at: i64,
}

/// Fields to change in a plan. An empty `quant` or `schedule` clears it.
#[derive(Clone, Debug, Default)]
pub struct PlanChange {
    pub model: Option<String>,
    pub quant: Option<String>,
    pub percent: Option<u8>,
    pub idle_after_minutes: Option<u32>,
    pub schedule: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MemberRecord {
    id: String,
    name: String,
    platform: String,
    token_hash: String,
    joined_at: i64,
    /// The computer reported that it can run models (an NVIDIA GPU or Apple silicon).
    #[serde(default)]
    capable: bool,
    #[serde(default)]
    plan: Option<String>,
    #[serde(default)]
    assigned_at: Option<i64>,
    #[serde(default)]
    jobs: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyRecord {
    id: String,
    name: String,
    prefix: String,
    hash: String,
    created_at: i64,
    #[serde(default)]
    last_used_at: Option<i64>,
    #[serde(default)]
    requests: u64,
    #[serde(default)]
    failures: u64,
    #[serde(default)]
    tokens_in: u64,
    #[serde(default)]
    tokens_out: u64,
}

/// What a member computer says about a model it runs for the grid.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelReport {
    pub model: String,
    pub state: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quant: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu: Option<String>,
}

/// A model name the hub accepts in a plan: `OWNER/MODEL` from Hugging Face or a published
/// `yg/PUBLISHER/MODEL`. The engine checks the repository itself before saving a plan.
pub fn plan_model(raw: &str) -> Result<String, String> {
    let model = model_name(raw);
    let parts = model.split('/').count();
    let fits = model.len() <= 200
        && (parts == 2 || parts == 3 && model.starts_with("yg/"))
        && model.split('/').all(|part| {
            !part.is_empty()
                && !part.starts_with(['.', '-'])
                && !part.ends_with('.')
                && part.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
        });
    fits.then_some(model).ok_or_else(|| "Choose a model as hf.co/OWNER/MODEL or yg/PUBLISHER/MODEL".into())
}

fn plan_quant(raw: &str) -> Result<Option<String>, String> {
    let quant = raw.trim();
    if quant.is_empty() {
        return Ok(None);
    }
    if quant.len() > 32 || !quant.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-')) {
        return Err("--quant must name a GGUF quantization such as Q4_K_M".into());
    }
    Ok(Some(quant.to_owned()))
}

fn plan_percent(percent: u8) -> Result<u8, String> {
    (1..=100).contains(&percent).then_some(percent).ok_or_else(|| "--percent must be 1–100".into())
}

/// Creates a new grid's record at `path` and returns the certificate's private key for the OS
/// vault. `salt` is the one the company password's key was derived with. Port 0 picks any
/// free port (tests only).
pub fn create(path: &Path, name: &str, address: IpAddr, port: u16, hostname: Option<&str>, salt: &str) -> Result<String, String> {
    let name = label(name, "The company name")?;
    if !net::private(address) {
        return Err("The hub needs this computer's private LAN or VPN address, for example 10.0.0.5 or 192.168.1.20".into());
    }
    if port != 0 && port < 1024 {
        return Err("Choose a hub port between 1024 and 65535".into());
    }
    let hostname = hostname.map(str::trim).filter(|name| !name.is_empty()).map(str::to_ascii_lowercase);
    if hostname.as_deref().is_some_and(|name| !net::valid_hostname(name)) {
        return Err("--hostname must be a DNS name such as grid.example.internal".into());
    }
    if path.exists() {
        return Err("This computer already runs a Closed Neo Grid hub".into());
    }
    let identity = net::new_identity(address, hostname.as_deref())?;
    let record = Record {
        version: 1,
        id: format!("grid-{}", &token()[..16]),
        name,
        address,
        port,
        hostname,
        certificate: identity.certificate,
        salt: salt.to_owned(),
        created_at: now(),
        plans: Vec::new(),
        members: Vec::new(),
        keys: Vec::new(),
    };
    save(path, &record)?;
    Ok(identity.key)
}

pub fn load(path: &Path) -> Result<Record, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("Cannot read the grid hub's settings: {error}"))?;
    serde_json::from_slice(&bytes).map_err(|_| "The grid hub's settings are damaged".to_owned())
}

fn save(path: &Path, record: &Record) -> Result<(), String> {
    let folder = path.parent().ok_or("Invalid grid folder")?;
    std::fs::create_dir_all(folder).map_err(|error| error.to_string())?;
    let mut file = tempfile::NamedTempFile::new_in(folder).map_err(|error| error.to_string())?;
    let bytes = serde_json::to_vec_pretty(record).map_err(|error| error.to_string())?;
    std::io::Write::write_all(&mut file, &bytes).map_err(|error| error.to_string())?;
    file.persist(path).map_err(|error| error.to_string())?;
    Ok(())
}

/// Shares the capable computers among the plans. Assignments are sticky, so computers keep
/// their model (and its downloaded files) when others join or leave; each plan gets
/// `percent` of the capable computers, rounded up, in the order the plans were created.
fn reconcile(record: &mut Record) -> bool {
    let current = now();
    let mut changed = false;
    let plans: Vec<(String, u8)> = record.plans.iter().map(|plan| (plan.id.clone(), plan.percent)).collect();
    for member in &mut record.members {
        if member.plan.as_ref().is_some_and(|plan| !member.capable || !plans.iter().any(|(id, _)| id == plan)) {
            member.plan = None;
            member.assigned_at = None;
            changed = true;
        }
    }
    let capable = record.members.iter().filter(|member| member.capable).count();
    let quota = |percent: u8| (capable * usize::from(percent)).div_ceil(100);
    for (plan, percent) in &plans {
        let mut assigned: Vec<usize> = (0..record.members.len()).filter(|index| record.members[*index].plan.as_ref() == Some(plan)).collect();
        assigned.sort_by_key(|index| record.members[*index].assigned_at);
        while assigned.len() > quota(*percent) {
            let index = assigned.pop().expect("longer than the quota");
            record.members[index].plan = None;
            record.members[index].assigned_at = None;
            changed = true;
        }
    }
    for (plan, percent) in &plans {
        let mut missing = quota(*percent).saturating_sub(record.members.iter().filter(|member| member.plan.as_ref() == Some(plan)).count());
        let mut free: Vec<usize> = (0..record.members.len()).filter(|index| record.members[*index].capable && record.members[*index].plan.is_none()).collect();
        free.sort_by_key(|index| record.members[*index].joined_at);
        for index in free {
            if missing == 0 {
                break;
            }
            record.members[index].plan = Some(plan.clone());
            record.members[index].assigned_at = Some(current);
            missing -= 1;
            changed = true;
        }
    }
    changed
}

/// The work a member is told to do: its plan's model and serving rules.
fn assignment(record: &Record, member: &str) -> Value {
    let plan = record.members.iter().find(|entry| entry.id == member).and_then(|entry| entry.plan.as_ref());
    match plan.and_then(|plan| record.plans.iter().find(|entry| &entry.id == plan)) {
        Some(plan) => json!({
            "planId": plan.id, "model": plan.model, "quant": plan.quant,
            "idleAfterMinutes": plan.policy.idle_after_minutes, "schedule": plan.policy.schedule,
        }),
        None => Value::Null,
    }
}

/// Receives audit events: a dotted kind and non-secret details.
pub type Events = Arc<dyn Fn(&'static str, Value) + Send + Sync>;

/// A running hub. Dropping it closes the service and every connection.
pub struct Hub {
    shared: Arc<Shared>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

struct Shared {
    path: PathBuf,
    bound: SocketAddr,
    fingerprint: String,
    /// The company password's derived key (hex).
    password: Mutex<String>,
    /// Taken before `live` when both are needed; saved to disk while held.
    record: Mutex<Record>,
    live: Mutex<Live>,
    work: Notify,
    events: Events,
    dirty: AtomicBool,
}

#[derive(Default)]
struct Live {
    presence: HashMap<String, Presence>,
    queue: VecDeque<Job>,
    running: HashMap<String, Running>,
    refused: HashMap<IpAddr, (u32, Instant)>,
}

struct Presence {
    seen: Instant,
    address: IpAddr,
    version: String,
    models: Vec<ModelReport>,
}

struct Job {
    id: String,
    model: String,
    request: Value,
    key: String,
    created: Instant,
    attempts: u8,
    skip: Vec<(String, Instant)>,
    reply: oneshot::Sender<Response<Body>>,
}

struct Running {
    job: Job,
    member: String,
    since: Instant,
    accepted: bool,
}

enum Availability {
    Unknown,
    Unavailable(String),
    Ready,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn json_response(status: StatusCode, value: &Value) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .body(net::full(value.to_string()))
        .expect("static response")
}

/// An OpenAI-compatible error.
fn error(status: StatusCode, kind: &str, message: impl Into<String>) -> Response<Body> {
    json_response(status, &json!({"error": {"message": message.into(), "type": kind, "code": kind}}))
}

fn empty(status: StatusCode) -> Response<Body> {
    Response::builder().status(status).body(net::full(Bytes::new())).expect("static response")
}

fn bearer(request: &Request<Incoming>) -> Option<&str> {
    request.headers().get(header::AUTHORIZATION)?.to_str().ok()?.strip_prefix("Bearer ").map(str::trim)
}

fn key_summary(key: &KeyRecord) -> Value {
    json!({
        "id": key.id, "name": key.name, "prefix": key.prefix, "createdAt": key.created_at, "lastUsedAt": key.last_used_at,
        "requests": key.requests, "failures": key.failures, "tokensIn": key.tokens_in, "tokensOut": key.tokens_out,
    })
}

fn describe_state(state: &str) -> &'static str {
    match state {
        "person_active" => "in use by their person",
        "outside_schedule" => "outside the plan's hours",
        "activity_unknown" => "unable to read user activity",
        "offline" => "offline",
        "preparing" => "still downloading the model",
        "loading" => "still loading the model",
        "stopped" => "with the model stopped",
        "locked" => "locked down",
        _ => "not ready",
    }
}

/// Each reported model with how many computers run it and how many can serve now.
fn models(live: &Live) -> Vec<Value> {
    let mut models: BTreeMap<String, (String, usize, usize, BTreeMap<String, usize>)> = BTreeMap::new();
    for presence in live.presence.values() {
        let online = presence.seen.elapsed() < ONLINE;
        for report in &presence.models {
            let entry = models.entry(model_key(&report.model)).or_insert_with(|| (model_name(&report.model), 0, 0, BTreeMap::new()));
            entry.1 += 1;
            let state = if online { report.state.as_str() } else { "offline" };
            if matches!(state, "available" | "busy") {
                entry.2 += 1;
            } else {
                *entry.3.entry(state.to_owned()).or_default() += 1;
            }
        }
    }
    models
        .into_values()
        .map(|(name, computers, ready, waiting)| json!({"id": name, "computers": computers, "ready": ready, "waiting": waiting}))
        .collect()
}

fn availability(live: &Live, key: &str) -> Availability {
    let (mut computers, mut ready) = (0, 0);
    let mut waiting: BTreeMap<&str, usize> = BTreeMap::new();
    for presence in live.presence.values() {
        let online = presence.seen.elapsed() < ONLINE;
        for report in presence.models.iter().filter(|report| model_key(&report.model) == key) {
            computers += 1;
            let state = if online { report.state.as_str() } else { "offline" };
            if matches!(state, "available" | "busy") {
                ready += 1;
            } else {
                *waiting.entry(state).or_default() += 1;
            }
        }
    }
    if computers == 0 {
        return Availability::Unknown;
    }
    if ready > 0 {
        return Availability::Ready;
    }
    let reasons = waiting.iter().map(|(state, count)| format!("{count} {}", describe_state(state))).collect::<Vec<_>>().join(", ");
    Availability::Unavailable(format!("None of the {computers} computer(s) running this model can serve right now ({reasons}). Try again later."))
}

impl Hub {
    /// Opens the hub saved at `path` with the certificate's private key and the company
    /// password's derived key, both from the OS vault.
    pub async fn start(path: PathBuf, key: &str, password_key: &str, events: Events) -> Result<Hub, String> {
        let record = load(&path)?;
        let tls = TlsAcceptor::from(net::server_config(&net::Identity { certificate: record.certificate.clone(), key: key.to_owned() })?);
        let fingerprint = net::fingerprint(&record.certificate)?;
        let listener = tokio::net::TcpListener::bind(SocketAddr::new(record.address, record.port)).await.map_err(|error| {
            format!(
                "Cannot open the grid hub on {}:{} ({error}). Check that this computer still has that address and that no other program uses the port.",
                record.address, record.port
            )
        })?;
        let bound = listener.local_addr().map_err(|error| error.to_string())?;
        let shared = Arc::new(Shared {
            path,
            bound,
            fingerprint,
            password: Mutex::new(password_key.to_owned()),
            record: Mutex::new(record),
            live: Mutex::new(Live::default()),
            work: Notify::new(),
            events,
            dirty: AtomicBool::new(false),
        });
        let tasks = vec![tokio::spawn(serve(shared.clone(), listener, tls)), tokio::spawn(sweep(shared.clone()))];
        Ok(Hub { shared, tasks })
    }

    pub fn address(&self) -> SocketAddr {
        self.shared.bound
    }

    pub fn record(&self) -> Record {
        lock(&self.shared.record).clone()
    }

    pub fn status(&self) -> Value {
        let record = self.record();
        let live = lock(&self.shared.live);
        let port = self.shared.bound.port();
        let url = |host: &str| format!("https://{host}:{port}/v1");
        let host = match record.address {
            IpAddr::V6(address) => format!("[{address}]"),
            address => address.to_string(),
        };
        let online = |member: &str| live.presence.get(member).is_some_and(|presence| presence.seen.elapsed() < ONLINE);
        let members = record
            .members
            .iter()
            .map(|member| {
                let presence = live.presence.get(&member.id);
                json!({
                    "id": member.id, "name": member.name, "platform": member.platform, "joinedAt": member.joined_at,
                    "capable": member.capable, "planId": member.plan, "jobs": member.jobs,
                    "online": online(&member.id),
                    "lastSeenSeconds": presence.map(|presence| presence.seen.elapsed().as_secs()),
                    "address": presence.map(|presence| presence.address.to_string()),
                    "appVersion": presence.map(|presence| presence.version.clone()),
                    "running": live.running.values().filter(|running| running.member == member.id).count(),
                    "models": presence.map(|presence| presence.models.clone()).unwrap_or_default(),
                })
            })
            .collect::<Vec<_>>();
        let capable = record.members.iter().filter(|member| member.capable).count();
        let plans = record
            .plans
            .iter()
            .map(|plan| {
                let assigned: Vec<&MemberRecord> = record.members.iter().filter(|member| member.plan.as_ref() == Some(&plan.id)).collect();
                let ready = assigned
                    .iter()
                    .filter(|member| {
                        online(&member.id)
                            && live.presence[&member.id].models.iter().any(|report| model_key(&report.model) == model_key(&plan.model) && matches!(report.state.as_str(), "available" | "busy"))
                    })
                    .count();
                json!({
                    "id": plan.id, "model": plan.model, "quant": plan.quant, "percent": plan.percent,
                    "idleAfterMinutes": plan.policy.idle_after_minutes, "schedule": plan.policy.schedule, "rules": plan.policy.describe(),
                    "computers": assigned.len(), "target": (capable * usize::from(plan.percent)).div_ceil(100), "ready": ready, "createdAt": plan.created_at,
                })
            })
            .collect::<Vec<_>>();
        let requested: u32 = record.plans.iter().map(|plan| u32::from(plan.percent)).sum();
        json!({
            "id": record.id, "name": record.name, "address": record.address.to_string(), "port": port,
            "hostname": record.hostname, "url": url(&host), "hostnameUrl": record.hostname.as_deref().map(url),
            "certificate": record.certificate, "fingerprint": self.shared.fingerprint, "createdAt": record.created_at,
            "computers": {"total": record.members.len(), "capable": capable, "online": record.members.iter().filter(|member| online(&member.id)).count()},
            "plans": plans,
            "planWarning": (requested > 100).then(|| format!("Plans ask for {requested}% of the computers; later plans get fewer")),
            "members": members,
            "models": models(&live),
            "keys": record.keys.iter().map(key_summary).collect::<Vec<_>>(),
            "queue": {"waiting": live.queue.len(), "running": live.running.len()},
        })
    }

    /// Replaces the company password. Computers that already joined stay members.
    pub fn set_password(&self, salt: &str, password_key: &str) -> Result<(), String> {
        let mut record = lock(&self.shared.record);
        let previous = std::mem::replace(&mut record.salt, salt.to_owned());
        if let Err(error) = save(&self.shared.path, &record) {
            record.salt = previous;
            return Err(error);
        }
        *lock(&self.shared.password) = password_key.to_owned();
        Ok(())
    }

    /// Applies a changed record and reassigns computers, or restores the record on failure.
    fn commit(&self, record: &mut MutexGuard<'_, Record>, previous: Record) -> Result<(), String> {
        reconcile(record);
        if let Err(error) = save(&self.shared.path, record) {
            **record = previous;
            return Err(error);
        }
        Ok(())
    }

    pub fn add_plan(&self, model: &str, quant: Option<&str>, percent: u8, policy: IdlePolicy) -> Result<Value, String> {
        let plan = Plan {
            id: format!("plan-{}", &token()[..12]),
            model: plan_model(model)?,
            quant: plan_quant(quant.unwrap_or_default())?,
            percent: plan_percent(percent)?,
            policy,
            created_at: now(),
        };
        let mut record = lock(&self.shared.record);
        if record.plans.len() >= MAX_PLANS {
            return Err(format!("A grid can have at most {MAX_PLANS} plans"));
        }
        let previous = record.clone();
        record.plans.push(plan.clone());
        self.commit(&mut record, previous)?;
        let computers = record.members.iter().filter(|member| member.plan.as_ref() == Some(&plan.id)).count();
        Ok(json!({"plan": plan, "computers": computers}))
    }

    pub fn update_plan(&self, id: &str, change: PlanChange) -> Result<Value, String> {
        let mut record = lock(&self.shared.record);
        let previous = record.clone();
        let plan = record.plans.iter_mut().find(|plan| plan.id == id).ok_or("No plan with that ID exists in this grid")?;
        if let Some(model) = change.model {
            plan.model = plan_model(&model)?;
        }
        if let Some(quant) = change.quant {
            plan.quant = plan_quant(&quant)?;
        }
        if let Some(percent) = change.percent {
            plan.percent = plan_percent(percent)?;
        }
        let schedule = match change.schedule {
            Some(schedule) => Some(schedule),
            None => plan.policy.schedule.clone(),
        };
        plan.policy = IdlePolicy::new(Some(change.idle_after_minutes.unwrap_or(plan.policy.idle_after_minutes)), schedule.as_deref())?;
        let plan = plan.clone();
        self.commit(&mut record, previous)?;
        let computers = record.members.iter().filter(|member| member.plan.as_ref() == Some(&plan.id)).count();
        Ok(json!({"plan": plan, "computers": computers}))
    }

    pub fn remove_plan(&self, id: &str) -> Result<Value, String> {
        let mut record = lock(&self.shared.record);
        let previous = record.clone();
        let index = record.plans.iter().position(|plan| plan.id == id).ok_or("No plan with that ID exists in this grid")?;
        let plan = record.plans.remove(index);
        self.commit(&mut record, previous)?;
        Ok(json!({"planId": plan.id, "model": plan.model, "removed": true}))
    }

    pub fn remove_member(&self, id: &str) -> Result<Value, String> {
        let removed = {
            let mut record = lock(&self.shared.record);
            let previous = record.clone();
            let index = record.members.iter().position(|member| member.id == id).ok_or("No computer with that ID is in this grid")?;
            let member = record.members.remove(index);
            self.commit(&mut record, previous)?;
            member
        };
        forget_member(&self.shared, id);
        Ok(json!({"memberId": removed.id, "name": removed.name, "removed": true}))
    }

    /// A new API key for a company app. The key is returned once and kept only as a hash.
    pub fn create_key(&self, name: &str) -> Result<Value, String> {
        let name = label(name, "The key name")?;
        let secret = token();
        let api_key = format!("{KEY_PREFIX}{secret}");
        let mut record = lock(&self.shared.record);
        if record.keys.len() >= MAX_KEYS {
            return Err(format!("This grid already has {MAX_KEYS} API keys; revoke unused ones first"));
        }
        let key = KeyRecord {
            id: format!("key-{}", &token()[..12]),
            name,
            prefix: api_key[..KEY_PREFIX.len() + 6].to_owned(),
            hash: digest("key", &secret),
            created_at: now(),
            last_used_at: None,
            requests: 0,
            failures: 0,
            tokens_in: 0,
            tokens_out: 0,
        };
        let summary = key_summary(&key);
        record.keys.push(key);
        if let Err(error) = save(&self.shared.path, &record) {
            record.keys.pop();
            return Err(error);
        }
        Ok(json!({"key": summary, "apiKey": api_key}))
    }

    pub fn revoke_key(&self, id: &str) -> Result<Value, String> {
        let mut record = lock(&self.shared.record);
        let index = record.keys.iter().position(|key| key.id == id).ok_or("No API key with that ID exists in this grid")?;
        let key = record.keys.remove(index);
        if let Err(error) = save(&self.shared.path, &record) {
            record.keys.insert(index, key);
            return Err(error);
        }
        Ok(json!({"keyId": key.id, "name": key.name, "revoked": true}))
    }

    /// Saves usage counters now.
    pub fn flush(&self) {
        if self.shared.dirty.swap(false, Ordering::Relaxed) {
            let record = lock(&self.shared.record);
            let _ = save(&self.shared.path, &record);
        }
    }
}

impl Drop for Hub {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
        self.flush();
    }
}

async fn serve(shared: Arc<Shared>, listener: tokio::net::TcpListener, tls: TlsAcceptor) {
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    // Dropping the set when the hub stops closes every open connection.
    let mut connections = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((socket, peer)) = accepted else {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                };
                if !net::private(peer.ip()) {
                    continue;
                }
                let Ok(permit) = slots.clone().try_acquire_owned() else { continue };
                let (shared, tls) = (shared.clone(), tls.clone());
                connections.spawn(async move {
                    let _permit = permit;
                    let Ok(Ok(stream)) = tokio::time::timeout(Duration::from_secs(10), tls.accept(socket)).await else { return };
                    let service = hyper::service::service_fn(move |request| {
                        let shared = shared.clone();
                        async move { Ok::<_, std::convert::Infallible>(route(shared, peer.ip(), request).await) }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .timer(TokioTimer::new())
                        .header_read_timeout(Duration::from_secs(30))
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

async fn route(shared: Arc<Shared>, peer: IpAddr, request: Request<Incoming>) -> Response<Body> {
    let path = request.uri().path().to_owned();
    match (request.method().clone(), path.as_str()) {
        (Method::POST, "/v1/chat/completions") => chat(&shared, request).await,
        (Method::GET, "/v1/models") => list_models(&shared, &request),
        (Method::GET, "/grid/v1/hello") => hello(&shared),
        (Method::POST, "/grid/v1/join") => join(&shared, peer, request).await,
        (Method::POST, path) if path.starts_with("/grid/v1/") => {
            let Some(member) = member_of(&shared, &request) else {
                return error(StatusCode::UNAUTHORIZED, "member_unknown", "This computer is not a member of the grid; join it again with the company password");
            };
            match path {
                "/grid/v1/heartbeat" => heartbeat(&shared, &member, peer, request).await,
                "/grid/v1/work" => {
                    touch(&shared, &member, peer);
                    work(&shared, &member, request).await
                }
                "/grid/v1/leave" => leave(&shared, &member),
                _ => match path.strip_prefix("/grid/v1/jobs/").and_then(|rest| rest.split_once('/')) {
                    Some((job, "accept")) => accept_job(&shared, &member, job),
                    Some((job, "release")) => release_job(&shared, &member, job),
                    Some((job, "response")) => respond(&shared, &member, job, request).await,
                    _ => error(StatusCode::NOT_FOUND, "not_found", "Unknown grid path"),
                },
            }
        }
        _ => error(StatusCode::NOT_FOUND, "not_found", "Unknown path. This grid serves POST /v1/chat/completions and GET /v1/models"),
    }
}

fn member_of(shared: &Shared, request: &Request<Incoming>) -> Option<String> {
    let secret = bearer(request).filter(|secret| is_token(secret))?;
    let hash = digest("member", secret);
    lock(&shared.record).members.iter().find(|member| member.token_hash == hash).map(|member| member.id.clone())
}

fn key_of(shared: &Shared, request: &Request<Incoming>) -> Option<String> {
    let secret = bearer(request)?.strip_prefix(KEY_PREFIX).filter(|secret| is_token(secret))?;
    let hash = digest("key", secret);
    lock(&shared.record).keys.iter().find(|key| key.hash == hash).map(|key| key.id.clone())
}

fn touch(shared: &Shared, member: &str, peer: IpAddr) {
    let mut live = lock(&shared.live);
    let presence = live.presence.entry(member.to_owned()).or_insert_with(|| Presence { seen: Instant::now(), address: peer, version: String::new(), models: Vec::new() });
    presence.seen = Instant::now();
    presence.address = peer;
}

fn throttled(shared: &Shared, peer: IpAddr) -> bool {
    lock(&shared.live).refused.get(&peer).is_some_and(|(count, since)| *count >= 10 && since.elapsed() < Duration::from_secs(600))
}

fn refuse(shared: &Shared, peer: IpAddr) {
    let mut live = lock(&shared.live);
    if live.refused.len() >= 1024 {
        live.refused.retain(|_, (_, since)| since.elapsed() < Duration::from_secs(600));
        if live.refused.len() >= 1024 {
            return;
        }
    }
    let entry = live.refused.entry(peer).or_insert((0, Instant::now()));
    if entry.1.elapsed() >= Duration::from_secs(600) {
        *entry = (0, Instant::now());
    }
    entry.0 += 1;
}

/// What a computer needs before joining: which company this is and the password's salt.
fn hello(shared: &Shared) -> Response<Body> {
    let record = lock(&shared.record);
    json_response(StatusCode::OK, &json!({"gridId": record.id, "name": record.name, "salt": record.salt}))
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
        (shared.events)("grid.join.refused", json!({"address": peer.to_string()}));
        return error(StatusCode::FORBIDDEN, "password_wrong", "The company name or password is wrong");
    }
    let name = label(body["name"].as_str().unwrap_or_default(), "name").unwrap_or_else(|_| "Computer".into());
    let platform: String = body["platform"].as_str().unwrap_or_default().chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_')).take(32).collect();
    let (reply, event) = {
        let mut record = lock(&shared.record);
        if record.members.len() >= MAX_MEMBERS {
            return error(StatusCode::CONFLICT, "grid_full", format!("This grid already has {MAX_MEMBERS} computers"));
        }
        let member_token = token();
        let member = MemberRecord {
            id: format!("member-{}", &token()[..12]),
            name,
            platform,
            token_hash: digest("member", &member_token),
            joined_at: now(),
            capable: body["capable"] == true,
            plan: None,
            assigned_at: None,
            jobs: 0,
        };
        let id = member.id.clone();
        let event = json!({"memberId": member.id, "name": member.name, "address": peer.to_string()});
        let previous = record.clone();
        record.members.push(member);
        reconcile(&mut record);
        if let Err(message) = save(&shared.path, &record) {
            *record = previous;
            return error(StatusCode::INTERNAL_SERVER_ERROR, "storage", format!("The hub could not save the new member: {message}"));
        }
        let reply = json!({
            "memberId": id, "memberToken": member_token, "grid": {"id": record.id, "name": record.name},
            "proof": password::prove(&key, "hub", &shared.fingerprint, nonce, &id),
            "assignment": assignment(&record, &id),
        });
        (reply, event)
    };
    (shared.events)("grid.member.joined", event);
    json_response(StatusCode::OK, &reply)
}

async fn heartbeat(shared: &Shared, member: &str, peer: IpAddr, request: Request<Incoming>) -> Response<Body> {
    let body = match net::json_body(request.into_body(), REQUEST_LIMIT).await {
        Ok(body) => body,
        Err(message) => return error(StatusCode::BAD_REQUEST, "invalid_request_error", message),
    };
    let Ok(mut models) = serde_json::from_value::<Vec<ModelReport>>(body["models"].clone()) else {
        return error(StatusCode::BAD_REQUEST, "invalid_request_error", "models must be a list of model reports");
    };
    if models.len() > MAX_MODELS {
        return error(StatusCode::BAD_REQUEST, "invalid_request_error", format!("A computer can report at most {MAX_MODELS} models"));
    }
    let short = |text: &str, limit: usize| text.chars().filter(|c| !c.is_control()).take(limit).collect::<String>();
    for report in &mut models {
        report.model = short(&model_name(&report.model), 200);
        if !STATES.contains(&report.state.as_str()) {
            report.state = "error".into();
        }
        report.reason = short(&report.reason, 300);
        report.quant = report.quant.as_deref().map(|quant| short(quant, 64));
        report.gpu = report.gpu.as_deref().map(|gpu| short(gpu, 64));
    }
    {
        let mut live = lock(&shared.live);
        let presence = live.presence.entry(member.to_owned()).or_insert_with(|| Presence { seen: Instant::now(), address: peer, version: String::new(), models: Vec::new() });
        presence.seen = Instant::now();
        presence.address = peer;
        presence.version = short(body["appVersion"].as_str().unwrap_or_default(), 32);
        presence.models = models;
    }
    let mut record = lock(&shared.record);
    let capable = body["capable"] == true;
    if let Some(index) = record.members.iter().position(|entry| entry.id == member) {
        if record.members[index].capable != capable {
            record.members[index].capable = capable;
            reconcile(&mut record);
            // Saved by the sweep: no file write on the serving thread for a routine check-in.
            shared.dirty.store(true, Ordering::Relaxed);
        }
    }
    json_response(StatusCode::OK, &json!({"grid": {"id": record.id, "name": record.name}, "memberId": member, "assignment": assignment(&record, member)}))
}

/// Long poll: answers with a job for one of `models` as soon as one is queued.
async fn work(shared: &Arc<Shared>, member: &str, request: Request<Incoming>) -> Response<Body> {
    let body = match net::json_body(request.into_body(), 16 * 1024).await {
        Ok(body) => body,
        Err(message) => return error(StatusCode::BAD_REQUEST, "invalid_request_error", message),
    };
    let models: Vec<String> = body["models"].as_array().into_iter().flatten().filter_map(Value::as_str).map(model_key).take(MAX_MODELS).collect();
    if models.is_empty() {
        return error(StatusCode::BAD_REQUEST, "invalid_request_error", "List the models this computer serves");
    }
    let deadline = Instant::now() + POLL;
    loop {
        let notified = shared.work.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if let Some(offer) = take(shared, member, &models) {
            return json_response(StatusCode::OK, &offer);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return empty(StatusCode::NO_CONTENT);
        }
        tokio::select! {
            _ = &mut notified => {}
            _ = tokio::time::sleep(remaining) => return empty(StatusCode::NO_CONTENT),
        }
    }
}

fn take(shared: &Shared, member: &str, models: &[String]) -> Option<Value> {
    let mut live = lock(&shared.live);
    live.queue.retain(|job| !job.reply.is_closed());
    let index = live.queue.iter().position(|job| {
        models.contains(&job.model) && !job.skip.iter().any(|(skipped, at)| skipped == member && at.elapsed() < SKIP)
    })?;
    let job = live.queue.remove(index)?;
    let offer = json!({"jobId": job.id, "model": job.model, "request": job.request});
    live.running.insert(job.id.clone(), Running { job, member: member.to_owned(), since: Instant::now(), accepted: false });
    Some(offer)
}

fn assigned(live: &Live, member: &str, job: &str) -> bool {
    live.running.get(job).is_some_and(|running| running.member == member)
}

fn accept_job(shared: &Shared, member: &str, job: &str) -> Response<Body> {
    let mut live = lock(&shared.live);
    if !assigned(&live, member, job) {
        return error(StatusCode::NOT_FOUND, "job_unknown", "This job is no longer assigned to this computer");
    }
    if live.running[job].job.reply.is_closed() {
        live.running.remove(job);
        return error(StatusCode::GONE, "caller_left", "The app that sent this request has left");
    }
    let running = live.running.get_mut(job).expect("checked above");
    running.accepted = true;
    running.since = Instant::now();
    empty(StatusCode::NO_CONTENT)
}

/// The member could not run the job (its model is busy or stopped): another computer may.
fn release_job(shared: &Shared, member: &str, job: &str) -> Response<Body> {
    let failed = {
        let mut live = lock(&shared.live);
        if !assigned(&live, member, job) {
            return error(StatusCode::NOT_FOUND, "job_unknown", "This job is no longer assigned to this computer");
        }
        let mut job = live.running.remove(job).expect("checked above").job;
        job.attempts += 1;
        job.skip.push((member.to_owned(), Instant::now()));
        // Each attempt gets the full pickup time.
        job.created = Instant::now();
        if job.attempts >= MAX_ATTEMPTS {
            Some(job)
        } else {
            live.queue.push_front(job);
            None
        }
    };
    match failed {
        Some(job) => fail(shared, job, StatusCode::SERVICE_UNAVAILABLE, "grid_unavailable", "No computer in the grid could run this request; try again later"),
        None => shared.work.notify_waiters(),
    }
    empty(StatusCode::NO_CONTENT)
}

fn fail(shared: &Shared, job: Job, status: StatusCode, kind: &str, message: &str) {
    count(shared, &job.key, false, (0, 0));
    let _ = job.reply.send(error(status, kind, message));
}

fn count(shared: &Shared, key: &str, ok: bool, (tokens_in, tokens_out): (u64, u64)) {
    let mut record = lock(&shared.record);
    if let Some(entry) = record.keys.iter_mut().find(|entry| entry.id == key) {
        entry.failures += u64::from(!ok);
        entry.tokens_in += tokens_in;
        entry.tokens_out += tokens_out;
    }
    shared.dirty.store(true, Ordering::Relaxed);
}

/// Token counts from a reply: the last `usage` of an event stream, or of a JSON body.
struct Usage {
    streaming: bool,
    buffer: Vec<u8>,
    overflow: bool,
    tokens: (u64, u64),
}

impl Usage {
    fn new(streaming: bool) -> Self {
        Self { streaming, buffer: Vec::new(), overflow: false, tokens: (0, 0) }
    }
    fn push(&mut self, data: &[u8]) {
        if self.overflow {
            return;
        }
        self.buffer.extend_from_slice(data);
        if self.streaming {
            while let Some(end) = self.buffer.iter().position(|byte| *byte == b'\n') {
                let line: Vec<u8> = self.buffer.drain(..=end).collect();
                if let Some(Ok(value)) = line.strip_prefix(b"data:").map(|json| serde_json::from_slice::<Value>(json.trim_ascii())) {
                    self.read(&value);
                }
            }
        }
        if self.buffer.len() > USAGE_LIMIT {
            self.overflow = true;
            self.buffer = Vec::new();
        }
    }
    fn read(&mut self, value: &Value) {
        if let (Some(input), Some(output)) = (value["usage"]["prompt_tokens"].as_u64(), value["usage"]["completion_tokens"].as_u64()) {
            self.tokens = (input, output);
        }
    }
    fn finish(mut self) -> (u64, u64) {
        if !self.streaming && !self.overflow {
            if let Ok(value) = serde_json::from_slice::<Value>(&self.buffer) {
                self.read(&value);
            }
        }
        self.tokens
    }
}

/// Relays a member's streamed reply to the app that is waiting for it.
async fn respond(shared: &Shared, member: &str, job: &str, request: Request<Incoming>) -> Response<Body> {
    let status = request
        .headers()
        .get("x-grid-status")
        .and_then(|value| value.to_str().ok()?.parse::<u16>().ok())
        .and_then(|code| StatusCode::from_u16(code).ok())
        .filter(|status| status.as_u16() >= 200)
        .unwrap_or(StatusCode::BAD_GATEWAY);
    let content_type = request.headers().get(header::CONTENT_TYPE).cloned().unwrap_or_else(|| header::HeaderValue::from_static("application/json"));
    let job = {
        let mut live = lock(&shared.live);
        if !assigned(&live, member, job) {
            return error(StatusCode::NOT_FOUND, "job_unknown", "This job is no longer assigned to this computer");
        }
        live.running.remove(job).expect("checked above").job
    };
    let streaming = content_type.to_str().unwrap_or_default().starts_with("text/event-stream");
    let (sender, receiver) = mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(32);
    let stream = futures_util::stream::unfold(receiver, |mut receiver| async move { receiver.recv().await.map(|item| (item, receiver)) });
    let reply = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "no-store")
        .body(StreamBody::new(stream).boxed_unsync())
        .expect("relay response");
    let Job { key, reply: waiting, .. } = job;
    if waiting.send(reply).is_err() {
        count(shared, &key, false, (0, 0));
        return error(StatusCode::GONE, "caller_left", "The app that sent this request has left");
    }
    let mut incoming = request.into_body();
    let mut usage = Usage::new(streaming);
    let (mut total, mut complete) = (0, false);
    loop {
        match tokio::time::timeout(GENERATION, incoming.frame()).await {
            Ok(Some(Ok(frame))) => {
                let Ok(data) = frame.into_data() else { continue };
                total += data.len();
                if total > RESPONSE_LIMIT {
                    let _ = sender.send(Err(std::io::Error::other("The reply exceeded 16 MiB"))).await;
                    break;
                }
                usage.push(&data);
                if sender.send(Ok(Frame::data(data))).await.is_err() {
                    break;
                }
            }
            Ok(None) => {
                complete = true;
                break;
            }
            _ => {
                let _ = sender.send(Err(std::io::Error::other("The member computer stopped answering"))).await;
                break;
            }
        }
    }
    drop(sender);
    count(shared, &key, complete && status.is_success(), usage.finish());
    if let Some(entry) = lock(&shared.record).members.iter_mut().find(|entry| entry.id == member) {
        entry.jobs += 1;
    }
    if complete {
        empty(StatusCode::NO_CONTENT)
    } else {
        error(StatusCode::GONE, "caller_left", "The reply was cut short")
    }
}

fn leave(shared: &Shared, member: &str) -> Response<Body> {
    {
        let mut record = lock(&shared.record);
        let before = record.members.len();
        record.members.retain(|entry| entry.id != member);
        if record.members.len() != before {
            reconcile(&mut record);
            shared.dirty.store(true, Ordering::Relaxed);
        }
    }
    forget_member(shared, member);
    (shared.events)("grid.member.left", json!({"memberId": member}));
    empty(StatusCode::NO_CONTENT)
}

/// A removed member's unconfirmed jobs go to other computers; confirmed ones fail.
fn forget_member(shared: &Shared, member: &str) {
    let mut failed = Vec::new();
    {
        let mut live = lock(&shared.live);
        live.presence.remove(member);
        let jobs: Vec<String> = live.running.iter().filter(|(_, running)| running.member == member).map(|(id, _)| id.clone()).collect();
        for id in jobs {
            if let Some(running) = live.running.remove(&id) {
                if running.accepted {
                    failed.push(running.job);
                } else {
                    live.queue.push_front(running.job);
                }
            }
        }
    }
    for job in failed {
        fail(shared, job, StatusCode::BAD_GATEWAY, "grid_unavailable", "The computer running this request left the grid");
    }
    shared.work.notify_waiters();
}

fn list_models(shared: &Shared, request: &Request<Incoming>) -> Response<Body> {
    if key_of(shared, request).is_none() {
        return error(StatusCode::UNAUTHORIZED, "invalid_api_key", "Use an API key created with `yougori grid add-key`");
    }
    let owner = lock(&shared.record).name.clone();
    let data: Vec<Value> = models(&lock(&shared.live))
        .into_iter()
        .map(|model| json!({"id": model["id"], "object": "model", "created": 0, "owned_by": owner, "computers": model["computers"], "ready": model["ready"]}))
        .collect();
    json_response(StatusCode::OK, &json!({"object": "list", "data": data}))
}

async fn chat(shared: &Shared, request: Request<Incoming>) -> Response<Body> {
    let Some(key) = key_of(shared, &request) else {
        return error(StatusCode::UNAUTHORIZED, "invalid_api_key", "Use an API key created with `yougori grid add-key`");
    };
    let mut body = match net::json_body(request.into_body(), REQUEST_LIMIT).await {
        Ok(Value::Object(body)) => body,
        Ok(_) => return error(StatusCode::BAD_REQUEST, "invalid_request_error", "Send a JSON chat completion request"),
        Err(message) => return error(StatusCode::BAD_REQUEST, "invalid_request_error", message),
    };
    // Each member's model server knows its own model name, so the field is dropped here.
    let model = match body.remove("model") {
        Some(Value::String(model)) if !model.trim().is_empty() && model.len() <= 200 => model_key(&model),
        _ => return error(StatusCode::BAD_REQUEST, "invalid_request_error", "Choose a model; GET /v1/models lists this grid's models"),
    };
    if !body.get("messages").is_some_and(Value::is_array) {
        return error(StatusCode::BAD_REQUEST, "invalid_request_error", "messages must be a list");
    }
    let (reply, answer) = oneshot::channel();
    {
        let mut live = lock(&shared.live);
        match availability(&live, &model) {
            Availability::Unknown => {
                return error(StatusCode::NOT_FOUND, "model_not_found", "No computer in this grid runs this model; GET /v1/models lists the grid's models")
            }
            Availability::Unavailable(reason) => {
                let mut response = error(StatusCode::SERVICE_UNAVAILABLE, "grid_unavailable", reason);
                response.headers_mut().insert(header::RETRY_AFTER, header::HeaderValue::from_static("60"));
                return response;
            }
            Availability::Ready => {}
        }
        live.queue.retain(|job| !job.reply.is_closed());
        if live.queue.len() >= MAX_QUEUE {
            return error(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "The grid's queue is full; try again shortly");
        }
        let mine = live.queue.iter().filter(|job| job.key == key).count() + live.running.values().filter(|running| running.job.key == key).count();
        if mine >= MAX_PER_KEY {
            return error(StatusCode::TOO_MANY_REQUESTS, "rate_limited", format!("This API key already has {MAX_PER_KEY} requests waiting or running"));
        }
        live.queue.push_back(Job {
            id: format!("job-{}", &token()[..24]),
            model,
            request: Value::Object(body),
            key: key.clone(),
            created: Instant::now(),
            attempts: 0,
            skip: Vec::new(),
            reply,
        });
    }
    if let Some(entry) = lock(&shared.record).keys.iter_mut().find(|entry| entry.id == key) {
        entry.requests += 1;
        entry.last_used_at = Some(now());
    }
    shared.dirty.store(true, Ordering::Relaxed);
    shared.work.notify_waiters();
    match tokio::time::timeout(PICKUP + GENERATION + Duration::from_secs(60), answer).await {
        Ok(Ok(response)) => response,
        _ => error(StatusCode::GATEWAY_TIMEOUT, "timeout", "The grid did not answer in time"),
    }
}

/// Every second: expire waiting requests, hand unconfirmed jobs to other computers and
/// save usage counters every 30 seconds.
async fn sweep(shared: Arc<Shared>) {
    let mut saved = Instant::now();
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let mut failed = Vec::new();
        let mut requeued = false;
        {
            let mut live = lock(&shared.live);
            for job in std::mem::take(&mut live.queue) {
                if job.reply.is_closed() {
                    continue;
                }
                if job.created.elapsed() >= PICKUP {
                    failed.push((job, StatusCode::SERVICE_UNAVAILABLE, "grid_busy", "Every computer running this model is busy or away; try again shortly"));
                    continue;
                }
                live.queue.push_back(job);
            }
            let expired: Vec<String> = live
                .running
                .iter()
                .filter(|(_, running)| running.job.reply.is_closed() || running.since.elapsed() >= if running.accepted { GENERATION } else { ACCEPT })
                .map(|(id, _)| id.clone())
                .collect();
            for id in expired {
                let Some(Running { mut job, member, accepted, .. }) = live.running.remove(&id) else { continue };
                if job.reply.is_closed() {
                    continue;
                }
                if accepted {
                    failed.push((job, StatusCode::GATEWAY_TIMEOUT, "timeout", "The computer running this request stopped answering"));
                    continue;
                }
                job.attempts += 1;
                job.skip.push((member, Instant::now()));
                job.created = Instant::now();
                if job.attempts >= MAX_ATTEMPTS {
                    failed.push((job, StatusCode::BAD_GATEWAY, "grid_unavailable", "No computer in the grid confirmed this request; try again later"));
                } else {
                    live.queue.push_front(job);
                    requeued = true;
                }
            }
        }
        for (job, status, kind, message) in failed {
            fail(&shared, job, status, kind, message);
        }
        if requeued {
            shared.work.notify_waiters();
        }
        if saved.elapsed() >= Duration::from_secs(30) {
            saved = Instant::now();
            if shared.dirty.swap(false, Ordering::Relaxed) {
                let record = lock(&shared.record);
                let _ = save(&shared.path, &record);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn presence(models: &[(&str, &str)], online: bool) -> Presence {
        Presence {
            seen: if online { Instant::now() } else { Instant::now() - ONLINE - Duration::from_secs(1) },
            address: "10.0.0.9".parse().unwrap(),
            version: String::new(),
            models: models.iter().map(|(model, state)| ModelReport { model: (*model).into(), state: (*state).into(), reason: String::new(), quant: None, gpu: None }).collect(),
        }
    }
    fn record(capable: &[bool]) -> Record {
        Record {
            version: 1,
            id: "grid-1".into(),
            name: "Acme".into(),
            address: "10.0.0.5".parse().unwrap(),
            port: 7460,
            hostname: None,
            certificate: String::new(),
            salt: String::new(),
            created_at: 0,
            plans: Vec::new(),
            members: capable
                .iter()
                .enumerate()
                .map(|(index, capable)| MemberRecord {
                    id: format!("m{index}"),
                    name: format!("Computer {index}"),
                    platform: "windows".into(),
                    token_hash: String::new(),
                    joined_at: index as i64,
                    capable: *capable,
                    plan: None,
                    assigned_at: None,
                    jobs: 0,
                })
                .collect(),
            keys: Vec::new(),
        }
    }
    fn plan(id: &str, percent: u8) -> Plan {
        Plan { id: id.into(), model: "Acme/Chat".into(), quant: None, percent, policy: IdlePolicy::default(), created_at: 0 }
    }
    fn plans_of(record: &Record) -> Vec<Option<&str>> {
        record.members.iter().map(|member| member.plan.as_deref()).collect()
    }
    #[test]
    fn plans_get_their_share_of_capable_computers_and_keep_them() {
        let mut grid = record(&[true, true, false, true, true]);
        grid.plans.push(plan("a", 50));
        assert!(reconcile(&mut grid));
        assert_eq!(plans_of(&grid), [Some("a"), Some("a"), None, None, None], "half of 4 capable computers, oldest first");
        grid.plans.push(plan("b", 25));
        reconcile(&mut grid);
        assert_eq!(plans_of(&grid), [Some("a"), Some("a"), None, Some("b"), None]);
        assert!(!reconcile(&mut grid), "nothing changes once settled");
        // Removing a computer never moves the others to another model. 50% of the 3 capable
        // computers left rounds up to 2, so the free computer joins plan a.
        grid.members.remove(0);
        reconcile(&mut grid);
        assert_eq!(plans_of(&grid), [Some("a"), None, Some("b"), Some("a")]);
        grid.members[1].capable = true;
        assert!(!reconcile(&mut grid), "a fourth capable computer is not needed");
        // Lowering a plan's share releases its most recently assigned computers.
        grid.plans[0].percent = 10;
        reconcile(&mut grid);
        assert_eq!(plans_of(&grid), [Some("a"), None, Some("b"), None]);
        grid.plans.remove(0);
        reconcile(&mut grid);
        assert_eq!(plans_of(&grid), [None, None, Some("b"), None]);
    }
    #[test]
    fn oversubscribed_plans_fill_in_creation_order() {
        let mut grid = record(&[true, true, true]);
        grid.plans.push(plan("a", 100));
        grid.plans.push(plan("b", 50));
        reconcile(&mut grid);
        assert_eq!(plans_of(&grid), [Some("a"), Some("a"), Some("a")]);
        assert_eq!(assignment(&grid, "m0")["planId"], "a");
        assert_eq!(assignment(&grid, "missing"), Value::Null);
    }
    #[test]
    fn plan_fields_are_checked() {
        assert_eq!(plan_model("hf.co/Qwen/Qwen3-8B").unwrap(), "Qwen/Qwen3-8B");
        assert_eq!(plan_model("yg/alice/model").unwrap(), "yg/alice/model");
        for bad in ["Qwen", "a/b/c", "a//b", "a/b c", "../etc"] {
            assert!(plan_model(bad).is_err(), "{bad}");
        }
        assert_eq!(plan_quant(" Q4_K_M ").unwrap().as_deref(), Some("Q4_K_M"));
        assert_eq!(plan_quant("").unwrap(), None);
        assert!(plan_quant("Q4 K").is_err());
        assert!(plan_percent(0).is_err() && plan_percent(101).is_err() && plan_percent(100).is_ok());
    }
    #[test]
    fn availability_explains_why_nobody_can_serve() {
        let mut live = Live::default();
        assert!(matches!(availability(&live, "acme/chat"), Availability::Unknown));
        live.presence.insert("a".into(), presence(&[("hf.co/Acme/Chat", "person_active")], true));
        live.presence.insert("b".into(), presence(&[("Acme/Chat", "available")], false));
        live.presence.insert("c".into(), presence(&[("Acme/Chat", "outside_schedule")], true));
        let Availability::Unavailable(reason) = availability(&live, "acme/chat") else { panic!("expected unavailable") };
        assert!(reason.contains("3 computer(s)") && reason.contains("1 in use by their person") && reason.contains("1 offline") && reason.contains("1 outside the plan's hours"), "{reason}");
        live.presence.insert("d".into(), presence(&[("acme/chat", "busy")], true));
        assert!(matches!(availability(&live, "acme/chat"), Availability::Ready));
        let listed = models(&live);
        assert_eq!(listed.len(), 1);
        assert_eq!((listed[0]["computers"].as_u64(), listed[0]["ready"].as_u64()), (Some(4), Some(1)));
    }
    #[test]
    fn usage_is_read_from_event_streams_and_json() {
        let mut stream = Usage::new(true);
        stream.push(b"data: {\"choices\":[]}\n\ndata: {\"usage\":{\"prompt_tok");
        stream.push(b"ens\":7,\"completion_tokens\":3}}\r\n\r\ndata: [DONE]\n\n");
        assert_eq!(stream.finish(), (7, 3));
        let mut body = Usage::new(false);
        body.push(br#"{"usage":{"prompt_tokens":4,"#);
        body.push(br#""completion_tokens":2}}"#);
        assert_eq!(body.finish(), (4, 2));
    }
    #[test]
    fn records_refuse_public_addresses_and_duplicates() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("hub.json");
        assert!(create(&path, "Acme", "8.8.8.8".parse().unwrap(), 7460, None, "salt").unwrap_err().contains("private"));
        assert!(create(&path, "Acme", "10.0.0.5".parse().unwrap(), 80, None, "salt").is_err());
        assert!(create(&path, "Acme", "10.0.0.5".parse().unwrap(), 7460, Some("bad host"), "salt").is_err());
        let key = create(&path, "Acme", "10.0.0.5".parse().unwrap(), 7460, Some("Grid.Acme.Internal"), "salt").unwrap();
        assert!(!key.is_empty() && !std::fs::read_to_string(&path).unwrap().contains(&key));
        let record = load(&path).unwrap();
        assert_eq!((record.name.as_str(), record.port, record.hostname.as_deref(), record.salt.as_str()), ("Acme", 7460, Some("grid.acme.internal"), "salt"));
        assert!(create(&path, "Acme", "10.0.0.5".parse().unwrap(), 7460, None, "salt").unwrap_err().contains("already"));
    }
}
