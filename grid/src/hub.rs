//! The hub: one company computer, run by the grid's admin. It keeps the member computers, the
//! admin's plans (which model runs on what share of the computers, in which hours and after how
//! long without input) and the API keys of company apps. It queues the apps' requests, hands
//! each to an idle member computer and relays the member's streamed reply. Prompts pass through
//! memory only and are never stored or logged.
mod enterprise;
use crate::{
    desks::{self, Capacity, Desk, DeskReport, DeskSpec, DeskState, HostView, Person, Share},
    digest, is_token, label, model_key, model_name,
    net::{self, Body},
    now, password,
    policy::IdlePolicy,
    provisioning, relay, token, tunnel,
};
use bytes::Bytes;
use crate::harness::{self, Harness};
use futures_util::future::BoxFuture;
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
/// Signed-in desk people held at once. Named rather than written where it is used: a bare number
/// in a file is how the address limit came to be ten here and sixty in the Access hub.
const MAX_SESSIONS: usize = 4096;
/// A member confirms each job it receives; an unconfirmed job goes to another computer.
const ACCEPT: Duration = Duration::from_secs(15);
/// After releasing a job, a member is skipped for it this long.
const SKIP: Duration = Duration::from_secs(5);
/// Members report every 30 seconds; one missed report is tolerated.
const ONLINE: Duration = Duration::from_secs(75);
const MAX_QUEUE: usize = 256;
const MAX_PER_KEY: usize = 32;
/// A streaming swarm call hears from the hub at least this often while its team works.
const SWARM_KEEPALIVE: Duration = Duration::from_secs(10);
/// How long a relayed reply may wait for the app to read the next piece of it.
const RELAY_STALL: Duration = Duration::from_secs(60);
/// A job larger than this cannot reach a computer, which reads work offers up to 1 MiB.
const JOB_LIMIT: usize = 768 * 1024;
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
    /// The loopback port `cloudflared` forwards a tunnel to, when the grid has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel_port: Option<u16>,
    pub certificate: String,
    pub salt: String,
    pub created_at: i64,
    #[serde(default)]
    pub(crate) plans: Vec<Plan>,
    #[serde(default)]
    pub(crate) members: Vec<MemberRecord>,
    // Readable inside this crate so that core::compat::survey can count them without starting a
    // hub. Neither is readable outside it: a key record holds a hash and an app's name.
    #[serde(default)]
    pub(crate) keys: Vec<KeyRecord>,
    /// Teams of models an app calls as `swarm/NAME`.
    #[serde(default)]
    pub(crate) harnesses: Vec<Harness>,
    /// Sandboxes ordered for people, hosted on company computers within the share each allows.
    #[serde(default)]
    pub(crate) desks: Vec<Desk>,
    /// People who sign in to open their desks.
    #[serde(default)]
    pub(crate) people: Vec<Person>,
    #[serde(default)]
    pub(crate) enterprise: crate::enterprise::Enterprise,
    /// The admin deleted the grid: paused until `until`, then gone. Saved so a restart keeps it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    closing: Option<Closing>,
}

/// How long a deleted grid stays paused, and can be restored, before it is gone.
pub const GRACE: i64 = 3 * 24 * 60 * 60;
/// How long a gone grid keeps telling computers that come back online, at most.
pub const TELL_FOR: i64 = 30 * 24 * 60 * 60;

/// A deletion the admin asked for. Until `until` the grid is paused: nothing serves, nothing is
/// built, nobody signs in, and the admin can restore it. From `until` on it is gone: every
/// computer that checks in is told so, leaves and cleans up; `told` lists those that heard.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Closing {
    pub requested_at: i64,
    pub until: i64,
    #[serde(default)]
    pub told: Vec<String>,
}

/// Where a grid is in its life.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Open,
    /// Paused until this time, then gone.
    Paused(i64),
    Gone,
}

fn phase(record: &Record) -> Phase {
    match &record.closing {
        None => Phase::Open,
        Some(closing) if now() < closing.until => Phase::Paused(closing.until),
        Some(_) => Phase::Gone,
    }
}

fn closing_json(record: &Record) -> Value {
    match &record.closing {
        None => Value::Null,
        Some(closing) => json!({
            "requestedAt": closing.requested_at, "until": closing.until, "gone": phase(record) == Phase::Gone,
            "told": record.members.iter().filter(|member| closing.told.contains(&member.id)).count(), "computers": record.members.len(),
            "tellUntil": closing.until + TELL_FOR,
        }),
    }
}

fn paused_message(until: i64) -> String {
    let when = chrono::DateTime::from_timestamp(until, 0).map(|at| at.format("%Y-%m-%d %H:%M UTC").to_string()).unwrap_or_default();
    format!("This grid is paused: its admin scheduled it for deletion on {when}. It works again if the admin restores it before then.")
}

/// The admin's decision: run `model` on the computers `target` names, serving under `policy`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Plan {
    pub id: String,
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quant: Option<String>,
    /// The share of the computers in `target`; unused when the admin picked the computers.
    pub percent: u8,
    pub policy: IdlePolicy,
    pub created_at: i64,
    /// Plans saved before targets existed ran on a share of all computers.
    #[serde(default)]
    pub target: Target,
}

/// Which computers a plan runs on.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum Target {
    /// `percent` of all the computers that can run models.
    #[default]
    All,
    /// `percent` of the computers that can run models and that the admin did not pick by hand.
    Remaining,
    /// Exactly these computers, picked by the admin; a pick always wins over a share.
    Computers { members: Vec<String> },
}

impl Target {
    pub(crate) fn picked(&self) -> &[String] {
        match self {
            Target::Computers { members } => members,
            _ => &[],
        }
    }
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
pub(crate) struct MemberRecord {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) platform: String,
    token_hash: String,
    pub(crate) joined_at: i64,
    /// The computer reported that it can run models (an NVIDIA GPU or Apple silicon).
    #[serde(default)]
    pub(crate) capable: bool,
    #[serde(default)]
    pub(crate) plan: Option<String>,
    #[serde(default)]
    pub(crate) assigned_at: Option<i64>,
    #[serde(default)]
    jobs: u64,
    /// The admin left this computer out: it gets no model and no work until brought back.
    #[serde(default)]
    pub(crate) excluded: bool,
    /// What the grid may take from it for desks; unset until the admin decides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) share: Option<Share>,
}

impl MemberRecord {
    /// The computer can take a model now: it is able to and the admin has not left it out.
    pub(crate) fn eligible(&self) -> bool {
        self.capable && !self.excluded
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KeyRecord {
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
    /// How far a model that is not ready yet has come. Members before this field sent none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress: Option<Progress>,
}

/// A model on its way to ready: `phase` is `preparing`, `installing`, `downloading`,
/// `verifying` or `loading`; `done` and `total` count bytes in the phases that measure them,
/// and `rate` is bytes per second while downloading.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Progress {
    pub phase: String,
    #[serde(default)]
    pub done: u64,
    #[serde(default)]
    pub total: u64,
    #[serde(default)]
    pub rate: u64,
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
/// vault. `salt` is the one the company password's key was derived with. `tunnel_port` is the
/// loopback port a tunnel forwards to, for computers outside the network. Port 0 picks any free
/// port (tests only).
pub fn create(path: &Path, name: &str, address: IpAddr, port: u16, hostname: Option<&str>, tunnel_port: Option<u16>, salt: &str) -> Result<String, String> {
    let name = label(name, "The company name")?;
    if !net::private(address) {
        return Err("The hub needs this computer's private LAN or VPN address, for example 10.0.0.5 or 192.168.1.20".into());
    }
    if port != 0 && port < 1024 {
        return Err("Choose a hub port between 1024 and 65535".into());
    }
    if let Some(tunnel) = tunnel_port {
        if tunnel != 0 && (tunnel < 1024 || tunnel == port) {
            return Err("Choose a tunnel port between 1024 and 65535, other than the hub's own port".into());
        }
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
        tunnel_port,
        certificate: identity.certificate,
        salt: salt.to_owned(),
        created_at: now(),
        plans: Vec::new(),
        members: Vec::new(),
        keys: Vec::new(),
        harnesses: Vec::new(),
        desks: Vec::new(),
        people: Vec::new(),
        enterprise: Default::default(),
        closing: None,
    };
    save(path, &record)?;
    Ok(identity.key)
}

/// The version of this record that this build writes.
///
/// Every build that has ever shipped writes 1. The constant exists so that a record written by a
/// newer build is refused rather than read: serde ignores fields it does not know, so without the
/// check below an older build would read a newer grid, drop everything it had not heard of, and
/// save that back over it. A quiet loss is worse than a refusal, and the refusal is the only
/// protection an installation nobody knows about has.
pub const VERSION: u8 = 1;

pub fn load(path: &Path) -> Result<Record, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("Cannot read the grid hub's settings: {error}"))?;
    read(&bytes)
}

/// The same, from bytes already in hand, so a record found on a disk can be read without
/// starting a hub.
///
/// A record with no version at all reads as 0 here, falls through the gate, and is then refused
/// by the deserialiser as damaged, because `version` is a required field of the record and always
/// has been. The gate only ever adds a refusal; it changes nothing that already read.
///
/// The comparison is between two `u64` and never a narrower type: a version of 256 narrowed to a
/// `u8` would come out as 0 and be read as an old record, which is exactly the case the gate
/// exists for.
pub fn read(bytes: &[u8]) -> Result<Record, String> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| "The grid hub's settings are damaged".to_owned())?;
    let found = value["version"].as_u64().unwrap_or(0);
    if found > u64::from(VERSION) {
        return Err(format!("This grid's settings were written by a newer Yougori (version {found}); update Yougori to open them"));
    }
    serde_json::from_value(value).map_err(|_| "The grid hub's settings are damaged".to_owned())
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

/// Shares the capable computers among the plans. A computer the admin picked for a plan runs
/// that plan; the rest are shared out by percentage. Assignments are sticky, so computers keep
/// their model (and its downloaded files) when others join or leave; each share plan gets its
/// `percent` of its computers, rounded up, in the order the plans were created.
pub(crate) fn reconcile(record: &mut Record) -> bool {
    let current = now();
    let mut changed = false;
    // The plan each computer was picked for; the earliest plan keeps a computer picked twice.
    let mut picked: HashMap<String, String> = HashMap::new();
    for plan in &record.plans {
        for member in plan.target.picked() {
            picked.entry(member.clone()).or_insert_with(|| plan.id.clone());
        }
    }
    let plans: Vec<(String, u8, bool)> = record
        .plans
        .iter()
        .filter(|plan| !matches!(plan.target, Target::Computers { .. }))
        .map(|plan| (plan.id.clone(), plan.percent, plan.target == Target::Remaining))
        .collect();
    for member in &mut record.members {
        if let Some(plan) = picked.get(&member.id).filter(|_| member.eligible()) {
            if member.plan.as_ref() != Some(plan) {
                member.plan = Some(plan.clone());
                member.assigned_at = Some(current);
                changed = true;
            }
            continue;
        }
        if member.plan.as_ref().is_some_and(|plan| !member.eligible() || !plans.iter().any(|(id, _, _)| id == plan)) {
            member.plan = None;
            member.assigned_at = None;
            changed = true;
        }
    }
    let capable = record.members.iter().filter(|member| member.eligible()).count();
    let unpicked = record.members.iter().filter(|member| member.eligible() && !picked.contains_key(&member.id)).count();
    let quota = |percent: u8, remaining: bool| {
        let base = if remaining { unpicked } else { capable };
        (base * usize::from(percent)).div_ceil(100)
    };
    for (plan, percent, remaining) in &plans {
        let mut assigned: Vec<usize> = (0..record.members.len()).filter(|index| record.members[*index].plan.as_ref() == Some(plan)).collect();
        assigned.sort_by_key(|index| record.members[*index].assigned_at);
        while assigned.len() > quota(*percent, *remaining) {
            let index = assigned.pop().expect("longer than the quota");
            record.members[index].plan = None;
            record.members[index].assigned_at = None;
            changed = true;
        }
    }
    for (plan, percent, remaining) in &plans {
        let mut missing = quota(*percent, *remaining).saturating_sub(record.members.iter().filter(|member| member.plan.as_ref() == Some(plan)).count());
        let mut free: Vec<usize> = (0..record.members.len()).filter(|index| record.members[*index].eligible() && record.members[*index].plan.is_none()).collect();
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

/// Adds a plan to `record`. Picking computers moves them off the plan they were picked for
/// before, so a computer runs the model it was given last, and a plan left with no computers is
/// removed; picking more computers for a model already picked for others adds them to that plan.
pub(crate) fn place(record: &mut Record, model: &str, quant: Option<&str>, percent: u8, policy: IdlePolicy, target: Target) -> Result<Plan, String> {
    let model = plan_model(model)?;
    let quant = plan_quant(quant.unwrap_or_default())?;
    let target = match target {
        Target::Computers { members } => {
            let mut picked: Vec<String> = Vec::new();
            for id in members {
                if !record.members.iter().any(|member| member.id == id) {
                    return Err(format!("No computer with the ID {id} is in this grid"));
                }
                if !picked.contains(&id) {
                    picked.push(id);
                }
            }
            if picked.is_empty() {
                return Err("Pick at least one computer".into());
            }
            Target::Computers { members: picked }
        }
        share => {
            plan_percent(percent)?;
            share
        }
    };
    let picked = target.picked().to_vec();
    if !picked.is_empty() {
        for plan in &mut record.plans {
            if let Target::Computers { members } = &mut plan.target {
                members.retain(|member| !picked.contains(member));
            }
        }
        record.plans.retain(|plan| !matches!(&plan.target, Target::Computers { members } if members.is_empty()));
        let same = record.plans.iter_mut().find(|plan| matches!(plan.target, Target::Computers { .. }) && plan.model == model && plan.quant == quant && plan.policy == policy);
        if let Some(plan) = same {
            if let Target::Computers { members } = &mut plan.target {
                members.extend(picked);
            }
            return Ok(plan.clone());
        }
    }
    if record.plans.len() >= MAX_PLANS {
        return Err(format!("A grid can have at most {MAX_PLANS} plans"));
    }
    let plan = Plan { id: format!("plan-{}", &token()[..12]), model, quant, percent: if picked.is_empty() { percent } else { 100 }, policy, created_at: now(), target };
    record.plans.push(plan.clone());
    Ok(plan)
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
    /// The loopback address `cloudflared` forwards the grid's tunnel to, when it has one.
    tunnel: Option<SocketAddr>,
    fingerprint: String,
    /// The company password's derived key (hex).
    password: Mutex<String>,
    /// What decoy salts are keyed with: derived from the hub's TLS private key, which never
    /// leaves its computer. Not the password's key: its salt is public, so a decoy keyed with it
    /// would let anyone test password guesses offline.
    decoys: String,
    /// The bucket credentials for parking desks' data, set by the hub computer from its OS
    /// vault: `{provider, location, accessKey, secretKey}`. Never saved by the hub, never shown
    /// in status, sent only to a computer that is packing or unpacking a desk.
    parking: Mutex<Option<Value>>,
    /// Connectors' secrets by connection id, set by the hub computer from its OS vault. Never
    /// saved by the hub, never shown; used only on the hub computer to reach the provider.
    credentials: Mutex<HashMap<String, Value>>,
    /// The identity provider's discovery document and signing keys, fetched by the hub itself.
    sso: Mutex<SsoCache>,
    /// Taken before `live` when both are needed; saved to disk while held.
    record: Mutex<Record>,
    live: Mutex<Live>,
    work: Notify,
    events: Events,
    dirty: AtomicBool,
}

/// What the hub learned from the identity provider, and when.
#[derive(Default)]
struct SsoCache {
    issuer: String,
    discovery: Option<(Value, Instant)>,
    keys: Option<(Value, Instant)>,
    refreshed: Option<Instant>,
}

struct Live {
    presence: HashMap<String, Presence>,
    sessions: HashMap<String, enterprise::Session>,
    /// Desk share invitations from hosts, by desk: secrets kept in memory only, with their expiry.
    invitations: HashMap<String, (Value, i64)>,
    queue: VecDeque<Job>,
    running: HashMap<String, Running>,
    /// Replies still being relayed to their apps, by API key: they count against the key's
    /// limit until the last byte is through.
    relaying: HashMap<String, usize>,
    /// Connections host computers are holding open for desk sessions, by computer.
    desk_relays: HashMap<String, Vec<WaitingRelay>>,
    /// Wrong sign-ins per address (a public IPv6 address by its /64), and per account as guessed
    /// at from that address. The address count has far more room, because an office, a school or
    /// a shared connection is one address and ordinary mistyping must never gate everybody on it.
    refused: crate::access::throttle::Throttle<IpAddr>,
    refused_names: crate::access::throttle::Throttle<String>,
    /// The last two-step time step each person used, so a code works once.
    used_codes: HashMap<String, i64>,
}

impl Default for Live {
    fn default() -> Self {
        Self {
            presence: HashMap::new(),
            sessions: HashMap::new(),
            invitations: HashMap::new(),
            queue: VecDeque::new(),
            running: HashMap::new(),
            relaying: HashMap::new(),
            desk_relays: HashMap::new(),
            // Written out rather than derived, because the address count needs a limit of its
            // own: one address covers everybody behind it, and deriving Default here silently
            // gave a whole office the same ten tries one account gets.
            refused: crate::access::throttle::Throttle::with_limit(crate::access::throttle::ADDRESS_LIMIT),
            refused_names: crate::access::throttle::Throttle::default(),
            used_codes: HashMap::new(),
        }
    }
}

/// Whether a two-step code from `step` may be accepted for `person`: only a step later than the
/// last one they used anywhere. Records the step when it may.
///
/// A code is good for a step either side of now, which is a minute and a half in which anybody
/// who saw it — over a shoulder, in a screen share, on an unlocked phone — can use it themselves.
/// Checking the code cannot tell the second use from the first, because both are the same right
/// answer; only remembering which step was used can.
///
/// One memory for the person, not one per door. A code that signs somebody in and then moves
/// two-step to the thief's own phone is one code doing both, and keeping the sign-in's memory
/// apart from the settings' memory would allow exactly that inside one minute. The cost is that
/// somebody who has just signed in waits for the next code before changing two-step, which is
/// thirty seconds and is what a one-time code means.
///
/// This takes the map rather than the whole of `Shared` so that it can be checked on its own.
fn fresh_code(used: &mut HashMap<String, i64>, person: &str, step: i64) -> bool {
    if used.get(person).is_some_and(|last| step <= *last) {
        return false;
    }
    // A person who has not signed in for a while would otherwise be remembered for ever.
    if used.len() >= 4096 {
        used.retain(|_, last| *last >= step - 2);
    }
    used.insert(person.to_owned(), step);
    true
}

/// A host's open connection, waiting for someone to open a desk through it.
struct WaitingRelay {
    since: Instant,
    /// Hands the person's side of the session to the waiting host.
    hand: oneshot::Sender<(String, relay::Stream)>,
}

impl Live {
    /// Everything one key has in flight: waiting, running on a computer, or still streaming back.
    fn key_load(&self, key: &str) -> usize {
        self.queue.iter().filter(|job| job.key == key).count() + self.running.values().filter(|running| running.job.key == key).count() + self.relaying.get(key).copied().unwrap_or(0)
    }
}

struct Presence {
    seen: Instant,
    address: IpAddr,
    version: String,
    models: Vec<ModelReport>,
    /// What the computer can host, from its last check-in.
    capacity: Option<Capacity>,
    /// Desk reports in its last check-in that this hub could not read, so the audit says so once
    /// when that changes rather than at every check-in.
    unreadable_reports: usize,
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
    /// Set to the member that takes the job, for a harness to report who did what.
    taken: Option<Arc<Mutex<Option<String>>>>,
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

/// Writes the record when something changed. A failed write leaves the marker set, so the next
/// flush or sweep tries again instead of forgetting the change.
fn save_if_dirty(shared: &Shared) {
    if shared.dirty.swap(false, Ordering::Relaxed) {
        let record = lock(&shared.record);
        if let Err(error) = save(&shared.path, &record) {
            shared.dirty.store(true, Ordering::Relaxed);
            (shared.events)("grid.save.failed", json!({"error": error}));
        }
    }
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
        let mut record = load(&path)?;
        // Nothing is running yet, so nothing may still be marked as running.
        if resume_interrupted(&mut record) {
            save(&path, &record)?;
        }
        let tls = TlsAcceptor::from(net::server_config(&net::Identity { certificate: record.certificate.clone(), key: key.to_owned() })?);
        let fingerprint = net::fingerprint(&record.certificate)?;
        let listener = tokio::net::TcpListener::bind(SocketAddr::new(record.address, record.port)).await.map_err(|error| {
            format!(
                "Cannot open the grid hub on {}:{} ({error}). Check that this computer still has that address and that no other program uses the port.",
                record.address, record.port
            )
        })?;
        let bound = listener.local_addr().map_err(|error| error.to_string())?;
        // The tunnel's entry listens on loopback only: `cloudflared` on this computer forwards to it.
        let tunnel = match record.tunnel_port {
            Some(port) => Some(tokio::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), port)).await.map_err(|error| {
                format!("Cannot open the grid's tunnel entry on 127.0.0.1:{port} ({error}). Check that no other program uses the port.")
            })?),
            None => None,
        };
        let tunnel_bound = tunnel.as_ref().map(|listener| listener.local_addr()).transpose().map_err(|error| error.to_string())?;
        let shared = Arc::new(Shared {
            path,
            bound,
            tunnel: tunnel_bound,
            fingerprint,
            password: Mutex::new(password_key.to_owned()),
            decoys: decoy_secret(key),
            parking: Mutex::new(None),
            credentials: Mutex::new(HashMap::new()),
            sso: Mutex::new(SsoCache::default()),
            record: Mutex::new(record),
            live: Mutex::new(Live::default()),
            work: Notify::new(),
            events,
            dirty: AtomicBool::new(false),
        });
        let mut tasks = vec![tokio::spawn(serve(shared.clone(), listener, tls.clone())), tokio::spawn(sweep(shared.clone()))];
        if let Some(tunnel) = tunnel {
            tasks.push(tokio::spawn(serve_tunnel(shared.clone(), tunnel, tls)));
        }
        Ok(Hub { shared, tasks })
    }

    pub fn address(&self) -> SocketAddr {
        self.shared.bound
    }

    /// The loopback address a tunnel forwards to, when the grid has one.
    pub fn tunnel_address(&self) -> Option<SocketAddr> {
        self.shared.tunnel
    }

    pub fn record(&self) -> Record {
        lock(&self.shared.record).clone()
    }

    pub fn enterprise(&self, request: Value) -> Result<Value, String> { enterprise::manage(&self.shared, None, request) }

    /// A membership made ahead of time for a computer the hub itself creates (a cloud one): the
    /// token goes to that computer over SSH, so it never needs the company password. Returns
    /// what `member::adopt` needs on that computer.
    pub fn preregister_member(&self, name: &str, platform: &str) -> Result<Value, String> {
        let name = label(name, "name")?;
        let mut record = lock(&self.shared.record);
        if record.enterprise.computer_limit.is_some_and(|limit| record.members.len() >= limit) {
            return Err("The administrator-configured computer limit has been reached".into());
        }
        let member_token = token();
        let member = MemberRecord {
            id: format!("member-{}", &token()[..12]),
            name,
            platform: platform.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_')).take(32).collect(),
            token_hash: digest("member", &member_token),
            joined_at: now(),
            capable: false,
            plan: None,
            assigned_at: None,
            jobs: 0,
            excluded: false,
            share: None,
        };
        let id = member.id.clone();
        let previous = record.clone();
        record.members.push(member);
        self.commit(&mut record, previous)?;
        (self.shared.events)("grid.member.preregistered", json!({"memberId": id, "platform": platform}));
        Ok(json!({"memberId": id, "memberToken": member_token, "grid": {"id": record.id, "name": record.name}, "fingerprint": self.shared.fingerprint}))
    }

    /// Why a cloud computer is needed now, if a desk has waited too long with no room anywhere.
    pub fn needs_computer(&self) -> Option<String> {
        self.needs_computer_at(now())
    }

    /// The same, judged as of `at`.
    pub fn needs_computer_at(&self, at: i64) -> Option<String> {
        let record = lock(&self.shared.record);
        let live = lock(&self.shared.live);
        desks::needs_computer(&record.desks, &host_views(&record, &live), at)
    }

    /// The bucket credentials desks park with, or none to park with the hub. Kept in memory only.
    pub fn set_parking(&self, credentials: Option<Value>) {
        *lock(&self.shared.parking) = credentials.filter(|value| value["accessKey"].as_str().is_some_and(|key| !key.is_empty()) && value["secretKey"].as_str().is_some_and(|key| !key.is_empty()));
    }

    /// A connector's secret (`{clientSecret}` or `{password}`), from the hub computer's vault,
    /// or none to forget it. Kept in memory only.
    pub fn set_connection_credential(&self, connection: &str, secret: Option<Value>) {
        let mut credentials = lock(&self.shared.credentials);
        match secret.filter(|value| value.as_object().is_some_and(|map| map.values().any(|v| v.as_str().is_some_and(|s| !s.is_empty())))) {
            Some(secret) => {
                credentials.insert(connection.to_owned(), secret);
            }
            None => {
                credentials.remove(connection);
            }
        }
    }

    /// Connectors with a credential on record, so the hub computer can load their secrets.
    pub fn connections_with_credentials(&self) -> Vec<String> {
        lock(&self.shared.record).enterprise.connections.iter().filter(|c| c.credential_set).map(|c| c.id.clone()).collect()
    }

    /// What connectors are asked to do now: each pending task becomes running and is returned
    /// with everything needed to do it, the secret included. Tasks whose credential is not loaded
    /// fail at once, saying so.
    pub fn provisioning_due(&self) -> Vec<(String, provisioning::Task)> {
        let mut record = lock(&self.shared.record);
        if !record.enterprise.provisioning.iter().any(|task| task.state == "pending") {
            return Vec::new();
        }
        let previous = record.clone();
        let credentials = lock(&self.shared.credentials);
        let mut due = Vec::new();
        let connections = record.enterprise.connections.clone();
        for task in record.enterprise.provisioning.iter_mut().filter(|task| task.state == "pending") {
            let Some(connection) = connections.iter().find(|c| c.id == task.connection_id) else {
                task.state = "failed".into();
                task.note = "The connection was removed".into();
                task.finished_at = Some(now());
                continue;
            };
            let Some(secret) = credentials.get(&connection.id).cloned() else {
                task.state = "failed".into();
                task.note = "The connection's credential is not in the hub computer's vault; enter it again".into();
                task.finished_at = Some(now());
                continue;
            };
            let Some(want) = provisioning::Want::parse(&task.want) else {
                task.state = "failed".into();
                task.note = "Unknown request".into();
                task.finished_at = Some(now());
                continue;
            };
            task.state = "running".into();
            task.attempts += 1;
            due.push((task.id.clone(), provisioning::Task { provider: connection.provider, url: connection.url.clone(), target: connection.target.clone(), secret, want, email: task.email.clone(), name: task.person_name.clone() }));
        }
        drop(credentials);
        if let Err(error) = self.commit(&mut record, previous) {
            (self.shared.events)("grid.connection.error", json!({"error": error}));
            return Vec::new();
        }
        due
    }

    /// How a connector's task went; the note is what the admin sees.
    pub fn provisioning_report(&self, id: &str, outcome: Result<String, String>) {
        let mut record = lock(&self.shared.record);
        let previous = record.clone();
        let Some(task) = record.enterprise.provisioning.iter_mut().find(|task| task.id == id) else { return };
        let clean = |text: &str| text.chars().filter(|c| !c.is_control()).take(400).collect::<String>();
        let (state, note) = match &outcome {
            Ok(note) => ("done", clean(note)),
            Err(error) => ("failed", clean(error)),
        };
        task.state = state.into();
        task.note = note.clone();
        task.finished_at = Some(now());
        let event = json!({"taskId": id, "connectionId": task.connection_id, "want": task.want, "personId": task.person_id, "note": note});
        let _ = self.commit(&mut record, previous);
        drop(record);
        (self.shared.events)(if outcome.is_ok() { "grid.connection.done" } else { "grid.connection.failed" }, event);
    }

    /// Sign-in through the company's identity provider, when the admin set it up.
    pub fn sso(&self) -> Option<crate::enterprise::Sso> {
        lock(&self.shared.record).enterprise.sso.clone()
    }

    /// Whether desks park in the company's bucket: the place is saved, the keys are loaded.
    pub fn parks_in_bucket(&self) -> bool {
        lock(&self.shared.record).enterprise.parking.is_some() && lock(&self.shared.parking).is_some()
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
                    "capable": member.capable, "excluded": member.excluded, "planId": member.plan, "jobs": member.jobs,
                    "online": online(&member.id),
                    "lastSeenSeconds": presence.map(|presence| presence.seen.elapsed().as_secs()),
                    "address": presence.map(|presence| presence.address.to_string()),
                    "appVersion": presence.map(|presence| presence.version.clone()),
                    "running": live.running.values().filter(|running| running.member == member.id).count(),
                    "models": presence.map(|presence| presence.models.clone()).unwrap_or_default(),
                    "capacity": presence.and_then(|presence| presence.capacity.clone()),
                    // The admin's share, or the suggestion in force until they set one.
                    "share": member.share.clone().or_else(|| presence.and_then(|presence| presence.capacity.as_ref()).map(Share::suggested)),
                    "shareSet": member.share.is_some(),
                    "desks": record.desks.iter().filter(|desk| desk.host.as_ref() == Some(&member.id)).count(),
                    // Desks this computer is still packing to hand off. They have no host while
                    // the data is being packed, so they are in neither computer's count, and
                    // anything deciding whether a computer is finished with — retiring a cloud
                    // computer, above all — has to add this or it will take away the computer
                    // holding the only copy of somebody's desk.
                    "packing": record.desks.iter().filter(|desk| desk.moving_from.as_ref() == Some(&member.id)).count(),
                })
            })
            .collect::<Vec<_>>();
        let capable = record.members.iter().filter(|member| member.eligible()).count();
        let picked: Vec<&String> = record.plans.iter().flat_map(|plan| plan.target.picked()).collect();
        let unpicked = record.members.iter().filter(|member| member.eligible() && !picked.contains(&&member.id)).count();
        let plans = record
            .plans
            .iter()
            .map(|plan| {
                let target = match &plan.target {
                    Target::All => (capable * usize::from(plan.percent)).div_ceil(100),
                    Target::Remaining => (unpicked * usize::from(plan.percent)).div_ceil(100),
                    Target::Computers { members } => record.members.iter().filter(|member| member.eligible() && members.contains(&member.id)).count(),
                };
                let names: Vec<&str> = plan.target.picked().iter().filter_map(|id| record.members.iter().find(|member| &member.id == id).map(|member| member.name.as_str())).collect();
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
                    "computers": assigned.len(), "target": target, "ready": ready, "createdAt": plan.created_at,
                    "scope": plan.target, "names": names,
                })
            })
            .collect::<Vec<_>>();
        let share = |scope: Target| record.plans.iter().filter(|plan| plan.target == scope).map(|plan| u32::from(plan.percent)).sum::<u32>();
        let requested = share(Target::All).max(share(Target::Remaining));
        let current = now();
        let desk_views = record
            .desks
            .iter()
            .map(|desk| {
                let host = desk.host.as_ref().and_then(|id| record.members.iter().find(|member| &member.id == id));
                let invited = live.invitations.get(&desk.id).is_some_and(|(_, expires)| *expires > current);
                desks::desk_json(desk, &record.people, host.map(|member| member.name.as_str()), desk.host.as_deref().is_some_and(online), invited)
            })
            .collect::<Vec<_>>();
        json!({
            "id": record.id, "name": record.name, "address": record.address.to_string(), "port": port,
            "closing": closing_json(&record),
            "hostname": record.hostname, "url": url(&host), "hostnameUrl": record.hostname.as_deref().map(url),
            "certificate": record.certificate, "fingerprint": self.shared.fingerprint, "createdAt": record.created_at,
            "tunnelPort": self.shared.tunnel.map(|address| address.port()),
            "computers": {"total": record.members.len(), "capable": capable, "online": record.members.iter().filter(|member| online(&member.id)).count()},
            "plans": plans,
            "planWarning": (requested > 100).then(|| format!("Plans ask for {requested}% of the computers; later plans get fewer")),
            "members": members,
            "models": models(&live),
            "keys": record.keys.iter().map(key_summary).collect::<Vec<_>>(),
            "desks": desk_views,
            "enterprise": record.enterprise,
            "people": record.people.iter().map(|person| desks::person_json(person, &record.desks)).collect::<Vec<_>>(),
            "harnesses": record.harnesses.iter().map(|harness| {
                let mut entry = json!(harness);
                entry["model"] = json!(harness.model());
                entry["ready"] = json!(harness.models().iter().all(|model| matches!(availability(&live, model), Availability::Ready)));
                entry
            }).collect::<Vec<_>>(),
            "queue": {"waiting": live.queue.len(), "running": live.running.len(), "streaming": live.relaying.values().sum::<usize>()},
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

    pub fn add_plan(&self, model: &str, quant: Option<&str>, percent: u8, policy: IdlePolicy, target: Target) -> Result<Value, String> {
        let mut record = lock(&self.shared.record);
        let previous = record.clone();
        let plan = match place(&mut record, model, quant, percent, policy, target) {
            Ok(plan) => plan,
            Err(error) => {
                *record = previous;
                return Err(error);
            }
        };
        self.commit(&mut record, previous)?;
        let computers = record.members.iter().filter(|member| member.plan.as_ref() == Some(&plan.id)).count();
        Ok(json!({"plan": plan, "computers": computers}))
    }

    pub fn update_plan(&self, id: &str, change: PlanChange) -> Result<Value, String> {
        let mut record = lock(&self.shared.record);
        let previous = record.clone();
        let current = record.plans.iter().find(|plan| plan.id == id).ok_or("No plan with that ID exists in this grid")?.clone();
        // Every field is checked before any of them changes: a refused update changes nothing.
        let model = match change.model {
            Some(model) => plan_model(&model)?,
            None => current.model.clone(),
        };
        let quant = match change.quant {
            Some(quant) => plan_quant(&quant)?,
            None => current.quant.clone(),
        };
        let percent = match change.percent {
            Some(percent) => plan_percent(percent)?,
            None => current.percent,
        };
        let schedule = match change.schedule {
            Some(schedule) => Some(schedule),
            None => current.policy.schedule.clone(),
        };
        let policy = IdlePolicy::new(Some(change.idle_after_minutes.unwrap_or(current.policy.idle_after_minutes)), schedule.as_deref())?;
        let plan = record.plans.iter_mut().find(|plan| plan.id == id).expect("found above");
        plan.model = model;
        plan.quant = quant;
        plan.percent = percent;
        plan.policy = policy;
        let plan = plan.clone();
        self.commit(&mut record, previous)?;
        let computers = record.members.iter().filter(|member| member.plan.as_ref() == Some(&plan.id)).count();
        Ok(json!({"plan": plan, "computers": computers}))
    }

    /// Saves a harness. `missing` lists its models that no plan runs yet.
    pub fn add_harness(&self, harness: Harness) -> Result<Value, String> {
        let mut record = lock(&self.shared.record);
        if record.harnesses.iter().any(|entry| entry.name == harness.name) {
            return Err(format!("A harness named {} already exists; remove it first to change it", harness.name));
        }
        if record.harnesses.len() >= harness::MAX_HARNESSES {
            return Err(format!("A grid can have at most {} harnesses", harness::MAX_HARNESSES));
        }
        let previous = record.clone();
        record.harnesses.push(harness.clone());
        self.commit(&mut record, previous)?;
        let planned: Vec<String> = record.plans.iter().map(|plan| model_key(&plan.model)).collect();
        let missing: Vec<String> = harness.models().into_iter().filter(|model| !planned.contains(model)).collect();
        Ok(json!({"harness": harness, "model": harness.model(), "missing": missing}))
    }

    pub fn remove_harness(&self, id: &str) -> Result<Value, String> {
        let mut record = lock(&self.shared.record);
        let previous = record.clone();
        let wanted = id.trim().to_ascii_lowercase();
        let index = record.harnesses.iter().position(|entry| entry.id == wanted || entry.name == wanted.trim_start_matches(harness::PREFIX)).ok_or("No harness with that ID or name exists in this grid")?;
        let removed = record.harnesses.remove(index);
        self.commit(&mut record, previous)?;
        Ok(json!({"harnessId": removed.id, "model": removed.model(), "removed": true}))
    }

    /// Runs harnesses after the caller lets go of whatever lock found this hub.
    pub fn swarm(&self) -> Swarm {
        Swarm { shared: self.shared.clone() }
    }

    pub fn remove_plan(&self, id: &str) -> Result<Value, String> {
        let mut record = lock(&self.shared.record);
        let previous = record.clone();
        let index = record.plans.iter().position(|plan| plan.id == id).ok_or("No plan with that ID exists in this grid")?;
        let plan = record.plans.remove(index);
        self.commit(&mut record, previous)?;
        Ok(json!({"planId": plan.id, "model": plan.model, "removed": true}))
    }

    // ---- Desks, people and shares: every change goes through `enterprise::manage`, the one place
    // with the rules (authorization, atomic save, session and invitation invalidation, audit).
    // These are the same operations by name, for the engine and the tests.

    /// Adds a person who may sign in. `salt` and `key` are the password's salt and derived key;
    /// only the key's hash is kept. With `desk`, their desk is ordered with them, named after them.
    pub fn add_person(&self, username: &str, name: &str, salt: &str, key: &str, desk: Option<DeskSpec>) -> Result<Value, String> {
        let result = self.enterprise(json!({"action": "personAdd", "username": username, "name": name, "salt": salt, "key": key, "spec": desk}))?;
        let mut person = result["person"].clone();
        if result.get("desk").is_some_and(|desk| !desk.is_null()) {
            person["desk"] = result["desk"].clone();
        }
        Ok(person)
    }

    /// Changes a person's password; their desks are untouched, their sign-ins end.
    pub fn set_person_password(&self, id: &str, salt: &str, key: &str) -> Result<Value, String> {
        let result = self.enterprise(json!({"action": "personPassword", "id": id, "salt": salt, "key": key}))?;
        Ok(json!({"personId": result["id"], "changed": true}))
    }

    /// Removes a person; their desks stay, unassigned, with their data.
    pub fn remove_person(&self, id: &str) -> Result<Value, String> {
        let result = self.enterprise(json!({"action": "personRemove", "id": id}))?;
        Ok(json!({"personId": result["id"], "removed": true}))
    }

    /// Orders a desk of the given size, for a person when given, and places it at once if a
    /// computer has room.
    pub fn add_desk(&self, name: &str, spec: DeskSpec, person: Option<&str>) -> Result<Value, String> {
        Ok(self.enterprise(json!({"action": "deskOrder", "name": name, "spec": spec, "person": person}))?["desk"].clone())
    }

    /// Gives a desk to a person, or to nobody; its data stays.
    pub fn assign_desk(&self, id: &str, person: Option<&str>) -> Result<Value, String> {
        Ok(self.enterprise(json!({"action": "deskAssign", "id": id, "person": person}))?["desk"].clone())
    }

    /// Tries a failed desk again, on any computer with room.
    pub fn retry_desk(&self, id: &str) -> Result<Value, String> {
        Ok(self.enterprise(json!({"action": "deskRetry", "id": id}))?["desk"].clone())
    }

    /// Removes a desk; its host deletes the sandbox and its data at its next check-in.
    pub fn remove_desk(&self, id: &str) -> Result<Value, String> {
        let result = self.enterprise(json!({"action": "deskRemove", "id": id}))?;
        Ok(json!({"deskId": result["id"], "name": result["name"], "removed": true}))
    }

    /// The share in force for a computer: the admin's, else the suggestion from its last report,
    /// else a small default for a computer that has not reported yet.
    pub fn member_share(&self, id: &str) -> Result<Share, String> {
        let record = lock(&self.shared.record);
        let member = record.members.iter().find(|member| member.id == id).ok_or("No computer with that ID is in this grid")?;
        if let Some(share) = &member.share {
            return Ok(share.clone());
        }
        let live = lock(&self.shared.live);
        Ok(live.presence.get(id).and_then(|presence| presence.capacity.as_ref()).map(Share::suggested).unwrap_or(Share { cpu: 2.0, memory_gb: 4.0, disk_gb: 50.0, gpu: false, idle_only: false }))
    }

    /// Sets what the grid may take from a computer, or with `None` goes back to the suggested
    /// share. Desks waiting for room are placed at once; desks already on the computer stay,
    /// since their data is there.
    pub fn set_member_share(&self, id: &str, share: Option<Share>) -> Result<Value, String> {
        let result = self.enterprise(json!({"action": "computerShare", "id": id, "share": share}))?;
        Ok(json!({"memberId": result["id"], "name": result["name"], "share": result["share"], "shareSet": result["shareSet"]}))
    }

    /// Deletes the grid: `at_once` makes it gone now, otherwise it is paused for `GRACE` and can
    /// be restored until then. Either way the hub keeps answering, so computers hear about it.
    pub fn close(&self, at_once: bool) -> Result<Value, String> {
        let mut record = lock(&self.shared.record);
        let at = now();
        let until = match (phase(&record), at_once) {
            (Phase::Gone, _) => return Err("This grid is already deleted; its computers are being told".into()),
            (_, true) => at,
            (Phase::Paused(until), false) => until,
            (Phase::Open, false) => at + GRACE,
        };
        let previous = record.clone();
        let requested_at = previous.closing.as_ref().map_or(at, |closing| closing.requested_at);
        record.closing = Some(Closing { requested_at, until, told: Vec::new() });
        self.commit(&mut record, previous)?;
        // Paused desks are not shared: invitations end now and are minted afresh after a restore.
        lock(&self.shared.live).invitations.clear();
        (self.shared.events)("grid.closing", json!({"until": until, "atOnce": at_once}));
        Ok(closing_json(&record))
    }

    /// Takes back a deletion while the grid is still paused: everything works again.
    pub fn restore(&self) -> Result<Value, String> {
        let mut record = lock(&self.shared.record);
        match phase(&record) {
            Phase::Open => return Err("This grid is not scheduled for deletion".into()),
            Phase::Gone => return Err("This grid is already deleted and can no longer be restored".into()),
            Phase::Paused(_) => {}
        }
        let previous = record.clone();
        record.closing = None;
        self.commit(&mut record, previous)?;
        (self.shared.events)("grid.restored", json!({}));
        Ok(json!({"restored": true}))
    }

    /// Where the grid is in its life.
    pub fn phase(&self) -> Phase {
        phase(&lock(&self.shared.record))
    }

    /// Gone, and every computer has heard (or `TELL_FOR` passed): its files can go.
    pub fn finished(&self) -> bool {
        let record = lock(&self.shared.record);
        let Some(closing) = record.closing.as_ref().filter(|_| phase(&record) == Phase::Gone) else { return false };
        now() >= closing.until + TELL_FOR || record.members.iter().all(|member| closing.told.contains(&member.id))
    }

    /// Leaves a computer out of the grid's work, or brings it back. A computer left out gets no
    /// model and no work, so it drops the model the grid gave it; brought back, the plans may
    /// pick it again.
    pub fn set_excluded(&self, id: &str, excluded: bool) -> Result<Value, String> {
        let mut record = lock(&self.shared.record);
        let previous = record.clone();
        let member = record.members.iter_mut().find(|member| member.id == id).ok_or("No computer with that ID is in this grid")?;
        member.excluded = excluded;
        let name = member.name.clone();
        self.commit(&mut record, previous)?;
        Ok(json!({"memberId": id, "name": name, "excluded": excluded}))
    }

    pub fn remove_member(&self, id: &str) -> Result<Value, String> {
        let removed = {
            let mut record = lock(&self.shared.record);
            let previous = record.clone();
            let member = remove_member_record(&mut record, id).ok_or("No computer with that ID is in this grid")?;
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
        save_if_dirty(&self.shared);
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
                    connection(shared, tls, socket, peer.ip()).await;
                });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

/// The tunnel's entry: each connection `cloudflared` forwards is unwrapped from its WebSocket,
/// then served exactly like one from the LAN, through the same pinned TLS. `peer` is the
/// computer behind Cloudflare, so a wrong password locks out only its own address.
async fn serve_tunnel(shared: Arc<Shared>, listener: tokio::net::TcpListener, tls: TlsAcceptor) {
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut connections = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((socket, from)) = accepted else {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                };
                // Only `cloudflared` on this computer forwards to the entry.
                if !from.ip().is_loopback() {
                    continue;
                }
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

/// One connection's pinned TLS and HTTP, answering as `peer`.
async fn connection<S>(shared: Arc<Shared>, tls: TlsAcceptor, socket: S, peer: IpAddr)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let Ok(Ok(stream)) = tokio::time::timeout(Duration::from_secs(10), tls.accept(socket)).await else { return };
    let service = hyper::service::service_fn(move |request| {
        let shared = shared.clone();
        async move { Ok::<_, std::convert::Infallible>(route(shared, peer, request).await) }
    });
    let _ = hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(30))
        .serve_connection(TokioIo::new(stream), service)
        .await;
}

async fn route(shared: Arc<Shared>, peer: IpAddr, request: Request<Incoming>) -> Response<Body> {
    let path = request.uri().path().to_owned();
    let current = phase(&lock(&shared.record));
    match current {
        // Gone: everyone is told so; a member that hears it is counted, then leaves and cleans up.
        Phase::Gone => {
            if let Some(member) = member_of(&shared, &request) {
                let mut record = lock(&shared.record);
                if let Some(closing) = record.closing.as_mut().filter(|closing| !closing.told.contains(&member)) {
                    closing.told.push(member.clone());
                    shared.dirty.store(true, Ordering::Relaxed);
                    (shared.events)("grid.member.told_deleted", json!({"memberId": member}));
                }
            }
            return error(StatusCode::GONE, "grid_deleted", crate::GRID_DELETED);
        }
        // Paused: members still check in (and hear about the pause); nothing else works.
        Phase::Paused(until) if !matches!(path.as_str(), "/grid/v1/heartbeat" | "/grid/v1/leave" | "/grid/v1/hello") => {
            return error(StatusCode::SERVICE_UNAVAILABLE, "grid_paused", paused_message(until));
        }
        _ => {}
    }
    match (request.method().clone(), path.as_str()) {
        (Method::POST, "/v1/chat/completions") => chat(&shared, request).await,
        (Method::GET, "/v1/models") => list_models(&shared, &request),
        (Method::GET, "/grid/v1/hello") => hello(&shared),
        (Method::POST, "/grid/v1/join") => join(&shared, peer, request).await,
        (Method::POST, "/grid/v1/person/salt") => person_salt(&shared, peer, request).await,
        (Method::POST, "/grid/v1/person/login") => person_login(&shared, peer, request).await,
        (Method::GET, "/grid/v1/person/sso") => sso_config(&shared).await,
        (Method::POST, "/grid/v1/person/sso") => person_sso(&shared, peer, request).await,
        (Method::POST, "/grid/v1/desks/relay/host") => desk_relay_host(&shared, &request).map_or_else(|response| response, |member| hold_relay(&shared, member, request)),
        (Method::POST, "/grid/v1/desks/relay/open") => open_relay(&shared, request).await,
        (Method::POST, "/grid/v1/desks/manage") => enterprise::route(&shared, request).await,
        (Method::POST, "/grid/v1/desks/lease") => enterprise::lease(&shared, request).await,
        (Method::POST, "/grid/v1/desks/image") => enterprise::image_bytes(&shared, request).await,
        (Method::POST, "/grid/v1/desks/parcel") => enterprise::parcel_put(&shared, request).await,
        (Method::POST, "/grid/v1/desks/parcel/fetch") => enterprise::parcel_get(&shared, request).await,
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

fn key_exists(shared: &Shared, key: &str) -> bool {
    lock(&shared.record).keys.iter().any(|entry| entry.id == key)
}

fn key_of(shared: &Shared, request: &Request<Incoming>) -> Option<String> {
    let secret = bearer(request)?.strip_prefix(KEY_PREFIX).filter(|secret| is_token(secret))?;
    let hash = digest("key", secret);
    lock(&shared.record).keys.iter().find(|key| key.hash == hash).map(|key| key.id.clone())
}

fn touch(shared: &Shared, member: &str, peer: IpAddr) {
    let mut live = lock(&shared.live);
    let presence = live.presence.entry(member.to_owned()).or_insert_with(|| Presence { seen: Instant::now(), address: peer, version: String::new(), models: Vec::new(), capacity: None, unreadable_reports: 0 });
    presence.seen = Instant::now();
    presence.address = peer;
}

fn throttled(shared: &Shared, peer: IpAddr) -> bool {
    lock(&shared.live).refused.blocked(&crate::access::throttle::network(peer))
}

fn refuse(shared: &Shared, peer: IpAddr) {
    lock(&shared.live).refused.fail(crate::access::throttle::network(peer));
}

/// Whether this account has had too many wrong sign-ins lately FROM THIS ADDRESS. Keying both
/// together is what stops a stranger who merely knows a username from locking its owner out of
/// their own desk, and what keeps one person guessing at a colleague from gating a whole office.
/// Unknown names count
/// the same way, so the answer says nothing about who exists.
/// A refusal by one of the counts, recorded as it is returned. Being kept out belongs in the
/// record as much as getting in does: without it, somebody locking a person out of their desk
/// leaves no trace at all.
fn rate_limited(shared: &Shared, peer: IpAddr, username: &str, said: &str) -> Response<Body> {
    (shared.events)("grid.person.refused", json!({"address": peer.to_string(), "person": username, "rateLimited": true}));
    error(StatusCode::TOO_MANY_REQUESTS, "rate_limited", said)
}

fn attempt_key(peer: IpAddr, username: &str) -> String {
    format!("{}|{username}", crate::access::throttle::network(peer))
}

fn name_throttled_pair(shared: &Shared, peer: IpAddr, username: &str) -> bool {
    !username.is_empty() && lock(&shared.live).refused_names.blocked(&attempt_key(peer, username))
}

fn refuse_name_pair(shared: &Shared, peer: IpAddr, username: &str) {
    if !username.is_empty() {
        lock(&shared.live).refused_names.fail(attempt_key(peer, username));
    }
}



/// The secret decoy salts are keyed with, from the hub's TLS private key (see `Shared::decoys`).
fn decoy_secret(tls_key: &str) -> String {
    crate::digest("desks-decoy-salts", tls_key)
}

/// What a computer needs before joining: which company this is and the password's salt.
fn hello(shared: &Shared) -> Response<Body> {
    let record = lock(&shared.record);
    json_response(StatusCode::OK, &json!({"gridId": record.id, "name": record.name, "salt": record.salt}))
}

async fn join(shared: &Arc<Shared>, peer: IpAddr, request: Request<Incoming>) -> Response<Body> {
    if throttled(shared, peer) {
        return rate_limited(shared, peer, "", "Too many wrong passwords from this address; wait 10 minutes");
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
        if record.enterprise.computer_limit.is_some_and(|limit| record.members.len() >= limit) {
            return error(StatusCode::CONFLICT, "grid_full", "The administrator-configured computer limit has been reached");
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
            excluded: false,
            share: None,
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

/// The desk reports in a check-in, each read on its own, at most `desks::MAX_DESKS`, with how many
/// could not be read. A computer newer than this hub can send a report it cannot read, such as a
/// parcel in a store it does not know. Read as one list, that report took every report beside it
/// with it, fresh invitations and finished parcels included, and moves and shares stalled with
/// nobody told. Now an unreadable report costs only itself.
fn reports_in(raw: &Value) -> (Vec<DeskReport>, usize) {
    let mut unreadable = 0;
    let reports = raw.as_array().into_iter().flatten().take(desks::MAX_DESKS).filter_map(|report| serde_json::from_value(report.clone()).map_err(|_| unreadable += 1).ok()).collect();
    (reports, unreadable)
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
        let presence = live.presence.entry(member.to_owned()).or_insert_with(|| Presence { seen: Instant::now(), address: peer, version: String::new(), models: Vec::new(), capacity: None, unreadable_reports: 0 });
        presence.seen = Instant::now();
        presence.address = peer;
        presence.version = short(body["appVersion"].as_str().unwrap_or_default(), 32);
        presence.models = models;
    }
    let capacity = serde_json::from_value::<Option<Capacity>>(body["capacity"].clone()).ok().flatten().map(Capacity::checked);
    let (reports, unreadable) = reports_in(&body["desks"]);
    let mut record = lock(&shared.record);
    let capable = body["capable"] == true;
    let mut changed = false;
    if let Some(index) = record.members.iter().position(|entry| entry.id == member) {
        if record.members[index].capable != capable {
            record.members[index].capable = capable;
            reconcile(&mut record);
            changed = true;
        }
    }
    let orders = {
        let mut live = lock(&shared.live);
        if let Some(presence) = live.presence.get_mut(member) {
            presence.capacity = capacity;
            if presence.unreadable_reports != unreadable {
                presence.unreadable_reports = unreadable;
                if unreadable > 0 {
                    (shared.events)("grid.desk.report_unreadable", json!({"memberId": member, "reports": unreadable, "version": presence.version}));
                }
            }
        }
        for report in &reports {
            if let Some(desk) = record.desks.iter_mut().find(|desk| desk.id == report.id) {
                if desk.generation == report.generation && desks::apply_report(desk, member, report) {
                    changed = true;
                    // Its new computer has the data now: the hub keeps no copy.
                    if report.state == "adopted" {
                        enterprise::forget_parcel(shared, &desk.id);
                    }
                }
                if desk.host.as_deref() == Some(member) && desk.generation == report.generation {
                    if let (Some(invitation), Some(expires)) = (&report.invitation, report.invitation_expires_at) {
                        live.invitations.insert(desk.id.clone(), (invitation.clone(), expires));
                        (shared.events)("grid.desk.shared", json!({"deskId": desk.id, "memberId": member}));
                    }
                }
            }
        }
        changed |= reclaim_desks(&mut record);
        let hosts = host_views(&record, &live);
        changed |= desks::hand_off(&mut record.desks, &hosts);
        changed |= desks::place_parcels(&mut record.desks, &hosts);
        changed |= desks::place(&mut record.desks, &hosts);
        let current = now();
        let mut orders = desks::orders_for(&record.desks, &record.people, member, |desk| live.invitations.get(desk).is_some_and(|(_, expires)| expires - current > desks::RENEW_BEFORE));
        // Desks park in the company's bucket when it is set up; the credentials go only to the
        // computer packing or unpacking a desk, and only in that answer.
        let bucket = lock(&shared.parking).clone().filter(|_| record.enterprise.parking.is_some());
        if bucket.is_some() {
            for order in orders.iter_mut().filter(|order| order.park) {
                order.park_in = desks::ParcelStore::S3;
            }
        }
        let needs_bucket = orders.iter().any(|order| (order.park && order.park_in == desks::ParcelStore::S3) || order.adopt.as_ref().is_some_and(|parcel| parcel.store == desks::ParcelStore::S3));
        let parking = if needs_bucket { bucket } else { None };
        (orders, parking)
    };
    let (orders, parking) = orders;
    if changed {
        // Saved by the sweep: no file write on the serving thread for a routine check-in.
        shared.dirty.store(true, Ordering::Relaxed);
    }
    json_response(StatusCode::OK, &json!({"grid": {"id": record.id, "name": record.name}, "memberId": member, "assignment": assignment(&record, member), "desks": orders, "closing": closing_json(&record), "parking": parking}))
}

/// Takes a computer out of the record. A computer picked for a plan leaves it too; a plan left
/// with no computers goes.
fn remove_member_record(record: &mut Record, id: &str) -> Option<MemberRecord> {
    let index = record.members.iter().position(|member| member.id == id)?;
    let member = record.members.remove(index);
    for plan in &mut record.plans {
        if let Target::Computers { members } = &mut plan.target {
            members.retain(|picked| picked != id);
        }
    }
    record.plans.retain(|plan| !matches!(&plan.target, Target::Computers { members } if members.is_empty()));
    Some(member)
}

/// Desks whose host left the grid go back to waiting; their data trail remembers the host. A desk
/// that had failed there is tried elsewhere, up to the usual limit.
/// How many times a connector task may be picked up again after the hub stopped under it.
const RESUMES: u32 = 3;

/// Connector tasks that were running when the hub last stopped, put back where they can run.
///
/// A task is marked running the moment it is handed out, and only the computer running it moves
/// it off running again. So a hub that stops mid-task leaves one marked running with nobody
/// running it, for ever — and because queueing one treats pending and running alike as already
/// queued, assigning or taking back that person at that provider never happens again. The person
/// keeps an account they should have lost, or never gets the one they were given, and the grid
/// shows a task that looks busy.
///
/// Put back as pending rather than failed, because what it was asked to do still needs doing and
/// a connector is written to be asked twice. A task interrupted over and over is given up on
/// instead, so a hub that cannot get through one is not stopped by it every time it starts.
fn resume_interrupted(record: &mut Record) -> bool {
    let mut changed = false;
    for task in record.enterprise.provisioning.iter_mut().filter(|task| task.state == "running") {
        changed = true;
        if task.attempts >= RESUMES {
            task.state = "failed".into();
            task.note = "This grid's hub stopped while this was running, too many times to try again; somebody has to check the provider".into();
            task.finished_at = Some(now());
        } else {
            task.state = "pending".into();
            task.note = "This grid's hub stopped while this was running; it will be done again".into();
        }
    }
    changed
}

fn reclaim_desks(record: &mut Record) -> bool {
    let members: Vec<String> = record.members.iter().map(|member| member.id.clone()).collect();
    let mut changed = false;
    for desk in &mut record.desks {
        // A desk being handed off has no host: the computer giving it up is in `moving_from`
        // while it packs the data, and it is the one that has to still be here. Looking only at
        // `host` skipped exactly the desk whose computer left at the worst moment, leaving it
        // waiting for a report from a computer that is gone — and nothing else reaches it, since
        // Retry is for failed desks and placement only looks at a packed desk with a parcel.
        let Some(host) = desk.host.clone().or_else(|| desk.moving_from.clone()) else { continue };
        if members.contains(&host) {
            continue;
        }
        // Mid-hand-off, and the computer that was packing it has gone. Where that leaves the desk
        // is a question about the data, not about the desk: packed and parked, it is somewhere
        // else and safe and the desk needs only a computer; still on the computer that left, it
        // went with it, and the desk is rebuilt or given up on like any other desk there.
        if desk.host.is_none() {
            desk.moving_from = None;
            if desk.parcel.is_some() {
                desk.note = "Its data is packed and waiting for a computer with room".into();
            } else {
                let retry = desk.attempts < desks::MAX_ATTEMPTS;
                desk.state = if retry { DeskState::Planned } else { DeskState::Failed };
                desk.environment_id = None;
                desk.note = if retry {
                    "Its computer left the grid while it was being moved, before its data was packed; building it again".into()
                } else {
                    "Its computer left the grid while it was being moved, and it had already failed too often to try again".into()
                };
            }
            desk.updated_at = now();
            changed = true;
            continue;
        }
        let retry = match desk.state {
            DeskState::Building | DeskState::Ready => true,
            DeskState::Failed => desk.attempts < desks::MAX_ATTEMPTS,
            // Its data is packed and safe: it only needs a computer, not a rebuild.
            DeskState::Moving => {
                desk.host = None;
                desk.note = "Its data is packed and waiting for a computer with room".into();
                desk.updated_at = now();
                changed = true;
                continue;
            }
            DeskState::Planned => continue,
        };
        desk.state = if retry { DeskState::Planned } else { DeskState::Failed };
        desk.host = None;
        desk.environment_id = None;
        desk.note = if retry { "Its computer left the grid; finding a computer again".into() } else { "Its computer left the grid after it failed there repeatedly".into() };
        desk.updated_at = now();
        changed = true;
    }
    changed
}

/// Every member as placement sees it.
fn host_views(record: &Record, live: &Live) -> Vec<HostView> {
    record
        .members
        .iter()
        .map(|member| {
            let presence = live.presence.get(&member.id);
            let capacity = presence.and_then(|presence| presence.capacity.clone());
            HostView {
                id: member.id.clone(),
                online: presence.is_some_and(|presence| presence.seen.elapsed() < ONLINE),
                excluded: member.excluded,
                going_away: capacity.as_ref().is_some_and(|capacity| capacity.going_away.is_some()),
                capacity,
                share: member.share.clone(),
            }
        })
        .collect()
}

/// A person's sign-in, step one: the salt their key is derived with. A username nobody has
/// gets a decoy, so the answer does not say who exists.
async fn person_salt(shared: &Arc<Shared>, _peer: IpAddr, request: Request<Incoming>) -> Response<Body> {
    // Not rate limited, on purpose, and for the same reason as the Access hub's. A salt is not a
    // secret: it is what the person's own computer needs to turn their password into a key, an
    // unknown name gets a decoy that cannot be told from a real one, and a salt never changes —
    // so anybody guessing kept theirs from the first attempt and is slowed by nothing here.
    // Refusing it only stops the real person reaching their password prompt, from an address
    // somebody else has been guessing from.
    let body = match net::json_body(request.into_body(), 4096).await {
        Ok(body) => body,
        Err(message) => return error(StatusCode::BAD_REQUEST, "invalid_request_error", message),
    };
    let username = match desks::username(body["username"].as_str().unwrap_or_default()) {
        Ok(username) => username,
        Err(message) => return error(StatusCode::BAD_REQUEST, "invalid_request_error", message),
    };
    // Deliberately not counted against the username. A salt is not a secret — it is what the
    // person's own computer needs to turn their password into a key — and refusing it would stop
    // them even reaching the password prompt while somebody else was guessing at their name.
    // An unknown name gets a decoy keyed with a secret only the hub holds, so it cannot be told
    // from a real salt, nor used to check a guess at the company password.
    let record = lock(&shared.record);
    let salt = record.people.iter().find(|person| person.username == username).map(|person| person.salt.clone()).unwrap_or_else(|| desks::decoy_salt(&shared.decoys, &username));
    json_response(StatusCode::OK, &json!({"salt": salt}))
}

/// A person's sign-in, step two: the derived key, checked against its hash. Guessing is capped per
/// account AS GUESSED AT FROM ONE ADDRESS, so a stranger who knows a username cannot lock its
/// owner out; the address has its own, far larger, count behind that.
async fn person_login(shared: &Arc<Shared>, peer: IpAddr, request: Request<Incoming>) -> Response<Body> {
    if throttled(shared, peer) {
        return rate_limited(shared, peer, "", "Too many wrong sign-ins from this address; wait 10 minutes");
    }
    let body = match net::json_body(request.into_body(), 4096).await {
        Ok(body) => body,
        Err(message) => return error(StatusCode::BAD_REQUEST, "invalid_request_error", message),
    };
    let username = desks::username(body["username"].as_str().unwrap_or_default()).unwrap_or_default();
    // This account as guessed at from this address, then the address itself. Keying both together
    // is what stops a stranger locking somebody out of their own desk: to shut Ada out you would
    // have to be guessing from Ada's own address.
    if name_throttled_pair(shared, peer, &username) || throttled(shared, peer) {
        return rate_limited(shared, peer, &username, "Too many wrong sign-ins; wait 10 minutes");
    }
    let key = body["key"].as_str().filter(|key| key.len() == 64 && key.bytes().all(|c| c.is_ascii_hexdigit())).unwrap_or_default();
    let hash = desks::key_hash(key);
    let reply = {
        let mut record = lock(&shared.record);
        if record.enterprise.sso.as_ref().is_some_and(|sso| sso.passwordless) {
            return error(StatusCode::FORBIDDEN, "sso_only", "Sign in through your company's identity provider; passwords are off for this grid");
        }
        let found = record.people.iter().position(|person| person.username == username && desks::same_hash(&person.key_hash, &hash));
        let Some(index) = found.filter(|_| !key.is_empty()) else {
            drop(record);
            refuse(shared, peer);
            refuse_name_pair(shared, peer, &username);
            (shared.events)("grid.person.refused", json!({"address": peer.to_string()}));
            return error(StatusCode::FORBIDDEN, "password_wrong", "The username or password is wrong");
        };
        // Two-step sign-in: the password was right, now the code from their authenticator.
        if let Some(secret) = record.people[index].totp.clone() {
            let code = body["code"].as_str().unwrap_or_default();
            if code.is_empty() {
                drop(record);
                return error(StatusCode::UNAUTHORIZED, "mfa_required", crate::MFA_REQUIRED);
            }
            // Right, and not one that has been used. A code is good for a step either side of
            // now, so anybody who saw it — over a shoulder, in a screen share, on a phone left
            // unlocked — had a minute to use it again. The step it matched is remembered, and
            // nothing at or before that step signs this person in a second time.
            let fresh = crate::totp::step_of(&secret, code, now()).filter(|step| fresh_code(&mut lock(&shared.live).used_codes, &record.people[index].id, *step));
            if fresh.is_none() {
                drop(record);
                refuse(shared, peer);
                refuse_name_pair(shared, peer, &username);
                (shared.events)("grid.person.refused", json!({"address": peer.to_string(), "mfa": true}));
                return error(StatusCode::FORBIDDEN, "code_wrong", "The code from your authenticator app is wrong, expired, or has been used already");
            }
        }
        match issue_session(shared, &mut record, index, peer, false) {
            Ok(reply) => {
                // They proved who they are, so earlier mistypes stop counting against them.
                let mut live = lock(&shared.live);
                live.refused.forgive(&crate::access::throttle::network(peer));
                if !username.is_empty() {
                    live.refused_names.forgive(&attempt_key(peer, &username));
                }
                reply
            }
            Err(response) => return response,
        }
    };
    json_response(StatusCode::OK, &reply)
}

/// A signed-in person's session and what they may open: the same answer whether the password
/// or the company's identity provider proved who they are.
fn issue_session(shared: &Shared, record: &mut Record, index: usize, peer: IpAddr, sso: bool) -> Result<Value, Response<Body>> {
    record.people[index].last_login_at = Some(now());
    shared.dirty.store(true, Ordering::Relaxed);
    let person = record.people[index].clone();
    let live = lock(&shared.live);
    let current = now();
    let online = |member: &str| live.presence.get(member).is_some_and(|presence| presence.seen.elapsed() < ONLINE);
    let desks = record
        .desks
        .iter()
        .filter(|desk| desk.person.as_ref() == Some(&person.id))
        .map(|desk| {
            let host = desk.host.as_ref().and_then(|id| record.members.iter().find(|member| &member.id == id));
            let invitation = live.invitations.get(&desk.id).filter(|(_, expires)| *expires > current);
            let mut shown = desks::desk_json(desk, &record.people, host.map(|member| member.name.as_str()), desk.host.as_deref().is_some_and(online), invitation.is_some());
            shown["spec"]["image"] = json!("");
            shown.as_object_mut().unwrap().remove("environmentId");
            if let Some((invitation, _)) = invitation.filter(|_| desk.state == DeskState::Ready) {
                shown["invitation"] = invitation.clone();
            }
            shown
        })
        .collect::<Vec<_>>();
    drop(live);
    let session_token = token();
    let expires = now() + 8 * 60 * 60;
    let mut live = lock(&shared.live);
    live.sessions.retain(|_, session| session.expires > now());
    if live.sessions.len() >= MAX_SESSIONS {
        // Recorded, even though this is a ceiling rather than a guessing path. Somebody who
        // proved who they are has just been turned away, and an admin seeing that in the record
        // is how they learn the hub is full before everybody tells them separately.
        (shared.events)("grid.person.refused", json!({"personId": person.id, "address": peer.to_string(), "full": true}));
        return Err(error(StatusCode::TOO_MANY_REQUESTS, "sessions_full", "Too many active sign-ins; wait for a session to expire"));
    }
    live.sessions.insert(digest("desk-session", &session_token), enterprise::Session { person: person.id.clone(), key_hash: person.key_hash.clone(), expires });
    (shared.events)("grid.person.signed_in", json!({"personId": person.id, "address": peer.to_string(), "sso": sso}));
    Ok(json!({"personId": person.id, "name": person.name, "username": person.username, "grid": {"id": record.id, "name": record.name}, "desks": desks, "sessionToken": session_token, "sessionExpiresAt": expires, "adminRole": person.admin_role, "mfa": person.totp.is_some()}))
}

const DISCOVERY_FOR: Duration = Duration::from_secs(24 * 60 * 60);
const KEYS_FOR: Duration = Duration::from_secs(60 * 60);
const KEYS_REFRESH_GAP: Duration = Duration::from_secs(60);

/// Whether the identity provider says it has not checked the token's email. Some providers send
/// it as text ("False") or as 0; every way of writing no is refused, as the Access hub does.
fn email_unverified(claims: &Value) -> bool {
    let verified = &claims["email_verified"];
    *verified == Value::Bool(false) || verified.as_str().is_some_and(|text| text.trim().eq_ignore_ascii_case("false") || text.trim() == "0") || verified.as_i64() == Some(0)
}

/// The identity provider's discovery document, fetched by the hub from the issuer itself and
/// kept for a day.
async fn sso_discovery(shared: &Arc<Shared>) -> Result<(crate::enterprise::Sso, Value), String> {
    let sso = lock(&shared.record).enterprise.sso.clone().ok_or("This grid does not sign people in through an identity provider")?;
    {
        let cache = lock(&shared.sso);
        if cache.issuer == sso.issuer {
            if let Some((discovery, at)) = &cache.discovery {
                if at.elapsed() < DISCOVERY_FOR {
                    return Ok((sso, discovery.clone()));
                }
            }
        }
    }
    let answer = crate::https::json("GET", &format!("{}/.well-known/openid-configuration", sso.issuer), None, &[], None, Duration::from_secs(20)).await?;
    if !answer.ok() {
        return Err(format!("The identity provider's discovery document could not be read ({})", answer.said()));
    }
    let discovery = answer.json();
    if !discovery["jwks_uri"].is_string() || !discovery["authorization_endpoint"].is_string() || !discovery["token_endpoint"].is_string() {
        return Err("The identity provider's discovery document names no endpoints".into());
    }
    let mut cache = lock(&shared.sso);
    if cache.issuer != sso.issuer {
        *cache = SsoCache { issuer: sso.issuer.clone(), ..SsoCache::default() };
    }
    cache.discovery = Some((discovery.clone(), Instant::now()));
    Ok((sso, discovery))
}

/// The provider's signing keys, kept for an hour; `refresh` fetches them again (a key the
/// token names may be new), at most once a minute.
async fn sso_keys(shared: &Arc<Shared>, discovery: &Value, refresh: bool) -> Result<Value, String> {
    {
        let cache = lock(&shared.sso);
        if let Some((keys, at)) = &cache.keys {
            let fresh = at.elapsed() < KEYS_FOR;
            let gap = cache.refreshed.is_some_and(|last| last.elapsed() < KEYS_REFRESH_GAP);
            if (fresh && !refresh) || (refresh && gap) {
                return Ok(keys.clone());
            }
        }
    }
    let uri = discovery["jwks_uri"].as_str().unwrap_or_default();
    let answer = crate::https::json("GET", uri, None, &[], None, Duration::from_secs(20)).await?;
    if !answer.ok() || !answer.json()["keys"].is_array() {
        return Err("The identity provider's signing keys could not be read".into());
    }
    let keys = answer.json();
    let mut cache = lock(&shared.sso);
    cache.keys = Some((keys.clone(), Instant::now()));
    cache.refreshed = Some(Instant::now());
    Ok(keys)
}

/// What a person's computer needs to start the sign-in: who the provider is and where to send
/// the browser. Public, like the salt; the client ID of a public app is not a secret.
async fn sso_config(shared: &Arc<Shared>) -> Response<Body> {
    match sso_discovery(shared).await {
        Ok((sso, discovery)) => json_response(StatusCode::OK, &json!({"issuer": sso.issuer, "clientId": sso.client_id, "authorizationEndpoint": discovery["authorization_endpoint"], "tokenEndpoint": discovery["token_endpoint"], "passwordless": sso.passwordless})),
        Err(message) if message.starts_with("This grid does not") => error(StatusCode::NOT_FOUND, "sso_off", message),
        Err(message) => error(StatusCode::BAD_GATEWAY, "sso_unreachable", message),
    }
}

/// A person's sign-in through the identity provider: their computer brings the ID token the
/// provider issued for it; the hub checks the signature against the provider's keys, the claims
/// against its setup, and the email against its people. The provider's own second factor counts.
async fn person_sso(shared: &Arc<Shared>, peer: IpAddr, request: Request<Incoming>) -> Response<Body> {
    if throttled(shared, peer) {
        return rate_limited(shared, peer, "", "Too many wrong sign-ins from this address; wait 10 minutes");
    }
    let body = match net::json_body(request.into_body(), 32 * 1024).await {
        Ok(body) => body,
        Err(message) => return error(StatusCode::BAD_REQUEST, "invalid_request_error", message),
    };
    let token = body["idToken"].as_str().unwrap_or_default().trim().to_owned();
    let nonce = body["nonce"].as_str().unwrap_or_default().trim().to_owned();
    if token.is_empty() || nonce.is_empty() {
        return error(StatusCode::BAD_REQUEST, "invalid_request_error", "The sign-in needs the provider's token and the nonce it was asked for");
    }
    let (sso, discovery) = match sso_discovery(shared).await {
        Ok(found) => found,
        Err(message) if message.starts_with("This grid does not") => return error(StatusCode::NOT_FOUND, "sso_off", message),
        Err(message) => return error(StatusCode::BAD_GATEWAY, "sso_unreachable", message),
    };
    let keys = match sso_keys(shared, &discovery, false).await {
        Ok(keys) => keys,
        Err(message) => return error(StatusCode::BAD_GATEWAY, "sso_unreachable", message),
    };
    let claims = match crate::jwt::verify(&token, &keys) {
        Ok(claims) => claims,
        Err(crate::jwt::Reject::UnknownKey(_)) => match sso_keys(shared, &discovery, true).await {
            Ok(keys) => match crate::jwt::verify(&token, &keys) {
                Ok(claims) => claims,
                Err(_) => {
                    refuse(shared, peer);
                    return error(StatusCode::FORBIDDEN, "token_rejected", "The identity provider's token was signed with a key it does not publish");
                }
            },
            Err(message) => return error(StatusCode::BAD_GATEWAY, "sso_unreachable", message),
        },
        Err(crate::jwt::Reject::Invalid(message)) => {
            refuse(shared, peer);
            return error(StatusCode::FORBIDDEN, "token_rejected", message);
        }
    };
    let issuer_ok = claims["iss"].as_str().is_some_and(|iss| iss.trim_end_matches('/') == sso.issuer);
    let audience_ok = match &claims["aud"] {
        Value::String(aud) => aud == &sso.client_id,
        Value::Array(list) => list.iter().any(|aud| aud == &sso.client_id),
        _ => false,
    };
    let current = now();
    let expiry_ok = claims["exp"].as_i64().is_some_and(|exp| exp > current - 60);
    let nonce_ok = claims["nonce"].as_str() == Some(nonce.as_str());
    if !(issuer_ok && audience_ok && expiry_ok && nonce_ok) {
        refuse(shared, peer);
        let why = if !issuer_ok { "its issuer is not the one this grid trusts" } else if !audience_ok { "it was issued for another app" } else if !expiry_ok { "it has expired" } else { "it was not issued for this sign-in" };
        return error(StatusCode::FORBIDDEN, "token_rejected", format!("The identity provider's token was refused: {why}"));
    }
    let identity = claims[&sso.username_claim].as_str().unwrap_or_default().trim().to_ascii_lowercase();
    if identity.is_empty() {
        refuse(shared, peer);
        return error(StatusCode::FORBIDDEN, "token_rejected", format!("The identity provider's token carries no {} claim", sso.username_claim));
    }
    // An address the provider itself says it has not checked proves nothing about who holds it.
    // Some providers will put whatever a person typed into `email` and say so in the same token.
    if sso.username_claim == "email" && email_unverified(&claims) {
        refuse(shared, peer);
        return error(StatusCode::FORBIDDEN, "token_rejected", format!("The identity provider has not verified {identity}"));
    }
    // The provider's own id for the account. An email is not an identity: companies hand a
    // leaver's address to whoever replaces them, and matching on the address alone makes the new
    // holder of an address the old holder of an account. The `sub` is never handed on.
    let Some(subject) = claims["sub"].as_str().map(str::trim).filter(|sub| !sub.is_empty() && sub.len() <= 255).map(str::to_owned) else {
        refuse(shared, peer);
        return error(StatusCode::FORBIDDEN, "token_rejected", "The identity provider's token names no account (no sub claim)");
    };
    let reply = {
        let mut record = lock(&shared.record);
        // The account somebody is tied to signs them in whatever address it carries now. Only
        // when nobody is tied to it does the address find them, and that first sign-in ties them.
        let found = record
            .people
            .iter()
            .position(|person| person.sso_subject.as_deref() == Some(subject.as_str()))
            .or_else(|| {
                record.people.iter().position(|person| person.email.as_deref().is_some_and(|email| email.trim().eq_ignore_ascii_case(&identity)) || person.username == identity)
            });
        let Some(index) = found else {
            drop(record);
            refuse(shared, peer);
            (shared.events)("grid.person.refused", json!({"address": peer.to_string(), "sso": true}));
            return error(StatusCode::FORBIDDEN, "no_person", format!("Nobody in this grid has the email {identity}; ask your admin to add it to your account"));
        };
        match record.people[index].sso_subject.as_deref() {
            Some(tied) if tied == subject => {}
            Some(_) => {
                let username = record.people[index].username.clone();
                drop(record);
                refuse(shared, peer);
                (shared.events)("grid.person.refused", json!({"address": peer.to_string(), "sso": true}));
                return error(
                    StatusCode::FORBIDDEN,
                    "no_person",
                    // The action named here is the one that unties (`enterprise::set_email`), and it
                    // unties on the same address too: a refusal must never send an admin to do
                    // something that does nothing.
                    format!("That token is for another account at the identity provider than the one {username} signs in with. If their account there really changed, ask an admin to set {username}'s email again in Sandbox Grid, even to the same address, then sign in again."),
                );
            }
            None => {
                record.people[index].sso_subject = Some(subject.clone());
                shared.dirty.store(true, Ordering::Relaxed);
            }
        }
        match issue_session(shared, &mut record, index, peer, true) {
            Ok(reply) => reply,
            Err(response) => return response,
        }
    };
    json_response(StatusCode::OK, &reply)
}

/// How many connections one computer may hold open for desk sessions.
const DESK_RELAYS_PER_HOST: usize = 4;
/// How long a held connection waits for someone to use it before the host opens another.
const RELAY_WAIT: Duration = Duration::from_secs(55);

/// Which computer is offering to carry desk sessions, or why it may not.
fn desk_relay_host(shared: &Arc<Shared>, request: &Request<Incoming>) -> Result<String, Response<Body>> {
    let Some(member) = member_of(shared, request) else {
        return Err(error(StatusCode::UNAUTHORIZED, "unauthorized", "Join the grid before carrying desk sessions"));
    };
    let live = lock(&shared.live);
    if live.desk_relays.get(&member).is_some_and(|held| held.len() >= DESK_RELAYS_PER_HOST) {
        return Err(error(StatusCode::TOO_MANY_REQUESTS, "relays_full", "This computer already holds enough connections for desk sessions"));
    }
    Ok(member)
}

/// Holds a host's connection open until a person opens one of its desks through it, then copies
/// bytes between the two. The hub reads nothing: the desk's own TLS runs inside.
fn hold_relay(shared: &Arc<Shared>, member: String, request: Request<Incoming>) -> Response<Body> {
    let (to_host, host_body) = mpsc::channel(relay::WINDOW);
    let (hand, handed) = oneshot::channel();
    {
        let mut live = lock(&shared.live);
        let held = live.desk_relays.entry(member.clone()).or_default();
        held.retain(|waiting| !waiting.hand.is_closed() && waiting.since.elapsed() < RELAY_WAIT * 2);
        held.push(WaitingRelay { since: Instant::now(), hand });
    }
    let shared = shared.clone();
    tokio::spawn(async move {
        let host = relay::Stream::new(request.into_body(), to_host);
        let joined = tokio::time::timeout(RELAY_WAIT, handed).await;
        {
            let mut live = lock(&shared.live);
            if let Some(held) = live.desk_relays.get_mut(&member) {
                held.retain(|waiting| !waiting.hand.is_closed());
                if held.is_empty() {
                    live.desk_relays.remove(&member);
                }
            }
        }
        let Ok(Ok((desk, person))) = joined else { return };
        // The host is told which desk this connection is for, then the two are joined and the
        // hub only copies bytes.
        let mut host = host;
        if tokio::io::AsyncWriteExt::write_all(&mut host, format!("{desk}\n").as_bytes()).await.is_err() {
            return;
        }
        (shared.events)("grid.desk.relayed", json!({"memberId": member, "deskId": desk}));
        let _ = tokio::time::timeout(relay::SESSION, relay::join(host, person)).await;
    });
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CACHE_CONTROL, "no-store")
        .body(relay::body(host_body))
        .expect("relay response")
}

/// A person's computer asks for one of their desks. The hub checks the desk is theirs and is
/// ready, then hands this connection to the computer that hosts it.
async fn open_relay(shared: &Arc<Shared>, request: Request<Incoming>) -> Response<Body> {
    let Some(token) = bearer(&request).filter(|token| is_token(token)).map(str::to_owned) else {
        return error(StatusCode::UNAUTHORIZED, "unauthorized", "Sign in to open your desk");
    };
    let desk = request.uri().query().and_then(|query| query.split('&').find_map(|pair| pair.strip_prefix("desk="))).unwrap_or_default().to_owned();
    let hash = digest("desk-session", &token);
    let host = {
        let mut live = lock(&shared.live);
        let Some(session) = live.sessions.get(&hash).filter(|session| session.expires > now()).map(|session| session.person.clone()) else {
            return error(StatusCode::UNAUTHORIZED, "unauthorized", "Sign in again; this session expired or was revoked");
        };
        let record = lock(&shared.record);
        // The person must still own this desk, the desk must be ready, and its computer must be
        // the one holding the connection. None of that is taken from the request.
        let Some(found) = record.desks.iter().find(|entry| entry.id == desk && entry.person.as_deref() == Some(session.as_str()) && entry.state == DeskState::Ready) else {
            return error(StatusCode::NOT_FOUND, "desk_unavailable", "This desk is not ready, or is not yours");
        };
        if !record.people.iter().any(|person| person.id == session) {
            return error(StatusCode::UNAUTHORIZED, "unauthorized", "This account was changed; sign in again");
        }
        let Some(host) = found.host.clone() else {
            return error(StatusCode::SERVICE_UNAVAILABLE, "desk_unavailable", "This desk has no computer right now");
        };
        if !live.presence.get(&host).is_some_and(|presence| presence.seen.elapsed() < ONLINE) {
            return error(StatusCode::SERVICE_UNAVAILABLE, "host_offline", "The computer that hosts this desk is not answering");
        }
        drop(record);
        let Some(waiting) = live.desk_relays.get_mut(&host).and_then(|held| held.pop()) else {
            return error(StatusCode::SERVICE_UNAVAILABLE, "relay_busy", "The computer that hosts this desk is not ready to carry a session; try again in a moment");
        };
        (host, waiting)
    };
    let (host_id, waiting) = host;
    let (to_person, person_body) = mpsc::channel(relay::WINDOW);
    let person = relay::Stream::new(request.into_body(), to_person);
    if waiting.hand.send((desk.clone(), person)).is_err() {
        return error(StatusCode::SERVICE_UNAVAILABLE, "relay_busy", "That connection closed before the desk could be opened; try again");
    }
    let _ = host_id;
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CACHE_CONTROL, "no-store")
        .body(relay::body(person_body))
        .expect("relay response")
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
        // Checked again on every wake: a computer removed, left out or reassigned while its poll
        // waits is told so, and gets only its assigned model's work.
        let serving = match assigned_models(shared, member, &models) {
            Ok(serving) => serving,
            Err(response) => return response,
        };
        if let Some(offer) = take(shared, member, &serving) {
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

/// Which of the models a computer offers it may actually serve. A computer with a plan serves
/// that plan's model and no other; one without a plan may serve a model it runs on its own, but
/// never a model the admin organised through a plan. A computer left out, no longer capable or
/// no longer a member serves nothing.
fn assigned_models(shared: &Shared, member: &str, offered: &[String]) -> Result<Vec<String>, Response<Body>> {
    let record = lock(&shared.record);
    let Some(entry) = record.members.iter().find(|entry| entry.id == member) else {
        return Err(error(StatusCode::UNAUTHORIZED, "member_removed", "This computer is no longer a member of the grid"));
    };
    if !entry.eligible() {
        return Ok(Vec::new());
    }
    match entry.plan.as_ref().and_then(|id| record.plans.iter().find(|plan| &plan.id == id)).map(|plan| model_key(&plan.model)) {
        Some(assigned) => Ok(offered.iter().filter(|model| **model == assigned).cloned().collect()),
        None => {
            let planned: Vec<String> = record.plans.iter().map(|plan| model_key(&plan.model)).collect();
            Ok(offered.iter().filter(|model| !planned.contains(model)).cloned().collect())
        }
    }
}

fn take(shared: &Shared, member: &str, models: &[String]) -> Option<Value> {
    if models.is_empty() {
        return None;
    }
    let mut live = lock(&shared.live);
    live.queue.retain(|job| !job.reply.is_closed());
    let index = live.queue.iter().position(|job| {
        models.contains(&job.model) && !job.skip.iter().any(|(skipped, at)| skipped == member && at.elapsed() < SKIP)
    })?;
    let job = live.queue.remove(index)?;
    if let Some(taken) = &job.taken {
        *lock(taken) = Some(member.to_owned());
    }
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
        let job = live.running.remove(job).expect("checked above").job;
        *live.relaying.entry(job.key.clone()).or_default() += 1;
        job
    };
    // Whatever happens below, the reply stops counting against its key once this returns.
    struct Relaying<'a>(&'a Shared, String);
    impl Drop for Relaying<'_> {
        fn drop(&mut self) {
            let mut live = lock(&self.0.live);
            if let Some(count) = live.relaying.get_mut(&self.1) {
                *count -= 1;
                if *count == 0 {
                    live.relaying.remove(&self.1);
                }
            }
        }
    }
    let _relaying = Relaying(shared, job.key.clone());
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
    // One generation window for the whole reply, however many frames it comes in; an app that
    // stops reading gets a bounded wait too.
    let finish_by = tokio::time::Instant::now() + GENERATION + Duration::from_secs(60);
    loop {
        match tokio::time::timeout_at(finish_by.min(tokio::time::Instant::now() + GENERATION), incoming.frame()).await {
            Ok(Some(Ok(frame))) => {
                let Ok(data) = frame.into_data() else { continue };
                total += data.len();
                if total > RESPONSE_LIMIT {
                    let _ = sender.send(Err(std::io::Error::other("The reply exceeded 16 MiB"))).await;
                    break;
                }
                usage.push(&data);
                match tokio::time::timeout(RELAY_STALL, sender.send(Ok(Frame::data(data)))).await {
                    Ok(Ok(())) => {}
                    _ => break,
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
        // The same cleanup as an admin's removal: plans that picked this computer forget it.
        if remove_member_record(&mut record, member).is_some() {
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
    let (owner, harnesses) = {
        let record = lock(&shared.record);
        (record.name.clone(), record.harnesses.clone())
    };
    let live = lock(&shared.live);
    let mut data: Vec<Value> = models(&live)
        .into_iter()
        .map(|model| json!({"id": model["id"], "object": "model", "created": 0, "owned_by": owner, "computers": model["computers"], "ready": model["ready"]}))
        .collect();
    for harness in harnesses {
        let ready = harness.models().iter().all(|model| matches!(availability(&live, model), Availability::Ready));
        data.push(json!({"id": harness.model(), "object": "model", "created": harness.created_at, "owned_by": owner, "ready": ready, "swarm": {"strategy": harness.strategy, "computers": harness.computers}}));
    }
    json_response(StatusCode::OK, &json!({"object": "list", "data": data}))
}

async fn chat(shared: &Arc<Shared>, request: Request<Incoming>) -> Response<Body> {
    let Some(key) = key_of(shared, &request) else {
        return error(StatusCode::UNAUTHORIZED, "invalid_api_key", "Use an API key created with `yougori grid add-key`");
    };
    let mut body = match net::json_body(request.into_body(), REQUEST_LIMIT).await {
        Ok(Value::Object(body)) => body,
        Ok(_) => return error(StatusCode::BAD_REQUEST, "invalid_request_error", "Send a JSON chat completion request"),
        Err(message) => return error(StatusCode::BAD_REQUEST, "invalid_request_error", message),
    };
    // The key is checked again now that the whole request is in: one revoked while the body was
    // still arriving does not get its work queued.
    if !key_exists(shared, &key) {
        return error(StatusCode::UNAUTHORIZED, "invalid_api_key", "This API key was revoked");
    }
    // Each member's model server knows its own model name, so the field is dropped here.
    let model = match body.remove("model") {
        Some(Value::String(model)) if !model.trim().is_empty() && model.len() <= 200 => model_key(&model),
        _ => return error(StatusCode::BAD_REQUEST, "invalid_request_error", "Choose a model; GET /v1/models lists this grid's models"),
    };
    if !body.get("messages").is_some_and(Value::is_array) {
        return error(StatusCode::BAD_REQUEST, "invalid_request_error", "messages must be a list");
    }
    if let Some(name) = model.strip_prefix(harness::PREFIX) {
        return swarm(shared, key, name, body).await;
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
        if live.key_load(&key) >= MAX_PER_KEY {
            return error(StatusCode::TOO_MANY_REQUESTS, "rate_limited", format!("This API key already has {MAX_PER_KEY} requests waiting, running or streaming back"));
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
            taken: None,
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

/// A harness's requests go on the grid's own queue, under the calling app's key, so the computers
/// running each model share them out and the key's usage counts the whole team's work.
struct HubAsk {
    shared: Arc<Shared>,
    key: String,
}

impl harness::Ask for HubAsk {
    fn ask<'a>(&'a self, model: &'a str, request: Value) -> BoxFuture<'a, Result<harness::Answer, String>> {
        Box::pin(async move {
            let model = model_key(model);
            let (reply, answer) = oneshot::channel();
            let taken = Arc::new(Mutex::new(None));
            // A team's request must reach a computer whole: computers read offers up to 1 MiB.
            if request.to_string().len() > JOB_LIMIT {
                return Err(format!("The request for {model} is too large for a computer to receive ({} KiB); the team's results do not fit one call", request.to_string().len() / 1024));
            }
            if self.key != "admin" && !key_exists(&self.shared, &self.key) {
                return Err("This API key was revoked".into());
            }
            {
                let mut live = lock(&self.shared.live);
                match availability(&live, &model) {
                    Availability::Unknown => return Err(format!("No computer in this grid runs {model}")),
                    Availability::Unavailable(reason) => return Err(reason),
                    Availability::Ready => {}
                }
                if live.queue.len() >= MAX_QUEUE {
                    return Err("The grid's queue is full".into());
                }
                // Each of the team's calls takes one of the key's places, like a direct request.
                if self.key != "admin" && live.key_load(&self.key) >= MAX_PER_KEY {
                    return Err(format!("This API key already has {MAX_PER_KEY} requests waiting, running or streaming back"));
                }
                live.queue.push_back(Job {
                    id: format!("job-{}", &token()[..24]),
                    model: model.clone(),
                    request,
                    key: self.key.clone(),
                    created: Instant::now(),
                    attempts: 0,
                    skip: Vec::new(),
                    reply,
                    taken: Some(taken.clone()),
                });
            }
            self.shared.work.notify_waiters();
            let response = match tokio::time::timeout(PICKUP + GENERATION + Duration::from_secs(60), answer).await {
                Ok(Ok(response)) => response,
                _ => return Err("The grid did not answer in time".into()),
            };
            let status = response.status();
            let bytes = tokio::time::timeout(GENERATION, response.into_body().collect())
                .await
                .map_err(|_| format!("{model} did not finish its reply in time"))?
                .map_err(|error| error.to_string())?
                .to_bytes();
            let value: Value = serde_json::from_slice(&bytes).map_err(|_| format!("{model} sent a reply that is not JSON"))?;
            if !status.is_success() {
                return Err(value["error"]["message"].as_str().map(str::to_owned).unwrap_or_else(|| format!("{model} answered {status}")));
            }
            let member = lock(&taken).clone();
            let computer = member.map(|id| lock(&self.shared.record).members.iter().find(|entry| entry.id == id).map(|entry| entry.name.clone()).unwrap_or(id));
            harness::Answer::from_completion(&value, computer)
        })
    }
}

/// An app called `swarm/NAME`: the harness runs its team and answers as one chat completion.
/// A streaming caller gets keep-alive comments while the team works, then the answer.
async fn swarm(shared: &Arc<Shared>, key: String, name: &str, body: serde_json::Map<String, Value>) -> Response<Body> {
    let Some(found) = lock(&shared.record).harnesses.iter().find(|entry| entry.name == name).cloned() else {
        return error(StatusCode::NOT_FOUND, "model_not_found", "No swarm harness has that name; GET /v1/models lists this grid's models");
    };
    // What a team cannot honour is refused rather than silently dropped: tools and structured
    // output are not forwarded to any of its models.
    if body.get("tools").is_some_and(|tools| tools.as_array().is_some_and(|list| !list.is_empty())) || body.get("tool_choice").is_some_and(|choice| !choice.is_null()) {
        return error(StatusCode::BAD_REQUEST, "invalid_request_error", "A swarm harness does not support tools; call one of the grid's models directly for tool use");
    }
    if body.get("response_format").is_some_and(|format| format["type"].as_str().is_some_and(|kind| kind != "text")) {
        return error(StatusCode::BAD_REQUEST, "invalid_request_error", "A swarm harness answers in plain text; response_format is not supported");
    }
    // The caller's output cap applies to the final answer; the team's inner steps keep their own.
    let final_tokens = body.get("max_tokens").or_else(|| body.get("max_completion_tokens")).and_then(Value::as_u64).map(|tokens| tokens.clamp(1, 32_768) as u32);
    {
        let live = lock(&shared.live);
        if live.key_load(&key) >= MAX_PER_KEY {
            return error(StatusCode::TOO_MANY_REQUESTS, "rate_limited", format!("This API key already has {MAX_PER_KEY} requests waiting, running or streaming back"));
        }
    }
    if let Some(entry) = lock(&shared.record).keys.iter_mut().find(|entry| entry.id == key) {
        entry.requests += 1;
        entry.last_used_at = Some(now());
    }
    shared.dirty.store(true, Ordering::Relaxed);
    let messages: Vec<Value> = body.get("messages").and_then(Value::as_array).cloned().unwrap_or_default();
    let asker = HubAsk { shared: shared.clone(), key };
    if body.get("stream") != Some(&Value::Bool(true)) {
        return match harness::run_with(&found, &asker, &messages, final_tokens).await {
            Ok(run) => json_response(StatusCode::OK, &completion(&found, &run)),
            Err(message) => error(StatusCode::SERVICE_UNAVAILABLE, "swarm_failed", message),
        };
    }
    let (sender, receiver) = mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(8);
    tokio::spawn(async move {
        let work = harness::run_with(&found, &asker, &messages, final_tokens);
        tokio::pin!(work);
        let result = loop {
            tokio::select! {
                result = &mut work => break result,
                _ = tokio::time::sleep(SWARM_KEEPALIVE) => {
                    if sender.send(Ok(Frame::data(Bytes::from_static(b": the swarm is working\n\n")))).await.is_err() {
                        return;
                    }
                }
            }
        };
        let events = match result {
            Ok(run) => {
                let done = completion(&found, &run);
                let mut chunk = json!({"id": done["id"], "object": "chat.completion.chunk", "created": done["created"], "model": done["model"]});
                chunk["choices"] = json!([{"index": 0, "delta": {"role": "assistant", "content": run.answer}, "finish_reason": null}]);
                let mut last = chunk.clone();
                last["choices"] = json!([{"index": 0, "delta": {}, "finish_reason": "stop"}]);
                last["usage"] = done["usage"].clone();
                last["yougori_swarm"] = done["yougori_swarm"].clone();
                format!("data: {chunk}\n\ndata: {last}\n\ndata: [DONE]\n\n")
            }
            Err(message) => format!("data: {}\n\ndata: [DONE]\n\n", json!({"error": {"message": message, "type": "swarm_failed"}})),
        };
        let _ = sender.send(Ok(Frame::data(Bytes::from(events)))).await;
    });
    let stream = futures_util::stream::unfold(receiver, |mut receiver| async move { receiver.recv().await.map(|item| (item, receiver)) });
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-store")
        .body(StreamBody::new(stream).boxed_unsync())
        .expect("swarm stream")
}

/// A harness's answer as an OpenAI chat completion; `yougori_swarm` shows who did what.
fn completion(harness: &Harness, run: &harness::Run) -> Value {
    json!({
        "id": format!("chatcmpl-swarm-{}", &token()[..16]), "object": "chat.completion", "created": now(), "model": harness.model(),
        "choices": [{"index": 0, "message": {"role": "assistant", "content": run.answer}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": run.prompt_tokens, "completion_tokens": run.completion_tokens, "total_tokens": run.prompt_tokens + run.completion_tokens},
        "yougori_swarm": run.trace,
    })
}

/// Runs harnesses for the admin, outside whatever lock found the hub.
#[derive(Clone)]
pub struct Swarm {
    shared: Arc<Shared>,
}

impl Swarm {
    /// Runs the harness named `name` (or with that ID) on `messages`, as the admin.
    pub async fn run(&self, name: &str, messages: &[Value]) -> Result<Value, String> {
        let wanted = name.trim().to_ascii_lowercase();
        let wanted = wanted.trim_start_matches(harness::PREFIX);
        let found = lock(&self.shared.record).harnesses.iter().find(|entry| entry.name == wanted || entry.id == wanted).cloned().ok_or("No swarm harness has that name")?;
        let run = harness::run(&found, &HubAsk { shared: self.shared.clone(), key: "admin".into() }, messages).await?;
        Ok(json!({"model": found.model(), "answer": run.answer, "trace": run.trace, "usage": {"promptTokens": run.prompt_tokens, "completionTokens": run.completion_tokens}}))
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
            // A code is good for a step either side of now, so once a step is two behind, nothing
            // matching it can be offered again and remembering it is only a row taking up room.
            let oldest = now().div_euclid(crate::totp::STEP) - 2;
            live.used_codes.retain(|_, step| *step >= oldest);
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
            save_if_dirty(&shared);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// PROVES that an email the identity provider marks unverified is refused however the
    /// provider writes "no".
    ///
    /// Only `false` and "false" were refused, so a provider that wrote the claim as "False" or
    /// as 0 signed in whoever had typed that address, where the Access hub refused every one of
    /// these. A claim that is absent is the provider saying nothing either way, and both hubs
    /// leave that to the account tie (`sub`).
    #[test]
    fn an_unverified_email_is_refused_however_the_provider_writes_no() {
        for no in [json!(false), json!("false"), json!("False"), json!(" FALSE "), json!("0"), json!(0)] {
            assert!(email_unverified(&json!({"email_verified": no})), "{no} says the provider has not checked the address");
        }
        for yes in [json!(true), json!("true"), json!("True"), json!(1)] {
            assert!(!email_unverified(&json!({"email_verified": yes})), "{yes} says it has");
        }
        assert!(!email_unverified(&json!({})), "no claim is not a no");
    }

    /// PROVES that setting a person's email again unties them from their provider account, the
    /// same address included, which is what the sign-in refusal tells an admin to do.
    ///
    /// Untying happened only on a new address. When an account is rebuilt at the provider the
    /// address usually stays the same, so the admin did exactly what the refusal said and the
    /// person stayed locked out, with nothing saying why.
    #[test]
    fn setting_an_email_again_unties_the_provider_account_even_when_it_is_the_same() {
        let mut person = desks::new_person("ada".into(), "Ada".into(), "salt".into(), "key");
        person.email = Some("ada@acme.example".into());
        person.sso_subject = Some("sub-old".into());
        enterprise::set_email(&mut person, "ada@acme.example".into());
        assert_eq!((person.email.as_deref(), person.sso_subject.as_deref()), (Some("ada@acme.example"), None), "the same address unties too");
        person.sso_subject = Some("sub-new".into());
        enterprise::set_email(&mut person, "ada.lovelace@acme.example".into());
        assert_eq!((person.email.as_deref(), person.sso_subject.as_deref()), (Some("ada.lovelace@acme.example"), None));
        enterprise::set_email(&mut person, String::new());
        assert_eq!(person.email, None, "an empty address clears it");
    }

    /// PROVES that a two-step code signs a person in once.
    ///
    /// A code is good for a step either side of now, which is a minute in which anybody who saw
    /// it — over a shoulder, in a screen share, on an unlocked phone — can use it themselves.
    /// Checking the code cannot tell the second use from the first, because both are the same
    /// right answer; only remembering which step signed them in can.
    #[test]
    fn a_two_step_code_works_once_and_not_again() {
        let mut used = HashMap::new();
        assert!(fresh_code(&mut used, "person-1", 100), "the first use of a code is the person signing in");
        assert!(!fresh_code(&mut used, "person-1", 100), "the same code again is not");
        assert!(!fresh_code(&mut used, "person-1", 99), "nor is the code from the step before, which is still inside the leeway");
        assert!(fresh_code(&mut used, "person-1", 101), "the next code is theirs to use");

        // One person's code says nothing about another's, and each is remembered on their own.
        assert!(fresh_code(&mut used, "person-2", 100), "a code at a step somebody else used is still this person's first");
        assert!(!fresh_code(&mut used, "person-2", 100));
        assert_eq!(used.get("person-1"), Some(&101));

        // One memory, not one per door: a code that has signed somebody in cannot then move their
        // two-step to somebody else's phone, which is one code doing both inside a minute.
        assert!(!fresh_code(&mut used, "person-1", 101));
    }

    fn presence(models: &[(&str, &str)], online: bool) -> Presence {
        Presence {
            seen: if online { Instant::now() } else { Instant::now() - ONLINE - Duration::from_secs(1) },
            address: "10.0.0.9".parse().unwrap(),
            version: String::new(),
            models: models.iter().map(|(model, state)| ModelReport { model: (*model).into(), state: (*state).into(), reason: String::new(), quant: None, gpu: None, progress: None }).collect(), capacity: None, unreadable_reports: 0,
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
            tunnel_port: None,
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
                    share: None,
                    plan: None,
                    assigned_at: None,
                    jobs: 0,
                    excluded: false,
                })
                .collect(),
            keys: Vec::new(),
            harnesses: Vec::new(), desks: Vec::new(), people: Vec::new(), enterprise: Default::default(), closing: None,
        }
    }
    fn plan(id: &str, percent: u8) -> Plan {
        Plan { id: id.into(), model: "Acme/Chat".into(), quant: None, percent, policy: IdlePolicy::default(), created_at: 0, target: Target::All }
    }
    fn plans_of(record: &Record) -> Vec<Option<&str>> {
        record.members.iter().map(|member| member.plan.as_deref()).collect()
    }
    /// PROVES that a desk being packed when its computer leaves the grid is not left packing for
    /// ever.
    ///
    /// Reclaiming looked only at `host`, and a desk mid-hand-off has no host: the computer giving
    /// it up is in `moving_from` while it packs the data. So the one desk whose computer vanished
    /// at the worst possible moment was the one desk reclaiming skipped. It stayed `Moving`,
    /// waiting for a report from a computer that is gone, and nothing else reaches it — Retry is
    /// for failed desks, and placement only looks at a packed desk that has a parcel.
    ///
    /// What happens next depends on whether the data got out. Packed and parked, it only needs a
    /// computer. Still on the computer that left, it is gone with it, and the desk is rebuilt or
    /// given up on exactly as any other desk on a departed computer is.
    /// PROVES that a connector task does not stay running for ever because the hub stopped under
    /// it, which would mean that person is never assigned or taken back at that provider again.
    ///
    /// A task goes to running when it is handed out, and only the computer running it moves it
    /// off. A hub that stops in between leaves one that nobody is running and nothing will
    /// finish; queueing treats pending and running alike as already queued, so every later
    /// attempt to assign or revoke that person at that connection is swallowed as a duplicate.
    #[test]
    fn a_connector_task_running_when_the_hub_stopped_is_picked_up_again() {
        let task = |state: &str, attempts: u32| crate::enterprise::Provisioning {
            id: format!("task-{state}-{attempts}"),
            connection_id: "connection-1".into(),
            want: "assign".into(),
            person_id: Some("person-1".into()),
            person_name: "Ada".into(),
            email: "ada@acme.example".into(),
            state: state.into(),
            note: String::new(),
            attempts,
            at: 0,
            finished_at: None,
        };
        let mut grid = record(&[true]);
        grid.enterprise.provisioning = vec![task("running", 1), task("pending", 0), task("done", 1), task("failed", 2), task("running", RESUMES)];

        assert!(resume_interrupted(&mut grid));
        let state = |index: usize| grid.enterprise.provisioning[index].state.clone();
        assert_eq!(state(0), "pending", "it still needs doing, and a connector is written to be asked twice");
        assert!(grid.enterprise.provisioning[0].note.contains("stopped while this was running"));
        assert_eq!(grid.enterprise.provisioning[0].finished_at, None, "it has not finished; it is waiting");
        assert_eq!((state(1), state(2), state(3)), ("pending".to_owned(), "done".to_owned(), "failed".to_owned()), "nothing else is touched");
        assert_eq!(state(4), "failed", "one interrupted this often is given up on rather than stopping every start");
        assert!(grid.enterprise.provisioning[4].finished_at.is_some());

        assert!(!resume_interrupted(&mut grid), "starting again with nothing running changes nothing");
    }

    /// PROVES that a desk report this hub cannot read costs only itself.
    ///
    /// A computer newer than the hub can report a parcel in a store the hub does not know. Read as
    /// one list, that report dropped every report beside it: the desk that finished building next
    /// to it, with its person's invitation, never arrived, and sat building with nobody told.
    #[test]
    fn a_desk_report_this_hub_cannot_read_costs_only_itself() {
        use crate::desks::{DeskKind, DeskSpec};
        let spec = DeskSpec::checked(DeskKind::Container, 2.0, 8.0, 40.0, false, "").unwrap();
        let mut desk = desks::new_desk("Ada's desk".into(), spec, None);
        desk.host = Some("m0".into());
        desk.state = DeskState::Building;
        let batch = json!([
            {"id": "desk-moving", "generation": 1, "state": "parked", "parcel": {"store": "azure", "key": "k", "bytes": 1, "sha256": "a", "at": 0}},
            {"id": desk.id, "generation": desk.generation, "state": "ready", "environmentId": "env-desk-1", "invitation": {"token": "t"}, "invitationExpiresAt": 1},
            {"id": 7, "state": "ready"},
        ]);
        let (reports, unreadable) = reports_in(&batch);
        assert_eq!((reports.len(), unreadable), (1, 2), "the two it cannot read are counted, not the one it can");
        assert_eq!(reports[0].invitation, Some(json!({"token": "t"})), "the invitation beside them arrives");
        assert!(desks::apply_report(&mut desk, "m0", &reports[0]), "and the report is applied");
        assert_eq!(desk.state, DeskState::Ready);

        // A check-in that reports nothing, or something that is not a list, has nothing to apply.
        for nothing in [Value::Null, json!({"id": desk.id}), json!([])] {
            assert_eq!(reports_in(&nothing), (Vec::new(), 0));
        }
        // No more than a computer can host are read, whatever it sends.
        let many = Value::Array(vec![json!({"id": "desk-1", "state": "ready"}); desks::MAX_DESKS + 5]);
        assert_eq!(reports_in(&many).0.len(), desks::MAX_DESKS);
    }

    #[test]
    fn a_desk_being_packed_when_its_computer_leaves_does_not_pack_for_ever() {
        use crate::desks::{DeskKind, DeskSpec, Parcel};
        let spec = DeskSpec::checked(DeskKind::Container, 2.0, 8.0, 40.0, false, "").unwrap();
        let packing = |parcel: Option<Parcel>, attempts: u8| {
            let mut desk = desks::new_desk("Ada's desk".into(), spec.clone(), None);
            desk.state = DeskState::Moving;
            desk.moving_from = Some("m0".into());
            desk.host = None;
            desk.parcel = parcel;
            desk.attempts = attempts;
            desk
        };
        let parked = Parcel { store: Default::default(), key: "desk-1".into(), bytes: 1_024, sha256: "a".repeat(64), at: 0 };

        // Its computer is still here, so there is nothing to reclaim: it is simply still packing.
        let mut grid = record(&[true]);
        grid.desks.push(packing(None, 0));
        assert!(!reclaim_desks(&mut grid), "a computer that is still in the grid is still packing");
        assert_eq!(grid.desks[0].state, DeskState::Moving);

        // Its computer leaves before the data is packed. The data went with it, so the desk is
        // rebuilt, the same as any desk whose computer left.
        grid.members.clear();
        assert!(reclaim_desks(&mut grid));
        assert_eq!(grid.desks[0].state, DeskState::Planned);
        assert_eq!(grid.desks[0].moving_from, None, "nothing is waiting on a computer that is gone");
        assert!(grid.desks[0].host.is_none() && grid.desks[0].environment_id.is_none());

        // The same, by a desk that has already failed as often as it may: it is given up on
        // rather than queued to fail again.
        let mut grid = record(&[true]);
        grid.desks.push(packing(None, desks::MAX_ATTEMPTS));
        grid.members.clear();
        assert!(reclaim_desks(&mut grid));
        assert_eq!(grid.desks[0].state, DeskState::Failed);
        assert_eq!(grid.desks[0].moving_from, None);

        // And a desk whose data was packed and parked before its computer left needs a computer,
        // not a rebuild: the parcel is still there and the desk is still the person's.
        let mut grid = record(&[true]);
        grid.desks.push(packing(Some(parked.clone()), 0));
        grid.members.clear();
        assert!(reclaim_desks(&mut grid));
        assert_eq!(grid.desks[0].state, DeskState::Moving, "packed and waiting, which is what placement looks for");
        assert_eq!(grid.desks[0].moving_from, None);
        assert_eq!(grid.desks[0].parcel.as_ref().map(|parcel| parcel.key.as_str()), Some("desk-1"), "its data is where it was put");
        assert!(!reclaim_desks(&mut grid), "and once reclaimed there is nothing left to do");
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
    fn picked(id: &str, members: &[&str]) -> Plan {
        Plan { target: Target::Computers { members: members.iter().map(|member| member.to_string()).collect() }, ..plan(id, 100) }
    }
    #[test]
    fn picked_computers_run_their_plan_whatever_the_shares_ask() {
        let mut grid = record(&[true, true, true, false]);
        grid.plans.push(plan("all", 100));
        reconcile(&mut grid);
        assert_eq!(plans_of(&grid), [Some("all"), Some("all"), Some("all"), None]);
        // A pick moves the computer even though the share plan already held it.
        grid.plans.push(picked("pick", &["m1", "m3"]));
        assert!(reconcile(&mut grid));
        assert_eq!(plans_of(&grid), [Some("all"), Some("pick"), Some("all"), None], "m3 cannot run models, so the pick gives it nothing");
        assert_eq!(assignment(&grid, "m1")["planId"], "pick");
        assert!(!reconcile(&mut grid), "nothing changes once settled");
        // Dropping the pick hands the computer back to the share plans.
        grid.plans.retain(|plan| plan.id != "pick");
        reconcile(&mut grid);
        assert_eq!(plans_of(&grid), [Some("all"), Some("all"), Some("all"), None]);
    }
    #[test]
    fn a_share_of_the_remaining_computers_counts_only_unpicked_ones() {
        let mut grid = record(&[true, true, true, true, true]);
        grid.plans.push(picked("pick", &["m0"]));
        grid.plans.push(Plan { target: Target::Remaining, ..plan("rest", 50) });
        reconcile(&mut grid);
        // Half of the 4 unpicked computers is 2; half of all 5 would have been 3.
        assert_eq!(plans_of(&grid), [Some("pick"), Some("rest"), Some("rest"), None, None]);
        grid.plans.push(Plan { target: Target::All, ..plan("all", 40) });
        reconcile(&mut grid);
        assert_eq!(plans_of(&grid), [Some("pick"), Some("rest"), Some("rest"), Some("all"), Some("all")], "40% of all 5 is 2, from the free ones");
    }
    #[test]
    fn picking_a_computer_again_moves_it_and_joins_the_same_model() {
        let mut grid = record(&[true, true, true]);
        let first = place(&mut grid, "Acme/Chat", None, 0, IdlePolicy::default(), Target::Computers { members: vec!["m0".into(), "m1".into()] }).unwrap();
        // m1 gets another model: it leaves the first plan, which keeps m0.
        let second = place(&mut grid, "Acme/Code", None, 0, IdlePolicy::default(), Target::Computers { members: vec!["m1".into()] }).unwrap();
        assert_eq!(grid.plans.iter().map(|plan| plan.target.picked().to_vec()).collect::<Vec<_>>(), [vec!["m0".to_owned()], vec!["m1".to_owned()]]);
        // Moving m0 too leaves the first plan empty, so it is removed.
        place(&mut grid, "Acme/Code", None, 0, IdlePolicy::default(), Target::Computers { members: vec!["m0".into()] }).unwrap();
        assert!(!grid.plans.iter().any(|plan| plan.id == first.id), "an emptied pick plan is removed");
        assert_eq!(grid.plans.len(), 1, "the same model picked again joins its plan");
        assert_eq!(grid.plans[0].id, second.id);
        assert_eq!(grid.plans[0].target.picked(), ["m1".to_owned(), "m0".to_owned()]);
        reconcile(&mut grid);
        assert_eq!(plans_of(&grid), [Some(second.id.as_str()), Some(second.id.as_str()), None]);
        assert!(place(&mut grid, "Acme/Chat", None, 0, IdlePolicy::default(), Target::Computers { members: vec!["nobody".into()] }).unwrap_err().contains("nobody"));
        assert!(place(&mut grid, "Acme/Chat", None, 0, IdlePolicy::default(), Target::Computers { members: Vec::new() }).is_err());
        assert!(place(&mut grid, "Acme/Chat", None, 0, IdlePolicy::default(), Target::Remaining).unwrap_err().contains("percent"), "a share still needs its percent");
    }
    #[test]
    fn plans_saved_before_targets_run_on_a_share_of_all_computers() {
        let saved: Plan = serde_json::from_value(json!({"id": "p", "model": "Acme/Chat", "percent": 50, "policy": IdlePolicy::default(), "createdAt": 0})).unwrap();
        assert_eq!(saved.target, Target::All);
        assert_eq!(serde_json::to_value(Target::Computers { members: vec!["m0".into()] }).unwrap(), json!({"kind": "computers", "members": ["m0"]}));
    }
    #[test]
    fn a_computer_left_out_gets_no_model_until_it_is_brought_back() {
        let mut grid = record(&[true, true, true, true]);
        grid.plans.push(plan("all", 50));
        reconcile(&mut grid);
        assert_eq!(plans_of(&grid), [Some("all"), Some("all"), None, None]);
        grid.members[0].excluded = true;
        assert!(reconcile(&mut grid));
        // Half of the 3 computers still taking part is 2: m0 drops its model and m2 takes it.
        assert_eq!(plans_of(&grid), [None, Some("all"), Some("all"), None]);
        assert_eq!(assignment(&grid, "m0"), Value::Null, "a computer left out is told to run nothing");
        grid.plans.push(picked("pick", &["m0"]));
        reconcile(&mut grid);
        assert_eq!(plans_of(&grid)[0], None, "picking does not bring a computer back");
        grid.members[0].excluded = false;
        reconcile(&mut grid);
        assert_eq!(plans_of(&grid)[0], Some("pick"), "brought back, its pick applies again");
    }
    #[test]
    fn reports_carry_progress_and_older_reports_still_read() {
        let older: ModelReport = serde_json::from_value(json!({"model": "Acme/Chat", "state": "loading"})).unwrap();
        assert_eq!(older.progress, None);
        let report = ModelReport { model: "Acme/Chat".into(), state: "loading".into(), reason: String::new(), quant: None, gpu: None, progress: Some(Progress { phase: "downloading".into(), done: 3, total: 10, rate: 2 }) };
        assert_eq!(serde_json::to_value(&report).unwrap()["progress"], json!({"phase": "downloading", "done": 3, "total": 10, "rate": 2}));
        let member: MemberRecord = serde_json::from_value(json!({"id": "m", "name": "PC", "platform": "linux", "tokenHash": "", "joinedAt": 0})).unwrap();
        assert!(!member.excluded, "computers saved before this setting still take part");
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
        assert!(create(&path, "Acme", "8.8.8.8".parse().unwrap(), 7460, None, None, "salt").unwrap_err().contains("private"));
        assert!(create(&path, "Acme", "10.0.0.5".parse().unwrap(), 80, None, None, "salt").is_err());
        assert!(create(&path, "Acme", "10.0.0.5".parse().unwrap(), 7460, Some("bad host"), None, "salt").is_err());
        assert!(create(&path, "Acme", "10.0.0.5".parse().unwrap(), 7460, None, Some(7460), "salt").unwrap_err().contains("tunnel port"));
        assert!(create(&path, "Acme", "10.0.0.5".parse().unwrap(), 7460, None, Some(80), "salt").unwrap_err().contains("tunnel port"));
        let key = create(&path, "Acme", "10.0.0.5".parse().unwrap(), 7460, Some("Grid.Acme.Internal"), Some(7461), "salt").unwrap();
        assert!(!key.is_empty() && !std::fs::read_to_string(&path).unwrap().contains(&key));
        let record = load(&path).unwrap();
        assert_eq!((record.name.as_str(), record.port, record.hostname.as_deref(), record.salt.as_str()), ("Acme", 7460, Some("grid.acme.internal"), "salt"));
        assert_eq!(record.tunnel_port, Some(7461));
        assert!(create(&path, "Acme", "10.0.0.5".parse().unwrap(), 7460, None, None, "salt").unwrap_err().contains("already"));
    }

    /// PROVES that the shape of this record cannot change without somebody noticing, by naming
    /// every field of every type in it with no `..`, down through the desks, the people and the
    /// enterprise settings: adding, removing or renaming one stops this file compiling. The two
    /// largest of those were missing, which meant a new field on a desk or on a person passed
    /// both halves of the freeze. This is the half that bytes cannot do. A field added with
    /// `#[serde(default, skip_serializing_if = "Option::is_none")]` deserialises out of the
    /// frozen fixture in its empty state and serialises back to exactly the same bytes, so the
    /// round-trip in `core::compat::frozen` would pass and the shape would have changed anyway.
    ///
    /// DOES NOT PROVE that a change is wrong. It proves it is deliberate: the six steps a frozen
    /// contract's change has to take are in docs/grid-core/frozen-contracts.md, and the first of
    /// them is coming here.
    #[test]
    fn every_field_of_the_grid_hub_record_is_named_here() {
        let record: Record = serde_json::from_value(json!({
            "version": 1, "id": "grid-1", "name": "Acme", "address": "10.0.0.5", "port": 7460,
            "certificate": "", "salt": "s", "createdAt": 0
        }))
        .unwrap();
        let Record { version, id, name, address, port, hostname, tunnel_port, certificate, salt, created_at, plans, members, keys, harnesses, desks, people, enterprise, closing } = record;
        assert_eq!((version, id.as_str(), name.as_str(), port), (1, "grid-1", "Acme", 7460));
        assert!(address.is_ipv4() && hostname.is_none() && tunnel_port.is_none() && certificate.is_empty() && salt == "s" && created_at == 0);
        assert!(plans.is_empty() && members.is_empty() && keys.is_empty() && harnesses.is_empty() && desks.is_empty() && people.is_empty() && closing.is_none());
        assert!(enterprise.images.is_empty());

        let plan: Plan = serde_json::from_value(json!({"id": "plan-1", "model": "m", "percent": 50, "policy": {"idleAfterMinutes": 10}, "createdAt": 0})).unwrap();
        let Plan { id, model, quant, percent, policy, created_at, target } = plan;
        assert_eq!((id.as_str(), model.as_str(), percent, created_at), ("plan-1", "m", 50, 0));
        assert!(quant.is_none() && policy.schedule.is_none() && target == Target::All);
        match (Target::Computers { members: vec!["member-1".to_owned()] }) {
            Target::All | Target::Remaining => unreachable!("that was built as a pick"),
            Target::Computers { members } => assert_eq!(members, vec!["member-1".to_owned()]),
        }

        let member: MemberRecord = serde_json::from_value(json!({"id": "member-1", "name": "PC", "platform": "linux", "tokenHash": "h", "joinedAt": 1})).unwrap();
        let MemberRecord { id, name, platform, token_hash, joined_at, capable, plan, assigned_at, jobs, excluded, share } = member;
        assert_eq!((id.as_str(), name.as_str(), platform.as_str(), token_hash.as_str(), joined_at), ("member-1", "PC", "linux", "h", 1));
        assert!(!capable && plan.is_none() && assigned_at.is_none() && jobs == 0 && !excluded && share.is_none());

        let key: KeyRecord = serde_json::from_value(json!({"id": "key-1", "name": "App", "prefix": "ygrid_a", "hash": "h", "createdAt": 2})).unwrap();
        let KeyRecord { id, name, prefix, hash, created_at, last_used_at, requests, failures, tokens_in, tokens_out } = key;
        assert_eq!((id.as_str(), name.as_str(), prefix.as_str(), hash.as_str(), created_at), ("key-1", "App", "ygrid_a", "h", 2));
        assert!(last_used_at.is_none() && requests == 0 && failures == 0 && tokens_in == 0 && tokens_out == 0);

        let Closing { requested_at, until, told } = Closing { requested_at: 3, until: 4, told: Vec::new() };
        assert_eq!((requested_at, until, told.len()), (3, 4, 0));

        // Everything else that hangs off the record. These are the two largest parts of it, the
        // desks and the people, and the enterprise settings under them; leaving them out meant a
        // new optional field on any of them passed the whole freeze, bytes and compiler alike.
        let IdlePolicy { idle_after_minutes, schedule } = IdlePolicy::default();
        assert!(idle_after_minutes > 0 && schedule.is_none());

        let Share { cpu, memory_gb, disk_gb, gpu, idle_only } = Share::checked(2.0, 4.0, 40.0, false, true).unwrap();
        assert_eq!((cpu, memory_gb, disk_gb, gpu, idle_only), (2.0, 4.0, 40.0, false, true));

        let harness: Harness = serde_json::from_value(json!({
            "id": "harness-1", "name": "team", "strategy": "plan", "lead": "m", "workers": ["w"],
            "computers": 1, "tasks": 1, "rounds": 1, "createdAt": 0
        }))
        .unwrap();
        let Harness { id, name, strategy, lead, workers, computers, tasks, rounds, created_at } = harness;
        assert_eq!((id.as_str(), name.as_str(), lead.as_str(), workers.len(), computers, tasks, rounds, created_at), ("harness-1", "team", "m", 1, 1, 1, 1, 0));
        match strategy {
            crate::harness::Strategy::Plan | crate::harness::Strategy::Mixture => {}
        }

        let desk: Desk = serde_json::from_value(json!({
            "id": "desk-1", "name": "Design",
            "spec": {"kind": "container", "cpu": 2.0, "memoryGb": 4.0, "diskGb": 40.0, "gpu": false, "image": "ubuntu:24.04"},
            "state": "planned", "createdAt": 1, "updatedAt": 2
        }))
        .unwrap();
        let Desk { id, name, spec, access, role_id, image_sha256, generation, moving_from, parcel, person, state, host, environment_id, note, trail, attempts, created_at, updated_at } = desk;
        assert_eq!((id.as_str(), name.as_str(), generation, attempts, created_at, updated_at), ("desk-1", "Design", 0, 0, 1, 2));
        assert!(role_id.is_none() && image_sha256.is_none() && moving_from.is_none() && parcel.is_none() && person.is_none() && host.is_none() && environment_id.is_none());
        assert!(note.is_empty() && trail.is_empty());
        let DeskSpec { kind, cpu, memory_gb, disk_gb, gpu, image } = spec;
        assert_eq!((cpu, memory_gb, disk_gb, gpu, image.as_str()), (2.0, 4.0, 40.0, false, "ubuntu:24.04"));
        match kind {
            desks::DeskKind::Container | desks::DeskKind::Vm | desks::DeskKind::MicroVm => {}
        }
        match state {
            DeskState::Planned | DeskState::Building | DeskState::Ready | DeskState::Moving | DeskState::Failed => {}
        }
        match access {
            crate::enterprise::DeskAccess::Standard | crate::enterprise::DeskAccess::Restricted => {}
        }
        let parcel: desks::Parcel = serde_json::from_value(json!({"key": "desk-1", "bytes": 1, "sha256": "a", "at": 3})).unwrap();
        let desks::Parcel { store, key, bytes, sha256, at } = parcel;
        assert_eq!((key.as_str(), bytes, sha256.as_str(), at), ("desk-1", 1, "a", 3));
        match store {
            desks::ParcelStore::Hub | desks::ParcelStore::S3 => {}
        }

        let person: Person = serde_json::from_value(json!({"id": "person-1", "username": "ada", "name": "Ada", "salt": "s", "keyHash": "h", "createdAt": 4})).unwrap();
        let Person { id, username, admin_role, role_id, name, salt, key_hash, created_at, last_login_at, totp, totp_pending, email, sso_subject } = person;
        assert_eq!((id.as_str(), username.as_str(), name.as_str(), salt.as_str(), key_hash.as_str(), created_at), ("person-1", "ada", "Ada", "s", "h", 4));
        assert!(role_id.is_none() && last_login_at.is_none() && totp.is_none() && totp_pending.is_none() && email.is_none() && sso_subject.is_none());
        match admin_role {
            crate::enterprise::AdminRole::User | crate::enterprise::AdminRole::Auditor | crate::enterprise::AdminRole::Operator | crate::enterprise::AdminRole::Administrator => {}
        }

        let crate::enterprise::Enterprise { images, roles, connections, audit, computer_limit, parking, cloud_fallback, sso, provisioning } = crate::enterprise::Enterprise::default();
        assert!(images.is_empty() && roles.is_empty() && connections.is_empty() && audit.is_empty() && provisioning.is_empty());
        assert!(computer_limit.is_none() && parking.is_none() && cloud_fallback.is_none() && sso.is_none());

        let image: crate::enterprise::Image = serde_json::from_value(json!({
            "id": "image-1", "name": "Ubuntu", "version": "24.04", "description": "", "applications": [],
            "spec": {"kind": "container", "cpu": 2.0, "memoryGb": 4.0, "diskGb": 40.0, "gpu": false, "image": "ubuntu:24.04"},
            "sha256": null, "createdAt": 5
        }))
        .unwrap();
        let crate::enterprise::Image { id, name, version, description, applications, spec, sha256, created_at } = image;
        assert_eq!((id.as_str(), name.as_str(), version.as_str(), created_at), ("image-1", "Ubuntu", "24.04", 5));
        assert!(description.is_empty() && applications.is_empty() && sha256.is_none() && spec.cpu == 2.0);

        let role: crate::enterprise::WorkspaceRole =
            serde_json::from_value(json!({"id": "role-1", "name": "Design", "description": "", "imageId": "image-1", "access": "restricted", "createdAt": 6})).unwrap();
        let crate::enterprise::WorkspaceRole { id, name, description, image_id, access, created_at } = role;
        assert_eq!((id.as_str(), name.as_str(), image_id.as_str(), created_at), ("role-1", "Design", "image-1", 6));
        assert!(description.is_empty() && access == crate::enterprise::DeskAccess::Restricted);

        let connection: crate::enterprise::Connection =
            serde_json::from_value(json!({"id": "connection-1", "name": "Citrix", "provider": "citrix", "url": "https://example.invalid", "roleIds": []})).unwrap();
        let crate::enterprise::Connection { id, name, provider, url, role_ids, target, credential_set, credential_at } = connection;
        assert_eq!((id.as_str(), name.as_str(), url.as_str(), role_ids.len()), ("connection-1", "Citrix", "https://example.invalid", 0));
        assert!(target.is_empty() && !credential_set && credential_at.is_none());
        match provider {
            crate::enterprise::Provider::Citrix
            | crate::enterprise::Provider::AzureVirtualDesktop
            | crate::enterprise::Provider::Windows365
            | crate::enterprise::Provider::Horizon => {}
        }

        let entry: crate::enterprise::Audit = serde_json::from_value(json!({"at": 7, "actor": "a", "action": "b", "subject": "c"})).unwrap();
        let crate::enterprise::Audit { at, actor, action, subject } = entry;
        assert_eq!((at, actor.as_str(), action.as_str(), subject.as_str()), (7, "a", "b", "c"));

        let crate::enterprise::Parking { provider, location, set_at } = crate::enterprise::Parking::checked("awsS3", "s3://bucket/prefix").unwrap();
        assert_eq!((provider.as_str(), location.as_str()), ("awsS3", "s3://bucket/prefix"));
        assert!(set_at >= 0);

        let fallback: crate::enterprise::CloudFallback = serde_json::from_value(json!({
            "enabled": true, "provider": "aws", "account": "a", "region": "r", "image": "i", "machineType": "m",
            "subnet": "s", "username": "ubuntu", "identityFile": "f", "maxComputers": 1
        }))
        .unwrap();
        let crate::enterprise::CloudFallback {
            enabled,
            provider,
            account,
            region,
            image,
            image_project,
            machine_type,
            subnet,
            security_group,
            key_pair,
            resource_group,
            ssh_public_key,
            username,
            identity_file,
            max_computers,
            set_at,
        } = fallback;
        assert_eq!((enabled, provider.as_str(), account.as_str(), region.as_str(), image.as_str(), machine_type.as_str()), (true, "aws", "a", "r", "i", "m"));
        assert_eq!((subnet.as_str(), username.as_str(), identity_file.as_str(), max_computers, set_at), ("s", "ubuntu", "f", 1, 0));
        assert!(image_project.is_empty() && security_group.is_empty() && key_pair.is_empty() && resource_group.is_empty() && ssh_public_key.is_empty());

        let sso: crate::enterprise::Sso = serde_json::from_value(json!({"issuer": "https://example.invalid", "clientId": "c"})).unwrap();
        let crate::enterprise::Sso { issuer, client_id, username_claim, passwordless, set_at } = sso;
        assert_eq!((issuer.as_str(), client_id.as_str(), username_claim.as_str(), passwordless, set_at), ("https://example.invalid", "c", "email", false, 0));

        let asked: crate::enterprise::Provisioning =
            serde_json::from_value(json!({"id": "task-1", "connectionId": "connection-1", "want": "assign", "state": "pending", "at": 8})).unwrap();
        let crate::enterprise::Provisioning { id, connection_id, want, person_id, person_name, email, state, note, at, finished_at, attempts } = asked;
        assert_eq!((id.as_str(), connection_id.as_str(), want.as_str(), state.as_str(), at, attempts), ("task-1", "connection-1", "assign", "pending", 8, 0));
        assert!(person_id.is_none() && person_name.is_empty() && email.is_empty() && note.is_empty() && finished_at.is_none());
    }

    /// PROVES that a record written by a newer build is refused with a sentence naming the
    /// version, instead of being read and then quietly saved back without the fields this build
    /// has never heard of.
    ///
    /// DOES NOT PROVE anything about a record a newer build has already written and an older
    /// build has already saved over. The gate only stops the next read; nothing can repair that
    /// one, which is why the gate is the first stage of the rollout.
    #[test]
    fn a_grid_record_from_a_newer_build_is_refused_rather_than_read() {
        let base = json!({"version": 1, "id": "grid-1", "name": "Acme", "address": "10.0.0.5", "port": 7460, "certificate": "", "salt": "s", "createdAt": 0});
        assert!(read(&serde_json::to_vec(&base).unwrap()).is_ok(), "this build's own version reads");

        let mut newer = base.clone();
        newer["version"] = json!(2);
        let Err(refused) = read(&serde_json::to_vec(&newer).unwrap()) else { panic!("a newer record must be refused") };
        assert_eq!(refused, "This grid's settings were written by a newer Yougori (version 2); update Yougori to open them");

        // A version far above anything a byte can hold is still the version refusal and never the
        // "damaged" one, which is what comparing in `u64` is for.
        let mut far = base.clone();
        far["version"] = json!(256);
        let Err(far_refused) = read(&serde_json::to_vec(&far).unwrap()) else { panic!("version 256 must be refused") };
        assert!(far_refused.contains("version 256"), "256 must not narrow to 0: {far_refused}");

        // A record with no version is not something this product has ever written: the field is
        // required by the type. It falls through the gate and the deserialiser refuses it, which
        // is what this loader did before the gate existed.
        let mut without = base;
        without.as_object_mut().unwrap().remove("version");
        let Err(damaged) = read(&serde_json::to_vec(&without).unwrap()) else { panic!("a record with no version at all is not a record") };
        assert_eq!(damaged, "The grid hub's settings are damaged", "the gate must not change what a record with no version does");
    }
}
