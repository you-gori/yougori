//! Security monitoring, the tamper-evident audit log and kill switches for local
//! environments. Everything here runs in the engine on the host, outside guest reach.
//!
//! - `audit`: append-only, hash-chained, rotated log of security-relevant events.
//! - `network`: counters fed by the host packet filter of each microVM, VM and container appliance.
//! - `monitor`: rolling windows and rules; only clear policy violations act by default.
//! - `containment`: lockdown/unlock and kill-switch steps, persisted until `unlock`.
pub(crate) mod audit;
pub(crate) mod containment;
pub(crate) mod monitor;
pub(crate) mod network;
#[cfg(test)]
mod tests;

use crate::{
    commands,
    models::{Environment, EnvironmentKind, EnvironmentStatus, PlatformState, RuntimeProviderKind},
    runtime::RuntimeManager,
    store::PlatformStore,
    AppHandle,
};
pub(crate) use audit::Event;
use chrono::{DateTime, SecondsFormat, Utc};
use containment::{Level, Power, Step, Target};
use network::Denial;
use serde_json::{json, Value};
use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, OnceLock, Weak,
    },
    time::{Duration, Instant},
};
use tauri::{Emitter, Manager, State};

static AUDIT: OnceLock<audit::AuditLog> = OnceLock::new();
static CONTAINMENT: OnceLock<containment::Store> = OnceLock::new();
static DROPPED: AtomicU64 = AtomicU64::new(0);
const TICK: Duration = Duration::from_secs(5);
const NOTIFY_EVERY: u64 = 600;

/// Opens the audit log and containment records beside platform state. Setup calls this
/// before startup reconciliation so the engine's own state changes are recorded too.
pub(crate) fn init(store: &PlatformStore) -> Result<(), String> {
    let root = store.data_folder("security");
    let log = audit::AuditLog::open(&root.join("audit"))?;
    let _ = CONTAINMENT.set(containment::Store::load(&root.join("state.json")));
    let _ = AUDIT.set(log);
    record(Event::new("engine.started").via("engine").text("version", env!("CARGO_PKG_VERSION")));
    Ok(())
}

/// Appends an event. A failed write never blocks the action it describes: it is counted
/// and an `audit.dropped` record follows the next successful write.
pub(crate) fn record(event: Event) {
    let Some(log) = AUDIT.get() else { return };
    let event = if event.has_via() { event } else { event.via(actor()) };
    let dropped = DROPPED.swap(0, Ordering::AcqRel);
    if dropped > 0 && log.append(Event::new("audit.dropped").via("engine").number("count", dropped)).is_err() {
        DROPPED.fetch_add(dropped, Ordering::AcqRel);
    }
    if let Err(error) = log.append(event) {
        DROPPED.fetch_add(1, Ordering::AcqRel);
        eprintln!("Audit record was not written: {}", crate::lifecycle::safe_diagnostic(&error));
    }
}

/// Writes the pending head anchor (monitor ticks and shutdown).
pub(crate) fn flush() {
    if let Some(log) = AUDIT.get() {
        log.flush_anchor();
    }
}

tokio::task_local! { static ACTOR: &'static str; }
thread_local! { static ENGINE: Cell<bool> = const { Cell::new(false) }; }

/// Attributes events inside `future` to `actor` (`cli`, `remote`, `lan`, `policy`).
pub(crate) async fn acting_as<T>(actor: &'static str, future: impl std::future::Future<Output = T>) -> T {
    ACTOR.scope(actor, future).await
}

/// Attributes state changes made by a synchronous engine step (reconciliation, sampling).
pub(crate) fn as_engine<T>(operation: impl FnOnce() -> T) -> T {
    let previous = ENGINE.with(|cell| cell.replace(true));
    let result = operation();
    ENGINE.with(|cell| cell.set(previous));
    result
}

pub(crate) fn actor() -> &'static str {
    if ENGINE.with(Cell::get) {
        return "engine";
    }
    if let Ok(actor) = ACTOR.try_with(|actor| *actor) {
        return actor;
    }
    if crate::automation::context::current().is_some() {
        return "cli";
    }
    "app"
}

/// A short, stable label for a terminal session ID, enough to pair `opened` with `closed`.
pub(crate) fn session_label(session: &str) -> String {
    use sha2::Digest;
    hex::encode(&sha2::Sha256::digest(session.as_bytes())[..6])
}

/// Who owns a guest terminal session, from its owner label.
pub(crate) fn terminal_actor(owner: &str) -> &'static str {
    if owner == "cli" { "cli" } else if owner.starts_with("remote-") { "remote" } else if owner.starts_with("share-") { "lan" } else { "app" }
}

// ---- Lifecycle changes from committed platform state -------------------------------

#[derive(Clone, Debug)]
pub(crate) struct Recorded {
    id: String,
    name: String,
    status: EnvironmentStatus,
    internet: bool,
    gpu: bool,
    shared: bool,
}

impl Recorded {
    fn of(environment: &Environment) -> Self {
        Self {
            id: environment.id.clone(),
            name: environment.name.clone(),
            status: environment.status.clone(),
            internet: environment.network_access,
            gpu: environment.gpu_access,
            shared: crate::peer_sharing::is_shared(environment),
        }
    }
}

/// A small summary taken under the state lock, only when the audit log is open.
pub(crate) fn before(state: &PlatformState) -> Option<Vec<Recorded>> {
    AUDIT.get()?;
    Some(state.environments.iter().map(Recorded::of).collect())
}

/// Records what a committed state change did; runs after the state lock is released.
pub(crate) fn committed(before: Option<Vec<Recorded>>, after: &PlatformState) {
    if let Some(before) = before {
        for event in lifecycle_events(&before, after) {
            record(event);
        }
    }
}

fn name_of<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value).ok().and_then(|value| value.as_str().map(str::to_owned)).unwrap_or_default()
}

pub(crate) fn lifecycle_events(before: &[Recorded], after: &PlatformState) -> Vec<Event> {
    let mut events = Vec::new();
    for environment in &after.environments {
        let Some(previous) = before.iter().find(|previous| previous.id == environment.id) else {
            events.push(Event::new("environment.created").env(&environment.id).text("name", &environment.name)
                .text("kind", &name_of(&environment.kind)).text("provider", &environment.provider.as_ref().map(name_of).unwrap_or_default())
                .path("source", &environment.runtime).flag("internet", environment.network_access));
            continue;
        };
        if previous.shared {
            continue;
        }
        if previous.status != environment.status {
            let kind = match (&previous.status, &environment.status) {
                (EnvironmentStatus::Paused, EnvironmentStatus::Running) => Some("environment.resumed"),
                (_, EnvironmentStatus::Running) => Some("environment.started"),
                (_, EnvironmentStatus::Paused) => Some("environment.paused"),
                (_, EnvironmentStatus::Stopped) => Some("environment.stopped"),
                (_, EnvironmentStatus::Error) => Some("environment.failed"),
                (_, EnvironmentStatus::Provisioning) => None,
            };
            if let Some(kind) = kind {
                events.push(Event::new(kind).env(&environment.id).text("from", &name_of(&previous.status)));
            }
        }
        if previous.internet != environment.network_access {
            events.push(Event::new("environment.internet").env(&environment.id).flag("enabled", environment.network_access));
        }
        if previous.gpu != environment.gpu_access {
            events.push(Event::new("environment.gpu").env(&environment.id).flag("enabled", environment.gpu_access));
        }
    }
    for previous in before {
        if !after.environments.iter().any(|environment| environment.id == previous.id) {
            events.push(Event::new("environment.deleted").env(&previous.id).text("name", &previous.name));
        }
    }
    events
}

// ---- Containment ----------------------------------------------------------------------

fn records() -> Result<&'static containment::Store, String> {
    CONTAINMENT.get().ok_or_else(|| "Security state is unavailable in this engine".to_string())
}

/// Refuses an action that would reopen a locked-down or kill-switched environment.
pub(crate) fn ensure_open(store: &PlatformStore, environment_id: &str, action: &str) -> Result<(), String> {
    let Some(containment) = CONTAINMENT.get().and_then(|records| records.get(environment_id)) else { return Ok(()) };
    let name = store.environment(environment_id).map(|environment| environment.name).unwrap_or_else(|_| environment_id.to_owned());
    let simple = !name.is_empty() && name.len() <= 64 && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    record(Event::new("containment.refused").env(environment_id).text("action", action));
    Err(containment::refusal(&name, if simple { &name } else { environment_id }, &containment, action))
}

/// Whether an environment is locked down or kill-switched, without recording a refusal: for
/// loops that re-check every few seconds.
pub(crate) fn contained(environment_id: &str) -> bool {
    CONTAINMENT.get().and_then(|records| records.get(environment_id)).is_some()
}

/// Local containers, GPU containers, microVMs and VMs: Internet can be cut and power paused.
fn controllable(environment: &Environment) -> Result<(), &'static str> {
    if crate::peer_sharing::is_shared(environment) {
        return Err("shared environments belong to their owner");
    }
    match (environment.kind.clone(), commands::provider(environment)) {
        (EnvironmentKind::Container, RuntimeProviderKind::YougoriOci | RuntimeProviderKind::YougoriCuda) => Ok(()),
        (EnvironmentKind::MicroVm | EnvironmentKind::FullVm, RuntimeProviderKind::Qemu) => Ok(()),
        (EnvironmentKind::Cloud, _) => Err("cloud servers run outside Yougori; disconnect them with `yougori stop`"),
        _ => Err("application branches cannot be cut off or paused; stop them instead"),
    }
}

fn target(environment: &Environment) -> Target {
    Target {
        internet: environment.network_access,
        power: match environment.status {
            EnvironmentStatus::Running => Power::Running,
            EnvironmentStatus::Paused => Power::Paused,
            EnvironmentStatus::Stopped => Power::Stopped,
            _ => Power::Other,
        },
        internet_control: true,
        pause_control: true,
    }
}

fn operation_lock(id: &str) -> Arc<tokio::sync::Mutex<()>> {
    static LOCKS: OnceLock<Mutex<HashMap<String, Weak<tokio::sync::Mutex<()>>>>> = OnceLock::new();
    let mut locks = LOCKS.get_or_init(Default::default).lock().unwrap_or_else(|error| error.into_inner());
    locks.retain(|_, lock| lock.strong_count() > 0);
    if let Some(lock) = locks.get(id).and_then(Weak::upgrade) {
        return lock;
    }
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    locks.insert(id.to_owned(), Arc::downgrade(&lock));
    lock
}

fn now_text() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

async fn apply(step: Step, id: &str, store: &State<'_, PlatformStore>, runtime: &State<'_, RuntimeManager>) -> Result<(), String> {
    match step {
        Step::CutInternet | Step::RestoreInternet => {
            commands::update_container_network(id.to_owned(), step == Step::RestoreInternet, store.clone(), runtime.clone()).await.map(drop)
        }
        Step::Pause | Step::Resume => {
            let status = if step == Step::Pause { EnvironmentStatus::Paused } else { EnvironmentStatus::Running };
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                match commands::set_environment_status(id.to_owned(), status.clone(), store.clone(), runtime.clone()).await {
                    Err(error) if error.starts_with("Another lifecycle or network operation") && Instant::now() < deadline => {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                    result => return result.map(drop),
                }
            }
        }
    }
}

fn steps_report(outcomes: &[(Step, Result<(), String>)]) -> Value {
    Value::Array(outcomes.iter().map(|(step, result)| match result {
        Ok(()) => json!({"step": step, "ok": true}),
        Err(error) => json!({"step": step, "ok": false, "error": crate::lifecycle::safe_diagnostic(error)}),
    }).collect())
}

/// Records containment first (so it survives a crash mid-way), then cuts Internet and pauses.
pub(crate) async fn contain(app: &AppHandle, id: &str, level: Level, reason: &str, via: &'static str, rule: Option<&'static str>) -> Result<Value, String> {
    let lock = operation_lock(id);
    let _serial = lock.lock().await;
    let store = app.state::<PlatformStore>();
    let runtime = app.state::<RuntimeManager>();
    let environment = store.environment(id)?;
    controllable(&environment).map_err(|reason| format!("{} cannot be locked down: {reason}", environment.name))?;
    let records = records()?;
    let existing = records.get(id);
    let (steps, containment) = containment::plan_contain(target(&environment), existing.as_ref(), level, reason, via, rule, &now_text());
    records.set(id, Some(containment.clone()))?;
    let mut outcomes = Vec::new();
    for step in steps {
        let result = acting_as(via, apply(step, id, &store, &runtime)).await;
        outcomes.push((step, result));
    }
    let ok = outcomes.iter().all(|(_, result)| result.is_ok());
    let mut event = Event::new(if via == "policy" { "killswitch.applied" } else { "lockdown.applied" }).env(id).via(via)
        .text("level", containment.level.label()).text("reason", reason).object("steps", steps_report(&outcomes)).succeeded(ok);
    if let Some(rule) = rule {
        event = event.text("rule", rule);
    }
    record(event);
    Ok(json!({"id": id, "name": environment.name, "containment": containment, "steps": steps_report(&outcomes), "ok": ok}))
}

/// Clears containment first, then restores exactly what containment changed.
pub(crate) async fn release(app: &AppHandle, id: &str, via: &'static str) -> Result<Value, String> {
    let lock = operation_lock(id);
    let _serial = lock.lock().await;
    let records = records()?;
    let Some(existing) = records.get(id) else {
        return Ok(json!({"id": id, "unlocked": false, "note": "This environment was not locked down."}));
    };
    let store = app.state::<PlatformStore>();
    let runtime = app.state::<RuntimeManager>();
    let Ok(environment) = store.environment(id) else {
        records.set(id, None)?;
        return Ok(json!({"id": id, "unlocked": true, "note": "The environment no longer exists."}));
    };
    let steps = containment::plan_release(target(&environment), Some(&existing));
    records.set(id, None)?;
    if let Ok(mut state) = monitor_state().lock() {
        state.trackers.entry(id.to_owned()).or_default().unlocked(unix_now());
    }
    let mut outcomes = Vec::new();
    for step in steps {
        let result = acting_as(via, apply(step, id, &store, &runtime)).await;
        outcomes.push((step, result));
    }
    let ok = outcomes.iter().all(|(_, result)| result.is_ok());
    record(Event::new("lockdown.released").env(id).via(via).text("previous", existing.level.label()).object("steps", steps_report(&outcomes)).succeeded(ok));
    Ok(json!({"id": id, "name": environment.name, "unlocked": true, "steps": steps_report(&outcomes), "ok": ok,
        "automaticActionsPausedMinutes": monitor::UNLOCK_GRACE / 60}))
}

fn selection(store: &PlatformStore, environment_id: Option<String>, all: bool) -> Result<Vec<Environment>, String> {
    let state = store.snapshot()?;
    match (environment_id, all) {
        (Some(_), true) | (None, false) => Err("Give one environment ID, or --all".into()),
        (Some(id), false) => Ok(vec![state.environments.into_iter().find(|environment| environment.id == id).ok_or("Environment not found")?]),
        (None, true) => Ok(state.environments),
    }
}

pub(crate) async fn lockdown(app: &AppHandle, environment_id: Option<String>, all: Option<bool>) -> Result<Value, String> {
    let all = all.unwrap_or(false);
    let environments = selection(&app.state::<PlatformStore>(), environment_id, all)?;
    if !all {
        if let Err(reason) = controllable(&environments[0]) {
            return Err(format!("{} cannot be locked down: {reason}", environments[0].name));
        }
    }
    let via = actor();
    let results = futures_util::future::join_all(environments.iter().map(|environment| async move {
        match controllable(environment) {
            Err(reason) => json!({"id": environment.id, "name": environment.name, "skipped": reason}),
            Ok(()) => contain(app, &environment.id, Level::Lockdown, "manual lockdown", via, None).await
                .unwrap_or_else(|error| json!({"id": environment.id, "name": environment.name, "ok": false, "error": crate::lifecycle::safe_diagnostic(&error)})),
        }
    })).await;
    emit_state(app);
    Ok(json!({"all": all, "environments": results, "undo": if all { "yougori unlock --all --yes" } else { "yougori unlock ENV --yes" }}))
}

pub(crate) async fn unlock(app: &AppHandle, environment_id: Option<String>, all: Option<bool>) -> Result<Value, String> {
    let all = all.unwrap_or(false);
    let ids: Vec<String> = match (environment_id, all) {
        (Some(_), true) | (None, false) => return Err("Give one environment ID, or --all".into()),
        (Some(id), false) => vec![id],
        (None, true) => records()?.all().into_keys().collect(),
    };
    let via = actor();
    let results = futures_util::future::join_all(ids.iter().map(|id| async move {
        release(app, id, via).await.unwrap_or_else(|error| json!({"id": id, "ok": false, "error": crate::lifecycle::safe_diagnostic(&error)}))
    })).await;
    emit_state(app);
    Ok(json!({"all": all, "environments": results}))
}

fn emit_state(app: &AppHandle) {
    if let Ok(state) = app.state::<PlatformStore>().snapshot() {
        let _ = app.emit("yougori-platform-state", state);
    }
}

// ---- Monitoring -----------------------------------------------------------------------

#[derive(Default)]
struct MonitorState {
    trackers: HashMap<String, monitor::Tracker>,
    /// Last cumulative (egress, ingress, connections) per filter instance; a restarted
    /// VM registers a new instance whose counters start again at zero.
    baselines: HashMap<String, (usize, u64, u64, u64)>,
    denials: HashMap<String, Denials>,
    notified: HashMap<(String, monitor::Rule), u64>,
    sampled_at: String,
    guest: HashMap<String, u64>,
}

#[derive(Default)]
struct Denials {
    counts: BTreeMap<&'static str, u64>,
    host_ports: BTreeSet<u16>,
    since: u64,
}

fn monitor_state() -> &'static Mutex<MonitorState> {
    static STATE: OnceLock<Mutex<MonitorState>> = OnceLock::new();
    STATE.get_or_init(Default::default)
}

fn unix_now() -> u64 {
    Utc::now().timestamp().max(0) as u64
}

fn time_text(seconds: u64) -> String {
    DateTime::<Utc>::from_timestamp(seconds as i64, 0).unwrap_or_default().to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Process-limit hits a guest agent reports as a running total (`pidsLimitHits`), once the
/// agent supports it. The current agent does not report them, so the rule stays dormant.
pub(crate) fn guest_pids_hits(environment_id: &str, total: u64) {
    let now = unix_now();
    let mut state = monitor_state().lock().unwrap_or_else(|error| error.into_inner());
    if let Some(previous) = state.guest.insert(environment_id.to_owned(), total) {
        let hits = total.saturating_sub(previous);
        state.trackers.entry(environment_id.to_owned()).or_default().record_pids(now, hits);
    }
}

fn pool_label(key: &str) -> String {
    let root = key.strip_prefix("appliance:").unwrap_or(key);
    format!("standard containers (shared VM, {root})")
}

/// CPU and memory as fractions of the allocation. VM memory is skipped: guest page cache
/// fills QEMU's resident memory during normal work.
fn usage(environment: &Environment) -> (Option<f64>, Option<f64>) {
    let policy = &environment.resource_policy;
    match commands::provider(environment) {
        RuntimeProviderKind::YougoriOci | RuntimeProviderKind::YougoriCuda if environment.kind == EnvironmentKind::Container => (
            (policy.cpu.current > 0.0).then(|| environment.cpu_usage / (100.0 * policy.cpu.current)),
            (policy.memory_gb.current > 0.0).then(|| environment.memory_usage_gb / policy.memory_gb.current),
        ),
        RuntimeProviderKind::Qemu => (Some(environment.cpu_usage / 100.0), None),
        _ => (None, None),
    }
}

fn coverage(environment: &Environment) -> Value {
    let (network, cpu, memory) = match (environment.kind.clone(), commands::provider(environment)) {
        _ if crate::peer_sharing::is_shared(environment) => ("not measured (owner's environment)", false, false),
        (EnvironmentKind::MicroVm | EnvironmentKind::FullVm, RuntimeProviderKind::Qemu) => ("host filter (exact)", true, false),
        (EnvironmentKind::Container, RuntimeProviderKind::YougoriOci) => ("guest firewall; per-container counters need a guest agent update", true, true),
        (EnvironmentKind::Container, RuntimeProviderKind::YougoriCuda) => ("not measured (GPU runtime)", true, true),
        _ => ("not measured", false, false),
    };
    json!({"network": network, "cpu": cpu, "memory": memory, "processLimit": "needs a guest agent update"})
}

fn accumulate(denials: &mut HashMap<String, Denials>, target: &str, window: &network::Window, now: u64) {
    let counted: u64 = network::DENIALS.iter().filter(|class| **class != Denial::Ignored).map(|class| window.packets(*class)).sum();
    if counted == 0 {
        return;
    }
    let entry = denials.entry(target.to_owned()).or_insert_with(|| Denials { since: now, ..Denials::default() });
    for class in network::DENIALS.iter().filter(|class| **class != Denial::Ignored) {
        let packets = window.packets(*class);
        if packets > 0 {
            *entry.counts.entry(class.name()).or_default() += packets;
        }
    }
    entry.host_ports.extend(window.host_ports.iter().take(64));
}

/// One monitoring pass: drain filter counters, sample usage, evaluate rules.
fn tick(app: &AppHandle, now: u64) -> Vec<(String, monitor::Decision)> {
    let Ok(platform) = app.state::<PlatformStore>().snapshot() else { return Vec::new() };
    let settings = platform.settings.security_monitoring.clone();
    let contained = CONTAINMENT.get().map(containment::Store::all).unwrap_or_default();
    let mut guard = monitor_state().lock().unwrap_or_else(|error| error.into_inner());
    let state = &mut *guard;
    let by_runtime: HashMap<&str, &Environment> = platform.environments.iter()
        .filter(|environment| commands::provider(environment) == RuntimeProviderKind::Qemu)
        .map(|environment| (environment.runtime_id.as_deref().unwrap_or(&environment.id), environment))
        .collect();
    let live = network::live();
    state.baselines.retain(|key, _| live.iter().any(|(live, _)| live == key));
    for (key, stats) in live {
        let drained = stats.drain();
        let instance = Arc::as_ptr(&stats) as usize;
        let (egress, ingress, connections) = match state.baselines.insert(key.clone(), (instance, drained.egress_bytes, drained.ingress_bytes, drained.connections)) {
            Some((previous, egress, ingress, connections)) if previous == instance => (egress, ingress, connections),
            _ => (0, 0, 0),
        };
        let target = match by_runtime.get(key.as_str()) {
            Some(environment) => environment.id.clone(),
            None if key.starts_with("appliance:") => key.clone(),
            None => continue,
        };
        let window = &drained.window;
        accumulate(&mut state.denials, &target, window, now);
        state.trackers.entry(target).or_default().record_network(now, monitor::NetworkTick {
            host_port_attempts: window.attempts(Denial::HostPort),
            host_ports: window.host_ports.iter().copied().collect(),
            metadata_attempts: window.attempts(Denial::Metadata),
            link_local: window.link_local.iter().copied().collect(),
            internet_off_attempts: window.attempts(Denial::InternetOff),
            other_denied: window.packets(Denial::Spoofed) + window.packets(Denial::Malformed) + window.packets(Denial::Filter),
            connections: drained.connections.saturating_sub(connections),
            peers: window.peers.iter().copied().collect(),
            egress_bytes: drained.egress_bytes.saturating_sub(egress),
            ingress_bytes: drained.ingress_bytes.saturating_sub(ingress),
        });
    }
    if platform.host.updated_at != state.sampled_at {
        state.sampled_at = platform.host.updated_at.clone();
        for environment in platform.environments.iter().filter(|environment| environment.status == EnvironmentStatus::Running && controllable(environment).is_ok()) {
            let (cpu, memory) = usage(environment);
            if cpu.is_some() || memory.is_some() {
                state.trackers.entry(environment.id.clone()).or_default().record_usage(now, cpu, memory);
            }
        }
    }
    if contained.keys().any(|id| !platform.environments.iter().any(|environment| &environment.id == id)) {
        let live: Vec<String> = platform.environments.iter().map(|environment| environment.id.clone()).collect();
        if let Some(records) = CONTAINMENT.get() {
            let _ = records.retain(&live);
        }
    }
    let mut decisions = Vec::new();
    let ids: Vec<String> = state.trackers.keys().cloned().collect();
    for id in ids {
        let environment = platform.environments.iter().find(|environment| environment.id == id);
        if environment.is_none() && !id.starts_with("appliance:") {
            state.trackers.remove(&id);
            state.denials.remove(&id);
            state.guest.remove(&id);
            continue;
        }
        let context = monitor::Context {
            actions_supported: environment.is_some_and(|environment| controllable(environment).is_ok()
                && matches!(environment.status, EnvironmentStatus::Running | EnvironmentStatus::Paused)),
            internet_cut: contained.contains_key(&id),
            paused: environment.is_some_and(|environment| environment.status == EnvironmentStatus::Paused),
        };
        let tracker = state.trackers.get_mut(&id).expect("tracker exists");
        decisions.extend(tracker.evaluate(now, &settings, context).into_iter().map(|decision| (id.clone(), decision)));
    }
    let due: Vec<String> = state.denials.iter().filter(|(_, denials)| now.saturating_sub(denials.since) >= 60).map(|(id, _)| id.clone()).collect();
    for id in due {
        let Some(denials) = state.denials.remove(&id) else { continue };
        let mut event = Event::new("network.denied").via("engine")
            .object("counts", json!(denials.counts))
            .object("hostPorts", json!(denials.host_ports.iter().take(32).collect::<Vec<_>>()))
            .number("windowSeconds", now.saturating_sub(denials.since));
        event = if id.starts_with("appliance:") { event.text("pool", &pool_label(&id)) } else { event.env(&id) };
        record(event);
    }
    decisions
}

fn notify(app: &AppHandle, title: &str, body: &str) {
    #[cfg(target_os = "windows")]
    {
        use tauri_plugin_notification::NotificationExt;
        let _ = app.notification().builder().title(title).body(body).show();
    }
    #[cfg(not(target_os = "windows"))]
    let _ = (app, title, body);
}

async fn act(app: AppHandle, id: String, decision: monitor::Decision, notifications: bool) {
    let store = app.state::<PlatformStore>();
    let name = store.environment(&id).map(|environment| environment.name).unwrap_or_else(|_| pool_label(&id));
    let mut event = Event::new(if decision.action.is_some() { "killswitch.triggered" } else { "monitor.alert" }).via("policy")
        .text("rule", decision.rule.name()).text("level", if decision.level == monitor::Level::Warning { "warning" } else { "notice" })
        .decimal("value", decision.value).decimal("threshold", decision.threshold).text("summary", &decision.summary);
    event = if id.starts_with("appliance:") { event.text("pool", &name) } else { event.env(&id) };
    if let Some(action) = decision.action {
        event = event.text("action", match action { monitor::Action::CutInternet => "cutInternet", monitor::Action::Pause => "pause" });
    }
    record(event);
    let outcome = match decision.action {
        Some(monitor::Action::CutInternet) => Some(contain(&app, &id, Level::InternetCut, &decision.summary, "policy", Some(decision.rule.name())).await),
        Some(monitor::Action::Pause) => Some(contain(&app, &id, Level::Paused, &decision.summary, "policy", Some(decision.rule.name())).await),
        None => None,
    };
    let step = match (decision.action, &outcome) {
        (Some(monitor::Action::CutInternet), Some(Ok(result))) if result["ok"] == true => "Its Internet access was cut.",
        (Some(monitor::Action::Pause), Some(Ok(result))) if result["ok"] == true => "It was paused.",
        (Some(_), _) => "The kill switch could not finish; check `yougori monitor`.",
        (None, _) => "No action was taken.",
    };
    let payload = json!({"environmentId": id, "name": name, "rule": decision.rule.name(), "level": decision.level, "action": decision.action, "summary": decision.summary, "step": step});
    let _ = app.emit("yougori-security-alert", &payload);
    if decision.level != monitor::Level::Warning || !notifications {
        return;
    }
    let now = unix_now();
    {
        let mut state = monitor_state().lock().unwrap_or_else(|error| error.into_inner());
        let last = state.notified.get(&(id.clone(), decision.rule)).copied();
        if decision.action.is_none() && last.is_some_and(|last| now.saturating_sub(last) < NOTIFY_EVERY) {
            return;
        }
        state.notified.insert((id.clone(), decision.rule), now);
    }
    let reference = if id.starts_with("appliance:") { String::new() } else { format!(" Review: yougori audit {}", if name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')) { &name } else { &id }) };
    notify(&app, "Yougori · security alert", &format!("{name}: {}. {step}{reference}", decision.summary));
}

/// Starts the 5-second monitoring loop; it idles cheaply when nothing runs.
pub(crate) fn start(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let shutdown = crate::automation::shutdown_signal(&app);
        loop {
            tokio::select! { _ = shutdown.cancelled() => break, _ = tokio::time::sleep(TICK) => {} }
            let notifications = app.state::<PlatformStore>().snapshot().map(|state| state.settings.security_monitoring.notifications).unwrap_or(true);
            for (id, decision) in tick(&app, unix_now()) {
                tauri::async_runtime::spawn(act(app.clone(), id, decision, notifications));
            }
            flush();
        }
    });
}

// ---- Engine methods -------------------------------------------------------------------

pub(crate) fn monitor_snapshot(store: &PlatformStore, environment_id: Option<String>) -> Result<Value, String> {
    let platform = store.snapshot()?;
    let settings = platform.settings.security_monitoring.clone();
    let now = unix_now();
    let contained = CONTAINMENT.get().map(containment::Store::all).unwrap_or_default();
    let state = monitor_state().lock().unwrap_or_else(|error| error.into_inner());
    let mut environments = Vec::new();
    for environment in platform.environments.iter().filter(|environment| environment_id.as_deref().is_none_or(|id| id == environment.id)) {
        let value = serde_json::to_value(environment).map_err(|error| error.to_string())?;
        let summary = state.trackers.get(&environment.id).map(|tracker| tracker.summary(now)).unwrap_or_else(|| monitor::Tracker::default().summary(now));
        let mut entry = json!({
            "id": environment.id, "name": environment.name, "type": yougori_cli::overview::env_type(&value),
            "status": environment.status, "internet": environment.network_access,
            "containment": contained.get(&environment.id), "coverage": coverage(environment),
        });
        if let (Some(entry), Value::Object(summary)) = (entry.as_object_mut(), summary) {
            entry.extend(summary);
        }
        environments.push(entry);
    }
    if environment_id.is_some() && environments.is_empty() {
        return Err("Environment not found".into());
    }
    let pools: Vec<Value> = if environment_id.is_none() {
        state.trackers.iter().filter(|(key, _)| key.starts_with("appliance:")).map(|(key, tracker)| json!({"key": key, "label": pool_label(key), "summary": tracker.summary(now)})).collect()
    } else {
        Vec::new()
    };
    Ok(json!({
        "observedAt": time_text(now), "monitoring": settings.enabled, "notifications": settings.notifications,
        "policies": settings, "environments": environments, "pools": pools,
        "auditFolder": AUDIT.get().map(|log| log.root().display().to_string()),
    }))
}

pub(crate) fn parse_since(text: &str, now: DateTime<Utc>) -> Result<DateTime<Utc>, String> {
    let text = text.trim();
    let invalid = || format!("--since must be a time such as 2026-10-11T08:00:00Z, a date such as 2026-10-11 (UTC) or a duration such as 30m, 2h or 7d; got {text:?}");
    if let Ok(time) = DateTime::parse_from_rfc3339(text) {
        return Ok(time.with_timezone(&Utc));
    }
    if let Ok(date) = chrono::NaiveDate::parse_from_str(text, "%Y-%m-%d") {
        return Ok(date.and_hms_opt(0, 0, 0).ok_or_else(invalid)?.and_utc());
    }
    let unit = text.chars().last().ok_or_else(invalid)?;
    let amount: i64 = text[..text.len() - unit.len_utf8()].parse().map_err(|_| invalid())?;
    let seconds = match unit { 's' => 1, 'm' => 60, 'h' => 3600, 'd' => 86_400, _ => return Err(invalid()) };
    if amount <= 0 || amount > 3650 * 86_400 / seconds {
        return Err(invalid());
    }
    Ok(now - chrono::Duration::seconds(amount * seconds))
}

pub(crate) fn audit_query(environment_id: Option<String>, since: Option<String>, limit: Option<u64>, verify: Option<bool>) -> Result<Value, String> {
    let log = AUDIT.get().ok_or("The audit log is unavailable in this engine")?;
    let since = since.map(|text| parse_since(&text, Utc::now())).transpose()?;
    let limit = limit.unwrap_or(50);
    if !(1..=1000).contains(&limit) {
        return Err("--limit must be between 1 and 1000".into());
    }
    let records = log.query(&audit::Query { environment: environment_id, since, limit: limit as usize })?;
    let verification = verify.unwrap_or(false).then(|| log.verify());
    Ok(json!({"count": records.len(), "records": records, "verification": verification, "folder": log.root().display().to_string()}))
}

/// `securityMonitoring` changes are audited; disabling a kill switch is itself security-relevant.
pub(crate) fn settings_changed(before: &monitor::Settings, after: &monitor::Settings) {
    if before != after {
        record(Event::new("settings.security").object("before", json!(before)).object("after", json!(after)));
    }
}
