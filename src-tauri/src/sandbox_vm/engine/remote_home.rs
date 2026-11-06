//! Existing SSH hosts, operated by this engine's real parent VM and V12 leases.
//! Journals contain identities and cleanup intent, never command input or keys.
use super::*;
use crate::runtime::cloud::Profile as SshProfile;
use crate::sandbox_contract::remote::{KnownHosts, RemoteHostId};
use crate::sandbox_contract::remote_ssh::{RemoteManagementRequest, RemoteVmObservation};
use serde::{Deserialize, Serialize};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Mutex,
};
use std::time::Instant;
#[allow(unused_imports)]
use tauri::Manager as _;

mod history;
mod trust;
mod worker;

const MAX_RUNS: usize = 256;
const MAX_LIVE: usize = 16;
const MAX_JOURNAL: u64 = 128 * 1024;

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Request {
    Trust {
        connection: String,
        accept_host_key: String,
    },
    Launch {
        /// Durable caller key: a retry can only observe the original effect.
        request_key: Option<Digest>,
        connection: String,
        parent: SandboxId,
        program: String,
        endpoint: String,
        engine_sha256: Digest,
        accept_host_key: Option<String>,
        #[serde(default = "default_memory")]
        memory_mib: u64,
        #[serde(default = "default_lifetime")]
        lifetime_seconds: u64,
    },
    Status {
        run: Option<Digest>,
        request_key: Option<Digest>,
        #[serde(default)]
        archived: bool,
        after: Option<Digest>,
    },
    Archive {
        run: Digest,
    },
    Stop {
        run: Digest,
    },
    Reconcile {
        run: Digest,
    },
    Start {
        run: Digest,
        input_hex: String,
        #[serde(default = "default_timeout")]
        timeout_seconds: u64,
        #[serde(default = "default_output")]
        output_bytes: usize,
    },
    Outcome {
        run: Digest,
        command: u32,
    },
    Cancel {
        run: Digest,
        command: u32,
    },
}
fn default_memory() -> u64 {
    1024
}
fn default_lifetime() -> u64 {
    3600
}
fn default_timeout() -> u64 {
    60
}
fn default_output() -> usize {
    256 * 1024
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Starting,
    Ready,
    Stopping,
    Ended,
    CreationCancelled,
    Unconfirmed,
}
impl Phase {
    fn terminal(self) -> bool {
        matches!(self, Self::Ended | Self::CreationCancelled)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Run {
    version: u32,
    run: Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    request_key: Option<Digest>,
    parent: SandboxId,
    parent_boot: SandboxBootGeneration,
    connection: String,
    profile: SshProfile,
    /// Explicit owner re-binding for cleanup only. Launch identity stays intact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cleanup_profile: Option<SshProfile>,
    host: RemoteHostId,
    program: String,
    endpoint: String,
    engine_sha256: Digest,
    memory_mib: u64,
    lifetime_seconds: u64,
    phase: Phase,
    observation: Option<RemoteVmObservation>,
    receipt: Option<Value>,
    detail: Option<String>,
}
impl Run {
    fn cleanup_profile(&self) -> &SshProfile {
        self.cleanup_profile.as_ref().unwrap_or(&self.profile)
    }
    fn view(&self) -> Value {
        json!({"run":self.run,"request_key":self.request_key,"parent":self.parent,"connection":self.connection,
            "host":self.profile.host,"port":self.profile.port,"phase":self.phase,
            "observation":self.observation,"receipt":self.receipt,"detail":self.detail,
            "launch":{"parent":self.parent,"connection":self.connection,"program":self.program,
                "endpoint":self.endpoint,"engine_sha256":self.engine_sha256,
                "memory_mib":self.memory_mib,"lifetime_seconds":self.lifetime_seconds},
            "archived":false,"billing":"externally_managed","server_power_changed":false,
            "trust":"owner_pinned_ssh_operator","credentials":"owner_file_on_home"})
    }
}

struct Work {
    request: RemoteManagementRequest,
    expires: Instant,
    reply: mpsc::SyncSender<Result<Value, String>>,
}
struct Entry {
    run: Mutex<Run>,
    stop: AtomicBool,
    finished: AtomicBool,
    sender: Mutex<Option<mpsc::SyncSender<Work>>>,
}
impl Entry {
    fn new(run: Run) -> Self {
        Self {
            run: Mutex::new(run),
            stop: AtomicBool::new(false),
            finished: AtomicBool::new(true),
            sender: Mutex::new(None),
        }
    }
    fn snapshot(&self) -> Run {
        self.run.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

pub(super) struct Manager {
    root: PathBuf,
    runs: Mutex<BTreeMap<Digest, Arc<Entry>>>,
    history: Mutex<history::History>,
    hosts: Mutex<BTreeMap<RemoteHostId, Arc<trust::Host>>>,
    failed: AtomicBool,
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    use std::io::Read;
    if !fs::symlink_metadata(path)
        .map_err(|e| e.to_string())?
        .is_file()
    {
        return Err("Remote journal must be a regular file.".into());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(MAX_JOURNAL + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_JOURNAL {
        return Err("Remote journal exceeds its bound.".into());
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| "Invalid remote journal; recovery was not bypassed.".into())
}

/// Temporary/non-record entries must never hide later live intents from recovery.
fn journal_paths(directory: &Path) -> Result<Vec<PathBuf>, String> {
    bounded_journal_paths(directory, MAX_RUNS)
}
fn bounded_journal_paths(directory: &Path, maximum: usize) -> Result<Vec<PathBuf>, String> {
    let mut paths = Vec::new();
    for (index, entry) in fs::read_dir(directory)
        .map_err(|e| e.to_string())?
        .enumerate()
    {
        if index >= maximum * 4 {
            return Err(
                "Remote journal directory exceeds its entry bound; recovery was not bypassed."
                    .into(),
            );
        }
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            paths.push(path);
            if paths.len() > maximum {
                return Err("Remote journal count exceeds its bound.".into());
            }
        }
    }
    Ok(paths)
}

fn owned_profile(app: &AppHandle, connection: &str) -> Result<SshProfile, String> {
    let state = app.state::<crate::store::PlatformStore>().snapshot()?;
    if !state.environments.iter().any(|e| {
        e.id == connection && e.provider == Some(crate::models::RuntimeProviderKind::CloudSsh)
    }) {
        return Err("Select an existing SSH connection owned by this engine.".into());
    }
    let profile = app
        .state::<crate::runtime::RuntimeManager>()
        .cloud
        .profile(connection)?;
    worker::preflight(&profile)?;
    Ok(profile)
}

impl Manager {
    fn open(p: &Production) -> Result<Arc<Self>, String> {
        let root = p
            .state_file
            .parent()
            .ok_or("No engine data directory")?
            .join("remote-home");
        fs::create_dir_all(root.join("runs")).map_err(|e| e.to_string())?;
        fs::create_dir_all(root.join("hosts")).map_err(|e| e.to_string())?;
        let (runs, history) = history::load(&root)?;
        let manager = Arc::new(Self {
            root,
            runs: Mutex::new(runs),
            history: Mutex::new(history),
            hosts: Mutex::new(BTreeMap::new()),
            failed: AtomicBool::new(false),
        });
        // An interrupted trust check cannot be forgotten by a restart. Recovery
        // may clean up over the old pin, but it never grants or silently resumes.
        let interrupted: Vec<Run> = manager
            .runs
            .lock()
            .map_err(|_| "Remote lock unavailable")?
            .values()
            .map(|e| e.snapshot())
            .filter(|r| !r.phase.terminal())
            .collect();
        for run in interrupted {
            let host = manager.host(run.cleanup_profile(), None, p.clock.now(), true)?;
            host.require_review()?;
        }
        Ok(manager)
    }
    fn path(&self, run: Digest) -> PathBuf {
        self.root
            .join("runs")
            .join(format!("{}.json", run.to_hex()))
    }
    fn save(&self, run: &Run) -> Result<(), String> {
        let bytes = serde_json::to_vec(run).map_err(|e| e.to_string())?;
        if bytes.len() as u64 > MAX_JOURNAL {
            return Err("Remote journal exceeds its bound.".into());
        }
        let result = write_atomic(&self.path(run.run), &bytes).map_err(|e| e.to_string());
        if result.is_err() {
            self.failed.store(true, Ordering::Release)
        }
        result
    }
    fn update(&self, entry: &Entry, change: impl FnOnce(&mut Run)) -> Result<(), String> {
        let mut run = entry
            .run
            .lock()
            .map_err(|_| "Remote run lock unavailable")?;
        let mut next = run.clone();
        change(&mut next);
        self.save(&next)?;
        *run = next;
        Ok(())
    }
    fn entry(&self, run: Digest) -> Result<Arc<Entry>, String> {
        self.runs
            .lock()
            .map_err(|_| "Remote lock unavailable")?
            .get(&run)
            .cloned()
            .ok_or("Unknown remote run.".into())
    }
    fn dispatch(
        self: &Arc<Self>,
        p: Arc<Production>,
        app: &AppHandle,
        request: Request,
    ) -> Result<Value, String> {
        match request {
            Request::Trust {
                connection,
                accept_host_key,
            } => {
                let profile = owned_profile(app, &connection)?;
                self.confirm_host(p, &profile, &accept_host_key)
            }
            Request::Launch {
                request_key,
                connection,
                parent,
                program,
                endpoint,
                engine_sha256,
                accept_host_key,
                memory_mib,
                lifetime_seconds,
            } => {
                // Serialize lookup with creation. Reporting an old effect does not
                // need a live parent, a working SSH key or fresh grant authority.
                let mut runs = self.runs.lock().map_err(|_| "Remote lock unavailable")?;
                if let Some(key) = request_key {
                    if let Some((previous, archived)) = self.find_request(&runs, key)? {
                        if previous.parent != parent
                            || previous.connection != connection
                            || previous.program != program
                            || previous.endpoint != endpoint
                            || previous.engine_sha256 != engine_sha256
                            || previous.memory_mib != memory_mib
                            || previous.lifetime_seconds != lifetime_seconds
                        {
                            return Err("This request key already belongs to a different remote launch; no new work was started.".into());
                        }
                        return Ok(history::view(&previous, archived));
                    }
                }
                if p.shutdown.is_cancelled() {
                    return Err("The engine is shutting down.".into());
                }
                if self.failed.load(Ordering::Acquire) {
                    return Err(
                        "Remote journal persistence failed; new authority is blocked.".into(),
                    );
                }
                if !(320..=65536).contains(&memory_mib) || !(30..=86400).contains(&lifetime_seconds)
                {
                    return Err("Remote launch needs 320..65536 MiB and 30..86400 seconds.".into());
                }
                crate::sandbox_contract::remote::ProgramPath::new(&program)
                    .map_err(|e| e.to_string())?;
                if endpoint.is_empty()
                    || endpoint.len() > 1024
                    || endpoint.chars().any(char::is_control)
                {
                    return Err("Invalid remote engine endpoint.".into());
                }
                // A real current ready parent is mandatory, checked again by issue/renew.
                let _authority = p.service.delegation(&parent).map_err(|e| e.to_string())?;
                let boot = p
                    .service
                    .status()
                    .into_iter()
                    .find(|s| s.sandbox == parent)
                    .and_then(|s| s.boot)
                    .ok_or("Parent VM has no current boot.")?;
                let profile = owned_profile(app, &connection)?;
                let (instance, _) = trust::target(&profile)?;
                if runs.len() >= MAX_RUNS
                    || runs
                        .values()
                        .filter(|e| !e.snapshot().phase.terminal())
                        .count()
                        >= MAX_LIVE
                {
                    return Err("Remote active-record or concurrent-worker bound reached. Archive confirmed ended runs with sandbox remote archive; unfinished recovery records are retained.".into());
                }
                let host = self.host(&profile, accept_host_key.as_deref(), p.clock.now(), false)?;
                host.check_new()?;
                let run = Run {
                    version: 1,
                    request_key,
                    run: digest(
                        "yougori/remote-home/run/v1",
                        &[uuid::Uuid::new_v4().as_bytes()],
                    ),
                    parent,
                    parent_boot: boot,
                    connection,
                    profile,
                    cleanup_profile: None,
                    host: instance.host(),
                    program,
                    endpoint,
                    engine_sha256,
                    memory_mib,
                    lifetime_seconds,
                    phase: Phase::Starting,
                    observation: None,
                    receipt: None,
                    detail: None,
                };
                self.save(&run)?;
                let entry = Arc::new(Entry::new(run));
                runs.insert(entry.snapshot().run, entry.clone());
                drop(runs);
                self.spawn(p, entry.clone(), false)?;
                Ok(entry.snapshot().view())
            }
            Request::Status {
                run,
                request_key,
                archived,
                after,
            } => self.status(run, request_key, archived, after),
            Request::Archive { run } => self.archive(run),
            Request::Stop { run } | Request::Reconcile { run } => {
                // Serialize writes with archive. A caller that fetched an old Arc
                // must not recreate its active journal after it was archived.
                let runs = self.runs.lock().map_err(|_| "Remote lock unavailable")?;
                let entry = match runs.get(&run) {
                    Some(entry) => entry.clone(),
                    None => {
                        return self
                            .history
                            .lock()
                            .map_err(|_| "Remote history lock unavailable")?
                            .records
                            .get(&run)
                            .map(|r| history::view(r, true))
                            .ok_or("Unknown remote run.".into())
                    }
                };
                if entry.snapshot().phase.terminal() {
                    return Ok(entry.snapshot().view());
                }
                entry.stop.store(true, Ordering::Release);
                self.update(&entry, |r| {
                    if !r.phase.terminal() {
                        r.phase = Phase::Stopping;
                    }
                })?;
                drop(runs);
                if !entry.snapshot().phase.terminal() && entry.finished.load(Ordering::Acquire) {
                    self.spawn(p, entry.clone(), true)?;
                }
                Ok(entry.snapshot().view())
            }
            other => {
                let run = match &other {
                    Request::Start { run, .. }
                    | Request::Outcome { run, .. }
                    | Request::Cancel { run, .. } => *run,
                    _ => unreachable!(),
                };
                let entry = self.entry(run)?;
                let snapshot = entry.snapshot();
                if snapshot.phase != Phase::Ready || entry.stop.load(Ordering::Acquire) {
                    return Err("Remote VM is not accepting work; inspect its status.".into());
                }
                let binding = snapshot
                    .observation
                    .ok_or("Remote VM has no binding")?
                    .binding;
                let request = match other {
                    Request::Start {
                        input_hex,
                        timeout_seconds,
                        output_bytes,
                        ..
                    } => {
                        if input_hex.len() > 512 * 1024
                            || !(1..=3600).contains(&timeout_seconds)
                            || !(1..=512 * 1024).contains(&output_bytes)
                        {
                            return Err("Remote command exceeds its bounds.".into());
                        }
                        RemoteManagementRequest::Start {
                            binding,
                            input_hex,
                            deadline_seconds: timeout_seconds,
                            output_bytes,
                        }
                    }
                    Request::Outcome { command, .. } => {
                        RemoteManagementRequest::Outcome { binding, command }
                    }
                    Request::Cancel { command, .. } => {
                        RemoteManagementRequest::Cancel { binding, command }
                    }
                    _ => unreachable!(),
                };
                let (send, receive) = mpsc::sync_channel(1);
                let guard = entry
                    .sender
                    .lock()
                    .map_err(|_| "Remote command lock unavailable")?;
                guard
                    .as_ref()
                    .ok_or("Remote worker ended")?
                    .try_send(Work {
                        request,
                        expires: Instant::now() + Duration::from_secs(4),
                        reply: send,
                    })
                    .map_err(|_| "Remote worker is busy or ended; this request was not queued.")?;
                drop(guard);
                receive
                    .recv_timeout(Duration::from_secs(8))
                    .map_err(|_| "Remote reply is uncertain; do not repeat a workload command.")?
            }
        }
    }
}

impl Production {
    pub(super) fn remote_home(self: &Arc<Self>) -> Result<Arc<Manager>, String> {
        self.remote_home.get_or_init(|| Manager::open(self)).clone()
    }
}

pub(super) async fn dispatch(
    p: Arc<Production>,
    app: AppHandle,
    params: Value,
) -> Result<Value, String> {
    let mut params = params;
    params
        .as_object_mut()
        .ok_or("Remote request must be an object")?
        .remove("action");
    let request: Request =
        serde_json::from_value(params).map_err(|_| "Invalid remote sandbox request.")?;
    tokio::task::spawn_blocking(move || p.remote_home()?.dispatch(p, &app, request))
        .await
        .map_err(|e| e.to_string())?
}

#[cfg(not(test))]
pub(super) async fn resume_if_needed(app: AppHandle) {
    let pending = (|| -> Result<bool, String> {
        let directory = crate::acceptance::app_data(&app)?
            .join(DATA_DIRECTORY)
            .join("remote-home/runs");
        if !directory.exists() {
            return Ok(false);
        }
        for path in journal_paths(&directory)? {
            let run: Run = read_json(&path)?;
            if !run.phase.terminal() {
                return Ok(true);
            }
        }
        Ok(false)
    })();
    match pending {
        Ok(true) => {
            if let Err(error) = production(&app).await {
                eprintln!(
                    "Remote VM cleanup needs attention: {}",
                    crate::lifecycle::safe_diagnostic(&error)
                );
            }
        }
        Err(error) => eprintln!(
            "Remote VM recovery record needs attention: {}",
            crate::lifecycle::safe_diagnostic(&error)
        ),
        Ok(false) => {}
    }
}

#[cfg(test)]
mod recovery_tests {
    use super::*;
    #[test]
    fn leftover_temporary_files_cannot_hide_a_live_journal() {
        let directory = tempfile::tempdir().unwrap();
        for index in 0..MAX_RUNS + 10 {
            fs::write(
                directory.path().join(format!("leftover-{index}.tmp")),
                b"not committed",
            )
            .unwrap();
        }
        let live = directory.path().join("active.json");
        fs::write(&live, b"{}").unwrap();
        assert_eq!(journal_paths(directory.path()).unwrap(), vec![live]);
        for index in MAX_RUNS + 10..MAX_RUNS * 4 + 1 {
            fs::write(
                directory.path().join(format!("leftover-{index}.tmp")),
                b"not committed",
            )
            .unwrap();
        }
        assert!(journal_paths(directory.path()).is_err());
    }
}
