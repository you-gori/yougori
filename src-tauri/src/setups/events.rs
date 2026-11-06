//! **Run on an event** (`run.events`): a job that says `trigger:` runs again when its own address
//! is called, or when the folder it reads changes.
//!
//! Each job with `trigger: {webhook: …}` gets an address of its own on this computer, with a long
//! random part in its path that only the setup's owner can read (a private output, `event_url`).
//! Who can reach it is what the template asked: programs on this computer (`private`, 127.0.0.1),
//! computers of this local network (`lan`, where anything from outside private, link-local and
//! loopback addresses is dropped before a byte is read), or anyone with the link (`quick`, a free
//! HTTPS link through Cloudflare). A `POST` to it runs the job once more; anything else is told
//! no. A job with `source_changes: true` runs again when a file is added, changed or removed in the
//! folder the person chose for it, looked at every thirty seconds.
//!
//! What an event does is always the same and always bounded: one more run of that job, never two
//! at once (one attempt at a time on this computer), never sooner than ten seconds after the
//! last, and never while the setup is stopped: a person who stopped it is not overruled by a
//! call. The body of a call is read, bounded, and not kept. The address goes when the job does,
//! and its secret part with it.
use super::jobs::Jobs;
use super::model::{Desired, Lifecycle};
use super::ordinary::BoxFuture;
use super::service::Service;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::io::AsyncWriteExt;
use yougori_setup::resource::Kind;

/// The least time between two runs one job's events start.
pub(crate) const SPACING: Duration = Duration::from_secs(10);
/// How often a watched folder is looked at.
const FOLDER_EVERY: Duration = Duration::from_secs(30);
/// The most files of a watched folder looked at, so a huge folder can't hold the watcher up.
const FOLDER_FILES: usize = 20_000;

/// Where a job's event address listens on this computer: the same for every change to the setup,
/// different for each setup and job, and clear of the ports of setups' services (20000-39999).
pub(crate) fn event_port(setup: &str, resource: &str) -> u16 {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(format!("{setup}/{resource}/event").as_bytes());
    40000 + u16::from_be_bytes([digest[0], digest[1]]) % 10000
}

/// Where a job's secret part is kept in this computer's credential vault.
fn token_account(setup: &str, resource: &str) -> String {
    format!("setup-events.{setup}.{resource}")
}

fn key(setup: &str, resource: &str) -> String {
    format!("{setup}/{resource}")
}

/// Whether two secrets are the same, taking as long either way.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0_u8, |seen, (x, y)| seen | (x ^ y)) == 0
}

/// What a folder holds, as far as noticing a change goes: every file's path, size and time.
pub(crate) fn fingerprint(folder: &Path) -> Option<u64> {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    let mut seen = 0_usize;
    let mut stack = vec![folder.to_path_buf()];
    while let Some(next) = stack.pop() {
        let mut entries: Vec<_> = std::fs::read_dir(&next).ok()?.flatten().collect();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let Ok(meta) = entry.metadata() else { continue };
            // A link is not followed: a watched folder never reaches outside itself.
            if meta.file_type().is_symlink() {
                continue;
            }
            entry.path().strip_prefix(folder).ok()?.hash(&mut hasher);
            if meta.is_dir() {
                stack.push(entry.path());
            } else {
                meta.len().hash(&mut hasher);
                meta.modified().ok().and_then(|at| at.duration_since(std::time::UNIX_EPOCH).ok()).map(|at| at.as_millis()).hash(&mut hasher);
            }
            seen += 1;
            if seen >= FOLDER_FILES {
                return Some(hasher.finish());
            }
        }
    }
    Some(hasher.finish())
}

/// One job's open address.
struct Hook {
    access: String,
    url: String,
    task: tokio::task::JoinHandle<()>,
    tunnel: Option<crate::workspace::cloudflare::Started>,
}

impl Drop for Hook {
    fn drop(&mut self) {
        self.task.abort();
        if let Some(tunnel) = self.tunnel.as_mut() {
            let _ = tunnel.child.start_kill();
            tunnel.logs.abort();
        }
    }
}

/// What opens a public link to a port on this computer. The engine's Cloudflare tunnel; nothing
/// in tests, where `quick` is refused.
pub(crate) trait Tunnels: Send + Sync {
    fn open<'a>(&'a self, port: u16) -> BoxFuture<'a, Result<crate::workspace::cloudflare::Started, String>>;
}

pub(crate) struct EngineTunnels {
    pub app: crate::AppHandle,
}

impl Tunnels for EngineTunnels {
    fn open<'a>(&'a self, port: u16) -> BoxFuture<'a, Result<crate::workspace::cloudflare::Started, String>> {
        Box::pin(async move {
            use tauri::Manager;
            let workspace = self.app.state::<crate::workspace::WorkspaceManager>();
            let root = workspace.storage_directory().to_path_buf();
            let executable = crate::workspace::cloudflared(&root).await?;
            crate::workspace::cloudflare::start(&executable, &root, port, None).await
        })
    }
}

/// Every job's event address and watched folder, and the runs they start.
#[derive(Clone)]
pub(crate) struct Events(Arc<Inner>);

struct Inner {
    service: Arc<Service>,
    jobs: Jobs,
    tunnels: Option<Arc<dyn Tunnels>>,
    hooks: Mutex<BTreeMap<String, Hook>>,
    folders: Mutex<BTreeMap<String, (PathBuf, Option<u64>)>>,
    last: Mutex<BTreeMap<String, Instant>>,
    /// Each job's event address, for its outputs (`event_url`).
    urls: Arc<Mutex<BTreeMap<String, String>>>,
    /// The secrets of this engine's run, by job, when the vault can't be reached (tests).
    tokens: Mutex<BTreeMap<String, String>>,
    vault: bool,
}

/// Why an event did not start a run, as the call is answered.
#[derive(Debug, PartialEq)]
pub(crate) struct Refused {
    pub status: u16,
    pub message: String,
}

impl Events {
    pub(crate) fn new(service: Arc<Service>, jobs: Jobs, tunnels: Option<Arc<dyn Tunnels>>, urls: Arc<Mutex<BTreeMap<String, String>>>, vault: bool) -> Events {
        Events(Arc::new(Inner {
            service,
            jobs,
            tunnels,
            hooks: Mutex::default(),
            folders: Mutex::default(),
            last: Mutex::default(),
            urls,
            tokens: Mutex::default(),
            vault,
        }))
    }

    fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The job's secret part: made the first time, kept in the vault after.
    fn token(&self, setup: &str, resource: &str) -> Result<String, String> {
        let account = token_account(setup, resource);
        if !self.0.vault {
            return Ok(Self::lock(&self.0.tokens).entry(account).or_insert_with(|| format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple())).clone());
        }
        if let Some(held) = crate::projects::secrets::resolve_bytes(&account)?.and_then(|bytes| String::from_utf8(bytes).ok()).filter(|token| token.len() == 64) {
            return Ok(held);
        }
        let token = format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple());
        crate::projects::secrets::store_bytes(&account, token.as_bytes())?;
        Ok(token)
    }

    fn forget_token(&self, setup: &str, resource: &str) {
        let account = token_account(setup, resource);
        if self.0.vault {
            let _ = crate::projects::secrets::forget(&account);
        } else {
            Self::lock(&self.0.tokens).remove(&account);
        }
    }

    /// The address a job's events come to, while it is open.
    #[cfg(test)]
    pub(crate) fn url(&self, setup: &str, resource: &str) -> Option<String> {
        Self::lock(&self.0.urls).get(&key(setup, resource)).cloned()
    }

    /// Makes the setup's open addresses and watched folders match what its jobs say now. Called
    /// after every change to the setup, and for every setup when the engine starts.
    pub(crate) async fn sync(&self, setup: &str) {
        let (exists, wanted) = self
            .0
            .service
            .observe(|registry| {
                let Some(instance) = registry.instances.get(setup).filter(|instance| instance.lifecycle != Lifecycle::Removed) else { return Ok((false, Vec::new())) };
                Ok((
                    true,
                    instance
                        .resources
                        .values()
                        .filter(|resource| resource.kind == Kind::Job && !resource.borrowed() && resource.desired != Desired::Absent && resource.runtime_id.is_some())
                        .filter(|resource| resource.spec["trigger"].is_object())
                        .map(|resource| (resource.id.clone(), resource.spec.clone()))
                        .collect::<Vec<_>>(),
                ))
            })
            .unwrap_or((false, Vec::new()));
        let prefix = format!("{setup}/");
        // Addresses and folders of jobs that no longer ask for them close.
        let hooked: Vec<(String, String)> = wanted.iter().filter_map(|(id, spec)| spec["trigger"]["webhook"]["access"].as_str().map(|access| (id.clone(), access.to_owned()))).collect();
        let stale: Vec<String> = Self::lock(&self.0.hooks)
            .iter()
            .filter(|(key, hook)| key.starts_with(&prefix) && !hooked.iter().any(|(id, access)| **key == self::key(setup, id) && hook.access == *access))
            .map(|(key, _)| key.clone())
            .collect();
        for gone in stale {
            Self::lock(&self.0.hooks).remove(&gone);
            Self::lock(&self.0.urls).remove(&gone);
            let resource = gone.trim_start_matches(&prefix).to_owned();
            if !hooked.iter().any(|(id, _)| *id == resource) {
                self.forget_token(setup, &resource);
            }
        }
        if !exists {
            // A removed setup's secrets go with it.
            Self::lock(&self.0.folders).retain(|key, _| !key.starts_with(&prefix));
            return;
        }
        for (resource, access) in hooked {
            if Self::lock(&self.0.hooks).contains_key(&key(setup, &resource)) {
                continue;
            }
            match self.open(setup, &resource, &access).await {
                Ok(hook) => {
                    Self::lock(&self.0.urls).insert(key(setup, &resource), hook.url.clone());
                    Self::lock(&self.0.hooks).insert(key(setup, &resource), hook);
                }
                Err(error) => eprintln!("A job's event address could not be opened: {error}"),
            }
        }
        let watched: Vec<(String, PathBuf)> = wanted
            .iter()
            .filter(|(_, spec)| spec["trigger"]["source_changes"].as_bool() == Some(true))
            .filter_map(|(id, spec)| spec["source_folder"].as_str().map(|folder| (id.clone(), PathBuf::from(folder))))
            .collect();
        let mut folders = Self::lock(&self.0.folders);
        folders.retain(|key, (folder, _)| !key.starts_with(&prefix) || watched.iter().any(|(id, path)| *key == self::key(setup, id) && path == folder));
        for (resource, folder) in watched {
            folders.entry(key(setup, &resource)).or_insert_with(|| {
                let seen = fingerprint(&folder);
                (folder, seen)
            });
        }
    }

    /// Opens one job's address: a listener here, and a public link to it for `quick`.
    async fn open(&self, setup: &str, resource: &str, access: &str) -> Result<Hook, String> {
        let token = self.token(setup, resource)?;
        let port = event_port(setup, resource);
        let network = access == "lan";
        let listener = tokio::net::TcpListener::bind((if network { "0.0.0.0" } else { "127.0.0.1" }, port))
            .await
            .map_err(|error| format!("port {port} on this computer is taken ({error})"))?;
        let events = self.clone();
        let (setup_id, resource_id, secret) = (setup.to_owned(), resource.to_owned(), token.clone());
        let task = tokio::spawn(async move { events.serve(listener, network, setup_id, resource_id, secret).await });
        let (url, tunnel) = match access {
            "quick" => {
                let tunnels = self.0.tunnels.clone().ok_or("a public link can't be opened here")?;
                let started = match tunnels.open(port).await {
                    Ok(started) => started,
                    Err(error) => {
                        task.abort();
                        return Err(error);
                    }
                };
                (format!("{}/event/{token}", started.url.trim_end_matches('/')), Some(started))
            }
            "lan" => (format!("http://{}:{port}/event/{token}", crate::workspace::lan_address()), None),
            _ => (format!("http://127.0.0.1:{port}/event/{token}"), None),
        };
        Ok(Hook { access: access.to_owned(), url, task, tunnel })
    }

    /// Answers calls to one job's address until it is closed.
    async fn serve(self, listener: tokio::net::TcpListener, network: bool, setup: String, resource: String, token: String) {
        let mut clients = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((mut socket, peer)) = accepted else { tokio::time::sleep(Duration::from_millis(100)).await; continue };
                    // Only this computer, or only this network: nothing else is read at all.
                    if (network && !crate::workspace::private_peer(peer.ip())) || (!network && !peer.ip().is_loopback()) || clients.len() >= 16 {
                        continue;
                    }
                    let (events, setup, resource, token) = (self.clone(), setup.clone(), resource.clone(), token.clone());
                    clients.spawn(async move {
                        let Ok(Ok((header, _body))) = tokio::time::timeout(Duration::from_secs(10), crate::host_files::read_http(&mut socket)).await else { return };
                        let (status, body) = events.answer(&setup, &resource, &token, &header).await;
                        let body = serde_json::to_vec(&body).unwrap_or_default();
                        let head = format!("HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n", reason(status), body.len());
                        let _ = tokio::time::timeout(Duration::from_secs(10), async {
                            socket.write_all(head.as_bytes()).await?;
                            socket.write_all(&body).await
                        })
                        .await;
                    });
                }
                _ = clients.join_next(), if !clients.is_empty() => {}
            }
        }
    }

    /// The answer to one call: only `POST /event/SECRET` runs the job.
    pub(crate) async fn answer(&self, setup: &str, resource: &str, token: &str, header: &str) -> (u16, Value) {
        let mut words = header.lines().next().unwrap_or_default().split(' ');
        let (method, path) = (words.next().unwrap_or_default(), words.next().unwrap_or_default());
        let given = path.split('?').next().unwrap_or_default().strip_prefix("/event/").unwrap_or_default();
        if !same(given, token) {
            return (404, json!({"error": "Nothing is here."}));
        }
        if method != "POST" {
            return (405, json!({"error": "Send a POST to run the job."}));
        }
        match self.fire(setup, resource, "a call to its address").await {
            Ok(job) => (202, json!({"accepted": true, "run": job})),
            Err(refused) => (refused.status, json!({"error": refused.message})),
        }
    }

    /// One more run of the job, if the setup is running and the last run an event started is not
    /// too recent. Answers the new run's ID in the setup's jobs.
    pub(crate) async fn fire(&self, setup: &str, resource: &str, why: &str) -> Result<String, Refused> {
        let found = self
            .0
            .service
            .observe(|registry| {
                let instance = registry.instances.get(setup);
                let lifecycle = instance.map(|instance| instance.lifecycle);
                let job = instance.and_then(|instance| instance.resources.get(resource)).filter(|job| job.kind == Kind::Job && job.desired != Desired::Absent).map(|job| job.spec.clone());
                let environment = job.as_ref().and_then(|spec| spec["compute"]["resource"].as_str()).and_then(|id| instance.and_then(|instance| instance.resources.get(id))).filter(|peer| peer.kind == Kind::Environment).map(|peer| peer.spec.clone());
                Ok((lifecycle, job, environment))
            })
            .unwrap_or((None, None, None));
        let (lifecycle, Some(spec), environment) = found else {
            return Err(Refused { status: 404, message: "Nothing is here.".into() });
        };
        if lifecycle != Some(Lifecycle::Running) {
            return Err(Refused { status: 409, message: "The setup is stopped, so its job doesn't run. Start the setup first.".into() });
        }
        // A daily limit counts the runs events started in the last day.
        if let Some(most) = spec["trigger"]["per_day"].as_u64() {
            let since = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|now| now.as_secs() as i64).unwrap_or_default() - 86_400;
            let today = self.0.jobs.runs(setup, resource).await.iter().filter(|run| run["at"].as_i64().is_some_and(|at| at >= since)).count() as u64;
            if today >= most {
                return Err(Refused { status: 429, message: format!("It has run {today} times in the last day, which is its limit. It can run again later.") });
            }
        }
        {
            let mut last = Self::lock(&self.0.last);
            let key = key(setup, resource);
            if last.get(&key).is_some_and(|at| at.elapsed() < SPACING) {
                return Err(Refused { status: 429, message: format!("It ran less than {} seconds ago. Try again in a moment.", SPACING.as_secs()) });
            }
            last.insert(key, Instant::now());
        }
        let event = format!("{}", uuid::Uuid::new_v4().simple());
        self.0
            .jobs
            .run_again(setup, resource, &spec, environment.as_ref(), &event, why)
            .await
            .map_err(|error| Refused { status: 503, message: crate::lifecycle::safe_diagnostic(&error) })
    }

    /// Looks at every watched folder and runs the job of each one that changed.
    pub(crate) async fn look_at_folders(&self) -> Vec<String> {
        let folders: Vec<(String, PathBuf, Option<u64>)> = Self::lock(&self.0.folders).iter().map(|(key, (folder, seen))| (key.clone(), folder.clone(), *seen)).collect();
        let mut ran = Vec::new();
        for (key, folder, seen) in folders {
            let now = fingerprint(&folder);
            if now == seen || now.is_none() {
                continue;
            }
            if let Some(entry) = Self::lock(&self.0.folders).get_mut(&key) {
                entry.1 = now;
            }
            let Some((setup, resource)) = key.split_once('/') else { continue };
            if self.fire(setup, resource, "a change in its folder").await.is_ok() {
                ran.push(key.clone());
            }
        }
        ran
    }

    /// Looks at watched folders every thirty seconds until the engine closes.
    pub(crate) async fn run(self, stopping: tokio_util::sync::CancellationToken) {
        loop {
            tokio::select! {
                _ = stopping.cancelled() => return,
                _ = tokio::time::sleep(FOLDER_EVERY) => {}
            }
            self.look_at_folders().await;
        }
    }
}

/// What the service calls after every change to a setup, so its jobs' addresses follow it.
impl super::service::EventsSync for Events {
    fn sync<'a>(&'a self, setup: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move { Events::sync(self, setup).await })
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        202 => "Accepted",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        429 => "Too Many Requests",
        _ => "Service Unavailable",
    }
}
