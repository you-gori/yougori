//! Session-scoped, read-only publication of a verified portable environment copy.
//! The public listener can serve only a landing page and one immutable artifact.
use crate::{local_backup, models::EnvironmentStatus, runtime::RuntimeManager, store::PlatformStore,
    workspace::{cloudflare, WorkspaceManager}, AppHandle};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::{Path, PathBuf}, sync::Arc, time::{Duration, Instant}};
use tauri::{Manager, State};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}, sync::{Mutex, Semaphore}, task::JoinHandle};
use tokio_util::sync::CancellationToken;

const LEASE: Duration = Duration::from_secs(120);

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StartRequest {
    pub environment_id: String,
    pub owner_id: String,
    pub domain: Option<String>,
    pub process_id: Option<u32>,
}

pub(crate) fn validate(request: &StartRequest) -> Result<(), String> {
    if uuid::Uuid::parse_str(&request.owner_id).is_err() || request.process_id == Some(0) {
        return Err("Invalid download-link owner".into());
    }
    if request.environment_id.is_empty() || request.environment_id.len() > 128 {
        return Err("Invalid environment ID".into());
    }
    Ok(())
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadInfo {
    environment_id: String,
    active: bool,
    url: Option<String>,
    domain: Option<String>,
    size_bytes: u64,
    downloads: u64,
}

struct Live {
    info: DownloadInfo,
    owner: String,
    process: (u32, u64),
    seen: Instant,
    cancel: CancellationToken,
    task: JoinHandle<()>,
    tunnel: cloudflare::Started,
    _temporary: tempfile::TempDir,
}
impl Drop for Live {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
        self.tunnel.logs.abort();
        // cloudflared uses kill_on_drop, including when the engine is closed.
    }
}

pub struct Downloads {
    root: PathBuf,
    operations: Mutex<()>,
    live: Mutex<HashMap<String, Live>>,
    pending: std::sync::Mutex<HashMap<String, CancellationToken>>,
    generations: std::sync::Mutex<HashMap<String, u64>>,
}
struct Pending<'a> { id: String, registry: &'a std::sync::Mutex<HashMap<String, CancellationToken>> }
impl Drop for Pending<'_> {
    fn drop(&mut self) { if let Ok(mut pending) = self.registry.lock() { pending.remove(&self.id); } }
}
impl Downloads {
    pub fn new(root: &Path) -> Self {
        let root = root.join("environment-downloads");
        clean_stale_copies(&root);
        Self { root, operations: Mutex::new(()), live: Mutex::new(HashMap::new()), pending: std::sync::Mutex::new(HashMap::new()), generations: std::sync::Mutex::new(HashMap::new()) }
    }
    pub async fn shutdown(&self) {
        if let Ok(mut generations) = self.generations.lock() { for generation in generations.values_mut() { *generation = generation.wrapping_add(1); } }
        if let Ok(pending) = self.pending.lock() { for token in pending.values() { token.cancel(); } }
        self.live.lock().await.clear();
    }
    async fn cleanup(&self, store: &PlatformStore) {
        let environments = store.snapshot().map(|s| s.environments).unwrap_or_default();
        let mut live = self.live.lock().await;
        live.retain(|id, link| {
            link.seen.elapsed() < LEASE && process_identity(link.process.0) == Some(link.process.1)
                && environments.iter().any(|environment| &environment.id == id)
                && !link.task.is_finished() && matches!(link.tunnel.child.try_wait(), Ok(None))
        });
    }
    pub(crate) async fn list(&self, store: &PlatformStore) -> Result<Vec<DownloadInfo>, String> {
        self.cleanup(store).await;
        let state = store.snapshot()?;
        let live = self.live.lock().await;
        Ok(state.environments.iter().map(|environment| {
            let mut info = live.get(&environment.id).map(|link| link.info.clone()).unwrap_or(DownloadInfo {
                environment_id: environment.id.clone(), active: false, url: None, domain: None, size_bytes: 0, downloads: 0,
            });
            info.downloads = state.environment_downloads.get(&environment.id).copied().unwrap_or(0);
            info
        }).collect())
    }
    pub(crate) async fn keep_alive(&self, owner_id: &str, store: &PlatformStore) -> Result<Vec<DownloadInfo>, String> {
        // Expired links cannot be revived by a late heartbeat.
        self.cleanup(store).await;
        for link in self.live.lock().await.values_mut().filter(|link| link.owner == owner_id) { link.seen = Instant::now(); }
        self.list(store).await
    }
    pub(crate) async fn stop(&self, environment_id: &str) {
        if let Ok(mut generations) = self.generations.lock() { let generation = generations.entry(environment_id.into()).or_default(); *generation = generation.wrapping_add(1); }
        if let Ok(pending) = self.pending.lock() { if let Some(token) = pending.get(environment_id) { token.cancel(); } }
        self.live.lock().await.remove(environment_id);
    }
    pub(crate) async fn start(&self, request: StartRequest, app: &AppHandle) -> Result<DownloadInfo, String> {
        self.start_generated(request, None, app).await
    }
    pub(crate) fn queued_generation(&self, id: &str) -> Result<u64, String> {
        Ok(*self.generations.lock().map_err(|_| "Download preparation is unavailable")?.entry(id.into()).or_default())
    }
    fn prepare(&self, request: &StartRequest, expected: Option<u64>) -> Result<CancellationToken, String> {
        validate(&request)?;
        // Linearize queued requests with Off before starting any export. Keep
        // this lock until the pending token is registered, so Off cannot miss it.
        let mut generations = self.generations.lock().map_err(|_| "Download preparation is unavailable")?;
        let generation = *generations.entry(request.environment_id.clone()).or_default();
        if expected.is_some_and(|expected| expected != generation) { return Err("Download link creation was cancelled.".into()); }
        let preparing = CancellationToken::new();
        {
            let mut pending = self.pending.lock().map_err(|_| "Download preparation is unavailable")?;
            if pending.contains_key(&request.environment_id) { return Err("A download copy is already being prepared for this environment.".into()); }
            pending.insert(request.environment_id.clone(), preparing.clone());
        }
        Ok(preparing)
    }
    pub(crate) async fn start_generated(&self, request: StartRequest, generation: Option<u64>, app: &AppHandle) -> Result<DownloadInfo, String> {
        let preparing = self.prepare(&request, generation)?;
        let _pending = Pending { id: request.environment_id.clone(), registry: &self.pending };
        let _serial = self.operations.lock().await;
        if preparing.is_cancelled() { return Err("Download link creation was cancelled.".into()); }
        let store = app.state::<PlatformStore>();
        self.cleanup(&store).await;
        if self.live.lock().await.contains_key(&request.environment_id) {
            return Err("This environment already has a download link. Turn it off before creating another one.".into());
        }
        let environment = store.environment(&request.environment_id)?;
        if environment.status != EnvironmentStatus::Stopped { return Err("Stop the environment before making its complete, consistent download copy.".into()); }
        let pid = request.process_id.unwrap_or(std::process::id());
        let identity = process_identity(pid).ok_or("The app or CLI creating this link is no longer running")?;
        tokio::fs::create_dir_all(&self.root).await.map_err(|e| e.to_string())?;
        let temporary = tempfile::Builder::new().prefix("session-").tempdir_in(&self.root).map_err(|e| e.to_string())?;
        let engine_pid = std::process::id();
        let engine_identity = process_identity(engine_pid).ok_or("Cannot identify the running engine")?;
        std::fs::write(temporary.path().join("owner.json"), serde_json::to_vec(&(engine_pid, engine_identity)).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        let manifest = local_backup::export_backup(request.environment_id.clone(), temporary.path().to_string_lossy().into_owned(),
            &store, &app.state::<RuntimeManager>()).await?;
        let artifact = temporary.path().join("environment.yougori");
        let destination = artifact.clone();
        let size = tokio::task::spawn_blocking(move || {
            let manifest = Path::new(&manifest);
            let size = local_backup::pack_download(manifest, &destination)?;
            // The verified single-file copy replaces the intermediate export.
            std::fs::remove_dir_all(manifest.parent().ok_or("Missing private export folder")?).map_err(|e| e.to_string())?;
            Ok::<u64, String>(size)
        })
            .await.map_err(|e| e.to_string())??;
        if preparing.is_cancelled() { return Err("Download link creation was cancelled. No link was published.".into()); }
        if process_identity(pid) != Some(identity) { return Err("The CLI closed while preparing the copy. No download link was published.".into()); }
        let manager = app.state::<WorkspaceManager>();
        let (listener, tunnel) = manager.download_tunnel(request.domain.as_deref(), &store).await?;
        let token = uuid::Uuid::new_v4().simple().to_string();
        let url = format!("{}/{}", tunnel.url, token);
        let cancel = CancellationToken::new();
        let task = serve(listener, artifact, size, environment.name, token, request.environment_id.clone(), app.clone(), cancel.clone());
        let info = DownloadInfo { environment_id: request.environment_id.clone(), active: true, url: Some(url), domain: request.domain,
            size_bytes: size, downloads: store.snapshot()?.environment_downloads.get(&request.environment_id).copied().unwrap_or(0) };
        let mut live = self.live.lock().await;
        if preparing.is_cancelled() { cancel.cancel(); task.abort(); return Err("Download link creation was cancelled.".into()); }
        live.insert(request.environment_id, Live { info: info.clone(), owner: request.owner_id, process: (pid, identity),
            seen: Instant::now(), cancel, task, tunnel, _temporary: temporary });
        Ok(info)
    }
}

fn process_identity(pid: u32) -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        // Kernel start ticks are stable. Converting uptime to wall-clock time
        // can round differently across refreshes and falsely expire a lease.
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let fields = stat.rsplit_once(')')?.1;
        if matches!(fields.split_whitespace().next(), Some("Z" | "X" | "x")) { return None; }
        return fields.split_whitespace().nth(19)?.parse().ok();
    }
    #[cfg(not(target_os = "linux"))]
    {
    let pid = sysinfo::Pid::from_u32(pid);
    let mut system = sysinfo::System::new();
    system.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), false);
    system.process(pid).map(|process| process.start_time())
    }
}

fn clean_stale_copies(root: &Path) {
    let Ok(entries) = std::fs::read_dir(root) else { return };
    for entry in entries.flatten() {
        if !entry.file_name().to_string_lossy().starts_with("session-") || !entry.file_type().is_ok_and(|kind| kind.is_dir()) { continue; }
        let marker = entry.path().join("owner.json");
        if !std::fs::symlink_metadata(&marker).is_ok_and(|meta| meta.is_file() && meta.len() <= 128) { continue; }
        let owner = std::fs::read(&marker).ok().and_then(|bytes| serde_json::from_slice::<(u32, u64)>(&bytes).ok());
        if owner.is_some_and(|(pid, identity)| process_identity(pid) != Some(identity)) {
            if let Err(error) = std::fs::remove_dir_all(entry.path()) { eprintln!("Could not remove an expired environment download copy: {error}"); }
        }
    }
}

fn html(value: &str) -> String {
    value.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

fn serve(listener: TcpListener, artifact: PathBuf, size: u64, name: String, token: String, environment_id: String,
    app: AppHandle, cancel: CancellationToken) -> JoinHandle<()> {
    tokio::spawn(async move {
        let slots = Arc::new(Semaphore::new(8));
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
                accepted = listener.accept() => {
                    let Ok((mut stream, _)) = accepted else { break };
                    let Ok(slot) = slots.clone().try_acquire_owned() else { continue };
                    let artifact = artifact.clone(); let name = name.clone(); let token = token.clone();
                    let app = app.clone(); let environment_id = environment_id.clone(); let cancel = cancel.clone();
                    tasks.spawn(async move {
                        let _slot = slot;
                        tokio::select! {
                            biased;
                            _ = cancel.cancelled() => {},
                            result = serve_request(&mut stream, &artifact, size, &name, &token) => {
                                if matches!(result, Ok(true)) {
                                    let persisted = tokio::task::spawn_blocking(move || record_download(&app.state::<PlatformStore>(), &environment_id)).await;
                                    if !matches!(persisted, Ok(Ok(_))) { eprintln!("Could not save environment download count; link revoked"); cancel.cancel(); }
                                }
                            }
                        }
                    });
                }
            }
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    })
}

fn record_download(store: &PlatformStore, id: &str) -> Result<(), String> {
    store.mutate(|state| {
        let count = state.environment_downloads.entry(id.to_owned()).or_default();
        *count = count.checked_add(1).ok_or("Download counter is full")?;
        Ok(())
    }).map(|_| ())
}

// HEAD and page visits never count. A completed full-body GET counts once;
// retries are downloads, not a claim of unique people or successful imports.
async fn serve_request(stream: &mut TcpStream, artifact: &Path, size: u64, name: &str, token: &str) -> Result<bool, String> {
    let request = tokio::time::timeout(Duration::from_secs(10), async {
        let mut bytes = Vec::with_capacity(4096);
        while bytes.len() < 16 * 1024 {
            let byte = stream.read_u8().await.map_err(|e| e.to_string())?;
            bytes.push(byte);
            if bytes.ends_with(b"\r\n\r\n") { return String::from_utf8(bytes).map_err(|e| e.to_string()); }
        }
        Err("Request header too large".into())
    }).await.map_err(|_| "Request timed out")??;
    let mut line = request.lines().next().unwrap_or_default().split_whitespace();
    let method = line.next().unwrap_or_default(); let path = line.next().unwrap_or_default();
    let head = method == "HEAD";
    if !matches!(method, "GET" | "HEAD") { response(stream, "405 Method Not Allowed", "text/plain", b"Use GET or HEAD.\n", head).await?; return Ok(false); }
    if path == format!("/{token}/environment.yougori") {
        // Refuse partial transfers rather than inflate lifetime counts from
        // arbitrary range probes or assemble a potentially misleading copy.
        if request.lines().skip(1).any(|line| line.split_once(':').is_some_and(|(key, _)| key.eq_ignore_ascii_case("range"))) {
            response(stream, "416 Range Not Satisfiable", "text/plain", b"Download the complete environment copy.\n", head).await?; return Ok(false);
        }
        let mut file = tokio::fs::File::open(artifact).await.map_err(|e| e.to_string())?;
        let header = format!("HTTP/1.1 200 OK\r\nContent-Type: application/vnd.yougori.environment\r\nContent-Disposition: attachment; filename=\"environment.yougori\"\r\nContent-Length: {size}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nAccept-Ranges: none\r\nConnection: close\r\n\r\n");
        stream.write_all(header.as_bytes()).await.map_err(|e| e.to_string())?;
        if head { return Ok(false); }
        let mut bytes = vec![0; 256 * 1024]; let mut remaining = size;
        while remaining > 0 {
            let count = file.read(&mut bytes).await.map_err(|e| e.to_string())?;
            if count == 0 || count as u64 > remaining { return Err("Environment copy changed".into()); }
            tokio::time::timeout(Duration::from_secs(60), stream.write_all(&bytes[..count])).await.map_err(|_| "Download stalled")?.map_err(|e| e.to_string())?;
            remaining -= count as u64;
        }
        stream.shutdown().await.map_err(|e| e.to_string())?;
        return Ok(true);
    }
    if path != format!("/{token}") && path != format!("/{token}/") {
        response(stream, "404 Not Found", "text/plain", b"This download link is unavailable.\n", head).await?; return Ok(false);
    }
    let page = format!("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>{} · Yougori</title><style>body{{font:16px system-ui;max-width:600px;margin:12vh auto;padding:24px;background:#111;color:#eee}}a{{color:#9cc9ff}}code{{display:block;padding:16px;background:#222;overflow-wrap:anywhere}}</style><h1>{}</h1><p>A complete copy of this environment’s disk, files, installed apps and configuration.</p><p><a href=\"/{token}/environment.yougori\" download>Download environment · {:.2} GB</a></p><p>In Yougori, choose Import backup, then open environment.yougori. Or run:</p><code>yougori backup import --path environment.yougori --yes</code><p>This link is temporary. The downloaded copy stays yours.</p></html>", html(name), html(name), size as f64 / 1_000_000_000.0);
    response(stream, "200 OK", "text/html; charset=utf-8", page.as_bytes(), head).await?;
    Ok(false)
}

async fn response(stream: &mut TcpStream, status: &str, content_type: &str, bytes: &[u8], head: bool) -> Result<(), String> {
    let header = format!("HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'\r\nConnection: close\r\n\r\n", bytes.len());
    tokio::time::timeout(Duration::from_secs(10), async {
        stream.write_all(header.as_bytes()).await?;
        if !head { stream.write_all(bytes).await?; }
        stream.shutdown().await
    }).await.map_err(|_| "Reply timed out")?.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn start_environment_download(request: StartRequest, app: AppHandle, downloads: State<'_, Downloads>) -> Result<DownloadInfo, String> {
    downloads.start(request, &app).await
}
#[tauri::command]
pub async fn list_environment_downloads(downloads: State<'_, Downloads>, store: State<'_, PlatformStore>) -> Result<Vec<DownloadInfo>, String> {
    downloads.list(&store).await
}
#[tauri::command]
pub async fn keep_environment_downloads_alive(owner_id: String, downloads: State<'_, Downloads>, store: State<'_, PlatformStore>) -> Result<Vec<DownloadInfo>, String> {
    downloads.keep_alive(&owner_id, &store).await
}
#[tauri::command]
pub async fn stop_environment_download(environment_id: String, downloads: State<'_, Downloads>) -> Result<(), String> {
    downloads.stop(&environment_id).await; Ok(())
}

pub fn start_cleanup(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            app.state::<Downloads>().cleanup(&app.state::<PlatformStore>()).await;
        }
    });
}

#[cfg(test)]
mod tests;
