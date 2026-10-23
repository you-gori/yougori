//! Hosting a Closed Bounty on this computer: publish a source, and other computers join with the
//! password to work it. The host runs no model. This is the engine side of the grid crate's
//! `bounty` hub, managed like the Closed Neo Grid hub. The member side (joining and working a
//! bounty) is separate; this module is only the host.
use crate::{projects::secrets, security::Event, store::PlatformStore};
use serde_json::{json, Value};
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tauri::Manager;
use crate::{AppHandle, WebviewWindow};
use yougori_grid::{
    bounty::{self as hub, Bounty, Hub, SourceFile},
    invite::{self, Invite},
    net::{self, HubAddress},
    password,
};

const KEY: &str = "yougori-bounty-hub-key";
const PASSWORD: &str = "yougori-bounty-hub-password";

/// How long a project a publisher inspected but never hosted is kept before its copy goes.
const IMPORT_KEPT: Duration = Duration::from_secs(24 * 60 * 60);
/// How long after a failed resume the next call tries again.
const RESUME_RETRY: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Default)]
enum Loaded {
    #[default]
    Never,
    Failed(Instant),
    Done,
}

#[derive(Default)]
pub struct ClosedBounty {
    inner: tokio::sync::Mutex<Option<Hub>>,
    /// Serializes hosting and deleting.
    admin: tokio::sync::Mutex<()>,
    loaded: tokio::sync::Mutex<Loaded>,
    pending: tokio::sync::Mutex<std::collections::BTreeMap<String, crate::swarm::closed::Connection>>,
}

fn folder(app: &AppHandle) -> PathBuf {
    app.state::<PlatformStore>().data_folder("bounty")
}

fn host_path(app: &AppHandle) -> PathBuf {
    folder(app).join("host.json")
}

fn events() -> hub::Events {
    Arc::new(|kind: &'static str, detail: Value| crate::security::record(Event::new(kind).object("detail", detail)))
}

/// Resumes a hosted bounty from disk after a restart. A resume that fails (a port still held, the
/// vault asleep) is tried again on a later call rather than given up on until the app restarts.
async fn ensure_loaded(app: &AppHandle) {
    let state = app.state::<ClosedBounty>();
    let mut loaded = state.loaded.lock().await;
    if matches!(*loaded, Loaded::Done) {
        return;
    }
    if let Loaded::Failed(at) = *loaded {
        if at.elapsed() < RESUME_RETRY {
            return;
        }
    }
    let path = host_path(app);
    if !path.exists() {
        *loaded = Loaded::Done;
        return;
    }
    if state.inner.lock().await.is_some() {
        *loaded = Loaded::Done;
        return;
    }
    if let (Ok(key), Ok(password_key)) = (secrets::resolve(KEY), secrets::resolve(PASSWORD)) {
        match Hub::start(path, &key, &password_key, events()).await {
            Ok(started) => {
                *state.inner.lock().await = Some(started);
                *loaded = Loaded::Done;
            }
            Err(error) => {
                crate::security::record(Event::new("bounty.host.resume_failed").text("error", &error));
                *loaded = Loaded::Failed(Instant::now());
            }
        }
    } else {
        *loaded = Loaded::Failed(Instant::now());
    }
}

/// Old import snapshots from inspections that were never hosted: each holds the project's source,
/// so they are not kept around.
fn prune_imports(app: &AppHandle) {
    let Ok(entries) = std::fs::read_dir(folder(app).join("imports")) else { return };
    for entry in entries.flatten() {
        let old = entry
            .metadata()
            .and_then(|data| data.modified())
            .is_ok_and(|at| at.elapsed().is_ok_and(|age| age > IMPORT_KEPT));
        if old {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

async fn derive(secret: String, salt: String) -> Result<String, String> {
    tokio::task::spawn_blocking(move || password::derive(&secret, &salt)).await.map_err(|error| error.to_string())?
}

/// This computer's private LAN or VPN address, which joining computers reach.
pub(crate) fn suggested_address() -> Option<String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("192.0.2.1:80").ok()?;
    Some(socket.local_addr().ok()?.ip()).filter(|ip| net::private(*ip)).map(|ip| ip.to_string())
}

/// The invite and status of the running hub, as the dashboard reads them.
fn view(hub: &Hub) -> Value {
    let mut status = hub.status();
    let record = hub.record();
    let reach = HubAddress::Direct(SocketAddr::new(record.address, hub.address().port()));
    if let Ok(fingerprint) = net::fingerprint(&record.certificate) {
        status["invite"] = json!(invite::encode_bounty(&Invite { company: record.name.clone(), address: reach, fingerprint }));
    }
    status
}

/// Reads the source files a caller gave: `[{path, data}]`, `data` base64 of the file's bytes.
fn read_files(value: &Value) -> Result<Vec<SourceFile>, String> {
    let files = value.as_array().ok_or("Give the bounty's source files")?;
    files
        .iter()
        .map(|file| {
            let path = file["path"].as_str().unwrap_or_default().trim().to_owned();
            // An empty file is ordinary (`__init__.py`), and its base64 is the empty string:
            // only a missing `data` field is a malformed request.
            let data = file["data"].as_str().ok_or("Each source file needs a path and its base64 data")?.to_owned();
            if path.is_empty() {
                return Err("Each source file needs a path and its base64 data".into());
            }
            Ok(SourceFile { path, data })
        })
        .collect()
}

/// Reads a staged `inspectProject` import by id. The files were read from disk and validated
/// engine-side, so a large source never crosses the client frame limit; only the id does.
fn read_import(app: &AppHandle, id: &str) -> Result<Vec<SourceFile>, String> {
    if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Import a project first".into());
    }
    let path = folder(app).join("imports").join(format!("{id}.json"));
    serde_json::from_slice(&std::fs::read(&path).map_err(|_| "Project import expired; choose it again")?)
        .map_err(|error: serde_json::Error| error.to_string())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn bounty_host(name: String, address_text: String, secret: String, title: String, instructions: Option<String>, authorization: Option<String>, files: Value, app: AppHandle) -> Result<Value, String> {
    let bounty = Bounty::checked(&title, &instructions.unwrap_or_default(), &authorization.unwrap_or_default(), read_files(&files)?)?;
    host_project(name,address_text,secret,bounty,app).await
}

async fn host_project(name:String,address_text:String,secret:String,bounty:Bounty,app:AppHandle)->Result<Value,String> {
    let state = app.state::<ClosedBounty>();
    let _admin = state.admin.lock().await;
    ensure_loaded(&app).await;
    if state.inner.lock().await.is_some() || host_path(&app).exists() {
        return Err("This computer already hosts a closed bounty; delete it first with `yougori bounty delete --yes`".into());
    }
    let ip: std::net::IpAddr = address_text.trim().parse().map_err(|_| "--ip is this computer's LAN or VPN address, such as 192.168.1.20")?;
    if ip.is_unspecified() || !net::private(ip) {
        return Err("Use this computer's private LAN or VPN address so other computers can reach it".into());
    }
    let title=bounty.title.clone();
    password::validate(&secret)?;
    let salt = password::new_salt();
    let password_key = derive(secret, salt.clone()).await?;
    let path = host_path(&app);
    // A bounty host uses its own port so it can run alongside a Closed Neo Grid (7460/7461).
    const BOUNTY_PORT: u16 = 7462;
    let key = hub::create(&path, &name, ip, BOUNTY_PORT, None, None, &salt, bounty)?;
    let started: Result<Hub, String> = async {
        secrets::store(KEY, &key)?;
        secrets::store(PASSWORD, &password_key)?;
        Hub::start(path.clone(), &key, &password_key, events()).await
    }
    .await;
    let hub = match started {
        Ok(hub) => hub,
        Err(error) => {
            let _ = secrets::delete_secret(KEY);
            let _ = secrets::delete_secret(PASSWORD);
            let _ = std::fs::remove_file(&path);
            return Err(error);
        }
    };
    crate::security::record(Event::new("bounty.hosted").text("name", &name).text("title", &title));
    let status = view(&hub);
    *state.inner.lock().await = Some(hub);
    Ok(status)
}

/// Project-first setup and private membership. Passwords are accepted only in the request body.
pub(crate) async fn bounty_dispatch(request:Value,app:AppHandle)->Result<Value,String> {
    let action=request["action"].as_str().ok_or("Choose a bounty operation")?;
    match action {
        "inspectProject"=>{
            let path=PathBuf::from(request["path"].as_str().ok_or("Choose a folder, file or ZIP archive")?);
            let(files,mut view)=tokio::task::spawn_blocking(move||crate::bounty_project::import(&path)).await.map_err(|e|e.to_string())??;
            prune_imports(&app);
            let id=uuid::Uuid::new_v4().simple().to_string();let dir=folder(&app).join("imports");std::fs::create_dir_all(&dir).map_err(|e|e.to_string())?;
            std::fs::write(dir.join(format!("{id}.json")),serde_json::to_vec(&files).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
            view["importId"]=id.into();Ok(view)
        },
        "hostProject"=>{
            if request["confirmed"]!=true {return Err("Confirm the project, sandbox commands and hosting scope".into());}
            // A live-URL bounty may carry no source, so the import is optional; without one the
            // source is empty and policy() requires a live URL target.
            let import=request["importId"].as_str();
            let files:Vec<SourceFile>=match import { Some(id)=>read_import(&app,id)?, None=>Vec::new() };
            let title=request["title"].as_str().unwrap_or("");let authorization=request["authorization"].as_str().unwrap_or("").trim();
            if authorization.is_empty(){return Err("Describe the project and testing you authorize".into());}
            let mut bounty=Bounty::checked(title,request["instructions"].as_str().unwrap_or("Investigate this project for reproducible security defects."),authorization,files)?;
            bounty.target=serde_json::from_value::<yougori_grid::bounty_project::Target>(request["target"].clone()).map_err(|e|e.to_string())?.checked()?;
            // Only an explicit yes from the host lets workers send this code to a rented GPU.
            bounty.rented_gpu=request["rentedGpu"]==true;
            let local=request["visibility"]=="local";
            if !local && request["visibility"]!="lan" {return Err("Choose this computer or your LAN".into());}
            let address=if local{"127.0.0.1"}else{request["address"].as_str().ok_or("Choose this computer's LAN address")?};
            let secret=if local{format!("{}{}",uuid::Uuid::new_v4().simple(),uuid::Uuid::new_v4().simple())}else{request["password"].as_str().unwrap_or("").to_owned()};
            let mut status=host_project(request["name"].as_str().unwrap_or("Private bounty").into(),address.into(),secret.clone(),bounty,app.clone()).await?;
            // The host can also contribute a worker. Connecting does not start inference or accept
            // work, and a connection that fails does not undo the bounty, which is already live:
            // it is reported beside it so the publisher does not retry the whole thing.
            match connect(status["invite"].as_str().ok_or("Missing bounty invite")?,&secret,"Host worker",&app).await {
                Ok(preview)=>{status["preview"]=preview;}
                Err(error)=>{status["previewError"]=error.clone().into();crate::security::record(Event::new("bounty.host.local_worker_failed").text("error",&error));}
            }
            if let Some(id)=import { let _=std::fs::remove_file(folder(&app).join("imports").join(format!("{id}.json"))); }
            Ok(status)
        },
        "hostSource"=>{
            // Headless host for the CLI: the publisher's computer hosts, workers join separately, so
            // unlike `hostProject` it starts no local worker. The source is a staged import read from
            // disk, so a whole repository is hosted without a byte crossing the client frame limit.
            // The import is optional: a live-URL bounty may carry no source at all.
            if request["confirmed"]!=true {return Err("Confirm the project and hosting scope".into());}
            let import=request["importId"].as_str();
            let files=match import { Some(id)=>read_import(&app,id)?, None=>Vec::new() };
            let mut bounty=Bounty::checked(request["title"].as_str().unwrap_or(""),request["instructions"].as_str().unwrap_or("Investigate this project for reproducible security defects."),request["authorization"].as_str().unwrap_or("").trim(),files)?;
            // A declared target (for example a live URL to probe) replaces the default source recipe.
            if !request["target"].is_null() {
                bounty.target=serde_json::from_value::<yougori_grid::bounty_project::Target>(request["target"].clone()).map_err(|e|e.to_string())?.checked()?;
            }
            let status=host_project(request["name"].as_str().unwrap_or("Private bounty").into(),request["address"].as_str().unwrap_or("").into(),request["password"].as_str().unwrap_or("").to_owned(),bounty,app.clone()).await?;
            if let Some(id)=import { let _=std::fs::remove_file(folder(&app).join("imports").join(format!("{id}.json"))); }
            Ok(status)
        },
        "connect"=>connect(request["invite"].as_str().unwrap_or(""),request["password"].as_str().unwrap_or(""),request["name"].as_str().unwrap_or("Private worker"),&app).await,
        "discardConnection"=>{
            let connection=app.state::<ClosedBounty>().pending.lock().await.remove(request["ticket"].as_str().unwrap_or(""));
            if let Some(connection)=connection {connection.discard().await;}
            Ok(json!({"discarded":true}))
        },
        "localConnect"=>{
            ensure_loaded(&app).await;
            let state=app.state::<ClosedBounty>();
            let member=state.inner.lock().await.as_ref().ok_or("Host a private bounty first")?.local_member("Host worker")?;
            preview_member(member,&app).await
        },
        "startWorker"=>{
            if request["confirmed"]!=true {return Err("Review the private project and its commands before starting".into());}
            let ticket=request["ticket"].as_str().ok_or("Connect to the private bounty first")?;
            // Claimed before anything is awaited: two overlapping starts cannot share one identity.
            let connection=app.state::<ClosedBounty>().pending.lock().await.remove(ticket).ok_or("Connection expired; connect again")?;
            let started=async {
                let policy=connection.request("GET","/api/swarm/agent/offer",None).await?["policy"].clone();
                crate::swarm::closed::check_distribution(&policy)?;
                if policy["termsDigest"]!=request["termsDigest"] {return Err("The project changed; review it again".to_owned());}
                // A worker on a rented GPU needs the host's permission before anything is accepted.
                if !request["worker"]["rentedGpu"].is_null() {crate::rented_gpu::bounty_allows(&policy,true)?;}
                let mut setup=request["worker"].clone();setup["action"]="prepare".into();crate::swarm::validate(&setup)?;
                connection.request("POST","/api/swarm/agent/accept",Some(&json!({"confirmed":true,"deferUntilReady":true,"termsDigest":policy["termsDigest"],"budgetMinutes":request["budgetMinutes"],"reportPolicy":request["reportPolicy"],"idempotencyKey":format!("accept-{ticket}")}))).await?;
                crate::swarm::prepare_worker(setup,app.clone(),Some(connection.clone()),policy).await
            }.await;
            // A start that never got as far as a worker gives the membership and its credential
            // back rather than leaving them behind.
            if started.is_err() { connection.discard().await; }
            started
        },
        "status"=>bounty_status(app).await,
        _=>Err("Unknown private bounty operation".into()),
    }
}
async fn connect(invitation:&str,secret:&str,name:&str,app:&AppHandle)->Result<Value,String> {
    let invite=invite::decode_bounty(invitation)?;
    let member=hub::member_join(&invite,secret,name,std::env::consts::OS,"").await?;
    preview_member(member,app).await
}
async fn preview_member(member:hub::Member,app:&AppHandle)->Result<Value,String> {
    let connection=crate::swarm::closed::Connection::save(member)?;
    // A preview that cannot read the policy gives its membership and credential back; nothing
    // half-joined is left behind.
    let policy=match connection.request("GET","/api/swarm/agent/offer",None).await {
        Ok(value)=>value["policy"].clone(),
        Err(error)=>{connection.discard().await;return Err(error);}
    };
    if let Err(error)=crate::swarm::closed::check_distribution(&policy) {connection.discard().await;return Err(error);}
    let ticket=uuid::Uuid::new_v4().simple().to_string();
    let state=app.state::<ClosedBounty>();let mut pending=state.pending.lock().await;
    if pending.len()>=32 {drop(pending);connection.discard().await;return Err("Close an unused private bounty preview before connecting more workers".into());}
    pending.insert(ticket.clone(),connection);Ok(json!({"ticket":ticket,"policy":policy}))
}

pub(crate) async fn bounty_status(app: AppHandle) -> Result<Value, String> {
    ensure_loaded(&app).await;
    let state = app.state::<ClosedBounty>();
    let inner = state.inner.lock().await;
    let status = inner.as_ref().map(view);
    if let Some(hub) = inner.as_ref() {
        if hub.take_dirty() {
            crate::security::record(Event::new("bounty.host.updated"));
        }
    }
    Ok(json!({"host": status}))
}

pub(crate) async fn bounty_member_remove(member_id: String, app: AppHandle) -> Result<Value, String> {
    ensure_loaded(&app).await;
    let state = app.state::<ClosedBounty>();
    let inner = state.inner.lock().await;
    let hub = inner.as_ref().ok_or("This computer does not host a closed bounty")?;
    let result = hub.remove_member(&member_id)?;
    crate::security::record(Event::new("bounty.member.removed").text("memberId", &member_id));
    Ok(result)
}

pub(crate) async fn bounty_delete(app: AppHandle) -> Result<Value, String> {
    let state = app.state::<ClosedBounty>();
    let _admin = state.admin.lock().await;
    ensure_loaded(&app).await;
    // Dropping the hub stops the service and closes every connection.
    *state.inner.lock().await = None;
    // What could not be removed is said plainly: files or credentials left behind would
    // otherwise block the next bounty with no explanation.
    let mut kept: Vec<String> = Vec::new();
    for path in [host_path(&app), host_path(&app).with_extension("coordination.json")] {
        if let Err(error) = std::fs::remove_file(&path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                kept.push(format!("{}: {error}", path.display()));
            }
        }
    }
    for name in [KEY, PASSWORD] {
        if let Err(error) = secrets::delete_secret(name) {
            kept.push(format!("{name}: {error}"));
        }
    }
    prune_imports(&app);
    crate::security::record(Event::new("bounty.deleted").text("kept", &kept.join("; ")));
    if !kept.is_empty() {
        return Err(format!("The bounty was stopped, but some of its data could not be removed: {}. Remove it before hosting another bounty.", kept.join("; ")));
    }
    Ok(json!({"deleted": true}))
}

/// App commands, from the main window only: an environment's window must not host a bounty.
pub(crate) mod commands {
    use super::*;

    fn main_window(window: &WebviewWindow) -> Result<(), String> {
        if window.label() == "main" { Ok(()) } else { Err("A closed bounty is hosted from the main Yougori window".into()) }
    }

    #[tauri::command]
    pub async fn bounty_dispatch(app:AppHandle,window:WebviewWindow,request:Value)->Result<Value,String> {
        main_window(&window)?;super::bounty_dispatch(request,app).await
    }

    #[tauri::command]
    pub async fn bounty_status(app: AppHandle, window: WebviewWindow) -> Result<Value, String> {
        main_window(&window)?;
        super::bounty_status(app).await
    }

    #[tauri::command]
    pub fn bounty_suggested_address(window: WebviewWindow) -> Result<Option<String>, String> {
        main_window(&window)?;
        Ok(super::suggested_address())
    }

    #[tauri::command]
    #[allow(clippy::too_many_arguments)]
    pub async fn bounty_host(app: AppHandle, window: WebviewWindow, name: String, address: String, password: String, title: String, instructions: Option<String>, authorization: Option<String>, files: Value) -> Result<Value, String> {
        main_window(&window)?;
        super::bounty_host(name, address, password, title, instructions, authorization, files, app).await
    }

    #[tauri::command]
    pub async fn bounty_member_remove(app: AppHandle, window: WebviewWindow, member_id: String) -> Result<Value, String> {
        main_window(&window)?;
        super::bounty_member_remove(member_id, app).await
    }

    #[tauri::command]
    pub async fn bounty_delete(app: AppHandle, window: WebviewWindow) -> Result<Value, String> {
        main_window(&window)?;
        super::bounty_delete(app).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_files_are_read_and_checked() {
        let files = json!([{"path": "src/app.py", "data": "cHJpbnQoMSk="}]);
        let read = read_files(&files).unwrap();
        assert_eq!(read.len(), 1);
        assert_eq!(read[0].path, "src/app.py");
        assert!(read_files(&json!([{"path": "", "data": "x"}])).is_err(), "a path is required");
        assert!(read_files(&json!([{"path": "a"}])).is_err(), "the data field is required");
        // An empty file is ordinary source, and its base64 is the empty string.
        let empty = read_files(&json!([{"path": "pkg/__init__.py", "data": ""}])).unwrap();
        assert_eq!((empty.len(), empty[0].data.as_str()), (1, ""));
        assert!(read_files(&json!({})).is_err(), "files is a list");
    }

    #[test]
    fn a_suggested_address_is_private_or_absent() {
        assert!(suggested_address().is_none_or(|address| address.parse().is_ok_and(net::private)));
    }
}
