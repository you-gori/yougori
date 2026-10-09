//! Authenticated, target-scoped HTTP gateway. Only this gateway is tunneled;
//! neither the engine API nor the Personal Vault is reachable through it.
pub(crate) mod client;
pub(crate) mod bridge;
mod terminal;
mod desktop;
mod files;
#[cfg(test)]
mod tests;
pub use client::{connect_remote_share, remote_share_request};
pub(crate) use client::{forget, request_saved};

use crate::{
    models::*,
    runtime::RuntimeManager,
    store::PlatformStore,
    workspace::{self, WorkspaceManager},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tauri::{Manager, State};
use crate::AppHandle;
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    sync::{Mutex, Semaphore},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}
fn secret() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}
fn hash(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}
fn equal(a: &str, b: &str) -> bool {
    let a = Sha256::digest(a.as_bytes());
    let b = Sha256::digest(b.as_bytes());
    a.iter().zip(b.iter()).fold(0u8, |v, (a, b)| v | (a ^ b)) == 0
}
fn verifier(password: &str, salt: &str) -> Result<String, String> {
    let mut output = [0; 32];
    scrypt::scrypt(
        password.as_bytes(),
        salt.as_bytes(),
        &scrypt::Params::new(15, 8, 1, 32).map_err(|_| "Invalid password parameters")?,
        &mut output,
    )
    .map_err(|_| "Cannot protect password")?;
    Ok(hex::encode(output))
}
fn validate_password(password: &str) -> Result<(), String> {
    if !(8..=256).contains(&password.len()) {
        return Err("Use a share password between 8 and 256 characters".into());
    }
    Ok(())
}
fn username(value: &str) -> Result<String, String> {
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err(
            "Use 1–64 letters, numbers, dots, underscores or hyphens for the username".into(),
        );
    }
    Ok(value)
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub enum Permission {
    View,
    Edit,
    Control,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateShare {
    pub target_id: String,
    pub username: String,
    pub password: String,
    pub permission: Permission,
    pub expires_at: Option<i64>,
    pub folder: Option<String>,
    #[serde(default)]
    pub confirm_pc_files: bool,
    #[serde(default)]
    pub acknowledge_existing_access: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Grant {
    id: String,
    target_id: String,
    username: String,
    permission: Permission,
    expires_at: Option<i64>,
    folder: Option<String>,
    salt: String,
    verifier: String,
    revoked: bool,
    acknowledge_existing_access: bool,
}
impl Grant {
    fn active(&self) -> bool {
        !self.revoked && self.expires_at.is_none_or(|expiry| expiry > now())
    }
    fn authorize(&self, method: &str, params: &Value) -> Result<(), String> {
        if !self.active() {
            return Err("This share has expired or was revoked".into());
        }
        let allowed = match method {
            "inspect" | "logout" => true,
            "console" => self.target_id != "my-pc",
            "files" => {
                self.folder.is_some()
                    && (matches!(params["operation"].as_str(), Some("list" | "stat" | "read"))
                        || self.permission != Permission::View)
            }
            "desktop" | "power" | "terminal" | "exec" | "apps" | "installer" | "skills" => {
                self.target_id != "my-pc" && self.permission == Permission::Control
            }
            _ => false,
        };
        if allowed {
            Ok(())
        } else {
            Err("The owner has not granted this capability".into())
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Audit {
    at: i64,
    share_id: String,
    event: String,
    success: bool,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Database {
    grants: Vec<Grant>,
    audit: VecDeque<Audit>,
}
struct Session {
    grant: String,
    owner: String,
    expires: i64,
    seen: i64,
    cancel: CancellationToken,
}
impl Drop for Session {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
struct Live {
    task: JoinHandle<()>,
    tunnel: workspace::cloudflare::Started,
    port: u16,
}
impl Drop for Live {
    fn drop(&mut self) {
        self.task.abort();
        self.tunnel.logs.abort();
        let _ = self.tunnel.child.start_kill();
    }
}
pub struct RemoteAccess {
    root: PathBuf,
    db: Mutex<Database>,
    sessions: Mutex<HashMap<String, Session>>,
    live: Mutex<Option<Live>>,
    operations: Mutex<()>,
    attempts: Mutex<VecDeque<(i64, String)>>,
    hashes: Arc<Semaphore>,
    bridge_slots: Arc<Semaphore>,
    terminal_slots: Arc<Semaphore>,
    displays: Mutex<HashMap<String, desktop::Display>>,
}
impl RemoteAccess {
    pub fn new(root: PathBuf) -> Result<Self, String> {
        let path = root.join("remote-access.json");
        let db = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|_| "Remote sharing state is unreadable; sharing was not enabled")?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Database::default(),
            Err(_) => return Err("Cannot read remote sharing state".into()),
        };
        Ok(Self {
            root,
            db: Mutex::new(db),
            sessions: Mutex::new(HashMap::new()),
            live: Mutex::new(None),
            operations: Mutex::new(()),
            attempts: Mutex::new(VecDeque::new()),
            displays: Mutex::new(HashMap::new()),
            hashes: Arc::new(Semaphore::new(2)),
            bridge_slots: Arc::new(Semaphore::new(8)),
            // Leave gateway admission slots for login/RPC alongside streams.
            terminal_slots: Arc::new(Semaphore::new(16)),
        })
    }
    fn save(&self, db: &Database) -> Result<(), String> {
        std::fs::create_dir_all(&self.root).map_err(|_| "Cannot create sharing storage")?;
        let mut file = tempfile::NamedTempFile::new_in(&self.root)
            .map_err(|_| "Cannot save sharing settings")?;
        serde_json::to_writer(&mut file, db).map_err(|_| "Cannot save sharing settings")?;
        file.as_file()
            .sync_all()
            .map_err(|_| "Cannot save sharing settings")?;
        file.persist(self.root.join("remote-access.json"))
            .map_err(|_| "Cannot save sharing settings")?;
        Ok(())
    }
    async fn audit(&self, id: &str, event: &str, success: bool) {
        let mut db = self.db.lock().await;
        push_audit(&mut db, id, event, success);
        let _ = self.save(&db);
    }
    async fn rate_limit(&self, key: &str) -> Result<(), String> {
        let mut attempts = self.attempts.lock().await;
        attempts.retain(|(at, _)| *at > now() - 60);
        if attempts.len() >= 30 || attempts.iter().filter(|(_, k)| k == key).count() >= 5 {
            return Err("Too many sign-in attempts. Wait one minute before retrying.".into());
        }
        attempts.push_back((now(), key.to_owned()));
        Ok(())
    }
    async fn invalidate(&self, app: &AppHandle, grant: Option<&str>) {
        let owners = {
            let mut sessions = self.sessions.lock().await;
            let keys: Vec<_> = sessions
                .iter()
                .filter(|(_, s)| grant.is_none_or(|id| s.grant == id))
                .map(|(k, _)| k.clone())
                .collect();
            keys.into_iter()
                .filter_map(|k| sessions.remove(&k).map(|s| s.owner.clone()))
                .collect::<Vec<_>>()
        };
        for owner in owners {
            desktop::close_owner(self, &owner).await;
            app.state::<WorkspaceManager>()
                .close_window(
                    &owner,
                    &app.state::<PlatformStore>(),
                    &app.state::<RuntimeManager>(),
                )
                .await;
        }
    }
}
fn push_audit(db: &mut Database, id: &str, event: &str, success: bool) {
    db.audit.push_back(Audit {
        at: now(),
        share_id: id.to_owned(),
        event: event.to_owned(),
        success,
    });
    while db.audit.len() > 500 {
        db.audit.pop_front();
    }
}
fn target(app: &AppHandle, id: &str) -> Result<Environment, String> {
    let env = app
        .state::<PlatformStore>()
        .snapshot()?
        .environments
        .into_iter()
        .find(|e| e.id == id)
        .ok_or("Environment not found")?;
    if crate::peer_sharing::is_shared(&env) || env.kind == EnvironmentKind::ComputerBranch {
        return Err("This target cannot be reshared".into());
    }
    Ok(env)
}
async fn check_control_scope(app: &AppHandle, id: &str, acknowledged: bool) -> Result<(), String> {
    if acknowledged {
        return Ok(());
    }
    let state = app.state::<PlatformStore>().snapshot()?;
    if state
        .connections
        .iter()
        .any(|c| c.active && (c.source_id == id || c.target_id == id))
        || !app
            .state::<WorkspaceManager>()
            .host_shares_for(id)
            .await
            .is_empty()
    {
        return Err("This environment already has PC folders or node connections. Explicitly acknowledge that command access also reaches those grants, or disconnect them first.".into());
    }
    Ok(())
}

#[tauri::command]
pub async fn create_remote_share(
    request: CreateShare,
    app: AppHandle,
    manager: State<'_, RemoteAccess>,
) -> Result<Value, String> {
    let _serial = manager.operations.lock().await;
    validate_password(&request.password)?;
    let username = username(&request.username)?;
    if request.expires_at.is_some_and(|e| e <= now()) {
        return Err("Choose an expiration in the future".into());
    }
    if request.target_id == "my-pc" {
        if !request.confirm_pc_files || request.folder.is_none() {
            return Err("Explicitly confirm the PC folder you want to share".into());
        }
        if request.permission == Permission::Control {
            return Err("Unrestricted PC commands and desktop control are unavailable: they could reach local engine or vault approval channels. Choose folder-only access.".into());
        }
        files::validate_pc_root(request.folder.as_deref().unwrap(), &manager.root)?;
    } else {
        let env = target(&app, &request.target_id)?;
        if request.folder.is_some() && env.kind == EnvironmentKind::FullVm {
            return Err("File sharing needs a Yougori guest agent; this full VM currently supports lifecycle sharing only".into());
        }
        if request.permission == Permission::Edit
            && request
                .folder
                .as_deref()
                .is_none_or(|f| f.trim().is_empty())
        {
            return Err("Choose a folder for file editing".into());
        }
        if request.permission == Permission::Control {
            check_control_scope(
                &app,
                &request.target_id,
                request.acknowledge_existing_access,
            )
            .await?;
        }
        if let Some(folder) = &request.folder {
            files::validate_guest_root(folder)?;
        }
    }
    let salt = secret();
    let password = request.password;
    let salt_copy = salt.clone();
    let _hash = manager
        .hashes
        .acquire()
        .await
        .map_err(|_| "Sharing is closing")?;
    let verifier = tokio::task::spawn_blocking(move || verifier(&password, &salt_copy))
        .await
        .map_err(|_| "Cannot protect password")??;
    let mut db = manager.db.lock().await;
    if db.grants.iter().filter(|g| g.active()).count() >= 128 {
        return Err("The maximum of 128 recipients has been reached".into());
    }
    let grant = Grant {
        id: format!("share-{}", uuid::Uuid::new_v4().simple()),
        target_id: request.target_id,
        username,
        permission: request.permission,
        expires_at: request.expires_at,
        folder: request.folder,
        salt,
        verifier,
        revoked: false,
        acknowledge_existing_access: request.acknowledge_existing_access,
    };
    let mut next = db.clone();
    if next.grants.len() >= 128 {
        next.grants.retain(Grant::active);
    }
    next.grants.push(grant.clone());
    push_audit(&mut next, &grant.id, "recipient created", true);
    manager.save(&next)?;
    *db = next;
    Ok(json!({"id":grant.id}))
}

#[tauri::command]
pub async fn start_remote_tunnel(
    cloudflare: Option<workspace::cloudflare::AccountOptions>,
    host_port: Option<u16>,
    app: AppHandle,
    manager: State<'_, RemoteAccess>,
) -> Result<Value, String> {
    let _serial = manager.operations.lock().await;
    let mut live = manager.live.lock().await;
    if let Some(current) = live.as_mut() {
        if current
            .tunnel
            .child
            .try_wait()
            .map_err(|_| "Cannot inspect tunnel")?
            .is_none()
            && !current.task.is_finished()
        {
            return Ok(json!({"url":current.tunnel.url,"port":current.port}));
        }
        live.take();
    }
    if !manager.db.lock().await.grants.iter().any(Grant::active) {
        return Err("Create a recipient before enabling remote access".into());
    }
    let account = cloudflare
        .map(|options| {
            workspace::cloudflare::Account::resolve("remote-access", 7445, host_port, options)
        })
        .transpose()?;
    let workspace = app.state::<workspace::WorkspaceManager>();
    let _workspace_operation = workspace.operations.lock().await;
    if let Some(account) = &account {
        workspace::cloudflare::finish_setup(&workspace, account).await?;
    }
    let listener = TcpListener::bind(("127.0.0.1", host_port.unwrap_or(0)))
        .await
        .map_err(|_| "The local tunnel port is unavailable")?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let executable = workspace::cloudflared(&manager.root).await?;
    let serving_app = app.clone();
    let task = tokio::spawn(serve(listener, serving_app));
    let tunnel = match workspace::cloudflare::start(
        &executable,
        &manager.root,
        port,
        account.as_ref(),
    )
    .await
    {
        Ok(tunnel) => tunnel,
        Err(error) => {
            task.abort();
            return Err(error);
        }
    };
    let result = json!({"url":tunnel.url,"port":port});
    *live = Some(Live { task, tunnel, port });
    if let Some(account) = account {
        account.remember("remote-access", 7445)?;
    }
    manager.audit("", "tunnel enabled", true).await;
    Ok(result)
}
#[tauri::command]
pub async fn stop_remote_tunnel(
    app: AppHandle,
    manager: State<'_, RemoteAccess>,
) -> Result<(), String> {
    let _serial = manager.operations.lock().await;
    manager.live.lock().await.take();
    manager.invalidate(&app, None).await;
    manager
        .audit("", "remote users disconnected; tunnel stopped", true)
        .await;
    Ok(())
}
#[tauri::command]
pub async fn list_remote_shares(manager: State<'_, RemoteAccess>) -> Result<Value, String> {
    let mut live = manager.live.lock().await;
    let url = live
        .as_mut()
        .filter(|l| !l.task.is_finished())
        .and_then(|l| {
            l.tunnel
                .child
                .try_wait()
                .ok()
                .filter(Option::is_none)
                .map(|_| l.tunnel.url.clone())
        });
    let db = manager.db.lock().await;
    let sessions = manager.sessions.lock().await;
    let grants:Vec<_>=db.grants.iter().map(|g| json!({"id":g.id,"targetId":g.target_id,"username":g.username,"permission":g.permission,"folder":g.folder,"expiresAt":g.expires_at,"status":if g.revoked {"revoked"} else if !g.active(){"expired"} else if url.is_some(){"online"}else{"offline"},"link":url.as_ref().map(|u|format!("{u}/share/{}",g.id)),"connectedUsers":sessions.values().filter(|s|s.grant==g.id && s.expires>now() && s.seen>now()-900).count()})).collect();
    Ok(json!({"grants":grants,"audit":db.audit,"url":url,"port":live.as_ref().map(|l|l.port)}))
}
#[tauri::command]
pub async fn update_remote_share(
    share_id: String,
    permission: Option<Permission>,
    password: Option<String>,
    revoke: bool,
    app: AppHandle,
    manager: State<'_, RemoteAccess>,
) -> Result<(), String> {
    let _serial = manager.operations.lock().await;
    let replacement = if let Some(password) = password {
        validate_password(&password)?;
        let salt = secret();
        let copy = salt.clone();
        let _hash = manager
            .hashes
            .acquire()
            .await
            .map_err(|_| "Sharing is closing")?;
        Some((
            salt,
            tokio::task::spawn_blocking(move || verifier(&password, &copy))
                .await
                .map_err(|_| "Cannot protect password")??,
        ))
    } else {
        None
    };
    let mut db = manager.db.lock().await;
    let mut next = db.clone();
    let grant = next
        .grants
        .iter_mut()
        .find(|g| g.id == share_id)
        .ok_or("Recipient not found")?;
    if let Some(permission) = permission {
        if permission == Permission::Edit && grant.folder.is_none() {
            return Err(
                "This share has no folder to edit; create a recipient with a selected folder"
                    .into(),
            );
        }
        if permission == Permission::Control {
            if grant.target_id == "my-pc" {
                return Err("PC command/desktop access is unavailable".into());
            }
            check_control_scope(&app, &grant.target_id, grant.acknowledge_existing_access).await?;
        }
        grant.permission = permission;
    }
    if let Some((salt, verifier)) = replacement {
        grant.salt = salt;
        grant.verifier = verifier;
    }
    if revoke {
        grant.revoked = true;
    }
    push_audit(
        &mut next,
        &share_id,
        if revoke {
            "recipient revoked"
        } else {
            "permissions/credentials updated; sessions disconnected"
        },
        true,
    );
    manager.save(&next)?;
    *db = next;
    drop(db);
    manager.invalidate(&app, Some(&share_id)).await;
    Ok(())
}

/// Deletes a recipient entirely (usually after revoking or expiry) so it no longer counts toward the recipient limit.
#[tauri::command]
pub async fn remove_remote_share(
    share_id: String,
    app: AppHandle,
    manager: State<'_, RemoteAccess>,
) -> Result<(), String> {
    let _serial = manager.operations.lock().await;
    let mut db = manager.db.lock().await;
    let mut next = db.clone();
    let before = next.grants.len();
    next.grants.retain(|g| g.id != share_id);
    if next.grants.len() == before {
        return Err("Recipient not found".into());
    }
    push_audit(&mut next, &share_id, "recipient removed", true);
    manager.save(&next)?;
    *db = next;
    drop(db);
    manager.invalidate(&app, Some(&share_id)).await;
    Ok(())
}

async fn serve(listener: TcpListener, app: AppHandle) {
    let mut clients = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            result=listener.accept()=>{let Ok((mut socket,peer))=result else{break}; if !peer.ip().is_loopback() || clients.len()>=32 {continue} let app=app.clone(); clients.spawn(async move {
                let mut preface = [0_u8; 32];
                let Ok(Ok(websocket)) = tokio::time::timeout(Duration::from_secs(12), async {
                    loop {
                        let read = socket.peek(&mut preface).await?;
                        if read == 0 { return Err(std::io::Error::other("Connection closed")); }
                        if read >= 4 { return Ok(preface[..read].starts_with(b"GET ")); }
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                }).await else { return };
                if websocket { terminal::serve_or_bridge(socket, app).await; return }
                let Ok(Ok((header,body)))=tokio::time::timeout(Duration::from_secs(12),crate::host_files::read_http(&mut socket)).await else{return};
                let result=tokio::time::timeout(Duration::from_secs(90),http(&app,&header,&body)).await.unwrap_or_else(|_|Err("Operation timed out; inspect the target before retrying".into()));
                let (status,body)=match result {Ok(v)=>(200,v),Err(error)=>(403,json!({"error":error}))};
                let body=serde_json::to_vec(&body).unwrap_or_default();
                if body.len()>4*1024*1024 {return}
                let header=format!("HTTP/1.1 {status} Response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",body.len());
                let _=tokio::time::timeout(Duration::from_secs(10),async {socket.write_all(header.as_bytes()).await?;socket.write_all(&body).await}).await;
            });},
            _=clients.join_next(),if !clients.is_empty()=>{},
        }
    }
}
fn header<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    headers
        .lines()
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim())
}
async fn http(app: &AppHandle, headers: &str, body: &[u8]) -> Result<Value, String> {
    // Native clients only. Browser origins and credentialed cross-site requests
    // are rejected; no cookies, CORS, automatic redirects or URL credentials.
    if header(headers, "origin").is_some() {
        return Err("Use Yougori Desktop or CLI to connect".into());
    }
    if header(headers, "content-type")
        .is_none_or(|s| s.split(';').next() != Some("application/json"))
    {
        return Err("Expected JSON".into());
    }
    let first = headers.lines().next().unwrap_or_default();
    let params: Value = serde_json::from_slice(body).map_err(|_| "Invalid request")?;
    if first == "POST /remote/login HTTP/1.1" {
        return login(app, params).await;
    }
    if first != "POST /remote/rpc HTTP/1.1" {
        return Err("Unknown remote endpoint".into());
    }
    let token = header(headers, "authorization")
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|v| v.len() == 64)
        .ok_or("Sign in to this share again")?;
    let manager = app.state::<RemoteAccess>();
    let (grant_id, owner, cancel) = {
        let mut sessions = manager.sessions.lock().await;
        let session = sessions
            .get_mut(&hash(token))
            .filter(|s| s.expires > now() && s.seen > now() - 900)
            .ok_or("Session expired or revoked; connect again")?;
        session.seen = now();
        (
            session.grant.clone(),
            session.owner.clone(),
            session.cancel.clone(),
        )
    };
    let grant = manager
        .db
        .lock()
        .await
        .grants
        .iter()
        .find(|g| g.id == grant_id)
        .cloned()
        .ok_or("Share no longer exists")?;
    let method = params["method"].as_str().ok_or("Missing remote method")?;
    let args = &params["params"];
    if let Err(error) = grant.authorize(method, args) {
        manager
            .audit(&grant.id, "denied remote action", false)
            .await;
        return Err(error);
    }
    if method == "logout" {
        manager.sessions.lock().await.remove(&hash(token));
        desktop::close_owner(&manager, &owner).await;
        app.state::<WorkspaceManager>()
            .close_window(
                &owner,
                &app.state::<PlatformStore>(),
                &app.state::<RuntimeManager>(),
            )
            .await;
        return Ok(json!({"ok":true}));
    }
    let result = tokio::select! {biased; _=cancel.cancelled()=>Err("Remote session was disconnected".into()), result=dispatch(app,&grant,&owner,cancel.clone(),method,args)=>result};
    if !matches!(method, "inspect" | "console")
        && !(method == "terminal" && args["action"] == "read")
        && method != "desktop"
        && !(method == "files"
            && (args["operation"] == "list"
                || (matches!(args["operation"].as_str(), Some("read" | "write"))
                    && args["offset"].as_u64().unwrap_or(0) > 0)))
    {
        manager
            .audit(
                &grant.id,
                match method {
                    "terminal" => "terminal activity",
                    "files" => "file operation",
                    "power" => "lifecycle action",
                    "exec" => "command executed",
                    _ => "remote operation",
                },
                result.is_ok(),
            )
            .await;
    }
    result
}
async fn login(app: &AppHandle, params: Value) -> Result<Value, String> {
    let manager = app.state::<RemoteAccess>();
    let id = params["shareId"]
        .as_str()
        .filter(|s| s.len() <= 64)
        .ok_or("Invalid credentials or unavailable share")?;
    manager.rate_limit(id).await?;
    let name = username(params["username"].as_str().unwrap_or_default()).unwrap_or_default();
    let password = params["password"]
        .as_str()
        .filter(|s| s.len() <= 256)
        .unwrap_or_default()
        .to_owned();
    let grant = manager
        .db
        .lock()
        .await
        .grants
        .iter()
        .find(|g| g.id == id)
        .cloned();
    let salt = grant
        .as_ref()
        .map(|g| g.salt.clone())
        .unwrap_or_else(|| "invalid-share-salt".into());
    let _hash = manager
        .hashes
        .clone()
        .try_acquire_owned()
        .map_err(|_| "Sign-in is busy; retry shortly")?;
    let computed = tokio::task::spawn_blocking(move || verifier(&password, &salt))
        .await
        .map_err(|_| "Sign-in unavailable")??;
    let valid = grant
        .as_ref()
        .is_some_and(|g| g.active() && g.username == name && equal(&computed, &g.verifier));
    manager
        .audit(
            if grant.is_some() { id } else { "unknown" },
            "sign-in",
            valid,
        )
        .await;
    if !valid {
        return Err("Invalid credentials or unavailable share".into());
    }
    let grant = grant.unwrap();
    // Serialize with owner changes so a reset cannot race creation of a session.
    let _serial = manager.operations.lock().await;
    if !manager.db.lock().await.grants.iter().any(|g| {
        g.id == grant.id
            && g.active()
            && g.verifier == grant.verifier
            && g.permission == grant.permission
    }) {
        return Err("Share changed; sign in again".into());
    }
    let token = secret();
    let expires = (now() + 12 * 3600).min(grant.expires_at.unwrap_or(i64::MAX));
    let mut sessions = manager.sessions.lock().await;
    if sessions.values().filter(|s| s.grant == grant.id).count() >= 8 {
        return Err("This recipient already has eight sessions. Disconnect them in the owner’s sharing settings before reconnecting.".into());
    }
    if sessions.len() >= 64 {
        return Err("The owner has too many remote sessions; retry later".into());
    }
    sessions.insert(
        hash(&token),
        Session {
            grant: grant.id.clone(),
            owner: format!("remote-{}", uuid::Uuid::new_v4().simple()),
            expires,
            seen: now(),
            cancel: CancellationToken::new(),
        },
    );
    Ok(json!({"token":token,"expiresAt":expires}))
}
async fn dispatch(
    app: &AppHandle,
    grant: &Grant,
    owner: &str,
    cancel: CancellationToken,
    method: &str,
    p: &Value,
) -> Result<Value, String> {
    if method == "files" {
        return files::dispatch(app, grant, p.clone()).await;
    }
    if grant.target_id == "my-pc" {
        return Ok(
            json!({"name":"My PC","status":"running","permission":grant.permission,"files":true,"commands":false,"power":false,"desktop":false}),
        );
    }
    let env = target(app, &grant.target_id)?;
    if method == "inspect" {
        let mut result =
            json!({"environment":crate::peer_sharing::summary(env.clone(),if grant.permission==Permission::Control {"control"}else{"view"})["environment"],"permission":grant.permission,"fabricId":if grant.permission==Permission::Control {Some(env.runtime_id.as_deref().unwrap_or(&env.id))} else {None},"files":grant.folder.is_some(),"commands":grant.permission==Permission::Control && env.kind!=EnvironmentKind::FullVm,"power":grant.permission==Permission::Control && env.kind!=EnvironmentKind::Cloud,"desktop":grant.permission==Permission::Control && env.kind==EnvironmentKind::FullVm,"apps":grant.permission==Permission::Control && crate::guest_apps::supports_apps(&env),"appKind":env.kind,"installers":grant.permission==Permission::Control && (env.kind==EnvironmentKind::Container || env.kind==EnvironmentKind::MicroVm && env.runtime=="builtin:alpine"),"internet":env.network_access,"skills":grant.permission==Permission::Control});
        result["terminalStreamVersion"] = json!(1);
        return Ok(result);
    }
    if grant.permission == Permission::Control {
        check_control_scope(app, &grant.target_id, grant.acknowledge_existing_access).await?;
    }
    if method == "installer" {
        let session = crate::peer_sharing::scoped_terminal_id(owner, p["sessionId"].as_str().ok_or("Missing terminal ID")?)?;
        return crate::workspace::installers::prepare_for_owner(env.id, session, p["tool"].as_str().ok_or("Missing tool")?.into(), owner, &app.state::<PlatformStore>(), &app.state::<RuntimeManager>(), &app.state::<WorkspaceManager>()).await.map(Value::String);
    }
    if method == "skills" {
        return if p["install"] == true {
            serde_json::to_value(crate::commands::connection_skills::install::install(&env.id, &app.state::<PlatformStore>(), &app.state::<RuntimeManager>(), &app.state::<WorkspaceManager>()).await?).map_err(|e| e.to_string())
        } else {
            crate::commands::connection_skills::get_connection_skills(env.id, app.state::<PlatformStore>(), app.state::<RuntimeManager>(), app.state::<WorkspaceManager>()).await.map(Value::String)
        };
    }
    if method == "apps" {
        let action = p["action"].as_str().ok_or("Missing app action")?;
        if !matches!(action, "status" | "install" | "launch" | "stop") { return Err("Unsupported remote app action".into()); }
        return crate::guest_apps::micro_vm_apps(env.id, action.into(), p["sessionId"].as_str().map(str::to_owned), p["name"].as_str().map(str::to_owned), p["command"].as_str().map(str::to_owned), p["package"].as_str().map(str::to_owned), app.state::<PlatformStore>(), app.state::<RuntimeManager>()).await;
    }
    if method == "desktop" {
        let result = desktop::action(app, &env, owner, cancel, p).await;
        if matches!(p["action"].as_str(), Some("create" | "close")) {
            app.state::<RemoteAccess>()
                .audit(&grant.id, "desktop session", result.is_ok())
                .await;
        }
        return result;
    }
    if method == "power" && env.kind == EnvironmentKind::Cloud {
        return Err("This SSH connection has no cloud lifecycle control service".into());
    }
    crate::peer_sharing::dispatch(
        app.clone(),
        grant.target_id.clone(),
        owner.to_owned(),
        if grant.permission == Permission::Control {
            "control"
        } else {
            "view"
        }
        .into(),
        json!({"method":method,"params":p}),
    )
    .await
}

pub fn start_cleanup(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            let manager = app.state::<RemoteAccess>();
            let db = manager.db.lock().await;
            let mut sessions = manager.sessions.lock().await;
            let expired: Vec<_> = sessions
                .iter()
                .filter(|(_, s)| {
                    s.expires <= now()
                        || s.seen <= now() - 900
                        || !db.grants.iter().any(|g| g.id == s.grant && g.active())
                })
                .map(|(k, _)| k.clone())
                .collect();
            let owners: Vec<_> = expired
                .into_iter()
                .filter_map(|k| sessions.remove(&k).map(|s| s.owner.clone()))
                .collect();
            drop(sessions);
            drop(db);
            for owner in owners {
                desktop::close_owner(&manager, &owner).await;
                app.state::<WorkspaceManager>()
                    .close_window(
                        &owner,
                        &app.state::<PlatformStore>(),
                        &app.state::<RuntimeManager>(),
                    )
                    .await;
            }
        }
    });
}
