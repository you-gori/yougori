use crate::{
    host_files::HostFolderServer,
    models::{Environment, EnvironmentKind, EnvironmentStatus},
    runtime::RuntimeManager,
    store::PlatformStore,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
#[cfg(any(windows, target_os = "linux"))]
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    net::IpAddr,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
    sync::Arc,
};
use tauri::{Emitter, Manager, State};
use crate::{AppHandle, WebviewWindow};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    process::Child,
    sync::Mutex,
    task::JoinHandle,
};
use uuid::Uuid;

pub mod cloudflare;

pub(crate) trait ApplicationStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> ApplicationStream for T {}
pub(crate) type BoxStream = Box<dyn ApplicationStream>;
pub mod installers;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum PublicationKind {
    Loopback,
    Local,
    Public,
    Cloudflare,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Publication {
    pub id: String,
    pub environment_id: String,
    pub port: u16,
    pub kind: PublicationKind,
    pub host_port: u16,
    pub urls: Vec<String>,
    pub status: String,
    pub message: String,
    pub cloudflare_account: bool,
}
struct LivePublication {
    info: Publication,
    task: Arc<ListenerTask>,
    cloudflare: Option<Child>,
    logs: Option<JoinHandle<()>>,
    tunnel_id: Option<String>,
    _cloudflare_config: Option<cloudflare::ConfigFile>,
    _vm_forward: Option<Arc<VmForward>>,
}
struct ListenerTask(JoinHandle<()>);
impl Drop for ListenerTask { fn drop(&mut self) { self.0.abort(); } }
struct VmForward(u16, u16);
impl Drop for VmForward {
    fn drop(&mut self) {
        let (qmp, port) = (self.0, self.1);
        tokio::spawn(async move {
            RuntimeManager::remove_workspace_vm_port(qmp, port).await;
        });
    }
}
impl Drop for LivePublication {
    fn drop(&mut self) {
        if let Some(logs) = &self.logs {
            logs.abort();
        }
    }
}

#[tauri::command]
pub async fn publication_preflight(environment_id: String, port: u16, kind: PublicationKind, host_port: Option<u16>, cloudflare: Option<cloudflare::AccountOptions>, domain: Option<String>, store: State<'_,PlatformStore>, manager: State<'_,WorkspaceManager>) -> Result<Value,String> {
    let (host_port,cloudflare)=if let Some(domain)=domain {
        if kind!=PublicationKind::Cloudflare || cloudflare.is_some(){return Err("A saved domain requires kind cloudflare and cannot be combined with inline account options".into())}
        let (options,saved_port)=cloudflare::domain_account(&store,&domain)?;
        if host_port.is_some_and(|p|p!=saved_port){return Err("The requested host port differs from the saved domain's tunnel port".into())}
        (Some(saved_port),Some(options))
    }else{(host_port,cloudflare)};
    publication_plan(&environment_id,port,&kind,host_port,cloudflare,&store,&manager).await
}
async fn publication_plan(environment_id: &str, port: u16, kind: &PublicationKind, host_port: Option<u16>, cloudflare: Option<cloudflare::AccountOptions>, store: &PlatformStore, manager: &WorkspaceManager) -> Result<Value,String> {
    if port==0 || port==7443 || host_port.is_some_and(|p|p==0||p==7443) { return Err("Choose nonzero application and host ports; 7443 is reserved".into()) }
    let state=store.snapshot()?;
    if !state.environments.iter().any(|e|e.id==environment_id) { return Err("Environment not found".into()) }
    if cloudflare.is_some() && *kind!=PublicationKind::Cloudflare { return Err("Cloudflare options require a Cloudflare publication".into()) }
    let account=cloudflare.map(|options|cloudflare::Account::resolve(environment_id,port,host_port,options)).transpose()?;
    let routes=manager.publications.lock().await;
    if let Some(account)=&account {
        if let Some(owner)=routes.values().find(|p|p.tunnel_id.as_deref()==Some(account.tunnel_id.as_str()) && (p.info.environment_id!=environment_id || p.info.port!=port)) {
            return Ok(json!({"allowed":false,"action":"conflict","code":"DOMAIN_IN_USE","owner":owner.info,"unrelatedPublicationsPreserved":true}));
        }
    }
    let existing=routes.values().find(|p|p.info.environment_id==environment_id && p.info.port==port && &p.info.kind==kind).map(|p|p.info.clone());
    if let Some(existing)=&existing {
        let live=&routes[&existing.id];
        let route_matches=existing.cloudflare_account==account.is_some() && account.as_ref().is_none_or(|a|live.tunnel_id.as_deref()==Some(a.tunnel_id.as_str())&&existing.urls==vec![a.public_url()]) && host_port.is_none_or(|h|h==existing.host_port);
        if route_matches&&existing.status=="active"{return Ok(json!({"allowed":true,"action":"reusePublication","existing":existing,"unrelatedPublicationsPreserved":true}))}
    }
    if let Some(host)=host_port {
        if let Some(owner)=routes.values().find(|p|p.info.host_port==host) {
            let compatible=owner.info.environment_id==environment_id && owner.info.port==port && matches!(owner.info.kind,PublicationKind::Loopback|PublicationKind::Cloudflare) && matches!(kind,PublicationKind::Loopback|PublicationKind::Cloudflare);
            return Ok(json!({"allowed":compatible,"action":if !compatible{"conflict"}else if existing.is_some(){"replaceOwnedRoute"}else{"reuseListener"},"code":if compatible{Value::Null}else{json!("PORT_IN_USE")},"hostPort":host,"owner":owner.info,"existing":existing,"rollbackSupported":compatible&&existing.is_some(),"unrelatedPublicationsPreserved":true}));
        }
        drop(routes);
        let address=if matches!(kind,PublicationKind::Loopback|PublicationKind::Cloudflare){"127.0.0.1"}else{"0.0.0.0"};
        if TcpListener::bind((address,host)).await.is_err() { return Ok(json!({"allowed":false,"action":"conflict","code":"PORT_IN_USE","hostPort":host,"owner":{"type":"externalProcess","processIds":listener_process_ids(host).await},"existing":existing,"unrelatedPublicationsPreserved":true})); }
    }
    Ok(json!({"allowed":true,"action":if existing.is_some(){"replaceOwnedRoute"}else{"create"},"existing":existing,"rollbackSupported":existing.is_some(),"hostPort":host_port,"unrelatedPublicationsPreserved":true}))
}
async fn listener_process_ids(port:u16)->Vec<u32> {
    #[cfg(windows)] let mut command=tokio::process::Command::new(std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(||PathBuf::from("C:/Windows")).join("System32/netstat.exe"));
    #[cfg(windows)] command.args(["-ano","-p","TCP"]);
    #[cfg(unix)] let mut command=tokio::process::Command::new("ss");
    #[cfg(unix)] command.args(["-ltnp","sport","=",&format!(":{port}")]);
    background(&mut command);
    let Ok(Ok(output))=tokio::time::timeout(Duration::from_secs(5),command.output()).await else{return vec![]};
    let text=String::from_utf8_lossy(&output.stdout);
    let mut ids=Vec::new();
    for line in text.lines().take(8192) {
        #[cfg(windows)] { let fields=line.split_whitespace().collect::<Vec<_>>(); if fields.len()>=5 && fields[1].rsplit(':').next()==Some(port.to_string().as_str()) && fields[3]=="LISTENING" { if let Ok(id)=fields[4].parse(){ids.push(id)} } }
        #[cfg(unix)] { for part in line.split("pid=").skip(1) { if let Some(id)=part.split(',').next().and_then(|id|id.parse().ok()){ids.push(id)} } }
    }
    ids.sort();ids.dedup();ids
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostShare {
    pub id: String,
    pub environment_id: String,
    pub path: String,
    pub read_only: bool,
    pub mount_path: Option<String>,
    // A capability, not metadata. Only the explicit credential operation exports it.
    #[serde(skip_serializing)]
    pub guest_url: String,
}
struct LiveShare {
    info: HostShare,
    environment: Environment,
    _server: HostFolderServer,
}
#[derive(Clone)]
struct TerminalLease {
    environment: Environment,
    owner: String,
}
pub struct WorkspaceManager {
    root: PathBuf,
    publications: Mutex<HashMap<String, LivePublication>>,
    setup_tunnels: Mutex<HashMap<String, cloudflare::SetupTunnel>>,
    shares: Mutex<HashMap<String, LiveShare>>,
    folder_operations: Mutex<HashMap<String,Arc<Mutex<()>>>>,
    terminals: Mutex<HashMap<String, TerminalLease>>,
    pub(crate) operations: Mutex<()>,
    local_ports_key: Mutex<String>,
}
impl WorkspaceManager {
    pub(crate) async fn download_tunnel(&self, domain: Option<&str>, store: &PlatformStore) -> Result<(TcpListener, cloudflare::Started), String> {
        let _serial = self.operations.lock().await;
        let account = if let Some(domain) = domain {
            let saved = cloudflare::find_domain(store, domain)?;
            let (options, port) = cloudflare::domain_account(store, domain)?;
            Some(cloudflare::Account::resolve(&saved.credential_environment_id, saved.port, Some(port), options)?)
        } else { None };
        if let Some(account) = &account {
            if self.publications.lock().await.values().any(|p| p.tunnel_id.as_deref() == Some(account.tunnel_id.as_str())) {
                return Err("This domain is serving another environment. Disconnect that publication or choose another domain.".into());
            }
            cloudflare::finish_setup(self, account).await?;
        }
        let listener = TcpListener::bind(("127.0.0.1", account.as_ref().map_or(0, cloudflare::Account::host_port))).await
            .map_err(|_| "This domain’s local port is already in use. Turn off the other link or choose another domain.")?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        let executable = cloudflared(&self.root).await?;
        let started = cloudflare::start(&executable, &self.root, port, account.as_ref()).await?;
        Ok((listener, started))
    }
    pub async fn host_shares_for(&self, environment_id: &str) -> Vec<HostShare> {
        let mut shares = self
            .shares
            .lock()
            .await
            .values()
            .filter(|share| share.info.environment_id == environment_id)
            .map(|share| share.info.clone())
            .collect::<Vec<_>>();
        shares.sort_by(|a, b| a.id.cmp(&b.id));
        shares
    }
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.into(),
            publications: Mutex::new(HashMap::new()),
            setup_tunnels: Mutex::new(HashMap::new()),
            shares: Mutex::new(HashMap::new()),
            folder_operations: Mutex::new(HashMap::new()),
            terminals: Mutex::new(HashMap::new()),
            operations: Mutex::new(()),
            local_ports_key: Mutex::new(String::new()),
        }
    }
    pub async fn cleanup(&self, store: &PlatformStore, runtime: &RuntimeManager) {
        let Ok(state) = store.snapshot() else { return };
        let running = |id: &str| {
            state
                .environments
                .iter()
                .any(|e| e.id == id && e.status == EnvironmentStatus::Running)
        };
        let mut routes = self.publications.lock().await;
        let stale = routes
            .iter()
            .filter(|(_, p)| !running(&p.info.environment_id))
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for id in stale {
            if let Some(mut publication) = routes.remove(&id) {
                if let Some(child) = publication.cloudflare.as_mut() { let _ = child.kill().await; }
            }
        }
        for route in routes.values_mut() {
            if let Some(child) = route.cloudflare.as_mut() {
                if child.try_wait().ok().flatten().is_some() {
                    route.info.status = "error".into();
                    route.info.message =
                        "Cloudflare Tunnel disconnected. Remove and reconnect it.".into();
                    route.info.urls.clear();
                }
            }
        }
        drop(routes);
        let stale_shares = self
            .shares
            .lock()
            .await
            .iter()
            .filter(|(_, share)| !running(&share.info.environment_id))
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for id in stale_shares {
            self.remove_share(&id, runtime).await;
        }
        let mut sessions = self.terminals.lock().await;
        let stale = sessions
            .iter()
            .filter(|(_, lease)| !running(&lease.environment.id))
            .map(|(id, lease)| (id.clone(), lease.clone()))
            .collect::<Vec<_>>();
        for (id, _) in &stale {
            sessions.remove(id);
        }
        drop(sessions);
        for (id, lease) in stale {
            let _ = runtime
                .workspace_request(
                    &lease.environment,
                    "/v1/terminal/close",
                    json!({"id":runtime_id(&lease.environment),"sessionId":id}),
                )
                .await;
        }
        for environment in state.environments.iter().filter(|environment| environment.status == EnvironmentStatus::Running) {
            if state.saved_environment_services.iter().any(|service| service.environment_id == environment.id) {
                if let Err(error) = restore_environment_publications(&environment.id, store, runtime, self).await {
                    eprintln!("Could not restore saved service connections for {}: {error}", environment.name);
                }
            }
        }
        let _ = self.sync_local_ports(store, runtime).await;
    }
    pub async fn sync_local_ports(
        &self,
        store: &PlatformStore,
        runtime: &RuntimeManager,
    ) -> Result<(), String> {
        let mut last_key = self.local_ports_key.lock().await;
        let mut ports = self
            .publications
            .lock()
            .await
            .values()
            .filter(|p| p.info.kind == PublicationKind::Local)
            .map(|p| p.info.host_port)
            .collect::<Vec<_>>();
        ports.sort();
        ports.dedup();
        let state = store.snapshot()?;
        let mut environments = state
            .environments
            .into_iter()
            .filter(|e| {
                e.kind == EnvironmentKind::Container
                    && e.network_access
                    && e.status == EnvironmentStatus::Running
            })
            .collect::<Vec<_>>();
        environments.sort_by(|a, b| a.id.cmp(&b.id));
        let ids = environments
            .iter()
            .map(|e| runtime_id(e).to_owned())
            .collect::<Vec<_>>();
        let host_address = lan_address();
        let key = serde_json::to_string(&json!([ports, ids, host_address])).map_err(|e| e.to_string())?;
        if *last_key == key || (last_key.is_empty() && ports.is_empty()) {
            return Ok(());
        }
        runtime.update_local_service_ports(&ids, &ports, &host_address).await?;
        *last_key = key;
        Ok(())
    }
    pub async fn remove_share(&self, id: &str, runtime: &RuntimeManager) {
        let share = self.shares.lock().await.remove(id);
        if let Some(share) = share {
            let env = share.environment.clone();
            let mounted = share.info.mount_path.is_some();
            // Revoke host access before waiting for the guest to unmount it.
            drop(share);
            if mounted {
                let _ = runtime
                    .workspace_request(
                        &env,
                        "/v1/shares/detach",
                        json!({"id":runtime_id(&env),"shareId":id}),
                    )
                    .await;
            }
        }
    }
    pub async fn shutdown(&self, runtime: &RuntimeManager) {
        self.publications.lock().await.clear();
        self.setup_tunnels.lock().await.clear();
        // Revoke all file servers immediately; the runtime shuts down the guest mounts next.
        self.shares.lock().await.clear();
        self.terminals.lock().await.clear();
        let _ = runtime;
    }
    pub async fn close_window(
        &self,
        window: &str,
        _store: &PlatformStore,
        runtime: &RuntimeManager,
    ) {
        let sessions = self
            .terminals
            .lock()
            .await
            .iter()
            .filter(|(_, lease)| lease.owner == window)
            .map(|(session, lease)| (session.clone(), lease.clone()))
            .collect::<Vec<_>>();
        for (session, lease) in sessions {
            self.terminals.lock().await.remove(&session);
            let env = lease.environment;
            let _ = runtime
                .workspace_request(
                    &env,
                    "/v1/terminal/close",
                    json!({"id":runtime_id(&env),"sessionId":session}),
                )
                .await;
        }
    }
}
fn runtime_id(env: &Environment) -> &str {
    env.runtime_id.as_deref().unwrap_or(&env.id)
}
fn environment(store: &PlatformStore, id: &str) -> Result<Environment, String> {
    let env = store.environment(&id)?;
    if env.status != EnvironmentStatus::Running {
        return Err("Start the environment first".into());
    }
    Ok(env)
}
fn background(command: &mut tokio::process::Command) {
    command.kill_on_drop(true);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.as_std_mut().creation_flags(0x08000000);
    }
}
fn private_peer(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_loopback() || ip.is_private() || ip.is_link_local(),
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip
                    .to_ipv4_mapped()
                    .is_some_and(|v| private_peer(IpAddr::V4(v)))
        }
    }
}
fn lan_address() -> String {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("192.0.2.1:80")?;
            s.local_addr()
        })
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "127.0.0.1".into())
}

#[tauri::command]
pub async fn terminal_action(
    environment_id: String,
    session_id: String,
    action: String,
    data: Option<String>,
    offset: Option<u64>,
    cols: Option<u16>,
    rows: Option<u16>,
    window: WebviewWindow,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
    manager: State<'_, WorkspaceManager>,
) -> Result<Value, String> {
    terminal_action_for_owner(environment_id, session_id, action, data, offset, cols, rows, window.label(), &store, &runtime, &manager).await
}

pub(crate) async fn terminal_action_for_owner(
    environment_id: String,
    session_id: String,
    action: String,
    data: Option<String>,
    offset: Option<u64>,
    cols: Option<u16>,
    rows: Option<u16>,
    owner: &str,
    store: &PlatformStore,
    runtime: &RuntimeManager,
    manager: &WorkspaceManager,
) -> Result<Value, String> {
    if !session_id.starts_with("term-")
        || session_id.len() > 80
        || !session_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err("Invalid terminal identifier".into());
    }
    if !["create", "read", "write", "resize", "close"].contains(&action.as_str()) {
        return Err("Invalid terminal action".into());
    }
    let env = environment(&store, &environment_id)?;
    let mut sessions = manager.terminals.lock().await;
    if action == "create" {
        if sessions.len() >= 64 {
            return Err("Close an unused terminal first".into());
        }
        if sessions.contains_key(&session_id) {
            return Err("Terminal already exists".into());
        }
        sessions.insert(
            session_id.clone(),
            TerminalLease {
                environment: env.clone(),
                owner: owner.into(),
            },
        );
    } else if !sessions.get(&session_id).is_some_and(|lease| {
        lease.environment.id == environment_id && lease.owner == owner
    }) {
        if action == "close" {
            return Ok(json!({"ok":true}));
        }
        return Err("Terminal is closed or belongs to another window".into());
    }
    drop(sessions);
    let result=runtime.workspace_request(&env,&format!("/v1/terminal/{action}"),json!({"id":runtime_id(&env),"sessionId":session_id,"data":data.unwrap_or_default(),"offset":offset.unwrap_or_default(),"cols":cols.unwrap_or(80),"rows":rows.unwrap_or(24)})).await;
    if action == "create"
        && result.is_ok()
        && !manager.terminals.lock().await.contains_key(&session_id)
    {
        let _ = runtime
            .workspace_request(
                &env,
                "/v1/terminal/close",
                json!({"id":runtime_id(&env),"sessionId":session_id}),
            )
            .await;
    }
    if action == "close" || (action == "create" && result.is_err()) {
        manager.terminals.lock().await.remove(&session_id);
    }
    result
}

#[tauri::command]
pub async fn list_environment_services(
    environment_id: String,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
    manager: State<'_, WorkspaceManager>,
) -> Result<Value, String> {
    list_services(&environment_id, &store, &runtime, &manager).await
}

pub(crate) async fn list_services(
    environment_id: &str,
    store: &PlatformStore,
    runtime: &RuntimeManager,
    manager: &WorkspaceManager,
) -> Result<Value, String> {
    let state = store.snapshot()?;
    let env = state.environments.iter().find(|e|e.id==environment_id).ok_or("Environment not found")?;
    // Cloud nodes skip local service discovery, but their managed model APIs
    // can have live localhost/Cloudflare publications. Keep those visible so
    // callers can show their addresses and revoke access.
    let (mut services, notice) = if env.kind == EnvironmentKind::Cloud {
        (json!([]), "Cloud nodes use private TCP connection rules. Managed model APIs also support localhost and Cloudflare access.".to_string())
    } else if env.status != EnvironmentStatus::Running {
        (json!([]), "Start this environment to discover listening services or publish ports.".to_string())
    } else { match runtime
        .workspace_request(&env, "/v1/services/list", json!({"id":runtime_id(&env)}))
        .await
    {
        Ok(value) => (value, String::new()),
        Err(error) => (json!([]), error),
    }};
    if let Some(services)=services.as_array_mut() {
        for port in state.manual_service_ports.get(environment_id).into_iter().flatten() {
            if !services.iter().any(|service|service["port"]==*port) {
                services.push(json!({"port":port,"name":"Manual port","protocol":"tcp","address":""}));
            }
        }
    }
    let publications=publication_metadata(environment_id,store,manager).await?;
    let shares = manager.host_shares_for(&environment_id).await;
    Ok(json!({"services":services,"publications":publications,"shares":shares,"notice":notice}))
}

/// Compact publication state without contacting the guest or listing its processes.
pub(crate) async fn publication_metadata(environment_id:&str,store:&PlatformStore,manager:&WorkspaceManager)->Result<Vec<Publication>,String>{
    let state=store.snapshot()?;
    let env=state.environments.iter().find(|env|env.id==environment_id).ok_or("Environment not found")?;
    let mut routes=manager.publications.lock().await;
    for route in routes.values_mut().filter(|route|route.info.environment_id==environment_id){
        if route.cloudflare.as_mut().is_some_and(|child|child.try_wait().ok().flatten().is_some()) {
            route.info.status="error".into();route.info.message="Cloudflare Tunnel disconnected; inspect and reconnect this publication".into();route.info.urls.clear();
        }
    }
    let mut publications = routes
        .values()
        .filter(|p| p.info.environment_id == environment_id)
        .map(|p| p.info.clone())
        .collect::<Vec<_>>();
    for saved in state.saved_environment_services.iter().filter(|saved| saved.environment_id == environment_id) {
        if publications.iter().any(|publication| publication.id == saved.id) { continue; }
        let hostname = saved.domain.as_deref().and_then(|id| state.saved_domains.iter().find(|domain| domain.id == id))
            .map(|domain| domain.hostname.clone()).or_else(|| saved.cloudflare_hostname.clone());
        let urls = match &saved.kind {
            PublicationKind::Cloudflare => hostname.map(|hostname| vec![format!("https://{hostname}")]).unwrap_or_default(),
            PublicationKind::Loopback => vec![format!("http://127.0.0.1:{}", saved.host_port)],
            _ => vec![format!("http://127.0.0.1:{}", saved.host_port), format!("http://{}:{}", lan_address(), saved.host_port)],
        };
        publications.push(Publication {
            id: saved.id.clone(), environment_id: saved.environment_id.clone(), port: saved.port,
            kind: saved.kind.clone(), host_port: saved.host_port, urls,
            status: if env.status == EnvironmentStatus::Running { "error" } else { "stopped" }.into(),
            message: if env.status == EnvironmentStatus::Running {
                "Saved connection is reconnecting. Refresh shortly if it stays offline.".into()
            } else { "Saved connection will reconnect when this node starts.".into() },
            cloudflare_account: saved.domain.is_some() || saved.remembered_account,
        });
    }
    Ok(publications)
}

#[tauri::command]
pub async fn host_share_credentials(share_id: String,window:WebviewWindow, manager: State<'_, WorkspaceManager>) -> Result<Value, String> {
    if window.label()!="main"{return Err("Retrieve the private folder link from the main Yougori window or its same-user CLI".into())}
    host_share_credential_data(&share_id,&manager).await
}
pub(crate) async fn host_share_credential_data(share_id:&str, manager:&WorkspaceManager)->Result<Value,String>{
    let shares = manager.shares.lock().await;
    let share = shares.get(share_id).ok_or("Shared folder is no longer connected")?;
    Ok(json!({"shareId":share_id,"guestUrl":share.info.guest_url,"sensitive":true,"lifetime":"until the folder is disconnected or the engine stops"}))
}

#[derive(Serialize,Deserialize)]
struct LogCursor { offset: usize, anchor: String, #[serde(default)] anchor_bytes:usize }
fn log_window(text:&str,cursor:Option<&str>,limit:usize,tail:usize)->Result<Value,String>{
    use base64::Engine;
    use sha2::{Digest,Sha256};
    let previous=cursor.map(|c| {
        if c.len()>512{return Err("Log cursor is invalid".to_string())}
        let bytes=base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(c).map_err(|_|"Log cursor is invalid")?;
        serde_json::from_slice::<LogCursor>(&bytes).map_err(|_|"Log cursor is invalid".to_string())
    }).transpose()?;
    let mut rotated=false;
    let mut start=if let Some(previous)=previous{
        let bytes=previous.anchor_bytes;
        if bytes>128{return Err("Log cursor is invalid".into())}
        let matches=|end:usize|end>=bytes&&text.as_bytes().get(end-bytes..end).is_some_and(|part|format!("{:x}",Sha256::digest(part))==previous.anchor);
        if matches(previous.offset){previous.offset}else{
            rotated=true;
            (bytes..=text.len()).rev().find(|end|matches(*end)).unwrap_or_else(||text.len().saturating_sub(tail))
        }
    }else{text.len().saturating_sub(tail)};
    while start<text.len()&&!text.is_char_boundary(start){start+=1}
    let mut end=(start+limit).min(text.len());while end>start&&!text.is_char_boundary(end){end-=1}
    let bytes=end.min(128);
    let next=LogCursor{offset:end,anchor:format!("{:x}",Sha256::digest(&text.as_bytes()[end-bytes..end])),anchor_bytes:bytes};
    let next_cursor=base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&next).map_err(|e|e.to_string())?);
    Ok(json!({"stdout":&text[start..end],"nextCursor":next_cursor,"truncated":end<text.len(),"rotated":rotated,"bytes":end-start,"outcome":"read"}))
}
#[tauri::command]
pub async fn get_environment_log_window(environment_id:String,cursor:Option<String>,limit:Option<usize>,tail:Option<usize>,store:State<'_,PlatformStore>,runtime:State<'_,RuntimeManager>)->Result<Value,String>{
    let limit=limit.unwrap_or(16*1024);let tail=tail.unwrap_or(16*1024);
    if !(1..=64*1024).contains(&limit)||tail>256*1024{return Err("Log limit must be 1–65536 bytes and tail at most 262144 bytes".into())}
    let env=store.environment(&environment_id)?;
    let values=bound_secret_values(&env,&runtime)?;
    let text=tokio::time::timeout(Duration::from_secs(20),crate::commands::workloads::get_environment_logs(environment_id,store,runtime)).await.map_err(|_|"Log read timed out; the environment remains unchanged")??;
    let text=mask_secret_output(&text,&values,true);
    log_window(&text,cursor.as_deref(),limit,tail)
}
pub(crate) fn bound_secret_values(environment:&Environment,runtime:&RuntimeManager)->Result<Vec<String>,String>{
    let options=runtime.workload_options(runtime_id(environment))?;
    let mut values=options.environment.into_iter().filter_map(|(name,value)|{let upper=name.to_ascii_uppercase();(!value.is_empty()&&["TOKEN","PASSWORD","SECRET","API_KEY"].iter().any(|marker|upper.contains(marker))).then_some(value)}).collect::<Vec<_>>();
    for reference in options.secret_environment.values(){let value=crate::projects::secrets::resolve(reference).map_err(|_|format!("Protected output masking is unavailable for reference {reference}; output was withheld"))?;if !value.is_empty(){values.push(value)}}
    values.sort_by_key(|value|std::cmp::Reverse(value.len()));values.dedup();Ok(values)
}
/// Equal-byte masking keeps guest/log cursors stable. Withhold unfinished tail prefixes.
pub(crate) fn mask_secret_output(text:&str,values:&[String],withhold_partial:bool)->String{
    crate::guest_execution::mask_protected_text(text,values,withhold_partial)
}

#[tauri::command]
pub fn get_manual_service_ports(store:State<'_,PlatformStore>)->Result<std::collections::BTreeMap<String,Vec<u16>>,String> {
    Ok(store.snapshot()?.manual_service_ports)
}

#[tauri::command]
pub fn set_manual_service_port(environment_id:String,port:u16,present:bool,app:AppHandle,store:State<'_,PlatformStore>)->Result<std::collections::BTreeMap<String,Vec<u16>>,String> {
    if port==0 || port==7443 {return Err("Choose an application port between 1 and 65535; 7443 is reserved.".into());}
    let state=store.mutate(|state| {
        let environment=state.environments.iter().find(|e|e.id==environment_id).ok_or("Environment not found")?;
        if environment.kind==EnvironmentKind::Cloud {return Err("Cloud ports belong in private connection rules, not Local network or Public access publishing".into());}
        let ports=state.manual_service_ports.entry(environment_id).or_default();
        if present && !ports.contains(&port) {if ports.len()>=128 {return Err("Remove an unused manual port first (128 per environment).".into());} ports.push(port);ports.sort_unstable();}
        if !present {ports.retain(|p|*p!=port);}
        Ok(())
    })?;
    let _=app.emit("yougori-service-ports",&state.manual_service_ports);
    Ok(state.manual_service_ports)
}

pub(crate) async fn agent_stream(base: &str, token: &str, id: &str, port: u16) -> Result<TcpStream, String> {
    let url = url::Url::parse(base).map_err(|e| e.to_string())?;
    let mut stream = TcpStream::connect(("127.0.0.1", url.port().ok_or("Missing agent port")?))
        .await
        .map_err(|e| e.to_string())?;
    let request=format!("CONNECT /v1/services/connect?id={id}&port={port} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    let mut response = Vec::new();
    while !response.ends_with(b"\r\n\r\n") {
        response.push(stream.read_u8().await.map_err(|e| e.to_string())?);
        if response.len() > 16 * 1024 {
            return Err("Invalid guest response".into());
        }
    }
    if !response.starts_with(b"HTTP/1.1 200 ") {
        return Err("The guest service is not accepting connections".into());
    }
    Ok(stream)
}
pub(crate) async fn cloudflared(root: &Path) -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("YOUGORI_CLOUDFLARED_PATH")
        .or_else(|| std::env::var_os("OPENDOCK_CLOUDFLARED_PATH")) {
        return Ok(PathBuf::from(path));
    }
    let path = root.join(if cfg!(windows) { "tools/cloudflared-2026.8.3.exe" } else { "tools/cloudflared-2026.8.3" });
    #[cfg(target_os = "macos")]
    {
        let _ = path;
        // Finder has a minimal PATH. Homebrew owns signing and updates for the
        // preview; never silently execute a similarly named file from cwd.
        let prefix = if cfg!(target_arch = "aarch64") { "/opt/homebrew" } else { "/usr/local" };
        let executable = PathBuf::from(prefix).join("opt/cloudflared/bin/cloudflared");
        if !executable.is_file() {
            return Err("Public access needs Cloudflare Tunnel on this Mac. Run 'brew install cloudflared', then retry. Nothing was published.".into());
        }
        return Ok(executable);
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = path;
        return Ok(PathBuf::from("cloudflared"));
    }
    #[cfg(any(windows, target_os = "linux"))]
    {
        if cfg!(target_os = "linux") && !cfg!(any(target_arch = "x86_64", target_arch = "aarch64")) {
            return Err("Public access downloads Cloudflare Tunnel for x86-64 Linux only. Install cloudflared for this CPU and set YOUGORI_CLOUDFLARED_PATH to it, then retry. Nothing was published.".into());
        }
        #[cfg(windows)]
        const HASH: &str = "83e726ed18ea78c5ad5213c4c3a3a27051393950d2bc8ed4de69bec12d14eaae";
        #[cfg(all(target_os = "linux", not(target_arch = "aarch64")))]
        const HASH: &str = "f29324fe934d1e100617484c78deef803c4dc2cd351d645bbde42e96b4fccc5e";
        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        const HASH: &str = "4bcfd35521a7cbc545ebfd5d57334a71ee180e2a64874981f374c81472118391";
        if path.is_file() {
            let bytes = tokio::fs::read(&path).await.map_err(|e| e.to_string())?;
            if hex::encode(Sha256::digest(&bytes)) == HASH {
                return Ok(path);
            }
        }
        let url = if cfg!(windows) { "https://github.com/cloudflare/cloudflared/releases/download/2026.8.3/cloudflared-windows-amd64.exe" } else if cfg!(target_arch = "aarch64") { "https://github.com/cloudflare/cloudflared/releases/download/2026.8.3/cloudflared-linux-arm64" } else { "https://github.com/cloudflare/cloudflared/releases/download/2026.8.3/cloudflared-linux-amd64" };
        let mut response=reqwest::Client::new().get(url).timeout(Duration::from_secs(180)).send().await.map_err(|e|e.to_string())?.error_for_status().map_err(|e|e.to_string())?;
        if response.content_length().unwrap_or(0) > 100 * 1024 * 1024 {
            return Err("Unexpected Cloudflare download size".into());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
            if bytes.len() + chunk.len() > 100 * 1024 * 1024 {
                return Err("Unexpected Cloudflare download size".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        if bytes.len() > 100 * 1024 * 1024 || hex::encode(Sha256::digest(&bytes)) != HASH {
            return Err("Cloudflare download verification failed".into());
        }
        tokio::fs::create_dir_all(path.parent().unwrap())
            .await
            .map_err(|e| e.to_string())?;
        tokio::fs::write(&path, &bytes)
            .await
            .map_err(|e| e.to_string())?;
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).await.map_err(|e| e.to_string())?;
        }
        Ok(path)
    }
}

#[tauri::command]
pub async fn publish_environment_service(
    window: WebviewWindow,
    environment_id: String,
    port: u16,
    kind: PublicationKind,
    host_port: Option<u16>,
    cloudflare: Option<cloudflare::AccountOptions>,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
    manager: State<'_, WorkspaceManager>,
) -> Result<Publication, String> {
    if cloudflare.is_some() && window.label() != "main" {
        return Err("Connect your Cloudflare account from the main Yougori window".into());
    }
    publish_service(
        environment_id,
        port,
        kind,
        host_port,
        cloudflare,
        &store,
        &runtime,
        &manager,
    )
    .await
}
pub(crate) async fn publish_service(
    environment_id: String,
    port: u16,
    kind: PublicationKind,
    host_port: Option<u16>,
    cloudflare: Option<cloudflare::AccountOptions>,
    store: &PlatformStore,
    runtime: &RuntimeManager,
    manager: &WorkspaceManager,
) -> Result<Publication, String> {
    publish_service_with_intent(environment_id, port, kind, host_port, cloudflare, store, runtime, manager, None, true).await
}

async fn publish_service_with_intent(
    environment_id: String,
    port: u16,
    kind: PublicationKind,
    host_port: Option<u16>,
    cloudflare: Option<cloudflare::AccountOptions>,
    store: &PlatformStore,
    runtime: &RuntimeManager,
    manager: &WorkspaceManager,
    restore_id: Option<String>,
    persist_intent: bool,
) -> Result<Publication, String> {
    if port == 0 || port == 7443 {
        return Err("Choose an application port, not the guest control port".into());
    }
    let _operation = manager.operations.lock().await;
    if manager.publications.lock().await.len() >= 128 {
        return Err("Disconnect an unused service first".into());
    }
    let env = environment(&store, &environment_id)?;
    if cloudflare.is_some() && kind != PublicationKind::Cloudflare {
        return Err("Cloudflare credentials can only be used for a Cloudflare publication".into());
    }
    let account_intent = cloudflare.as_ref().map(|options| {
        (options.hostname.clone(), options.preset_id.clone(), options.preset_id.is_some() || options.remember)
    });
    // Cloud access is limited to managed model APIs and private project containers.
    if env.kind == EnvironmentKind::Cloud {
        let model = port == 8000 && matches!(kind, PublicationKind::Loopback | PublicationKind::Cloudflare)
            && runtime.workload_options(runtime_id(&env))?.environment.contains_key("YOUGORI_MODEL");
        let project = !model && matches!(kind, PublicationKind::Loopback | PublicationKind::Local | PublicationKind::Cloudflare)
            && runtime.cloud.project_service(&env.id, port).await?;
        if !model && !project {
            return Err("Cloud access requires a managed model API or a running Yougori project container. Start projects with yougori launch --cloud.".into());
        }
    }
    let account = cloudflare
        .map(|options| cloudflare::Account::resolve(&environment_id, port, host_port, options))
        .transpose()?;
    let host_port=host_port.or_else(||account.as_ref().map(cloudflare::Account::host_port));
    let previous = {
    let mut routes=manager.publications.lock().await;
    let existing_id=routes.values().find(|p|p.info.environment_id==environment_id&&p.info.port==port&&p.info.kind==kind).map(|p|p.info.id.clone());
    if let Some(id)=existing_id {
        let existing=&routes[&id];
        if existing.info.status!="active" || existing.info.cloudflare_account != account.is_some()
            || account.as_ref().is_some_and(|account| {
                existing.tunnel_id.as_deref() != Some(account.tunnel_id.as_str())
                    || existing.info.urls != vec![account.public_url()]
                    || host_port.is_some_and(|p|p!=existing.info.host_port)
            }) || host_port.is_some_and(|port|port!=existing.info.host_port)
        {
            // The request explicitly changes this environment's route. Hold its live bridge
            // and tunnel until the replacement succeeds; errors restore this exact object.
            routes.remove(&id)
        }else{
            return Ok(existing.info.clone());
        }
    }else{None}
    };
    // Reconnect a saved service using its stable identity after engine interruption.
    // The old saved intent remains intact until a replacement has actually succeeded.
    let resumed_id=store.snapshot()?.saved_environment_services.into_iter().find(|saved|saved.environment_id==environment_id&&saved.port==port&&saved.kind==kind).map(|saved|saved.id);
    let prior_intent=previous.as_ref().and_then(|p|store.snapshot().ok()?.saved_environment_services.into_iter().find(|s|s.id==p.info.id));
    let result=async {
    if let Some(account) = &account {
        if manager.publications.lock().await.values().any(|p| {
            p.tunnel_id.as_deref() == Some(account.tunnel_id.as_str())
        }) {
            return Err("This Cloudflare tunnel is already connected in Yougori. Use a dedicated tunnel for each published service.".into());
        }
    }
    // A localhost bridge to the same guest port is compatible with an account tunnel.
    // Share its lease instead of tearing down a working listener to bind it again.
    let reused = if let Some(previous)=previous.as_ref().filter(|p|Some(p.info.host_port)==host_port) {
        Some((previous.task.clone(),previous._vm_forward.clone()))
    }else if let Some(host)=host_port {
        let routes=manager.publications.lock().await;
        if let Some(owner)=routes.values().find(|p|p.info.host_port==host) {
            if owner.info.environment_id!=environment_id || owner.info.port!=port || !matches!(owner.info.kind,PublicationKind::Loopback|PublicationKind::Cloudflare) || !matches!(kind,PublicationKind::Loopback|PublicationKind::Cloudflare) {
                return Err(format!("Host port {host} is owned by publication {} on environment {} (guest port {}). This unrelated connection was preserved; use publication_preflight to inspect the conflict.",owner.info.id,owner.info.environment_id,owner.info.port));
            }
            Some((owner.task.clone(),owner._vm_forward.clone()))
        }else{None}
    }else{None};
    let agent = if reused.is_none(){runtime.workspace_endpoint(&env).await.ok()}else{None};
    let cloud = if env.kind == EnvironmentKind::Cloud { Some(runtime.cloud.service_target(&env.id, port).await?) } else { None };
    let vm_forward = if let Some((_,forward))=&reused { forward.clone() } else if agent.is_none() && env.kind == EnvironmentKind::FullVm {
        let (qmp, port) = runtime.forward_workspace_vm_port(&env, port).await?;
        Some(Arc::new(VmForward(qmp, port)))
    } else {
        None
    };
    if reused.is_none() && agent.is_none() && vm_forward.is_none() && cloud.is_none() {
        return Err("This environment cannot expose services".into());
    }
    if let Some(account) = &account {
        // Release the setup placeholder before binding this environment's bridge.
        cloudflare::finish_setup(manager, account).await?;
    }
    let (host_port, task) = if let Some((task,_))=reused {(host_port.unwrap(),task)}else {
    let listener = TcpListener::bind((
        if matches!(kind, PublicationKind::Cloudflare | PublicationKind::Loopback) {
            "127.0.0.1"
        } else {
            "0.0.0.0"
        },
        host_port.unwrap_or(0),
    ))
    .await
    .map_err(|e| format!("Cannot bind host port: {e}"))?;
    let host_port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let local_only = kind == PublicationKind::Local;
    let id = runtime_id(&env).to_owned();
    let forwarded_port = vm_forward.as_ref().map(|f| f.1);
    let task = Arc::new(ListenerTask(tokio::spawn(async move {
        let mut clients = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                result=listener.accept()=>{
                    let Ok((mut client,peer))=result else{break};
                    if local_only&&!private_peer(peer.ip()){continue}
                    if clients.len()>=256{continue}
                    let agent=agent.clone();let id=id.clone();let cloud=cloud.clone();
                    clients.spawn(async move{
                        let connection=tokio::time::timeout(Duration::from_secs(12),async{
                            let stream: BoxStream = if let Some(cloud)=cloud { Box::new(cloud.connect()?) }
                            else if let Some((base,token))=agent { Box::new(agent_stream(&base,&token,&id,port).await?) }
                            else { Box::new(TcpStream::connect(("127.0.0.1",forwarded_port.unwrap())).await.map_err(|e|e.to_string())?) };
                            Ok::<_,String>(stream)
                        }).await;
                        if let Ok(Ok(mut upstream))=connection{let _=tokio::io::copy_bidirectional(&mut client,&mut upstream).await;}
                    });
                },
                _=clients.join_next(),if !clients.is_empty()=>{}
            }
        }
    })));
    (host_port,task)
    };
    let mut live = LivePublication {
        info: Publication {
            id: restore_id.or_else(||previous.as_ref().map(|p|p.info.id.clone())).or(resumed_id).unwrap_or_else(|| format!("pub-{}", Uuid::new_v4().simple())),
            environment_id,
            port,
            kind: kind.clone(),
            host_port,
            urls: if kind == PublicationKind::Loopback { vec![format!("http://127.0.0.1:{host_port}")] } else { vec![
                format!("http://127.0.0.1:{host_port}"),
                format!("http://{}:{host_port}", lan_address()),
                format!("http://10.0.2.2:{host_port}"),
            ] },
            status: "active".into(),
            message: if kind == PublicationKind::Public {
                "Direct publishing is listening. Internet reachability requires your public IP and router/firewall port forwarding; Yougori does not change them automatically.".into()
            } else {
                if kind == PublicationKind::Loopback { "Access is limited to this PC.".into() } else { "Local access is available on this PC and private network.".into() }
            },
            cloudflare_account: account.is_some(),
        },
        task,
        cloudflare: None,
        logs: None,
        tunnel_id: account.as_ref().map(|a| a.tunnel_id.clone()),
        _cloudflare_config: None,
        _vm_forward: vm_forward,
    };
    if kind == PublicationKind::Cloudflare {
        let executable = cloudflared(&manager.root).await?;
        let started =
            cloudflare::start(&executable, &manager.root, host_port, account.as_ref()).await?;
        live.info.urls = vec![started.url];
        live.info.message = if account.is_some() {
            "Account tunnel connected. The configured hostname is shown; DNS, routing, and visitor authentication are controlled in your Cloudflare dashboard and have not been verified by Yougori.".into()
        } else { "Public HTTPS preview link. Anyone with the link can access this service; the link lasts while this tunnel runs.".into() };
        live.logs = Some(started.logs);
        live.cloudflare = Some(started.child);
        live._cloudflare_config = Some(started.config);
    }
    environment(store, &live.info.environment_id)?;
    if let Some(account) = &account {
        if let Err(error) = account.remember(&live.info.environment_id, port) {
            live.info.message.push_str(&format!(" {error}"));
        }
    }
    let info = live.info.clone();
    let restore_account = account_intent.as_ref().is_none_or(|(_, _, persistent)| *persistent);
    if persist_intent && restore_account {
        let intent = crate::models::SavedEnvironmentService {
            id: info.id.clone(),
            environment_id: info.environment_id.clone(),
            port: info.port,
            kind: info.kind.clone(),
            host_port: info.host_port,
            domain: account_intent.as_ref().and_then(|(_, preset, _)| preset.clone()),
            cloudflare_hostname: account_intent.as_ref().map(|(hostname, _, _)| hostname.clone()),
            remembered_account: account_intent.as_ref().is_some_and(|(_, _, persistent)| *persistent),
        };
        if let Err(error) = store.mutate(|state| {
            state.saved_environment_services.retain(|saved| saved.id != intent.id);
            state.saved_environment_services.push(intent);
            Ok(())
        }) {
            drop(live);
            return Err(format!("The connection started but could not be saved for the next node start: {error}"));
        }
    }
    manager
        .publications
        .lock()
        .await
        .insert(info.id.clone(), live);
    if kind == PublicationKind::Local {
        if let Err(error) = manager.sync_local_ports(store, runtime).await {
            manager.publications.lock().await.remove(&info.id);
            let _ = store.mutate(|state| { state.saved_environment_services.retain(|saved| saved.id != info.id); Ok(()) });
            return Err(format!(
                "Local guest access could not be configured: {error}"
            ));
        }
    }
    Ok(info)
    }.await;
    if result.is_err() {
        if let Some(previous)=previous {
            manager.publications.lock().await.insert(previous.info.id.clone(),previous);
            if let Some(intent)=prior_intent { store.mutate(|state|{state.saved_environment_services.retain(|saved|saved.id!=intent.id);state.saved_environment_services.push(intent);Ok(())}).map_err(|_|"The previous live publication was restored but its saved intent needs reconciliation")?; }
        }
    }
    result
}

/// Reconnect the non-secret service settings saved for a node.
pub(crate) async fn restore_environment_publications(
    environment_id: &str,
    store: &PlatformStore,
    runtime: &RuntimeManager,
    manager: &WorkspaceManager,
) -> Result<(), String> {
    let saved = store.snapshot()?.saved_environment_services.into_iter()
        .filter(|service| service.environment_id == environment_id)
        .collect::<Vec<_>>();
    let mut failures = Vec::new();
    for service in saved {
        let cloudflare = if service.kind == PublicationKind::Cloudflare {
            if let Some(domain) = service.domain.as_deref() {
                let (options, port) = cloudflare::domain_account(store, domain)?;
                if port != service.host_port { return Err("The saved domain's tunnel port changed. Update this node's connection before reconnecting.".into()); }
                Some(options)
            } else if service.remembered_account {
                Some(cloudflare::AccountOptions {
                    hostname: service.cloudflare_hostname.clone().ok_or("Saved Cloudflare hostname is missing")?,
                    token: None,
                    preset_id: None,
                    preset_source_environment_id: None,
                    preset_port: None,
                    remember: true,
                    routes_reviewed: true,
                })
            } else { None }
        } else { None };
        if let Err(error) = publish_service_with_intent(
            service.environment_id,
            service.port,
            service.kind,
            Some(service.host_port),
            cloudflare,
            store,
            runtime,
            manager,
            Some(service.id),
            false,
        ).await { failures.push(error); }
    }
    if failures.is_empty() { Ok(()) } else { Err(failures.join("; ")) }
}

#[tauri::command]
pub async fn unpublish_environment_service(
    publication_id: String,
    manager: State<'_, WorkspaceManager>,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
) -> Result<(), String> {
    manager.publications.lock().await.remove(&publication_id);
    store.mutate(|state| { state.saved_environment_services.retain(|saved| saved.id != publication_id); Ok(()) })?;
    manager.sync_local_ports(&store, &runtime).await
}

#[tauri::command]
pub async fn attach_host_folder(
    environment_id: String,
    path: String,
    read_only: bool,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
    manager: State<'_, WorkspaceManager>,
) -> Result<HostShare, String> {
    attach_folder(environment_id, path, read_only, &store, &runtime, &manager).await
}
async fn attach_folder(
    environment_id: String,
    path: String,
    read_only: bool,
    store: &PlatformStore,
    runtime: &RuntimeManager,
    manager: &WorkspaceManager,
) -> Result<HostShare, String> {
    let lock={let mut locks=manager.folder_operations.lock().await;locks.retain(|_,lock|Arc::strong_count(lock)>1);locks.entry(environment_id.clone()).or_default().clone()};
    let _operation = lock.lock().await;
    let env = environment(&store, &environment_id)?;
    if env.kind == EnvironmentKind::Cloud { return Err("Cloud nodes use connection-owned shared folders, not direct My PC mounts".into()); }
    let folder = PathBuf::from(path)
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let managed = manager.root.canonicalize().unwrap_or(manager.root.clone());
    if folder.starts_with(&managed) || managed.starts_with(&folder) || folder.parent().is_none() {
        return Err("Yougori's managed runtime directory cannot be shared".into());
    }
    if manager.shares.lock().await.len() >= 64 {
        return Err("Disconnect an unused shared folder first".into());
    }
    let display_path = folder.to_string_lossy().into_owned();
    if let Some(share) = manager
        .shares
        .lock()
        .await
        .values()
        .find(|s| s.info.environment_id == environment_id && s.info.path == display_path)
    {
        if share.info.read_only != read_only { return Err("Disconnect this folder before changing its permission".into()); }
        return Ok(share.info.clone());
    }
    if let Err(error)=crate::changes::ensure_folder_baseline(runtime,&environment_id,&folder).await { eprintln!("Changes baseline: {error}"); }
    let server = HostFolderServer::start(folder.clone(), read_only).await?;
    let id = format!("share-{}", Uuid::new_v4().simple());
    let endpoint = runtime.host_folder_endpoint(&env, &server).await?;
    let mount_path = if env.kind == EnvironmentKind::FullVm {
        None
    } else {
        let value=runtime.workspace_request(&env,"/v1/shares/attach",json!({"id":runtime_id(&env),"shareId":id,"endpoint":endpoint,"token":server.token,"readOnly":read_only})).await?;
        value["mountPath"].as_str().map(str::to_owned)
    };
    let info = HostShare {
        id: id.clone(),
        environment_id,
        path: folder.to_string_lossy().into_owned(),
        read_only,
        mount_path,
        guest_url: format!("{endpoint}/{}/", server.token),
    };
    manager.shares.lock().await.insert(
        id,
        LiveShare {
            info: info.clone(),
            environment: env,
            _server: server,
        },
    );
    if let Err(error) = environment(store, &info.environment_id) {
        manager.remove_share(&info.id, runtime).await;
        return Err(error);
    }
    Ok(info)
}
#[tauri::command]
pub async fn detach_host_folder(
    share_id: String,
    runtime: State<'_, RuntimeManager>,
    manager: State<'_, WorkspaceManager>,
) -> Result<(), String> {
    manager.remove_share(&share_id, &runtime).await;
    Ok(())
}

#[tauri::command]
pub fn list_environment_windows(app: AppHandle) -> Vec<Value> {
    app.webview_windows()
        .into_iter()
        .filter(|(label, _)| label.starts_with("environment-"))
        .map(|(label, window)| json!({"label":label,"title":window.title().unwrap_or_default()}))
        .collect()
}
#[tauri::command]
pub fn focus_environment_window(label: String, app: AppHandle) -> Result<(), String> {
    if !label.starts_with("environment-") {
        return Err("Not an environment window".into());
    }
    let window = app.get_webview_window(&label).ok_or("Window is closed")?;
    window.unminimize().map_err(|e| e.to_string())?;
    window.show().map_err(|e| e.to_string())?;
    window.set_focus().map_err(|e| e.to_string())
}
#[tauri::command]
pub fn title_environment_window(
    environment_id: String,
    window: WebviewWindow,
    store: State<'_, PlatformStore>,
) -> Result<(), String> {
    if !window.label().starts_with("environment-") {
        return Ok(());
    }
    let env = environment(&store, &environment_id)?;
    window
        .set_title(&format!(
            "{} — Yougori",
            env.name.replace(['\r', '\n'], " ")
        ))
        .map_err(|e| e.to_string())
}
#[tauri::command]
pub fn open_workspace_url(url: String) -> Result<(), String> {
    let url = url::Url::parse(&url).map_err(|e| e.to_string())?;
    if !["http", "https"].contains(&url.scheme())
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err("Only web URLs can be opened".into());
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        std::process::Command::new("explorer.exe")
            .arg(url.as_str())
            .creation_flags(0x08000000)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(not(windows))]
    {
        std::process::Command::new(if cfg!(target_os = "macos") {
            "open"
        } else {
            "xdg-open"
        })
        .arg(url.as_str())
        .spawn()
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Opens one of this environment's own web services in a Yougori window.
/// Only this computer's loopback and private addresses are accepted, so the
/// in-app browser can never be pointed at a public site by a guest or a link.
pub fn local_service_url(value: &str) -> Result<url::Url, String> {
    let url = url::Url::parse(value).map_err(|e| e.to_string())?;
    if !["http", "https"].contains(&url.scheme())
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err("Only web URLs can be opened".into());
    }
    let host = url.host_str().ok_or("Missing service address")?;
    let local = host == "localhost"
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .is_ok_and(private_peer);
    if !local {
        return Err(
            "Only this computer's private service addresses open inside Yougori. Public links open in your browser.".into(),
        );
    }
    Ok(url)
}

#[tauri::command]
pub async fn open_service_window(
    environment_id: String,
    url: String,
    app: crate::AppHandle,
    store: State<'_, PlatformStore>,
) -> Result<bool, String> {
    let environment = store.environment(&environment_id)?;
    let address = local_service_url(&url)?;
    crate::require_windows(&format!("A service window (open {address} in a browser instead)"))?;
    let host = address.host_str().unwrap_or_default().to_owned();
    // Remote content loads without Tauri IPC; this window only browses the service.
    tauri::WebviewWindowBuilder::new(
        &app,
        format!("service-{}", uuid::Uuid::new_v4().simple()),
        tauri::WebviewUrl::External(address),
    )
    .title(format!(
        "{} · {host} — Yougori",
        environment.name.replace(['\r', '\n'], " ")
    ))
    .inner_size(1180.0, 820.0)
    .min_inner_size(480.0, 360.0)
    .resizable(true)
    .focused(true)
    .center()
    .build()
    .map_err(|e| e.to_string())?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_private_service_addresses_open_inside_yougori() {
        for value in [
            "http://127.0.0.1:8080/",
            "http://localhost:3000/app",
            "https://192.168.1.20:8443/",
        ] {
            local_service_url(value).unwrap();
        }
        for value in [
            "https://example.com/",
            "http://8.8.8.8/",
            "file:///C:/secrets.txt",
            "http://user:pass@127.0.0.1/",
            "javascript:alert(1)",
        ] {
            assert!(local_service_url(value).is_err(), "{value}");
        }
    }
    #[test]
    fn local_routes_reject_public_peers() {
        assert!(private_peer("127.0.0.1".parse().unwrap()));
        assert!(private_peer("192.168.1.10".parse().unwrap()));
        assert!(!private_peer("8.8.8.8".parse().unwrap()));
        assert!(!private_peer("2001:4860:4860::8888".parse().unwrap()));
    }
}

#[cfg(test)]
#[path = "workspace_runtime_tests.rs"]
mod runtime_tests;
