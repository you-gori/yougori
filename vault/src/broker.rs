use crate::{
    native, platform,
    policy::{Identity, Operation, QUEUE_LIMIT, REQUEST_LIFETIME},
    protocol::{self, ItemInput, Request},
    storage::{Audit, Contents, Item, Store},
};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    os::windows::io::AsRawHandle,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::sync::oneshot;
mod http;
mod oauth;
struct Session {
    identity: Identity,
    /// OS-verified Desktop process (pipe connections only); see `platform::peer`.
    desktop: bool,
    cancelled: Arc<AtomicBool>,
    connected: AtomicBool,
    allowed: AtomicBool,
    admission: AtomicU64,
}
struct Pending {
    summary: Mutex<Value>,
    decision: AtomicU8,
    cancel: Arc<AtomicBool>,
    session: std::sync::Weak<Session>,
}
struct Shared {
    locked: AtomicBool,
    generation: AtomicU64,
    snapshot: Mutex<Value>,
    pending: Mutex<BTreeMap<String, Arc<Pending>>>,
    remote: Mutex<Value>,
    remote_stop: Mutex<Option<tokio::task::AbortHandle>>,
    revocations: Mutex<BTreeMap<String, u64>>,
    http: tokio::sync::Mutex<Value>,
    oauth: Mutex<oauth::OAuth>,
}
impl Shared {
    fn lock(&self) {
        self.locked.store(true, Ordering::SeqCst);
        self.generation.fetch_add(1, Ordering::SeqCst);
        for entry in self.pending.lock().unwrap().values() {
            entry.cancel.store(true, Ordering::SeqCst);
        }
    }
    /// Item names, clients, request details and activity are for Desktop only.
    /// Other local processes learn only whether requests are waiting.
    fn status(&self, desktop: bool) -> Value {
        if !desktop {
            let pending: Vec<Value> = self
                .pending
                .lock()
                .unwrap()
                .values()
                .map(|p| json!({"ready": p.summary.lock().unwrap()["ready"] == true}))
                .collect();
            return json!({"running":true,"desktop":false,"version":env!("CARGO_PKG_VERSION"),"locked":self.locked.load(Ordering::SeqCst),"pendingCount":pending.len(),"pending":pending,"items":[],"clients":[],"activity":[]});
        }
        let mut status = self.snapshot.lock().unwrap().clone();
        status["running"] = json!(true);
        status["desktop"] = json!(true);
        status["locked"] = json!(self.locked.load(Ordering::SeqCst));
        status["pending"] = json!(self
            .pending
            .lock()
            .unwrap()
            .values()
            .map(|p| p.summary.lock().unwrap().clone())
            .collect::<Vec<_>>());
        status["remote"] = self.remote.lock().unwrap().clone();
        status["oauthReady"] = json!(self.oauth.lock().unwrap().configured());
        if let Ok(activity) = crate::storage::recent() {
            status["activity"] = json!(activity);
        }
        if self.locked.load(Ordering::SeqCst) {
            status["items"] = json!([]);
            status["clients"] = json!([]);
        }
        status
    }
}
enum Action {
    Connect,
    /// A connection already approved in Desktop while the worker stayed free.
    ApprovedConnect,
    Tool(Operation),
    AddItems(Vec<ItemInput>),
    Browse,
    HttpSetup,
    HttpCredentials,
    Remote,
    Revoke(String),
    Remove(String),
}
struct Job {
    id: String,
    session: Arc<Session>,
    action: Action,
    cancel: Arc<AtomicBool>,
    deadline: Instant,
    generation: u64,
    response: oneshot::Sender<Result<Value, String>>,
}
pub(crate) fn run() -> Result<(), String> {
    platform::require_broker()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let _entered = runtime.enter();
    let first = platform::bind(true)?;
    let shared = Arc::new(Shared {
        locked: AtomicBool::new(true),
        generation: AtomicU64::new(0),
        snapshot: Mutex::new(
            json!({"items":[],"clients":[],"activity":crate::storage::recent()?,"protection":"Protected Windows broker; one-time approval for each request","transport":"Local MCP stdio"}),
        ),
        pending: Mutex::new(BTreeMap::new()),
        remote: Mutex::new(Value::Null),
        remote_stop: Mutex::new(None),
        revocations: Mutex::new(BTreeMap::new()),
        http: tokio::sync::Mutex::new(Value::Null),
        oauth: Mutex::new(oauth::OAuth::load()?),
    });
    let (sender, receiver) = std::sync::mpsc::sync_channel::<Job>(QUEUE_LIMIT);
    let worker_state = shared.clone();
    let worker_runtime = runtime.handle().clone();
    let worker_sender = sender.clone();
    std::thread::Builder::new()
        .name("vault-operations".into())
        .spawn(move || worker(receiver, worker_state, worker_runtime, worker_sender))
        .map_err(|e| e.to_string())?;
    let monitor = shared.clone();
    runtime.spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(200)).await;
            if native::workstation_locked() && !monitor.locked.load(Ordering::SeqCst) {
                monitor.lock();
                let _ = crate::storage::record(&Audit {
                    time: chrono::Utc::now().to_rfc3339(),
                    client: "Windows session".into(),
                    request: uuid::Uuid::new_v4().to_string(),
                    operation: "vault".into(),
                    outcome: "locked_by_windows".into(),
                });
            }
        }
    });
    runtime.block_on(async move {
        let mut listener = first;
        let clients = Arc::new(tokio::sync::Semaphore::new(24));
        loop {
            listener.connect().await.map_err(|e| e.to_string())?;
            let next = platform::bind(false)?;
            let pipe = std::mem::replace(&mut listener, next);
            let Ok(permit) = clients.clone().try_acquire_owned() else {
                drop(pipe);
                continue;
            };
            let Ok((identity, desktop)) = platform::peer(pipe.as_raw_handle()) else {
                drop(pipe);
                continue;
            };
            let session = Arc::new(Session {
                identity,
                desktop,
                cancelled: Arc::new(AtomicBool::new(false)),
                connected: AtomicBool::new(true),
                allowed: AtomicBool::new(false),
                admission: AtomicU64::new(0),
            });
            let sender = sender.clone();
            let shared = shared.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let _ = serve(pipe, session.clone(), sender, shared, false).await;
                session.connected.store(false, Ordering::SeqCst);
                session.cancelled.store(true, Ordering::SeqCst);
            });
        }
        #[allow(unreachable_code)]
        Ok::<(), String>(())
    })
}
async fn serve<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static>(
    pipe: S,
    session: Arc<Session>,
    sender: std::sync::mpsc::SyncSender<Job>,
    shared: Arc<Shared>,
    remote: bool,
) -> Result<(), String> {
    let remote_port = shared.remote.lock().unwrap()["brokerPort"].clone();
    let (mut reader, mut writer) = tokio::io::split(pipe);
    let (incoming, mut messages) = tokio::sync::mpsc::channel(2);
    let reading_session = session.clone();
    let reading_state = shared.clone();
    let reading = tokio::spawn(async move {
        loop {
            let bytes =
                match tokio::time::timeout(Duration::from_secs(1800), protocol::read(&mut reader))
                    .await
                {
                    Ok(Ok(bytes)) => bytes,
                    _ => break,
                };
            // JSON-RPC cancellation cancels the current session's work. It never
            // implies consent and cannot be used to approve or resume anything.
            if let Ok(Request::Mcp { message }) = serde_json::from_slice::<Request>(&bytes) {
                if message["method"] == "notifications/cancelled" {
                    reading_session.cancelled.store(true, Ordering::SeqCst);
                    break;
                }
            }
            if incoming.try_send(bytes).is_err() {
                break;
            }
        }
        reading_session.connected.store(false, Ordering::SeqCst);
        reading_session.cancelled.store(true, Ordering::SeqCst);
        for pending in reading_state.pending.lock().unwrap().values() {
            if pending
                .session
                .upgrade()
                .is_some_and(|s| Arc::ptr_eq(&s, &reading_session))
            {
                pending.cancel.store(true, Ordering::SeqCst);
            }
        }
    });
    while let Some(bytes) = messages.recv().await {
        if remote {
            let current = shared.remote.lock().unwrap();
            if current.is_null() || current["brokerPort"] != remote_port {
                break;
            }
        }
        let mut response = match serde_json::from_slice::<Request>(&bytes) {
            Ok(request) if remote && !matches!(request, Request::Mcp { .. }) => {
                json!({"error":"Remote connections support MCP requests only"})
            }
            Ok(request) => handle(request, &session, &sender, &shared)
                .await
                .unwrap_or_else(|error| json!({"error":error})),
            Err(_) => json!({"error":"Invalid or unsupported vault request"}),
        };
        let written = protocol::write(&mut writer, &response).await;
        protocol::wipe(&mut response);
        if written.is_err() {
            break;
        }
    }
    reading.abort();
    Ok(())
}
async fn enqueue(
    action: Action,
    session: &Arc<Session>,
    sender: &std::sync::mpsc::SyncSender<Job>,
    shared: &Arc<Shared>,
) -> Result<Value, String> {
    let (response, received) = oneshot::channel();
    let id = uuid::Uuid::new_v4().to_string();
    let cancel = Arc::new(AtomicBool::new(false));
    let operation = match &action {
        Action::Connect | Action::ApprovedConnect => "connect",
        Action::Tool(v) => v.name(),
        Action::AddItems(_) => "add_items",
        Action::Browse => "browse",
        Action::HttpSetup => "setup",
        Action::HttpCredentials => "connection_key",
        Action::Remote => "remote_access",
        Action::Revoke(_) => "revoke",
        Action::Remove(_) => "remove",
    };
    {
        let mut pending = shared.pending.lock().unwrap();
        if pending.len() >= QUEUE_LIMIT {
            return Err(
                "The approval queue is full; wait before submitting another request".into(),
            );
        }
        pending.insert(id.clone(), Arc::new(Pending { summary: Mutex::new(json!({"id":id,"client":session.identity.summary(),"operation":operation,"expiresAt":(chrono::Utc::now()+chrono::Duration::seconds(120)).to_rfc3339()})), decision: AtomicU8::new(0), cancel: cancel.clone(), session:Arc::downgrade(session) }));
    }
    let job = Job {
        id: id.clone(),
        session: session.clone(),
        action,
        cancel,
        deadline: Instant::now() + REQUEST_LIFETIME,
        generation: shared.generation.load(Ordering::SeqCst),
        response,
    };
    if sender.try_send(job).is_err() {
        shared.pending.lock().unwrap().remove(&id);
        return Err("The approval queue is full".into());
    }
    received
        .await
        .map_err(|_| "Protected approval service stopped".to_string())?
}
async fn handle(
    request: Request,
    session: &Arc<Session>,
    sender: &std::sync::mpsc::SyncSender<Job>,
    shared: &Arc<Shared>,
) -> Result<Value, String> {
    match request {
        Request::Status {} => Ok(shared.status(session.desktop)),
        Request::Lock {} => {
            shared.lock();
            crate::storage::record(&Audit {
                time: chrono::Utc::now().to_rfc3339(),
                client: session.identity.id.clone(),
                request: uuid::Uuid::new_v4().to_string(),
                operation: "vault".into(),
                outcome: "locked".into(),
            })?;
            Ok(json!({"locked":true}))
        }
        Request::Deny { request } => {
            if !platform::desktop_foreground(&session.identity, session.desktop) { return Err("Open Yougori Desktop to deny requests".into()); }
            if let Some(p) = shared.pending.lock().unwrap().get(&request) {
                p.cancel.store(true, Ordering::SeqCst);
            }
            Ok(json!({"denied":true}))
        }
        Request::Approve { request } => {
            if !platform::desktop_foreground(&session.identity, session.desktop) || !native::unlocked_desktop() {
                return Err("Open Yougori Desktop to approve this request".into());
            }
            let pending = shared.pending.lock().unwrap().get(&request).cloned().ok_or("Request is no longer pending")?;
            if pending.summary.lock().unwrap()["ready"] != true || pending.cancel.load(Ordering::SeqCst) {
                return Err("Request is not ready for approval".into());
            }
            pending.decision.compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
                .map_err(|_| "Request already decided")?;
            Ok(json!({"approved":true}))
        }
        Request::Manage {} => Err("Use Add items in Yougori Desktop".into()),
        Request::AddItems { items } => {
            if !platform::desktop_foreground(&session.identity, session.desktop) || !native::unlocked_desktop() {
                return Err("Open Yougori Desktop to add vault items".into());
            }
            enqueue(Action::AddItems(items), session, sender, shared).await
        }
        Request::Browse {} => enqueue(Action::Browse, session, sender, shared).await,
        Request::HttpSetup {} => enqueue(Action::HttpSetup, session, sender, shared).await,
        Request::HttpCredentials {} => {
            enqueue(Action::HttpCredentials, session, sender, shared).await
        }
        Request::HttpEndpoint {} => {
            if !session.desktop { return Err("Only Yougori Desktop can start the vault gateway".into()); }
            http::start(shared.clone(), sender.clone()).await
        },
        Request::HttpOrigin { origin } => {
            if !session.desktop { return Err("Only Yougori Desktop can configure the vault gateway".into()); }
            shared.oauth.lock().unwrap().set_origin(origin)?;
            Ok(json!({"configured":true}))
        }
        Request::Remote {} => enqueue(Action::Remote, session, sender, shared).await,
        Request::RemoteOff {} => {
            if !platform::desktop_foreground(&session.identity, session.desktop) { return Err("Open Yougori Desktop to disable remote vault access".into()); }
            if let Some(stop) = shared.remote_stop.lock().unwrap().take() {
                stop.abort();
            }
            *shared.remote.lock().unwrap() = Value::Null;
            shared.generation.fetch_add(1, Ordering::SeqCst);
            Ok(json!({"disabled":true}))
        }
        Request::Revoke { client } => {
            if !platform::desktop_foreground(&session.identity, session.desktop) { return Err("Open Yougori Desktop to revoke a client".into()); }
            if !shared.snapshot.lock().unwrap()["clients"]
                .as_array()
                .is_some_and(|clients| clients.iter().any(|v| v["id"] == client))
            {
                return Err("Client is not in the approved-client list".into());
            }
            shared.oauth.lock().unwrap().revoke_client(&client)?;
            {
                let mut revoked = shared.revocations.lock().unwrap();
                let epoch = revoked.entry(client.clone()).or_insert(0);
                *epoch = epoch.saturating_add(1);
            }
            for pending in shared.pending.lock().unwrap().values() {
                if pending.summary.lock().unwrap()["client"]["id"] == client {
                    pending.cancel.store(true, Ordering::SeqCst);
                }
            }
            enqueue(Action::Revoke(client), session, sender, shared).await
        }
        Request::Remove { item } => enqueue(Action::Remove(item), session, sender, shared).await,
        Request::Mcp { message } => {
            let id = message.get("id").cloned();
            if message["jsonrpc"] != "2.0" || !message.is_object() {
                return Ok(
                    json!({"jsonrpc":"2.0","id":id,"error":{"code":-32600,"message":"Invalid JSON-RPC request"}}),
                );
            }
            if id
                .as_ref()
                .is_some_and(|v| !v.is_string() && !v.is_number())
            {
                return Ok(
                    json!({"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Invalid request ID"}}),
                );
            }
            let method = message["method"].as_str().unwrap_or("");
            if method.starts_with("notifications/") && id.is_none() {
                return Ok(Value::Null);
            }
            if id.is_none() {
                return Ok(Value::Null);
            }
            let result: Result<Value, String> = match method {
                "initialize" => {
                    let consent = if session.allowed.load(Ordering::SeqCst) {
                        Ok(Value::Null)
                    } else {
                        enqueue(Action::Connect, session, sender, shared).await
                    };
                    match consent {
                        Ok(_) => Ok(
                            json!({"protocolVersion":protocol::negotiate(message["params"]["protocolVersion"].as_str()),"capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"Yougori Personal Vault","version":env!("CARGO_PKG_VERSION")},"instructions":"Every protected tool requires explicit approval inside Yougori Desktop. Never ask the user to paste credentials into chat. Use list_vault_items to request names, IDs, types, and personal-information field names when needed. Use read_credential for one credential or read_all_credentials only when the user specifically asks to share all credentials; the latter shows the full set before approval. For personal_info, use exact item IDs and field names. Chat approval never replaces approval in Yougori. If a tool returns isError, explain its message and do not automatically retry denied requests."}),
                        ),
                        Err(e) => Err(e),
                    }
                }
                "ping" => Ok(json!({})),
                _ if !session.allowed.load(Ordering::SeqCst) => {
                    Err("Vault is locked or this connection has not been approved".into())
                }
                "tools/list" => Ok(protocol::tool_catalog()),
                "tools/call" => {
                    let parsed = serde_json::from_value::<Operation>(json!({"tool":message["params"]["name"],"arguments":message["params"]["arguments"]})).map_err(|_| "Unsupported tool or invalid arguments".to_string());
                    match parsed.and_then(|v| v.validate().map(|_| v)) {
                        Ok(operation) => {
                            match enqueue(Action::Tool(operation), session, sender, shared).await {
                                Ok(mut value) => {
                                    let text = zeroize::Zeroizing::new(serde_json::to_string(&value).unwrap());
                                    protocol::wipe(&mut value);
                                    Ok(json!({"content":[{"type":"text","text":&*text}],"isError":false}))
                                }
                                Err(error) => Ok(
                                    json!({"content":[{"type":"text","text":error}],"isError":true}),
                                ),
                            }
                        }
                        Err(error) => {
                            Ok(json!({"content":[{"type":"text","text":error}],"isError":true}))
                        }
                    }
                }
                _ => Err("Unsupported MCP method".into()),
            };
            if result.is_err() {
                crate::storage::record(&Audit {
                    time: chrono::Utc::now().to_rfc3339(),
                    client: session.identity.id.clone(),
                    request: uuid::Uuid::new_v4().to_string(),
                    operation: "mcp_request".into(),
                    outcome: "rejected".into(),
                })?;
            }
            Ok(match result {
                Ok(result) => json!({"jsonrpc":"2.0","id":id,"result":result}),
                Err(error) => {
                    json!({"jsonrpc":"2.0","id":id,"error":{"code":-32000,"message":error}})
                }
            })
        }
    }
}
fn valid(job: &Job, shared: &Shared) -> bool {
    let epoch = *shared
        .revocations
        .lock()
        .unwrap()
        .get(&job.session.identity.id)
        .unwrap_or(&0);
    (!job.session.allowed.load(Ordering::SeqCst)
        || job.session.admission.load(Ordering::SeqCst) == epoch)
        && !job.response.is_closed()
        && !job.cancel.load(Ordering::SeqCst)
        && !job.session.cancelled.load(Ordering::SeqCst)
        && job.session.connected.load(Ordering::SeqCst)
        && Instant::now() < job.deadline
        && job.generation == shared.generation.load(Ordering::SeqCst)
        && !native::workstation_locked()
}
fn desktop_decision(job: &Job, shared: &Shared, title: &str, content: &str, allow: &str) -> Result<bool, String> {
    let pending = shared.pending.lock().unwrap().get(&job.id).cloned().ok_or("Request is no longer pending")?;
    *pending.summary.lock().unwrap() = json!({
        "id": job.id,
        "client": job.session.identity.summary(),
        "operation": match &job.action { Action::Tool(op) => op.name(), Action::Connect | Action::ApprovedConnect => "connect", _ => "vault" },
        "title": title,
        "description": content,
        "allowLabel": allow,
        "ready": true,
        "expiresAt": (chrono::Utc::now() + chrono::Duration::seconds(120)).to_rfc3339(),
    });
    while valid(job, shared) {
        if pending.decision.load(Ordering::SeqCst) == 1 {
            return Ok(true);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(false)
}
fn audit(store: &Store, job: &Job, operation: &str, outcome: &str) -> Result<(), String> {
    store.audit(&Audit {
        time: chrono::Utc::now().to_rfc3339(),
        client: job.session.identity.id.clone(),
        request: job.id.clone(),
        operation: operation.into(),
        outcome: outcome.into(),
    })
}
fn who(identity: &Identity) -> String {
    format!("Verified application: {}\nSHA-256: {}\nProcess: {}\nDevice: {}\nEnvironment: {}\nWindows user: {}",identity.executable,identity.digest,identity.process,identity.device,identity.environment,identity.user)
}
fn vault_inventory(contents: &Contents) -> Value {
    let items: Vec<Value> = contents.items.values().map(|item| {
        let fields: Vec<String> = if item.kind == "personal" {
            serde_json::from_str::<BTreeMap<String, String>>(&item.value)
                .unwrap_or_default().into_keys().collect()
        } else { Vec::new() };
        json!({"id":item.id,"name":item.label,"kind":item.kind,"fields":fields})
    }).collect();
    json!({"count":items.len(),"items":items})
}
fn all_credentials(contents: &Contents) -> Value {
    let credentials: Vec<Value> = contents.items.values()
        .filter(|item| item.is_credential())
        .map(|item| json!({"id":item.id,"name":item.label,"kind":item.kind,"value":item.value}))
        .collect();
    json!({"count":credentials.len(),"credentials":credentials})
}
fn mcp_result_fits(value: &Value) -> bool {
    let Ok(text) = serde_json::to_string(value).map(zeroize::Zeroizing::new) else { return false; };
    let mut wrapper = json!({"jsonrpc":"2.0","id":"reserved-id","result":{"content":[{"type":"text","text":&*text}],"isError":false}});
    let fits = serde_json::to_vec(&wrapper)
        .map(zeroize::Zeroizing::new)
        .is_ok_and(|bytes| bytes.len() < protocol::MAX_FRAME - 1024);
    protocol::wipe(&mut wrapper);
    fits
}
const CONNECT_TITLE: &str = "Allow this client to submit requests?";
const CONNECT_ALLOW: &str = "Allow Requests";
fn connect_content(identity: &Identity) -> String {
    format!("{}\n\nRequested access: submit requests to Personal Vault.\nNo information, credentials, or execution permission is granted. Every tool call needs a new approval.",who(identity))
}
/// Waits for the Desktop decision on an unauthenticated (OAuth sign-in)
/// connection without occupying the single operation worker. Only one such
/// prompt may wait at a time, so sign-in attempts cannot crowd out agents.
async fn connection_decision(shared: &Arc<Shared>, session: &Arc<Session>) -> Result<(), String> {
    let id = uuid::Uuid::new_v4().to_string();
    let generation = shared.generation.load(Ordering::SeqCst);
    let deadline = Instant::now() + REQUEST_LIFETIME;
    let pending = Arc::new(Pending {
        summary: Mutex::new(json!({
            "id": id,
            "client": session.identity.summary(),
            "operation": "connect",
            "title": CONNECT_TITLE,
            "description": connect_content(&session.identity),
            "allowLabel": CONNECT_ALLOW,
            "ready": true,
            "unauthenticated": true,
            "expiresAt": (chrono::Utc::now() + chrono::Duration::seconds(120)).to_rfc3339(),
        })),
        decision: AtomicU8::new(0),
        cancel: Arc::new(AtomicBool::new(false)),
        session: Arc::downgrade(session),
    });
    {
        let mut waiting = shared.pending.lock().unwrap();
        if waiting.len() >= QUEUE_LIMIT
            || waiting.values().any(|p| p.summary.lock().unwrap()["unauthenticated"] == true)
        {
            return Err("Another sign-in is waiting for review in Yougori. Try again shortly.".into());
        }
        waiting.insert(id.clone(), pending.clone());
    }
    struct Waiting<'a>(&'a Shared, String);
    impl Drop for Waiting<'_> {
        fn drop(&mut self) {
            self.0.pending.lock().unwrap().remove(&self.1);
        }
    }
    let _waiting = Waiting(shared, id);
    loop {
        if pending.decision.load(Ordering::SeqCst) == 1 {
            return Ok(());
        }
        // Windows locking, revocation and vault locking all advance the generation.
        if pending.cancel.load(Ordering::SeqCst)
            || session.cancelled.load(Ordering::SeqCst)
            || !session.connected.load(Ordering::SeqCst)
            || Instant::now() >= deadline
            || shared.generation.load(Ordering::SeqCst) != generation
        {
            return Err("Connection denied or expired".into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
#[cfg(test)]
mod inventory_tests {
    use super::*;
    #[test]
    fn inventory_never_contains_values_and_bulk_excludes_personal_information() {
        let mut contents = Contents::default();
        for (id, label, kind, value) in [
            ("a", "GitHub", "api_key", "very-private-token"),
            ("b", "Profile", "personal", r#"{"email":"private@example.com"}"#),
        ] {
            contents.items.insert(id.into(), Item { id:id.into(), label:label.into(), kind:kind.into(), resource:String::new(), value:value.into() });
        }
        let inventory = vault_inventory(&contents);
        assert_eq!(inventory["count"], 2);
        assert_eq!(inventory["items"][0]["name"], "GitHub");
        assert_eq!(inventory["items"][1]["fields"][0], "email");
        assert!(!inventory.to_string().contains("very-private-token"));
        assert!(!inventory.to_string().contains("private@example.com"));
        let bulk = all_credentials(&contents);
        assert_eq!(bulk["count"], 1);
        assert_eq!(bulk["credentials"][0]["value"], "very-private-token");
        assert!(!bulk.to_string().contains("private@example.com"));
        assert!(mcp_result_fits(&bulk));
        let oversized = json!({"credentials":[{"value":"\\".repeat(protocol::MAX_FRAME)}]});
        assert!(!mcp_result_fits(&oversized));
    }
}
fn worker(
    receiver: std::sync::mpsc::Receiver<Job>,
    shared: Arc<Shared>,
    runtime: tokio::runtime::Handle,
    sender: std::sync::mpsc::SyncSender<Job>,
) {
    let mut store: Option<Store> = None;
    loop {
        let job = match receiver.recv_timeout(Duration::from_millis(200)) {
            Ok(job) => job,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if shared.locked.load(Ordering::SeqCst) {
                    store = None;
                }
                continue;
            }
            Err(_) => break,
        };
        if shared.locked.load(Ordering::SeqCst) {
            store = None;
        }
        let operation = match &job.action {
            Action::Tool(op) => op.name(),
            Action::Connect | Action::ApprovedConnect => "connect",
            Action::AddItems(_) => "add_items",
            Action::Browse => "browse",
            Action::HttpSetup => "setup",
            Action::HttpCredentials => "connection_key",
            Action::Remote => "remote_access",
            Action::Revoke(_) => "revoke",
            Action::Remove(_) => "remove",
        };
        let entry = Audit {
            time: chrono::Utc::now().to_rfc3339(),
            client: job.session.identity.id.clone(),
            request: job.id.clone(),
            operation: operation.into(),
            outcome: "requested".into(),
        };
        let result = crate::storage::record(&entry).and_then(|_| work(&job, &shared, &mut store, &runtime, &sender));
        if result.is_err() {
            let mut denied = entry;
            denied.time = chrono::Utc::now().to_rfc3339();
            denied.outcome = "rejected_or_cancelled".into();
            let _ = crate::storage::record(&denied);
        }
        shared.pending.lock().unwrap().remove(&job.id);
        if let Some(store) = &store {
            *shared.snapshot.lock().unwrap() = json!({"items":store.contents.items.values().map(|v|v.summary()).collect::<Vec<_>>(),"clients":store.contents.clients.values().map(|v|v.summary()).collect::<Vec<_>>(),"activity":store.recent().unwrap_or_default(),"protection":"Protected Windows broker; one-time approval for each request","transport":"Local MCP stdio"});
        }
        let _ = job.response.send(result);
    }
}
fn work(
    job: &Job,
    shared: &Arc<Shared>,
    state: &mut Option<Store>,
    runtime: &tokio::runtime::Handle,
    sender: &std::sync::mpsc::SyncSender<Job>,
) -> Result<Value, String> {
    if !valid(job, shared) {
        return Err("Request cancelled, expired, or Windows is locked".into());
    }
    if matches!(job.action, Action::HttpSetup | Action::HttpCredentials) {
        let setup = matches!(job.action, Action::HttpSetup);
        if !platform::desktop_foreground(&job.session.identity, job.session.desktop) || !valid(job, shared) {
            return Err("Open Yougori Desktop to manage the vault".into());
        }
        if setup {
            *state = Some(Store::open()?);
            shared.locked.store(false, Ordering::SeqCst);
            http::create_key()?;
        }
        let mut result = runtime.block_on(http::start(shared.clone(), sender.clone()))?;
        if !setup {
            result["token"] = json!(&*http::read_key()?);
        }
        return Ok(result);
    }
    if matches!(job.action, Action::Browse) {
        if !platform::desktop_foreground(&job.session.identity, job.session.desktop) || !valid(job, shared) { return Err("Open Yougori Desktop to view vault items".into()); }
        if state.is_none() {
            *state = Some(Store::open()?);
        }
        shared.locked.store(false, Ordering::SeqCst);
        return Ok(json!({"ready":true}));
    }
    if let Action::AddItems(inputs) = &job.action {
        if !platform::desktop_foreground(&job.session.identity, job.session.desktop) || !valid(job, shared) {
            return Err("Open Yougori Desktop to add vault items".into());
        }
        if state.is_none() {
            *state = Some(Store::open()?);
            shared.locked.store(false, Ordering::SeqCst);
        }
        let items: Vec<Item> = inputs.iter().map(|input| Item { id: uuid::Uuid::new_v4().to_string(), label: input.label.clone(), kind: input.kind.clone(), resource: input.resource.clone(), value: input.value.clone() }).collect();
        if items.is_empty() || items.len() > 128 {
            return Err("Add between 1 and 128 items".into());
        }
        for item in &items { item.validate()?; }
        if shared.locked.load(Ordering::SeqCst)
            || job.session.cancelled.load(Ordering::SeqCst)
            || job.generation != shared.generation.load(Ordering::SeqCst)
        {
            return Err("Session ended while saving items".into());
        }
        let store = state.as_mut().ok_or("Open your vault again")?;
        if store.contents.items.len() + items.len() > 128 {
            return Err("Vault supports up to 128 items. Nothing was saved.".into());
        }
        let ids: Vec<_> = items.iter().map(|item| item.id.clone()).collect();
        audit(store, job, "items", "add_requested")?;
        for item in items {
            store.contents.items.insert(item.id.clone(), item);
        }
        if let Err(error) = store.save() {
            for id in &ids {
                store.contents.items.remove(id);
            }
            return Err(error);
        }
        audit(store, job, "items", "added")?;
        return Ok(json!({"added":ids}));
    }
    if state.is_none() || shared.locked.load(Ordering::SeqCst) {
        *state = Some(Store::open()?);
        if !matches!(job.action, Action::Connect | Action::ApprovedConnect | Action::Tool(_)) {
            shared.locked.store(false, Ordering::SeqCst);
        }
    }
    let store = state.as_mut().ok_or("Vault is locked")?;
    match &job.action {
        Action::Remote => {
            if !shared.remote.lock().unwrap().is_null() {
                return Ok(shared.remote.lock().unwrap().clone());
            }
            if !platform::desktop_foreground(&job.session.identity, job.session.desktop) || !valid(job, shared) { return Err("Open Yougori Desktop to enable device requests".into()); }
            audit(store, job, "remote_access", "enabled")?;
            let remote = runtime.block_on(start_remote(shared.clone(), sender.clone()))?;
            *shared.remote.lock().unwrap() = remote.clone();
            Ok(remote)
        }
        Action::Connect | Action::ApprovedConnect => {
            if store.contents.clients.len() >= 32
                && !store
                    .contents
                    .clients
                    .contains_key(&job.session.identity.id)
            {
                return Err(
                    "Revoke an unused client before connecting another device (32-client limit)"
                        .into(),
                );
            }
            audit(store, job, "connect", "requested")?;
            let approved = matches!(job.action, Action::ApprovedConnect)
                || desktop_decision(job, shared, CONNECT_TITLE, &connect_content(&job.session.identity), CONNECT_ALLOW)?;
            if !approved || !valid(job, shared) {
                audit(store, job, "connect", "denied")?;
                return Err("Connection denied or expired".into());
            }
            audit(store, job, "connect", "allowed_requests")?;
            shared.locked.store(false, Ordering::SeqCst);
            store.contents.clients.insert(
                job.session.identity.id.clone(),
                job.session.identity.clone(),
            );
            store.save()?;
            job.session.admission.store(
                *shared
                    .revocations
                    .lock()
                    .unwrap()
                    .get(&job.session.identity.id)
                    .unwrap_or(&0),
                Ordering::SeqCst,
            );
            job.session.allowed.store(true, Ordering::SeqCst);
            Ok(json!({"allowedRequests":true}))
        }
        Action::Revoke(id) => {
            // Revocation only reduces access and takes effect before queuing,
            // including while another operation is awaiting in-app approval.
            audit(store, job, "client", "revoked")?;
            store.contents.clients.remove(id);
            store.save()?;
            shared.generation.fetch_add(1, Ordering::SeqCst);
            Ok(json!({"revoked":id}))
        }
        Action::Remove(id) => {
            if !store.contents.items.contains_key(id) { return Err("Item not found".into()); }
            if !platform::desktop_foreground(&job.session.identity, job.session.desktop) || !valid(job, shared) { return Err("Open Yougori Desktop to remove vault items".into()); }
            audit(store, job, "item", "remove_requested")?;
            let old = store.contents.items.remove(id);
            if let Err(e) = store.save() {
                if let Some(old) = old {
                    store.contents.items.insert(id.clone(), old);
                }
                return Err(e);
            }
            audit(store, job, "item", "removed")?;
            Ok(json!({"removed":id}))
        }
        Action::Tool(operation) => {
            if !job.session.allowed.load(Ordering::SeqCst)
                || !store
                    .contents
                    .clients
                    .contains_key(&job.session.identity.id)
            {
                return Err("Client access was revoked".into());
            }
            audit(store, job, operation.name(), "requested")?;
            if matches!(operation, Operation::ListItems(_) | Operation::AllCredentials(_)) {
                let bulk = matches!(operation, Operation::AllCredentials(_));
                let result = if bulk { all_credentials(&store.contents) } else { vault_inventory(&store.contents) };
                if !mcp_result_fits(&result) {
                    return Err("This vault has too much data for one MCP response. Request individual credentials by name or ID instead.".into());
                }
                let content = if bulk {
                    let names = store.contents.items.values().filter(|item| item.is_credential())
                        .map(|item| format!("• {} ({}, ID {})", item.label, item.kind, item.id))
                        .collect::<Vec<_>>().join("\n");
                    format!("{}\n\nShare ALL {} credential values with this agent ONCE?\n\n{}\n\nThis includes passwords, API keys, tokens, private keys, and Cloudflare tokens if stored. Values go into the requesting agent's AI context and provider, may appear in chat history, and cannot be recalled after sharing. Deny shares nothing.", who(&job.session.identity), result["count"], if names.is_empty() { "No credential items are stored." } else { &names })
                } else {
                    format!("{}\n\nShare the vault inventory with this agent ONCE? This reveals item names, types, IDs, and personal-information field names, but no values. The agent must request values separately.", who(&job.session.identity))
                };
                let approved = desktop_decision(job, shared,
                    if bulk { "Share all credentials with this agent?" } else { "Show vault item names to this agent?" },
                    &content,
                    if bulk { "Share all credentials once" } else { "Share item names once" },
                )?;
                if !approved || !valid(job, shared) {
                    audit(store, job, operation.name(), "denied_or_expired")?;
                    return Err("Request denied, cancelled, or expired; nothing shared".into());
                }
                shared.locked.store(false, Ordering::SeqCst);
                audit(store, job, operation.name(), "approved_once")?;
                if !valid(job, shared) || shared.locked.load(Ordering::SeqCst) {
                    return Err("Request result withheld because the client disconnected or vault locked".into());
                }
                audit(store, job, operation.name(), "completed")?;
                return Ok(result);
            }
            let item = store.contents.resolve_item(operation.item().ok_or("Select a vault item")?)?;
            // Validate the selection before asking for approval. Never disclose
            // values here; the protected read remains below the one-use ticket.
            if let Operation::Personal(value) = operation {
                item.validate_personal_fields(&value.fields)?;
            }
            let disclosure = match operation {
                Operation::ListItems(_) | Operation::AllCredentials(_) => unreachable!(),
                Operation::Credential(_) if item.is_credential() => "Share this item's complete credential value with this agent ONCE.\n\nDestination: the requesting agent's AI context and its provider. The agent may use or display it, and its provider may retain it in chat history. Disconnecting the vault cannot recall an already shared value.\n\nApprove only if you intend to disclose this credential. Deny shares nothing.".into(),
                Operation::Personal(value) if item.kind == "personal" => format!("Return only these fields: {}\n\nDestination: this MCP client's AI context. Once disclosed, these values cannot be recalled from that context.",value.fields.join(", ")),
                Operation::Dns(value) if item.kind == "cloudflare" => format!("Create one {} record: {}\nContent: {}\nTTL: {} seconds\nProxied: {}\nZone: {}\nDestination: https://api.cloudflare.com/client/v4/zones/{}/dns_records\n\nToken: •••••••• (used only inside the vault). Return record ID/name/type; never the token.",value.record_type,value.name,value.content,value.ttl,value.proxied,item.resource,item.resource),
                _ => return Err("This item type cannot be used with that tool. Use personal_info for personal fields or read_credential for a credential item, with separate disclosure approval.".into()),
            };
            let content = format!(
                "{}\n\nAccount/item: {}\nItem ID: {}\n\n{}",
                who(&job.session.identity),
                item.label,
                item.id,
                disclosure
            );
            let approved = desktop_decision(job, shared,
                if matches!(operation, Operation::Credential(_)) {
                    "Share a credential with this agent?"
                } else {
                    "Approval required — one operation"
                },
                &content,
                if matches!(operation, Operation::Credential(_)) {
                    "Share credential once"
                } else {
                    "Approve Once"
                },
            )?;
            if !approved || !valid(job, shared) {
                audit(store, job, operation.name(), "denied_or_expired")?;
                return Err("Request denied, cancelled, or expired; nothing executed".into());
            }
            shared.locked.store(false, Ordering::SeqCst);
            audit(store, job, operation.name(), "approved_once")?;
            audit(store, job, operation.name(), "execution_started")?;
            // The decision is single-use: `desktop_decision` consumed it and this
            // job owns the exact operation shown. Revalidate the session only.
            if !valid(job, shared) || shared.locked.load(Ordering::SeqCst) {
                return Err("Request cancelled before execution".into());
            }
            let result = match operation {
                Operation::ListItems(_) | Operation::AllCredentials(_) => unreachable!(),
                Operation::Credential(_) => Ok(json!({"item":item.id,"name":item.label,"kind":item.kind,"value":item.value})),
                Operation::Personal(value) => {
                    let values: BTreeMap<String,String> = serde_json::from_str(&item.value).map_err(|_| "Invalid personal information")?;
                    let mut selected = serde_json::Map::new();
                    for field in &value.fields { selected.insert(field.clone(),json!(values.get(field).ok_or("A requested field does not exist")?)); }
                    Ok(Value::Object(selected))
                }
                Operation::Dns(value) => runtime.block_on(async {
                    let client = reqwest::Client::builder().https_only(true).no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(25)).build().map_err(|_| "Provider connection unavailable")?;
                    let request = client.post(format!("https://api.cloudflare.com/client/v4/zones/{}/dns_records",item.resource)).bearer_auth(&item.value).json(&json!({"type":value.record_type,"name":value.name,"content":value.content,"ttl":value.ttl,"proxied":value.proxied}));
                    // This is the final authorization check before the network side effect.
                    if !valid(job,shared) || shared.locked.load(Ordering::SeqCst) { return Err("Request cancelled before execution".to_string()); }
                    let response = request.send().await.map_err(|_| "Provider response was not received. Outcome is unknown; inspect Cloudflare before retrying.")?;
                    if !response.status().is_success() { return Err(format!("Cloudflare rejected the request (HTTP {}). No provider response body or credential was disclosed.",response.status().as_u16())); }
                    if response.content_length().is_some_and(|n|n>65536) { return Err("Provider response exceeded the limit; inspect Cloudflare before retrying".into()); }
                    let mut response=response; let mut bytes=vec![];
                    while let Some(chunk)=response.chunk().await.map_err(|_|"Provider response ended; inspect Cloudflare before retrying")? { if bytes.len()+chunk.len()>65536{return Err("Provider response exceeded the limit".into());} bytes.extend_from_slice(&chunk); }
                    let result:Value=serde_json::from_slice(&bytes).map_err(|_|"Invalid provider response; inspect Cloudflare before retrying")?;
                    if result["success"] != true { return Err("Cloudflare did not confirm success; inspect the account before retrying".into()); }
                    let id=result["result"]["id"].as_str().filter(|s|s.len()==32 && s.bytes().all(|b|b.is_ascii_hexdigit())).ok_or("Unexpected provider record ID; inspect Cloudflare before retrying")?;
                    Ok(json!({"id":id,"name":value.name,"type":value.record_type}))
                }),
            };
            audit(
                store,
                job,
                operation.name(),
                if result.is_ok() {
                    "completed"
                } else {
                    "failed_or_outcome_unknown"
                },
            )?;
            if !valid(job, shared) || shared.locked.load(Ordering::SeqCst) {
                return Err("Request result withheld because the client disconnected or vault locked; inspect activity before retrying".into());
            }
            result
        }
        Action::AddItems(_) | Action::Browse | Action::HttpSetup | Action::HttpCredentials => {
            unreachable!()
        }
    }
}
async fn start_remote(
    shared: Arc<Shared>,
    sender: std::sync::mpsc::SyncSender<Job>,
) -> Result<Value, String> {
    use crate::{storage, transport::DeviceKey};
    use sha2::{Digest, Sha256};
    let path = platform::data_directory()?.join("server-identity.dpapi");
    let identity: DeviceKey = if path.exists() {
        serde_json::from_slice(&storage::dpapi(
            &storage::bounded_read(&path, 32768)?,
            false,
        )?)
        .map_err(|_| "Invalid protected TLS identity")?
    } else {
        let identity = DeviceKey::generate()?;
        let bytes = zeroize::Zeroizing::new(
            serde_json::to_vec(&identity).map_err(|_| "Cannot encode TLS identity")?,
        );
        storage::atomic_write(&path, &storage::dpapi(&bytes, true)?)?;
        identity
    };
    let fingerprint = identity.fingerprint()?;
    let config = Arc::new(crate::transport::server_config(&identity)?);
    // Only the desktop's container relay reaches this socket. Its contents are
    // mutually authenticated TLS, so a compromised relay cannot impersonate a
    // device, alter an approved request, or see a personal-information result.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|_| "Cannot start protected TLS endpoint")?;
    let port = listener
        .local_addr()
        .map_err(|_| "Cannot read TLS endpoint")?
        .port();
    let listener_state = shared.clone();
    let listener_task = tokio::spawn(async move {
        let slots = Arc::new(tokio::sync::Semaphore::new(16));
        while let Ok((stream, _)) = listener.accept().await {
            let Ok(permit) = slots.clone().try_acquire_owned() else {
                continue;
            };
            let config = config.clone();
            let shared = shared.clone();
            let sender = sender.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let stream = match tokio::time::timeout(
                    Duration::from_secs(10),
                    tokio_rustls::TlsAcceptor::from(config).accept(stream),
                )
                .await
                {
                    Ok(Ok(stream)) => stream,
                    _ => return,
                };
                let Some(cert) = stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|c| c.first())
                else {
                    return;
                };
                let fingerprint = hex::encode(Sha256::digest(cert));
                let identity = Identity {
                    id: format!("tls-{fingerprint}"),
                    executable: "Remote MCP client — certificate key authenticated".into(),
                    digest: fingerprint.clone(),
                    device: format!("Device key {fingerprint}"),
                    user: "Device certificate (no Windows account assertion)".into(),
                    process: 0,
                    environment: "Remote environment; executable identity is not attested".into(),
                };
                let session = Arc::new(Session {
                    identity,
                    desktop: false,
                    cancelled: Arc::new(AtomicBool::new(false)),
                    connected: AtomicBool::new(true),
                    allowed: AtomicBool::new(false),
                    admission: AtomicU64::new(0),
                });
                let _ = serve(stream, session.clone(), sender, shared, true).await;
                session.connected.store(false, Ordering::SeqCst);
                session.cancelled.store(true, Ordering::SeqCst);
            });
        }
    });
    *listener_state.remote_stop.lock().unwrap() = Some(listener_task.abort_handle());
    Ok(json!({"brokerPort":port,"fingerprint":fingerprint}))
}
