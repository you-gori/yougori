//! Yougori Network: one sign-in shared by the app and the CLI, and sharing local models
//! through yougori.com. The website keeps each model's public link and API key private and
//! serves callers through its own endpoint. Tokens live in the OS credential vault; only
//! non-secret share settings are saved on disk.
use crate::{models::EnvironmentStatus, projects::secrets, runtime::RuntimeManager, store::PlatformStore, AppHandle};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::LazyLock, time::{Duration, Instant}};
use tauri::{Emitter, Manager};

const SESSION: &str = "yougori-network-session";
pub(crate) fn registry_session() -> Option<String> { session() }
pub(crate) async fn registry_request(method: reqwest::Method, path: &str, body: Option<&Value>) -> Result<Value, String> {
    if !path.starts_with("/api/market/registry/") || path.contains("..") || path.contains(['#','%','\\']) || path.contains("//") { return Err("Invalid model registry path".into()); }
    api(method, path, session().as_deref(), body).await.map_err(String::from)
}
pub(crate) async fn registry_connect(body: &Value) -> Result<Value, String> {
    let mut result = api(reqwest::Method::POST, "/api/market/nodes", session().as_deref(), Some(body)).await.map_err(String::from)?;
    if let Some(map) = result.as_object_mut() { map.remove("nodeToken"); }
    Ok(result)
}
const HEARTBEAT: Duration = Duration::from_secs(60);
const TICK: Duration = Duration::from_secs(15);
const EVENT: &str = "yougori-market";

/// Direct native call; credentials/prompts do not enter automation jobs or history.
#[tauri::command]
pub async fn confidential_network_chat(api_key:String,node_id:String,model:String,prompt:String,policy_path:Option<String>)->Result<Value,String>{
    if prompt.len()>32768{return Err("Confidential prompt exceeds 32 KiB".into())}
    let api_key=age::secrecy::SecretString::from(api_key);
    use age::secrecy::ExposeSecret;
    yougori_cli::confidential::chat(&format!("{}/v1",website()),api_key.expose_secret(),node_id,json!({"model":model,"messages":[{"role":"user","content":prompt}],"max_tokens":1024}),policy_path.as_deref()).await
}

/// yougori.com, or `YOUGORI_NETWORK_URL` for a local website during development.
pub(crate) fn website() -> String {
    std::env::var("YOUGORI_NETWORK_URL")
        .ok()
        .map(|value| value.trim_end_matches('/').to_owned())
        .filter(|value| value.starts_with("https://") || value.starts_with("http://127.0.0.1:") || value.starts_with("http://localhost:"))
        .unwrap_or_else(|| "https://yougori.com".into())
}

#[derive(Default)]
pub struct Market {
    inner: tokio::sync::Mutex<Inner>,
    wake: tokio::sync::Notify,
    /// One sync pass at a time, so the loop and a share command never register a model twice.
    sync: tokio::sync::Mutex<()>,
    /// Serialize starting and cancelling browser sign-in attempts.
    auth: tokio::sync::Mutex<()>,
}

#[derive(Default)]
struct Inner {
    loaded: bool,
    account: Option<Value>,
    checked: Option<Instant>,
    login: Option<Login>,
    auth_generation: u64,
    shares: BTreeMap<String, Share>,
    emitted: String,
}

#[derive(Clone)]
struct Login {
    generation: u64,
    user_code: String,
    verification_url: String,
    verification_url_complete: String,
    expires: Instant,
    error: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Share {
    environment_id: String,
    model: String,
    mode: String,
    #[serde(default)]
    listen: bool,
    #[serde(default)]
    node_id: Option<String>,
    /// Some(true): closed weights; Some(false): open downloads; None: legacy API sharing.
    #[serde(default)]
    publish: Option<bool>,
    #[serde(default)]
    registry_version: Option<String>,
    /// The public link Yougori opened for sharing; removed again when sharing stops.
    #[serde(default)]
    published: Option<String>,
    #[serde(skip)]
    live: Live,
}

#[derive(Clone, Default)]
struct Live {
    status: String,
    listen_path: Option<String>,
    message: String,
    online: bool,
    files_online: bool,
    source_only: bool,
    beat: Option<Instant>,
    reported: Option<(String, Option<String>)>,
    sent_url: Option<String>,
    node: Option<Value>,
    warnings: Vec<String>,
    listing: Option<String>,
    link_since: Option<Instant>,
    link_failures: u8,
    reconnected: Option<Instant>,
    publication_synced: bool,
    model_page: Option<String>,
}

struct ApiError {
    status: u16,
    code: String,
    message: String,
}

impl From<ApiError> for String {
    fn from(error: ApiError) -> String {
        error.message
    }
}

static CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(40))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("Yougori/", env!("CARGO_PKG_VERSION")))
        .build()
        .expect("network client")
});

async fn api(method: reqwest::Method, path: &str, bearer: Option<&str>, body: Option<&Value>) -> Result<Value, ApiError> {
    let site = website();
    let mut request = CLIENT.request(method, format!("{site}{path}"));
    if let Some(token) = bearer {
        request = request.bearer_auth(token);
    }
    if let Some(body) = body {
        request = request.json(body);
    }
    let mut response = request.send().await.map_err(|error| ApiError {
        status: 0,
        code: "network".into(),
        message: format!("Cannot reach the Yougori Network at {site}: {}", error.without_url()),
    })?;
    let status = response.status().as_u16();
    const LIMIT: usize = 1024 * 1024;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ApiError { status, code: "network".into(), message: "The Yougori Network answer was interrupted".into() })? {
        if bytes.len() + chunk.len() > LIMIT {
            return Err(ApiError { status, code: "response_limit".into(), message: "The Yougori Network answer exceeded its size limit".into() });
        }
        bytes.extend_from_slice(&chunk);
    }
    let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    if (200..300).contains(&status) {
        return Ok(value);
    }
    Err(ApiError {
        status,
        code: value["code"].as_str().unwrap_or_default().into(),
        message: value["error"].as_str().map(str::to_owned).unwrap_or_else(|| format!("The Yougori Network returned HTTP {status}")),
    })
}

fn session() -> Option<String> {
    secrets::resolve(SESSION).ok()
}

fn hash(value: &str) -> String {
    hex::encode(Sha256::digest(format!("yougori-network:{value}").as_bytes()))
}

fn node_secret(environment_id: &str) -> String {
    format!("yougori-network-node-{}", &hash(environment_id)[..32])
}

fn shares_file(app: &AppHandle) -> std::path::PathBuf {
    app.state::<PlatformStore>().data_folder("network").join("shares.json")
}

async fn ensure_loaded(app: &AppHandle) {
    let market = app.state::<Market>();
    let mut inner = market.inner.lock().await;
    if inner.loaded {
        return;
    }
    inner.loaded = true;
    if let Ok(bytes) = std::fs::read(shares_file(app)) {
        if let Ok(shares) = serde_json::from_slice::<Vec<Share>>(&bytes) {
            inner.shares = shares.into_iter().map(|share| (share.environment_id.clone(), share)).collect();
        }
    }
}

fn persist(app: &AppHandle, shares: &BTreeMap<String, Share>) -> Result<(), String> {
    let path = shares_file(app);
    let folder = path.parent().ok_or("Invalid network folder")?;
    std::fs::create_dir_all(folder).map_err(|e| e.to_string())?;
    let mut file = tempfile::NamedTempFile::new_in(folder).map_err(|e| e.to_string())?;
    std::io::Write::write_all(&mut file, &serde_json::to_vec(&shares.values().collect::<Vec<_>>()).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    file.persist(&path).map_err(|e| e.to_string())?;
    Ok(())
}

fn describe(share: &Share) -> Value {
    json!({
        "environmentId": share.environment_id,
        "model": share.model,
        "listen": share.listen && share.mode == "free",
        "listenPath": share.live.listen_path,
        "closedWeights": share.publish,
        "modelPage": share.live.model_page,
        "mode": share.live.node.as_ref().and_then(|node| node["mode"].as_str()).unwrap_or(&share.mode),
        "nodeId": share.node_id,
        "status": if share.live.status.is_empty() { "starting" } else { share.live.status.as_str() },
        "message": share.live.message,
        "live": share.live.online,
        "filesOnline": share.live.files_online,
        "sourceOnly": share.live.source_only,
        "listing": share.live.listing.clone().or_else(|| share.node_id.as_ref().map(|id| format!("{}/network#{id}", website()))),
        "warnings": share.live.warnings,
        "node": share.live.node,
    })
}

fn snapshot(inner: &Inner) -> Value {
    let login = inner.login.as_ref().map(|login| json!({
        "userCode": login.user_code,
        "verificationUrl": login.verification_url,
        "verificationUrlComplete": login.verification_url_complete,
        "expiresIn": login.expires.saturating_duration_since(Instant::now()).as_secs(),
        "error": login.error,
    }));
    json!({
        "website": website(),
        "signedIn": inner.account.is_some(),
        "account": inner.account,
        "login": login,
        "shares": inner.shares.values().map(describe).collect::<Vec<_>>(),
    })
}

/// Tells open windows to refresh; the CLI and the app read the same state.
async fn changed(app: &AppHandle) {
    let market = app.state::<Market>();
    let mut inner = market.inner.lock().await;
    let value = snapshot(&inner);
    let fingerprint = value.to_string();
    if fingerprint != inner.emitted {
        inner.emitted = fingerprint;
        let _ = app.emit(EVENT, value);
    }
}

/// Reloads the account when signed in. An expired or revoked session signs this computer out.
async fn refresh_account(app: &AppHandle, force: bool) {
    let market = app.state::<Market>();
    let (token, generation) = {
        let mut inner = market.inner.lock().await;
        if !force && inner.checked.is_some_and(|at| at.elapsed() < Duration::from_secs(60)) {
            return;
        }
        let Some(token) = session() else {
            inner.account = None;
            inner.checked = Some(Instant::now());
            return;
        };
        (token, inner.auth_generation)
    };
    let result = api(reqwest::Method::GET, "/api/market/me", Some(&token), None).await;
    let mut inner = market.inner.lock().await;
    // An earlier account read must not restore an account after logout or a new sign-in.
    if inner.auth_generation != generation || session().as_deref() != Some(token.as_str()) {
        return;
    }
    inner.checked = Some(Instant::now());
    match result {
        Ok(value) => inner.account = Some(value["account"].clone()),
        Err(error) if error.status == 401 => {
            let _ = secrets::delete_secret(SESSION);
            inner.account = None;
        }
        // Offline: keep showing the last known account.
        Err(_) => {}
    }
}

#[tauri::command]
pub async fn market_status(app: AppHandle) -> Result<Value, String> {
    ensure_loaded(&app).await;
    refresh_account(&app, false).await;
    let market = app.state::<Market>();
    let inner = market.inner.lock().await;
    Ok(snapshot(&inner))
}

/// Starts a browser sign-in. Approving the code on yougori.com signs in this computer's app and CLI.
#[tauri::command]
pub async fn market_sign_in(app: AppHandle) -> Result<Value, String> {
    ensure_loaded(&app).await;
    let market = app.state::<Market>();
    let _auth = market.auth.lock().await;
    if session().is_some() {
        refresh_account(&app, true).await;
        if app.state::<Market>().inner.lock().await.account.is_some() {
            return market_status(app.clone()).await;
        }
    }
    let pending = {
        let market = app.state::<Market>();
        let inner = market.inner.lock().await;
        inner.login.as_ref().is_some_and(|login| login.error.is_none() && login.expires > Instant::now() + Duration::from_secs(60))
    };
    if !pending {
        let generation = {
            let mut inner = market.inner.lock().await;
            inner.auth_generation += 1;
            inner.login = None;
            inner.auth_generation
        };
        let host = app.state::<PlatformStore>().snapshot().map(|state| state.host.hostname).unwrap_or_default();
        let client = if host.trim().is_empty() { "Yougori".to_owned() } else { format!("Yougori on {}", host.trim()) };
        let start = api(reqwest::Method::POST, "/api/market/device/start", None, Some(&json!({"client": client}))).await?;
        let device = start["deviceCode"].as_str().ok_or("The Yougori Network returned an invalid sign-in code")?.to_owned();
        let login = Login {
            generation,
            user_code: start["userCode"].as_str().unwrap_or_default().to_owned(),
            verification_url: start["verificationUrl"].as_str().unwrap_or_default().to_owned(),
            verification_url_complete: start["verificationUrlComplete"].as_str().unwrap_or_default().to_owned(),
            expires: Instant::now() + Duration::from_secs(start["expiresIn"].as_u64().unwrap_or(600).min(1800)),
            error: None,
        };
        let interval = Duration::from_secs(start["interval"].as_u64().unwrap_or(3).clamp(2, 30));
        let browser = login.verification_url_complete.clone();
        app.state::<Market>().inner.lock().await.login = Some(login);
        let _ = crate::workspace::open_workspace_url(browser);
        let poller = app.clone();
        tauri::async_runtime::spawn(async move { poll_sign_in(poller, device, interval, generation).await });
    }
    changed(&app).await;
    market_status(app.clone()).await
}

fn complete_login(inner: &mut Inner, generation: u64, value: &Value, save: impl FnOnce(&str) -> Result<(), String>) -> bool {
    let Some(login) = inner.login.as_mut().filter(|login| login.generation == generation && login.error.is_none()) else { return false };
    if login.expires <= Instant::now() {
        login.error = Some("The sign-in code expired. Start again.".into());
        return true;
    }
    let Some(token) = value["token"].as_str() else {
        login.error = Some("The Yougori Network returned an invalid sign-in answer".into());
        return true;
    };
    match save(token) {
        Ok(()) => {
            inner.account = Some(value["account"].clone());
            inner.checked = Some(Instant::now());
            inner.login = None;
        }
        Err(error) => login.error = Some(error),
    }
    true
}

async fn poll_sign_in(app: AppHandle, device: String, interval: Duration, generation: u64) {
    loop {
        tokio::time::sleep(interval).await;
        {
            let market = app.state::<Market>();
            let mut inner = market.inner.lock().await;
            let Some(login) = inner.login.as_mut().filter(|login| login.generation == generation && login.error.is_none()) else { break };
            if login.expires <= Instant::now() {
                login.error = Some("The sign-in code expired. Start again.".into());
                break;
            }
        }
        match api(reqwest::Method::POST, "/api/market/device/token", None, Some(&json!({"deviceCode": device}))).await {
            Ok(value) => {
                let market = app.state::<Market>();
                let mut inner = market.inner.lock().await;
                // Validate the attempt and save under one lock so an in-flight approval
                // cannot write credentials after sign-out has cancelled it.
                let completed = complete_login(&mut inner, generation, &value, |token| secrets::store(SESSION, token));
                drop(inner);
                if completed { market.wake.notify_one(); }
                break;
            }
            Err(error) if error.code == "authorization_pending" || error.status == 0 || error.status == 429 || error.status >= 500 => continue,
            Err(error) => {
                if let Some(login) = app.state::<Market>().inner.lock().await.login.as_mut().filter(|login| login.generation == generation) {
                    login.error = Some(error.message);
                }
                break;
            }
        }
    }
    changed(&app).await;
}

/// Signs out and takes every shared model off the network.
#[tauri::command]
pub async fn market_sign_out(app: AppHandle) -> Result<Value, String> {
    ensure_loaded(&app).await;
    let market = app.state::<Market>();
    let _auth = market.auth.lock().await;
    {
        let mut inner = market.inner.lock().await;
        inner.auth_generation += 1;
        inner.login = None;
    }
    let token = session();
    let _guard = market.sync.lock().await;
    let shares = std::mem::take(&mut market.inner.lock().await.shares);
    for share in shares.values() {
        leave(&app, share, token.as_deref()).await;
    }
    persist(&app, &BTreeMap::new())?;
    if let Some(token) = &token {
        let _ = api(reqwest::Method::POST, "/api/market/logout", Some(token), Some(&json!({}))).await;
    }
    secrets::delete_secret(SESSION)?;
    {
        let mut inner = market.inner.lock().await;
        inner.account = None;
        inner.login = None;
        inner.checked = Some(Instant::now());
    }
    changed(&app).await;
    drop(_guard);
    market_status(app.clone()).await
}

/// Removes a share's registration, credentials and the public link Yougori opened for it.
async fn leave(app: &AppHandle, share: &Share, token: Option<&str>) {
    let _=crate::model_runner::configure_publishing(app,&share.environment_id,false).await;
    if share.listen { let _ = crate::model_runner::configure_listen(app, &share.environment_id, "free", false).await; }
    if let (Some(id), Some(token)) = (&share.node_id, token) {
        let _ = api(reqwest::Method::POST, &format!("/api/market/nodes/{id}/remove"), Some(token), Some(&json!({}))).await;
    }
    let _ = secrets::delete_secret(&node_secret(&share.environment_id));
    if let Some(publication) = &share.published {
        let _ = crate::automation::dispatch::dispatch(app, "unpublish_environment_service", &json!({"publicationId": publication})).await;
    }
}

fn model_of(app: &AppHandle, environment_id: &str) -> Result<(String, Option<String>, Option<String>), String> {
    let state = app.state::<PlatformStore>().snapshot()?;
    let env = state.environments.iter().find(|e| e.id == environment_id).ok_or("Model environment not found")?;
    let options = app.state::<RuntimeManager>().workload_options(env.runtime_id.as_deref().unwrap_or(&env.id))?;
    let model = options.environment.get("YOUGORI_REGISTRY_MODEL").or_else(|| options.environment.get("YOUGORI_MODEL")).cloned().ok_or("Only Yougori model environments can be shared on the network")?;
    let gguf = options.environment.get("YOUGORI_MODEL_FORMAT").is_some_and(|format| format == "gguf");
    let source_only=options.environment.get("YOUGORI_MODEL_FORMAT").is_some_and(|format|format=="source");
    Ok((model, Some(if source_only {"file-publisher"} else if gguf { "llama.cpp" } else { "transformers" }.to_owned()), options.environment.get("YOUGORI_MODEL_QUANT").cloned()))
}

/// `--now` (automatic paid pricing) or `--nowfree` (free).
#[tauri::command]
pub async fn market_share_model(environment_id: String, mode: String, listen: Option<bool>, publish: Option<bool>, app: AppHandle) -> Result<Value, String> {
    if !matches!(mode.as_str(), "paid" | "free") {
        return Err("Choose paid or free sharing".into());
    }
    let listen = listen.unwrap_or(false);
    if listen && mode != "free" { return Err("--listen requires --nowfree".into()); }
    ensure_loaded(&app).await;
    let market = app.state::<Market>();
    let _guard = market.sync.lock().await;
    if session().is_none() {
        return Err("Sign in to the Yougori Network first: run `yougori login` or choose Sign in in the App's Network panel.".into());
    }
    let (model, runner, _) = model_of(&app, &environment_id)?;
    let publish=if runner.as_deref()==Some("file-publisher") {
        if mode!="free" || listen || publish==Some(true) {return Err("This folder has source files only. Use free downloads; weights are required for inference and recording.".into())}
        Some(false)
    } else {publish};
    {
        let market = app.state::<Market>();
        let mut inner = market.inner.lock().await;
        let share = inner.shares.entry(environment_id.clone()).or_insert_with(|| Share {
            environment_id: environment_id.clone(),
            model: model.clone(),
            mode: mode.clone(),
            listen,
            node_id: None,
            publish,
            registry_version: None,
            published: None,
            live: Live::default(),
        });
        let reregister = share.mode != mode || share.model != model;
        if share.publish != publish { share.live.publication_synced=false; share.registry_version=None; }
        share.publish = publish;
        share.mode = mode;
        share.listen = listen;
        share.model = model;
        if reregister {
            if !crate::model_registry::is_registry(&share.model) {share.registry_version=None;}
            // A changed mode or model is a new registration of the same environment.
            share.live = Live::default();
            share.node_id = None;
        }
        persist(&app, &inner.shares)?;
    }
    {
        if let Err(error) = sync_one(&app, &environment_id).await {
            note(&app, &environment_id, error).await;
        }
    }
    changed(&app).await;
    let market = app.state::<Market>();
    let inner = market.inner.lock().await;
    let mut result = inner.shares.get(&environment_id).map(describe).unwrap_or(Value::Null);
    result["website"] = json!(website());
    Ok(result)
}

#[tauri::command]
pub async fn market_unshare_model(environment_id: String, app: AppHandle) -> Result<Value, String> {
    ensure_loaded(&app).await;
    let market = app.state::<Market>();
    let _guard = market.sync.lock().await;
    let share = {
        let mut inner = market.inner.lock().await;
        let share = inner.shares.remove(&environment_id).ok_or("This model is not shared on the Yougori Network")?;
        persist(&app, &inner.shares)?;
        share
    };
    leave(&app, &share, session().as_deref()).await;
    drop(_guard);
    changed(&app).await;
    Ok(json!({"environmentId": environment_id, "shared": false}))
}

async fn note(app: &AppHandle, environment_id: &str, message: String) {
    if let Some(share) = app.state::<Market>().inner.lock().await.shares.get_mut(environment_id) {
        share.live.message = message;
        share.live.online = false;
        share.live.files_online = false;
    }
}

async fn forget(app: &AppHandle, environment_id: &str, reason: &str) {
    let removed = {
        let market = app.state::<Market>();
        let mut inner = market.inner.lock().await;
        let removed = inner.shares.remove(environment_id);
        let _ = persist(app, &inner.shares);
        removed
    };
    if let Some(share) = removed {
        leave(app, &share, session().as_deref()).await;
        eprintln!("Yougori Network: stopped sharing {}: {reason}", share.model);
    }
}

fn waiting(status: &str) -> &'static str {
    match status {
        "stopped" => "The model is stopped. Start it to go back online.",
        "error" => "The model could not load. Check its logs.",
        "installing" => "Installing model dependencies",
        "downloading" => "Downloading the model",
        "verifying" => "Verifying model checksums",
        "loading" => "Loading onto the GPU",
        _ => "Starting the model server",
    }
}

/// Recover only our quick tunnel. Saved domains and other publications are preserved.
fn owned_quick_link(share: &Share, access: &Value) -> bool {
    share.published.as_deref().is_some_and(|id|access["publicId"]==id) && access["publicAccount"]!=true
}

fn reconnect_due(live: &Live) -> bool {
    live.link_failures >= 2 && live.link_since.is_some_and(|at|at.elapsed()>=Duration::from_secs(60))
        && live.reconnected.is_none_or(|at|at.elapsed()>=Duration::from_secs(120))
}

/// Brings one share up to date: public link when the model is ready, registration, heartbeat.
fn sharing_details(status: &str, health: &Value, runner: Option<&str>, quant: Option<&str>) -> Value {
    let measured_quant = health["quant"].as_str().or_else(|| match health["precision"].as_str() {
        Some("4bit") => Some("NF4"), Some("8bit") => Some("INT8"), _ => quant,
    });
    json!({
        "status": status, "runner": health["runner"].as_str().or(runner), "quant": measured_quant,
        "revision": health["revision"], "precision": health["precision"],
        "appVersion": env!("CARGO_PKG_VERSION"), "gpu": health["gpu"],
        "gpuCount": health["gpuCount"], "context": health["context"],
        "optimizer": health["optimizer"], "residency":health["status"],
        "sourceOnly": health["sourceOnly"], "inferenceAvailable": health["inferenceAvailable"],
    })
}

async fn sync_one(app: &AppHandle, environment_id: &str) -> Result<(), String> {
    let market = app.state::<Market>();
    let Some(mut share) = market.inner.lock().await.shares.get(environment_id).cloned() else { return Ok(()) };
    // Revoked/expired sign-in must stop advertising this computer's GPU too.
    // Closing our owned tunnel also prevents an old node registration from serving traffic.
    if session().is_none() {
        forget(app, environment_id, "the account was signed out").await;
        return Ok(());
    }
    let state = app.state::<PlatformStore>().snapshot()?;
    let Some(env) = state.environments.iter().find(|e| e.id == environment_id) else {
        forget(app, environment_id, "its environment was deleted").await;
        return Ok(());
    };
    let running = env.status == EnvironmentStatus::Running;
    let health = if running {
        tokio::time::timeout(Duration::from_secs(20), crate::model_runner::model_status(environment_id.to_owned(), app.clone())).await.ok().and_then(Result::ok)
    } else {
        None
    };
    // Apply recording before publishing/registering any model, including paid transitions.
    if let Some(health) = &health {
        if health["sourceOnly"]==true {
            share.live.listen_path=None;
        } else if health["listen"]["supported"] == true {
            let settings = crate::model_runner::configure_listen(app, environment_id, &share.mode, share.listen).await?;
            share.live.listen_path = settings["path"].as_str().map(str::to_owned);
        } else if share.listen {
            return Err("This running model uses an older runner. Stop it and run it again with --nowfree --listen to enable recording; its model files are kept.".into());
        }
    }
    if health.as_ref().is_some_and(|h|h["status"]=="ready" || h["weightsVerified"]==true && h["optimizer"]["enabled"]==true && matches!(h["status"].as_str(),Some("idle"|"queued"|"freeing_memory"|"loading"))) && share.publish.is_some() && !share.live.publication_synced {
        if let Err(error)=crate::model_runner::configure_publishing(app,environment_id,share.publish==Some(false)).await {store_share(app,share).await?;return Err(error)}
    }
    let status = if running {
        health.as_ref().map(|h| {
            let phase=h["status"].as_str().unwrap_or("starting");
            if h["optimizer"]["enabled"]==true && h["weightsVerified"]==true && matches!(phase,"idle"|"queued"|"freeing_memory"|"loading"|"unloading") {"ready"} else {phase}
        }).unwrap_or("starting")
    } else { "stopped" }.to_owned();
    let (_, runner, quant) = model_of(app, environment_id)?;
    let mut access = None;
    let mut link_error = None;
    if status == "ready" {
        let mut current = crate::model_runner::api_status(app, environment_id).await?;
        if current["publicUrl"].is_null() {
            if owned_quick_link(&share, &current) {
                let id=share.published.take().unwrap();
                crate::automation::dispatch::dispatch(app,"unpublish_environment_service",&json!({"publicationId":id})).await?;
            }
            match crate::automation::dispatch::dispatch(app, "publish_environment_service", &json!({"environmentId": environment_id, "port": 8000, "kind": "cloudflare"})).await {
                Ok(publication) => {
                    share.published = publication["id"].as_str().map(str::to_owned);
                    current = crate::model_runner::api_status(app, environment_id).await?;
                }
                Err(error) => link_error = Some(error),
            }
        }
        access = Some(current);
    }
    let public_url = access.as_ref().and_then(|a| a["publicUrl"].as_str()).map(str::to_owned);
    let api_key = access.as_ref().and_then(|a| a["apiKey"].as_str()).map(str::to_owned);
    if share.live.link_since.is_none() || share.live.sent_url!=public_url {
        share.live.link_since=Some(Instant::now());
        share.live.link_failures=0;
    }
    let health = health.unwrap_or(Value::Null);
    share.live.source_only=health["sourceOnly"]==true || runner.as_deref()==Some("file-publisher");
    if status!="ready" {share.live.files_online=false;}
    let mut details = sharing_details(&status, &health, runner.as_deref(), quant.as_deref());
    if let Some(map) = details.as_object_mut() {
        map.retain(|_, value| !value.is_null());
    }
    let secret = node_secret(environment_id);
    let mut token = secrets::resolve(&secret).ok();
    if share.node_id.is_none() || token.is_none() {
        let Some(session) = session() else {
            share.live.status = status.clone();
            share.live.message = "Sign in to share this model".into();
            share.live.online = false;
        share.live.files_online = false;
            return store_share(app, share).await;
        };
        let mut body = details.clone();
        body["environmentKey"] = json!(hash(environment_id));
        body["model"] = json!(share.model);
        let options = app.state::<RuntimeManager>().workload_options(env.runtime_id.as_deref().unwrap_or(&env.id))?;
        if let Some(version) = share.registry_version.as_ref().or_else(||options.environment.get("YOUGORI_REGISTRY_VERSION")) { body["registryVersionId"] = json!(version); }
        body["mode"] = json!(share.mode);
        body["timezone"] = json!(iana_time_zone::get_timezone().ok());
        if let (Some(url), Some(key)) = (&public_url, &api_key) {
            body["publicUrl"] = json!(url);
            body["apiKey"] = json!(key);
        }
        let registered = match api(reqwest::Method::POST, "/api/market/nodes", Some(&session), Some(&body)).await {
            Ok(value) => value,
            Err(error) => {
                if error.status == 401 {
                    let _ = secrets::delete_secret(SESSION);
                    market.inner.lock().await.account = None;
                }
                share.live.status = status;
                share.live.message = error.message.clone();
                share.live.online = false;
        share.live.files_online = false;
                store_share(app, share).await?;
                return Err(error.message);
            }
        };
        let id = registered["node"]["id"].as_str().ok_or("The Yougori Network returned an invalid registration")?.to_owned();
        let node_token = registered["nodeToken"].as_str().ok_or("The Yougori Network returned an invalid registration")?;
        secrets::store(&secret, node_token)?;
        token = Some(node_token.to_owned());
        share.node_id = Some(id);
        share.live.sent_url = public_url.clone();
        share.live.node = Some(registered["node"].clone());
        share.live.listing = registered["listing"].as_str().map(str::to_owned);
        share.live.warnings = registered["warnings"].as_array().into_iter().flatten().filter_map(|w| w.as_str().map(str::to_owned)).collect();
        share.live.beat = None;
    }
    let reported = Some((status.clone(), public_url.clone()));
    if share.live.beat.is_none_or(|at| at.elapsed() >= if status=="ready" && !share.live.online { TICK } else { HEARTBEAT }) || share.live.reported != reported {
        let mut body = details;
        if share.live.sent_url != public_url || link_error.is_some() {
            body["publicUrl"] = json!(public_url);
            if public_url.is_some() {
                body["apiKey"] = json!(api_key);
            }
        }
        let id = share.node_id.clone().unwrap_or_default();
        match api(reqwest::Method::POST, &format!("/api/market/nodes/{id}/heartbeat"), token.as_deref(), Some(&body)).await {
            Ok(value) => {
                share.live.online = value["live"] == true;
                share.live.files_online = value["filesOnline"] == true;
                share.live.node = Some(value["node"].clone());
                share.live.sent_url = public_url.clone();
                share.live.reported = reported;
                share.live.beat = Some(Instant::now());
                share.live.link_failures=if share.live.online {0} else if status=="ready" && value["lastErrorCode"]=="public_link_unavailable" {share.live.link_failures.saturating_add(1)} else {0};
                share.live.message = if share.live.files_online {
                    "Source files available for download".into()
                } else if share.live.online {
                    "Live on the Yougori Network".into()
                } else if status == "ready" {
                    if value["lastError"].is_string() {value["lastError"].as_str().unwrap().into()} else {"Checking provider eligibility and measuring token speed".into()}
                } else {
                    waiting(&status).into()
                };
            }
            Err(error) if error.status == 410 => {
                forget(app, environment_id, "sharing was stopped on yougori.com").await;
                return Ok(());
            }
            Err(error) if error.status == 401 => {
                // The website no longer knows this registration; register again on the next pass.
                let _ = secrets::delete_secret(&secret);
                share.node_id = None;
                share.live.online = false;
        share.live.files_online = false;
                share.live.message = error.message;
            }
            Err(error) => {
                share.live.online = false;
        share.live.files_online = false;
                share.live.message = error.message;
            }
        }
    }
    if status == "ready" && public_url.is_some() && share.publish.is_some() && !share.live.publication_synced {
        let body=json!({"nodeId":share.node_id,"closed":share.publish.unwrap(),"keepAccess":share.registry_version.is_some()});
        match registry_request(reqwest::Method::POST,"/api/market/registry/publisher",Some(&body)).await {
            Ok(value)=>{
                share.registry_version=value["model"]["version"]["id"].as_str().map(str::to_owned);
                share.live.model_page=value["page"].as_str().map(|path|format!("{}{path}",website()));
                share.live.publication_synced=true;
            }
            Err(error)=>{share.live.message=format!("{} connected; publishing page: {error}",if share.live.source_only{"Source files"}else{"Model API"});}
        }
    }
    if status!="ready" {share.live.publication_synced=false;}
    if status=="ready" && reconnect_due(&share.live) && access.as_ref().is_some_and(|a|owned_quick_link(&share,a)) {
        let id=share.published.clone().unwrap();
        crate::automation::dispatch::dispatch(app,"unpublish_environment_service",&json!({"publicationId":id})).await?;
        share.published=None;
        share.live.reconnected=Some(Instant::now());
        share.live.link_failures=0;
        share.live.message="Local model ready; reconnecting the public link".into();
        // Clear the stale website address before opening the replacement on the next tick.
        let id=share.node_id.clone().unwrap_or_default();
        let _=api(reqwest::Method::POST,&format!("/api/market/nodes/{id}/heartbeat"),token.as_deref(),Some(&json!({"status":"ready","publicUrl":null}))).await;
        share.live.sent_url=None;
        share.live.reported=None;
        share.live.beat=None;
    }
    if let Some(error) = link_error {
        share.live.online = false;
        share.live.files_online = false;
        share.live.message = format!("Model ready locally; public sharing offline. {error} Yougori will retry automatically.");
    }
    share.live.status = status;
    store_share(app, share).await
}

async fn store_share(app: &AppHandle, share: Share) -> Result<(), String> {
    let market = app.state::<Market>();
    let mut inner = market.inner.lock().await;
    let Some(current) = inner.shares.get_mut(&share.environment_id) else { return Ok(()) };
    let saved = current.node_id != share.node_id || current.published != share.published || current.registry_version != share.registry_version;
    // A share command may have changed the mode while this pass ran; keep the newer intent.
    if current.mode == share.mode && current.model == share.model && current.listen == share.listen && current.publish == share.publish {
        *current = share;
    }
    if saved {
        persist(app, &inner.shares)?;
    }
    Ok(())
}

/// Keeps shared models registered, linked and reported while the engine runs.
pub(crate) fn start(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let shutdown = crate::automation::shutdown_signal(&app);
        let mut accounts = Instant::now();
        loop {
            let market = app.state::<Market>();
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = market.wake.notified() => {}
                _ = tokio::time::sleep(TICK) => {}
            }
            ensure_loaded(&app).await;
            if accounts.elapsed() > Duration::from_secs(600) {
                accounts = Instant::now();
                refresh_account(&app, true).await;
            }
            let ids = market.inner.lock().await.shares.keys().cloned().collect::<Vec<_>>();
            if !ids.is_empty() {
                let _guard = market.sync.lock().await;
                for id in ids {
                    if let Err(error) = sync_one(&app, &id).await {
                        note(&app, &id, error).await;
                    }
                }
            }
            changed(&app).await;
        }
        // Report shared models offline at once instead of after the heartbeat grace period.
        let shares = app.state::<Market>().inner.lock().await.shares.values().cloned().collect::<Vec<_>>();
        let _ = tokio::time::timeout(Duration::from_secs(4), async {
            for share in shares {
                if let (Some(id), Ok(token)) = (&share.node_id, secrets::resolve(&node_secret(&share.environment_id))) {
                    let _ = api(reqwest::Method::POST, &format!("/api/market/nodes/{id}/heartbeat"), Some(&token), Some(&json!({"status": "stopped"}))).await;
                }
            }
        })
        .await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sharing_reports_actual_runtime_precision_and_revision() {
        let health = json!({"runner":"transformers", "precision":"4bit", "revision":"a".repeat(40)});
        let details = sharing_details("ready", &health, Some("transformers"), None);
        assert_eq!(details["quant"], "NF4");
        assert_eq!(details["revision"], health["revision"]);
        let gguf = sharing_details("ready", &json!({"quant":"Q5_K_M", "runner":"llama.cpp"}), Some("transformers"), Some("Q4_K_M"));
        assert_eq!(gguf["quant"], "Q5_K_M");
        assert_eq!(gguf["runner"], "llama.cpp");
    }
    #[test]
    fn tunnel_recovery_is_owned_bounded_and_waits_for_dns_propagation() {
        let share=Share { environment_id:"env".into(),model:"owner/model".into(),mode:"free".into(),listen:false,node_id:None,publish:None,registry_version:None,published:Some("owned".into()),live:Live::default() };
        assert!(owned_quick_link(&share,&json!({"publicId":"owned","publicAccount":false})));
        assert!(!owned_quick_link(&share,&json!({"publicId":"other","publicAccount":false})));
        assert!(!owned_quick_link(&share,&json!({"publicId":"owned","publicAccount":true})));
        let mut live=Live {link_failures:2,link_since:Some(Instant::now()),..Live::default()};
        assert!(!reconnect_due(&live));
        live.link_since=Some(Instant::now()-Duration::from_secs(61));assert!(reconnect_due(&live));
        live.reconnected=Some(Instant::now());assert!(!reconnect_due(&live));
        live.reconnected=Some(Instant::now()-Duration::from_secs(121));assert!(reconnect_due(&live));
        live.link_failures=1;assert!(!reconnect_due(&live));
    }
    fn pending_login(generation: u64) -> Login {
        Login {
            generation, user_code: "CODE-1234".into(), verification_url: "https://yougori.com/device".into(),
            verification_url_complete: "https://yougori.com/device?code=CODE-1234".into(),
            expires: Instant::now() + Duration::from_secs(600), error: None,
        }
    }
    #[test]
    fn cancelled_or_replaced_approval_never_writes_credentials() {
        let answer = json!({"token":"old-session","account":{"email":"old@example.com"}});
        let mut inner = Inner { auth_generation: 1, login: Some(pending_login(1)), ..Inner::default() };
        // Sign-out cancels the pending code while its approval request is in flight.
        inner.auth_generation += 1;
        inner.login = None;
        assert!(!complete_login(&mut inner, 1, &answer, |_| panic!("cancelled approval saved credentials")));
        assert!(inner.account.is_none());
        // A late approval for the old code cannot replace a later sign-in either.
        inner.auth_generation += 1;
        inner.login = Some(pending_login(3));
        assert!(!complete_login(&mut inner, 1, &answer, |_| panic!("old approval saved credentials")));
        assert_eq!(inner.login.as_ref().unwrap().generation, 3);
        assert!(complete_login(&mut inner, 3, &answer, |token| { assert_eq!(token, "old-session"); Ok(()) }));
        assert!(inner.login.is_none());
        assert_eq!(inner.account.unwrap()["email"], "old@example.com");
    }
    #[test]
    fn expired_approval_and_vault_failure_leave_computer_signed_out() {
        let answer = json!({"token":"session","account":{"email":"user@example.com"}});
        let mut inner = Inner { login: Some(pending_login(1)), ..Inner::default() };
        inner.login.as_mut().unwrap().expires = Instant::now() - Duration::from_secs(1);
        assert!(complete_login(&mut inner, 1, &answer, |_| panic!("expired approval saved credentials")));
        assert!(inner.login.as_ref().unwrap().error.as_ref().unwrap().contains("expired"));
        assert!(inner.account.is_none());
        inner.login = Some(pending_login(2));
        assert!(complete_login(&mut inner, 2, &answer, |_| Err("vault unavailable".into())));
        assert_eq!(inner.login.as_ref().unwrap().error.as_deref(), Some("vault unavailable"));
        assert!(inner.account.is_none());
    }
    #[test]
    fn credentials_use_valid_vault_names_and_stable_environment_keys() {
        let name = node_secret("env-0f0e4bd2-8f4c-4dd4-a7c0-6f4d7b4e2a11");
        assert!(yougori_cli::workload::identifier(&name), "{name}");
        assert!(yougori_cli::workload::identifier(SESSION));
        assert_eq!(hash("env-1"), hash("env-1"));
        assert_ne!(hash("env-1"), hash("env-2"));
        assert_eq!(hash("env-1").len(), 64);
    }
    #[test]
    fn status_lists_shares_without_credentials() {
        let mut inner = Inner::default();
        inner.shares.insert("env-1".into(), Share {
            environment_id: "env-1".into(), model: "google/gemma-4-31B".into(), mode: "paid".into(), listen: false, publish: None, registry_version: None,
            node_id: Some("nd_1".into()), published: Some("pub-1".into()),
            live: Live { status: "ready".into(), online: true, sent_url: Some("https://secret.trycloudflare.com/v1".into()), ..Live::default() },
        });
        let value = snapshot(&inner);
        assert_eq!(value["signedIn"], false);
        assert_eq!(value["shares"][0]["live"], true);
        assert!(!value.to_string().contains("trycloudflare"));
        let saved = serde_json::to_string(&inner.shares.values().collect::<Vec<_>>()).unwrap();
        assert!(saved.contains("nd_1") && !saved.contains("trycloudflare"));
    }
}
