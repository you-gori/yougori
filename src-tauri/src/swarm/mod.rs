//! Local Swarm Mining supervisor. Remote credentials never enter company code,
//! terminal output, or the worker JSON file. No public inference route is created.
mod guest;
mod memory;
mod model_lifecycle;
#[cfg(all(test, windows, not(feature = "engine-only")))]
mod real_tests;
mod runner;
#[cfg(test)]
mod tests;
use crate::{projects::secrets, store::PlatformStore, AppHandle};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tauri::Manager;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Default)]
pub struct Swarm {
    inner: Mutex<Workers>,
    pub(crate) operations: Mutex<BTreeMap<String, CancellationToken>>,
    prepare: Mutex<()>,
    execution_gates: Mutex<BTreeMap<String, Arc<Mutex<()>>>>,
    control_gates: Mutex<BTreeMap<String, Arc<Mutex<()>>>>,
}
#[derive(Default)]
struct Workers {
    loaded: bool,
    rows: BTreeMap<String, Worker>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Worker {
    id: String,
    name: String,
    model: String,
    state: String,
    stage: String,
    site: String,
    gpu: String,
    resources: Value,
    quota_gb: f64,
    keep_resident: bool,
    #[serde(default)]
    environment_id: Option<String>,
    #[serde(default)]
    test_environment_id: Option<String>,
    #[serde(default)]
    model_environment_id: Option<String>,
    #[serde(default)]
    server_id: Option<String>,
    #[serde(default)]
    credential_reference: Option<String>,
    #[serde(default)]
    credential_expires_at: i64,
    #[serde(default)]
    opencode_password_reference: Option<String>,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    policy: Value,
    #[serde(default)]
    membership: Value,
    #[serde(default)]
    cursor: u64,
    #[serde(default)]
    human_cursor: u64,
    #[serde(default)]
    attempt_count: u64,
    #[serde(default)]
    task_index: u64,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    lease: Value,
    #[serde(default)]
    quant: Option<String>,
    #[serde(default)]
    owned_model: bool,
    #[serde(default)]
    source_files: Vec<String>,
    #[serde(default)]
    guidance: Vec<Value>,
    #[serde(default)]
    generation: u64,
    #[serde(default)]
    skipped_offers: Vec<String>,
    #[serde(default)]
    pending_replies: BTreeMap<String, Value>,
    #[serde(default)]
    tool_results: BTreeMap<String, Value>,
}
impl Worker {
    fn view(&self) -> Value {
        json!({"id":self.id,"serverId":self.server_id,"name":self.name,"model":self.model,"state":self.state,"stage":self.stage,"environmentId":self.environment_id,"modelEnvironmentId":self.model_environment_id,"testEnvironmentId":self.test_environment_id,"gpu":self.gpu,"resources":self.resources,"workspaceQuotaGb":self.quota_gb,"keepResident":self.keep_resident,"error":self.error,"summary":self.summary,"completedAttempts":self.attempt_count,"bountyId":self.policy["bountyId"],"policyVersion":self.policy["termsVersion"],"cursor":self.cursor})
    }
    fn remote_id(&self) -> Result<&str, String> {
        self.server_id
            .as_deref()
            .ok_or("Worker registration has not completed".into())
    }
}
pub(crate) fn execution_authorized(state: &Value, worker: &Worker) -> bool {
    state["executionAllowed"] == true
        && direct_source_policy(&worker.policy).is_ok()
        && direct_source_policy(&state["policy"]).is_ok()
        && state["policy"]["authorizationDigest"] == worker.policy["authorizationDigest"]
        && state["policy"]["authorization"] == worker.policy["authorization"]
        && worker.policy["termsDigest"].as_str().is_some_and(|digest| {
            digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        && state["policy"]["termsDigest"] == worker.policy["termsDigest"]
        && source_payment_consents(&state["membership"], &worker.policy)
        && worker.policy["bountyId"].as_str().is_some_and(identifier)
        && worker.policy["termsVersion"]
            .as_u64()
            .is_some_and(|version| version > 0)
        && worker.policy["sourceDigest"]
            .as_str()
            .is_some_and(|digest| {
                digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        && state["policy"]["bountyId"] == worker.policy["bountyId"]
        && state["policy"]["termsVersion"] == worker.policy["termsVersion"]
        && state["policy"]["sourceDigest"] == worker.policy["sourceDigest"]
}

fn source_payment_consents(membership: &Value, policy: &Value) -> bool {
    membership["authorization_accepted"] == true
        && membership["direct_payment_accepted"] == true
        && membership["authorization_digest"] == policy["authorizationDigest"]
        && membership["payment_mode"] == "publisher_direct_external"
}

fn direct_source_policy(policy: &Value) -> Result<(), String> {
    if policy["paymentMode"] != "publisher_direct_external"
        || policy["legacyResolutionRequired"] == true
        || policy["rewardFundingVerified"] != false
        || policy["prefunded"] != false
        || policy["rewardGuaranteed"] != false
    {
        return Err("Legacy platform-funded or incomplete payment terms cannot authorize new Swarm work. Resolve historic obligations manually; reports and reward records remain available.".into());
    }
    yougori_cli::bounty::validate_source_authorization(
        &policy["authorization"],
        &policy["authorizationDigest"],
        &policy["sourceRevision"],
        &policy["sourceDigest"],
        &policy["termsVersion"],
    )
}

fn wallet_secret_or_transfer_input(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            matches!(
                key.to_ascii_lowercase().as_str(),
                "privatekey"
                    | "walletprivatekey"
                    | "walletkey"
                    | "walletsecret"
                    | "walletseed"
                    | "seedphrase"
                    | "mnemonic"
                    | "sendtransaction"
                    | "signtransaction"
                    | "withdrawal"
            ) || wallet_secret_or_transfer_input(value)
        }),
        Value::Array(values) => values.iter().any(wallet_secret_or_transfer_input),
        _ => false,
    }
}
fn now() -> i64 {
    chrono::Utc::now().timestamp()
}
fn key() -> String {
    Uuid::new_v4().simple().to_string()
}
fn string<'a>(v: &'a Value, field: &str) -> Result<&'a str, String> {
    v[field]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= 4096 && !s.chars().any(char::is_control))
        .ok_or_else(|| format!("{field} is required"))
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
}
fn worker_id(request: &Value) -> Result<&str, String> {
    let id = string(request, "workerId")?;
    if !identifier(id) {
        return Err("Invalid worker ID".into());
    }
    Ok(id)
}

pub(crate) fn validate(request: &Value) -> Result<(), String> {
    if wallet_secret_or_transfer_input(request) {
        return Err("Swarm accepts no wallet keys or seed phrases and cannot initiate, sign or withdraw transfers".into());
    }
    let action = string(request, "action")?;
    if !matches!(
        action,
        "prepare"
            | "list"
            | "workers"
            | "status"
            | "offers"
            | "details"
            | "accept"
            | "skip"
            | "chat"
            | "messages"
            | "pause"
            | "resume"
            | "stop"
            | "delete"
            | "leave"
            | "cancelPrepare"
            | "reports"
            | "rewards"
            | "doctor"
            | "bounties"
            | "apply"
            | "submitReport"
    ) {
        return Err("Unknown Swarm Mining action".into());
    }
    if action == "prepare" {
        crate::model_runner::normalize_model(string(request, "model")?)?;
        let gpu = request["gpu"].as_str().unwrap_or("nvidia");
        if !matches!(gpu, "nvidia" | "cpu") {
            return Err("Choose an NVIDIA GPU or CPU worker".into());
        }
        let r = &request["resources"];
        for (name, min, max) in [("cpu", 4., 255.), ("memoryGb", 8., 1024.)] {
            let n = r[name].as_f64().unwrap_or(min);
            if !n.is_finite() || n < min || n > max {
                return Err(format!("{name} is outside this worker's supported limits"));
            }
        }
        let quota = request["workspaceQuotaGb"].as_f64().unwrap_or(20.);
        if !quota.is_finite() || !(4.0..=1024.0).contains(&quota) {
            return Err("Workspace quota must be 4–1024 GB".into());
        }
        if request["name"].as_str().is_some_and(|name| {
            name.len() < 2 || name.len() > 80 || name.chars().any(char::is_control)
        }) {
            return Err("Worker name must be 2–80 characters".into());
        }
    } else if !matches!(action, "list" | "workers" | "rewards" | "bounties")
        && !(matches!(action, "reports" | "doctor") && request["workerId"].is_null())
    {
        worker_id(request)?;
    }
    if action == "accept" {
        if request["authorizationAccepted"] != true
            || request["directPaymentAccepted"] != true
            || !request["authorizationDigest"]
                .as_str()
                .is_some_and(|digest| {
                    digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
        {
            return Err("Explicitly accept the exact publisher source authorization and unverified direct-payment counterparty risk".into());
        }
        if request["termsVersion"]
            .as_u64()
            .is_none_or(|version| version == 0)
        {
            return Err("Accept an exact positive immutable terms version".into());
        }
        string(request, "sourceRevision")?;
        if !request["sourceDigest"].as_str().is_some_and(|digest| {
            digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        }) {
            return Err("Accept the exact immutable source snapshot digest".into());
        }
        if request["rulesAccepted"] != true
            || request["rulesVersion"].as_str().is_none_or(str::is_empty)
            || !request["rulesDigest"]
                .as_str()
                .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(
                "Read and explicitly accept the exact Swarm Mining responsible use rules".into(),
            );
        }
        if request["confirmed"] != true {
            return Err(
                "Review and explicitly accept the bounty terms before starting work".into(),
            );
        }
        if !matches!(
            request["reportPolicy"].as_str(),
            Some("automatic" | "review")
        ) {
            return Err("Choose automatic private submission or review first".into());
        }
        let budget = request["budgetMinutes"]
            .as_u64()
            .ok_or("Choose a work budget")?;
        if !(1..=1440).contains(&budget) {
            return Err("Work budget must be 1–1440 minutes".into());
        }
        string(request, "bountyId")?;
        string(request, "termsDigest")?;
        if !identifier(string(request, "bountyId")?) {
            return Err("Invalid bounty ID".into());
        }
    }
    if action == "delete" && request["confirmed"] != true {
        return Err("Confirm deletion of this worker's managed workspace".into());
    }
    if action == "apply" {
        if request["confirmed"] != true
            || request["termsVersion"]
                .as_u64()
                .is_none_or(|version| version == 0)
        {
            return Err(
                "Explicitly confirm an access application for the exact published version".into(),
            );
        }
        string(request, "termsDigest")?;
        if !identifier(string(request, "bountyId")?) {
            return Err("Invalid bounty ID for access application".into());
        }
    }
    if action == "chat"
        && (request["content"]
            .as_str()
            .is_none_or(|s| s.trim().is_empty() || s.len() > 8192))
    {
        return Err("Send a message of 1–8192 characters".into());
    }
    Ok(())
}
async fn load(app: &AppHandle) -> Result<(), String> {
    let manager = app.state::<Swarm>();
    let mut inner = manager.inner.lock().await;
    if inner.loaded {
        return Ok(());
    }
    let path = app
        .state::<PlatformStore>()
        .data_folder("swarm")
        .join("workers.json");
    match std::fs::read(&path) {
        Ok(bytes) => {
            if bytes.len() > 80 * 1024 * 1024 {
                return Err("Worker journal exceeds its limit; no workers were started".into());
            }
            inner.rows = serde_json::from_slice(&bytes)
                .map_err(|_| "Cannot read worker journal; no workers were started")?;
            for worker in inner.rows.values_mut() {
                if !matches!(worker.state.as_str(), "stopped" | "failed") {
                    worker.state = "paused".into();
                    worker.stage = "Worker restored. Resume to recheck authorization.".into();
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.to_string()),
    }
    inner.loaded = true;
    Ok(())
}
fn save(app: &AppHandle, inner: &Workers) -> Result<(), String> {
    use std::io::Write;
    let root = app.state::<PlatformStore>().data_folder("swarm");
    std::fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    let mut file = tempfile::NamedTempFile::new_in(&root).map_err(|e| e.to_string())?;
    file.write_all(&serde_json::to_vec(&inner.rows).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    file.as_file().sync_all().map_err(|e| e.to_string())?;
    file.persist(root.join("workers.json"))
        .map_err(|e| e.to_string())?;
    Ok(())
}
pub(crate) async fn read(app: &AppHandle, id: &str) -> Result<Worker, String> {
    load(app).await?;
    app.state::<Swarm>()
        .inner
        .lock()
        .await
        .rows
        .get(id)
        .cloned()
        .ok_or("Worker not found on this computer".into())
}
fn apply_progress(inner: &mut Workers, mut worker: Worker) -> Result<(), String> {
    let old = inner
        .rows
        .get(&worker.id)
        .ok_or("Worker was deleted; stale progress was not applied")?;
    if old.generation != worker.generation {
        return Err("Worker control changed; stale progress was not applied".into());
    }
    if old.credential_reference.is_some() {
        worker.credential_reference = old.credential_reference.clone();
        worker.credential_expires_at = old.credential_expires_at;
    }
    inner.rows.insert(worker.id.clone(), worker);
    Ok(())
}
pub(crate) async fn write(app: &AppHandle, worker: Worker) -> Result<(), String> {
    let m = app.state::<Swarm>();
    let mut i = m.inner.lock().await;
    apply_progress(&mut i, worker)?;
    save(app, &i)
}
async fn update(app: &AppHandle, id: &str, f: impl FnOnce(&mut Worker)) -> Result<Worker, String> {
    let m = app.state::<Swarm>();
    let mut i = m.inner.lock().await;
    let w = i.rows.get_mut(id).ok_or("Worker not found")?;
    f(w);
    let result = w.clone();
    save(app, &i)?;
    Ok(result)
}
async fn update_if_current(
    app: &AppHandle,
    id: &str,
    generation: u64,
    f: impl FnOnce(&mut Worker),
) -> Result<Worker, String> {
    let m = app.state::<Swarm>();
    let mut i = m.inner.lock().await;
    let w = i.rows.get_mut(id).ok_or("Worker was deleted")?;
    if w.generation != generation {
        return Err("Worker control changed; the earlier request was not resumed locally".into());
    }
    f(w);
    let result = w.clone();
    save(app, &i)?;
    Ok(result)
}

pub(crate) async fn agent(
    app: &AppHandle,
    worker: &Worker,
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
) -> Result<Value, String> {
    let current = read(app, &worker.id).await?;
    if current.generation != worker.generation {
        return Err("Worker control changed; stale agent action was not executed".into());
    }
    let result = agent_once(&current, method.clone(), path, body.clone()).await;
    if result
        .as_ref()
        .is_err_and(|e| e.starts_with("SWARM_API:401:"))
    {
        let mut current = read(app, &worker.id).await?;
        if current.generation != worker.generation {
            return Err("Worker control changed; old credentials were not refreshed".into());
        }
        current.credential_expires_at = 0;
        refresh(app, &mut current).await?;
        return agent_once(&current, method, path, body).await;
    }
    result
}
async fn agent_once(
    worker: &Worker,
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
) -> Result<Value, String> {
    if worker.site != crate::market::website() {
        return Err("Worker belongs to a different configured Yougori website. Reconnect to its original website.".into());
    }
    if !path.starts_with("/api/swarm/agent/")
        || path.contains("..")
        || path.contains(['#', '%', '\\'])
        || path.len() > 512
    {
        return Err("Invalid agent operation".into());
    }
    let reference = worker
        .credential_reference
        .as_deref()
        .ok_or("Worker credential unavailable")?;
    let token = secrets::resolve(reference)?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())?;
    let mut request = client
        .request(method, format!("{}{path}", worker.site))
        .bearer_auth(token);
    if let Some(body) = body {
        request = request.json(&body);
    }
    let mut reply = request
        .send()
        .await
        .map_err(|_| "Cannot reach the Swarm Mining service")?;
    let status = reply.status();
    let mut bytes = Vec::new();
    let limit = if path == "/api/swarm/agent/source" {
        96 * 1024 * 1024
    } else {
        8 * 1024 * 1024
    };
    while let Some(chunk) = reply
        .chunk()
        .await
        .map_err(|_| "Interrupted Swarm Mining response")?
    {
        if bytes.len() + chunk.len() > limit {
            return Err("Swarm Mining response exceeds its limit".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|_| "Invalid Swarm Mining response")?;
    if !status.is_success() {
        return Err(format!(
            "SWARM_API:{}:{}: {}",
            status.as_u16(),
            value["code"].as_str().unwrap_or("rejected"),
            value["error"]
                .as_str()
                .unwrap_or("Swarm Mining operation was rejected")
        ));
    }
    Ok(value)
}
pub(crate) async fn refresh(app: &AppHandle, worker: &mut Worker) -> Result<(), String> {
    if worker.credential_expires_at > now() + 180 {
        return Ok(());
    }
    let generation = worker.generation;
    let old_reference = worker.credential_reference.clone();
    if read(app, &worker.id).await?.generation != generation {
        return Err("Worker control changed before credential refresh".into());
    }
    let result = crate::market::swarm_account_request(
        reqwest::Method::POST,
        &format!("/api/swarm/workers/{}/credentials", worker.remote_id()?),
        Some(&json!({"idempotencyKey":format!("refresh-{}-{}",worker.id,key())})),
    )
    .await?;
    store_credential(worker, &result)?;
    let reference = worker.credential_reference.clone();
    let expires = worker.credential_expires_at;
    let result = update_if_current(app, &worker.id, generation, |w| {
        w.credential_reference = reference.clone();
        w.credential_expires_at = expires;
    })
    .await;
    match result {
        Ok(current) => *worker = current,
        Err(error) => {
            if let Some(reference) = reference {
                let _ = secrets::delete_secret(&reference);
            }
            return Err(error);
        }
    }
    if let Some(old) = old_reference.filter(|old| Some(old) != reference.as_ref()) {
        let _ = secrets::delete_secret(&old);
    }
    Ok(())
}
fn store_credential(worker: &mut Worker, result: &Value) -> Result<(), String> {
    let token = string(&result["credential"], "token")?;
    if !token.starts_with("swm_") {
        return Err("Invalid scoped worker credential".into());
    }
    let reference = format!("swarm-credential-{}-{}", worker.id, &key()[..12]);
    let expires = result["credential"]["expiresAt"]
        .as_i64()
        .ok_or("Missing worker credential expiry")?;
    secrets::store(&reference, token)?;
    worker.credential_reference = Some(reference);
    worker.credential_expires_at = expires;
    Ok(())
}
fn remove_worker_journals(root: &std::path::Path, id: &str) -> Result<(), String> {
    if !identifier(id) || !id.starts_with("worker-") {
        return Err("Invalid worker cleanup identity".into());
    }
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.to_string()),
    };
    let prefix = format!("{id}-");
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(&prefix)
            && name.ends_with(".jsonl")
            && entry.file_type().map_err(|e| e.to_string())?.is_file()
        {
            std::fs::remove_file(entry.path()).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}
fn cleanup_deleted_worker(app: &AppHandle, worker: &Worker) -> Result<(), String> {
    remove_worker_journals(
        &app.state::<PlatformStore>()
            .data_folder("swarm")
            .join("events"),
        &worker.id,
    )?;
    for reference in [
        worker.credential_reference.as_ref(),
        worker.opencode_password_reference.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        let _ = secrets::delete_secret(reference);
    }
    Ok(())
}
pub(crate) fn launch(app: &AppHandle, id: String, setup: bool) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let cancel = CancellationToken::new();
        {
            let m = app.state::<Swarm>();
            let mut ops = m.operations.lock().await;
            if let Some(old) = ops.insert(id.clone(), cancel.clone()) {
                old.cancel();
            }
        }
        let generation = match read(&app, &id).await {
            Ok(w) => w.generation,
            Err(_) => return,
        };
        let shutdown = crate::automation::shutdown_signal(&app);
        let gate = execution_gate(&app, &id).await;
        let _execution = tokio::select! {_=shutdown.cancelled()=>return,_=cancel.cancelled()=>return,guard=gate.lock_owned()=>guard};
        let current = match read(&app, &id).await {
            Ok(worker) => worker,
            Err(_) => return,
        };
        if cancel.is_cancelled()
            || current.generation != generation
            || matches!(current.state.as_str(), "stopped" | "failed")
            || (setup && current.state != "preparing")
        {
            return;
        }
        let work = async {
            if setup {
                prepare(&app, &id, &cancel).await?;
            }
            runner::run(&app, &id, &cancel).await
        };
        let result = tokio::select! { _=shutdown.cancelled()=>Err("Engine shutdown; worker progress was preserved".into()), result=work=>result};
        if let Err(error) = result {
            if read(&app, &id)
                .await
                .is_ok_and(|w| w.generation == generation)
            {
                if let Ok(worker) = update(&app, &id, |w| {
                    w.state = if setup { "failed" } else { "paused" }.into();
                    w.stage = "Worker needs attention".into();
                    w.error = Some(crate::lifecycle::safe_diagnostic(&error));
                })
                .await
                {
                    let _ = guest::abort_agent(&app, &worker).await;
                    if setup {
                        model_lifecycle::schedule_unused_cleanup(&app, &worker);
                        let _ = model_lifecycle::stop_if_unused(&app, &worker).await;
                    } else {
                        let _ = model_lifecycle::release_while_waiting(&app, &worker).await;
                    }
                }
            }
        }
        let m = app.state::<Swarm>();
        let mut operations = m.operations.lock().await;
        if read(&app, &id)
            .await
            .is_ok_and(|w| w.generation == generation)
        {
            operations.remove(&id);
        }
    });
}

pub(crate) async fn execution_gate(app: &AppHandle, id: &str) -> Arc<Mutex<()>> {
    let manager = app.state::<Swarm>();
    let mut gates = manager.execution_gates.lock().await;
    gates.entry(id.into()).or_default().clone()
}
async fn control_gate(app: &AppHandle, id: &str) -> Arc<Mutex<()>> {
    let manager = app.state::<Swarm>();
    let mut gates = manager.control_gates.lock().await;
    gates.entry(id.into()).or_default().clone()
}

#[tauri::command]
pub async fn swarm_dispatch(request: Value, app: AppHandle) -> Result<Value, String> {
    validate(&request)?;
    load(&app).await?;
    let action = string(&request, "action")?;
    if action == "doctor" && request["workerId"].is_null() {
        let host = serde_json::to_value(app.state::<PlatformStore>().snapshot()?.host)
            .map_err(|e| e.to_string())?;
        let preflight = if request["preflightModel"] == true {
            Some(
                crate::model_runner::model_preflight(
                    string(&request, "model")?.into(),
                    request["quant"].as_str().map(str::to_owned),
                    None,
                )
                .await?,
            )
        } else {
            None
        };
        return Ok(
            json!({"host":host,"preflight":preflight,"localOnly":true,"publicInference":false,"minimumResources":{"cpu":4,"memoryGb":8}}),
        );
    }
    if action == "prepare" {
        if request["platformUrl"]
            .as_str()
            .is_some_and(|s| s.trim_end_matches('/') != crate::market::website())
        {
            return Err("Set YOUGORI_NETWORK_URL before starting Yougori to select a development website. Account credentials stay bound to that website.".into());
        }
        let id = format!("worker-{}", key());
        let worker = Worker {
            id: id.clone(),
            name: request["name"].as_str().unwrap_or("Bounty worker").into(),
            model: crate::model_runner::normalize_model(string(&request, "model")?)?,
            state: "preparing".into(),
            stage: "Checking your model and resources".into(),
            site: crate::market::website(),
            gpu: request["gpu"].as_str().unwrap_or("nvidia").into(),
            resources: if request["resources"].is_object() {
                request["resources"].clone()
            } else {
                json!({"cpu":4,"memoryGb":8})
            },
            quota_gb: request["workspaceQuotaGb"].as_f64().unwrap_or(20.),
            keep_resident: request["keepResident"].as_bool().unwrap_or(true),
            environment_id: None,
            test_environment_id: None,
            model_environment_id: None,
            server_id: None,
            credential_reference: None,
            credential_expires_at: 0,
            opencode_password_reference: None,
            session_id: None,
            policy: Value::Null,
            membership: Value::Null,
            cursor: 0,
            human_cursor: 0,
            attempt_count: 0,
            task_index: 0,
            error: None,
            summary: String::new(),
            lease: Value::Null,
            quant: request["quant"].as_str().map(str::to_owned),
            owned_model: false,
            source_files: Vec::new(),
            guidance: Vec::new(),
            generation: 0,
            skipped_offers: Vec::new(),
            pending_replies: BTreeMap::new(),
            tool_results: BTreeMap::new(),
        };
        {
            let manager = app.state::<Swarm>();
            let mut inner = manager.inner.lock().await;
            if inner.rows.len() >= 32 {
                return Err("This computer already has 32 workers. Remove unused managed workers before creating more.".into());
            }
            inner.rows.insert(id.clone(), worker.clone());
            save(&app, &inner)?;
        }
        launch(&app, id, true);
        return Ok(json!({"worker":worker.view(),"background":true}));
    }
    if matches!(action, "list" | "workers") {
        let m = app.state::<Swarm>();
        let i = m.inner.lock().await;
        return Ok(json!({"workers":i.rows.values().map(Worker::view).collect::<Vec<_>>()}));
    }
    if action == "rewards" {
        return crate::market::swarm_account_request(
            reqwest::Method::GET,
            "/api/swarm/rewards",
            None,
        )
        .await;
    }
    if action == "bounties" {
        return crate::market::swarm_account_request(
            reqwest::Method::GET,
            "/api/swarm/bounties",
            None,
        )
        .await;
    }
    if action == "reports" && request["workerId"].is_null() {
        return crate::market::swarm_account_request(
            reqwest::Method::GET,
            "/api/swarm/reports",
            None,
        )
        .await;
    }
    let id = worker_id(&request)?;
    let _control = if matches!(
        action,
        "accept" | "resume" | "cancelPrepare" | "pause" | "stop" | "leave" | "delete"
    ) {
        Some(control_gate(&app, id).await.lock_owned().await)
    } else {
        None
    };
    let mut worker = read(&app, id).await?;
    if action == "status" {
        return Ok(json!({"worker":worker.view()}));
    }
    if action == "doctor" {
        let model = if let Some(model) = &worker.model_environment_id {
            crate::model_runner::model_status(model.clone(), app.clone())
                .await
                .ok()
        } else {
            None
        };
        return Ok(
            json!({"worker":worker.view(),"model":model,"localOnly":true,"publicInference":false,"credentialConfigured":worker.credential_reference.is_some()}),
        );
    }
    if action == "cancelPrepare" {
        if let Some(c) = app.state::<Swarm>().operations.lock().await.get(id) {
            c.cancel();
        }
        update(&app, id, |w| {
            w.generation += 1;
            w.state = "paused".into();
            w.stage = "Preparation cancelled; verified downloads are preserved".into();
        })
        .await?;
        let _execution = execution_gate(&app, id).await.lock_owned().await;
        worker = read(&app, id).await?;
        guest::stop_owned(&app, &worker, false).await?;
        model_lifecycle::schedule_unused_cleanup(&app, &worker);
        model_lifecycle::stop_if_unused(&app, &worker).await?;
        return Ok(json!({"worker":worker.view()}));
    }
    if action == "resume" && worker.server_id.is_none() {
        worker = update(&app, id, |w| {
            w.generation += 1;
            w.state = "preparing".into();
            w.error = None;
        })
        .await?;
        launch(&app, id.into(), true);
        return Ok(json!({"worker":worker.view(),"background":true}));
    }
    if worker.server_id.is_none() && matches!(action, "pause" | "stop" | "leave" | "delete") {
        if let Some(c) = app.state::<Swarm>().operations.lock().await.get(id) {
            c.cancel();
        }
        update(&app, id, |w| {
            w.generation += 1;
            w.state = if action == "pause" {
                "paused"
            } else {
                "stopped"
            }
            .into();
            w.stage = "Preparation stopped; verified files are retained".into();
        })
        .await?;
        let _execution = execution_gate(&app, id).await.lock_owned().await;
        worker = read(&app, id).await?;
        guest::stop_owned(&app, &worker, action == "delete").await?;
        model_lifecycle::schedule_unused_cleanup(&app, &worker);
        model_lifecycle::stop_if_unused(&app, &worker).await?;
        if action == "delete" {
            let m = app.state::<Swarm>();
            let mut inner = m.inner.lock().await;
            inner.rows.remove(id);
            save(&app, &inner)?;
            cleanup_deleted_worker(&app, &worker)?;
        }
        return Ok(json!({"worker":worker.view(),"deleted":action=="delete"}));
    }
    let remote = worker.remote_id()?.to_owned();
    if action == "apply" {
        return crate::market::swarm_account_request(reqwest::Method::POST,&format!("/api/swarm/workers/{remote}/apply"),Some(&json!({"bountyId":request["bountyId"],"termsVersion":request["termsVersion"],"termsDigest":request["termsDigest"],"idempotencyKey":format!("apply-{}-{}-{}",id,request["bountyId"].as_str().unwrap_or_default(),request["termsVersion"])}))).await;
    }
    if matches!(action, "offers" | "details" | "skip") {
        let mut result = crate::market::swarm_account_request(
            reqwest::Method::GET,
            &format!("/api/swarm/workers/{remote}/offers"),
            None,
        )
        .await?;
        if action == "details" {
            let offers = result["offers"]
                .as_array()
                .ok_or("Invalid offer response")?;
            let offer = offers
                .iter()
                .find(|o| {
                    Some(o["id"].as_str().unwrap_or("")) == request["offerId"].as_str()
                        || Some(o["bounty"]["id"].as_str().unwrap_or(""))
                            == request["bountyId"].as_str()
                })
                .ok_or("This offer is no longer available")?;
            return Ok(json!({"offer":offer}));
        }
        if action == "skip" {
            let offers = result["offers"]
                .as_array()
                .ok_or("Invalid offer response")?;
            let offer = offers
                .iter()
                .find(|o| {
                    Some(o["id"].as_str().unwrap_or("")) == request["offerId"].as_str()
                        || Some(o["bounty"]["id"].as_str().unwrap_or(""))
                            == request["bountyId"].as_str()
                })
                .ok_or("This offer is no longer available")?;
            let fingerprint = format!(
                "{}:{}",
                offer["id"].as_str().unwrap_or_default(),
                offer["termsDigest"].as_str().unwrap_or_default()
            );
            worker = update(&app, id, |w| {
                if w.skipped_offers.len() >= 1000 {
                    w.skipped_offers.remove(0);
                }
                if !w.skipped_offers.contains(&fingerprint) {
                    w.skipped_offers.push(fingerprint);
                }
            })
            .await?;
            return Ok(json!({"skipped":true,"worker":worker.view()}));
        }
        if let Some(offers) = result["offers"].as_array_mut() {
            offers.retain(|offer| {
                !worker.skipped_offers.contains(&format!(
                    "{}:{}",
                    offer["id"].as_str().unwrap_or_default(),
                    offer["termsDigest"].as_str().unwrap_or_default()
                ))
            });
        }
        return Ok(result);
    }
    if action == "accept" {
        if matches!(worker.state.as_str(), "running" | "preparing_bounty") {
            return Err("This worker is already working on a bounty. Pause and leave it before accepting another.".into());
        }
        let body = json!({"bountyId":request["bountyId"],"termsVersion":request["termsVersion"],"termsDigest":request["termsDigest"],"sourceRevision":request["sourceRevision"],"sourceDigest":request["sourceDigest"],"authorizationAccepted":request["authorizationAccepted"],"authorizationDigest":request["authorizationDigest"],"directPaymentAccepted":request["directPaymentAccepted"],"reportPolicy":request["reportPolicy"],"budgetMinutes":request["budgetMinutes"],"rulesAccepted":request["rulesAccepted"],"rulesVersion":request["rulesVersion"],"rulesDigest":request["rulesDigest"],"idempotencyKey":format!("accept-{}-{}-{}-{}",id,request["bountyId"].as_str().unwrap_or_default(),request["termsVersion"],worker.generation)});
        let result = crate::market::swarm_account_request(
            reqwest::Method::POST,
            &format!("/api/swarm/workers/{remote}/accept"),
            Some(&body),
        )
        .await?;
        store_credential(&mut worker, &result)?;
        let policy = result["policy"].clone();
        let membership = result["membership"].clone();
        direct_source_policy(&policy)?;
        if policy["authorizationDigest"] != request["authorizationDigest"]
            || policy["termsVersion"] != request["termsVersion"]
            || policy["termsDigest"] != request["termsDigest"]
            || policy["sourceRevision"] != request["sourceRevision"]
            || policy["sourceDigest"] != request["sourceDigest"]
            || membership["authorization_accepted"] != true
            || membership["direct_payment_accepted"] != true
            || membership["authorization_digest"] != request["authorizationDigest"]
            || membership["payment_mode"] != "publisher_direct_external"
        {
            return Err("The accepted source authorization or direct-payment consent receipt does not match this request; no work was launched".into());
        }
        let reference = worker.credential_reference.clone();
        let expiry = worker.credential_expires_at;
        worker = update_if_current(&app, id, worker.generation, |w| {
            w.generation += 1;
            w.credential_reference = reference;
            w.credential_expires_at = expiry;
            w.policy = policy;
            w.membership = membership;
            w.cursor = 0;
            w.state = "preparing_bounty".into();
            w.stage = "Preparing the approved isolated project".into();
            w.error = None;
            w.task_index = 0;
            w.attempt_count = 0;
            w.guidance.clear();
            w.session_id = None;
            w.lease = Value::Null;
        })
        .await?;
        launch(&app, id.into(), false);
        return Ok(json!({"worker":worker.view(),"background":true}));
    }
    if matches!(action, "messages" | "chat") {
        let path = format!("/api/swarm/workers/{remote}/messages");
        let body = if action == "chat" {
            Some(
                json!({"content":request["content"],"idempotencyKey":request["idempotencyKey"].as_str().map(str::to_owned).unwrap_or_else(key)}),
            )
        } else {
            None
        };
        return crate::market::swarm_account_request(
            if action == "chat" {
                reqwest::Method::POST
            } else {
                reqwest::Method::GET
            },
            &path,
            body.as_ref(),
        )
        .await;
    }
    if action == "reports" {
        return crate::market::swarm_account_request(
            reqwest::Method::GET,
            &format!("/api/swarm/workers/{remote}"),
            None,
        )
        .await;
    }
    if action == "submitReport" {
        let report = string(&request, "reportId")?;
        if !identifier(report) {
            return Err("Invalid report ID".into());
        }
        return crate::market::swarm_account_request(
            reqwest::Method::POST,
            &format!("/api/swarm/reports/{report}/submit"),
            Some(&json!({"confirm":true,"idempotencyKey":format!("submit-{report}")})),
        )
        .await;
    }
    if matches!(action, "pause" | "stop" | "leave" | "delete") {
        if let Some(c) = app.state::<Swarm>().operations.lock().await.get(id) {
            c.cancel();
        }
        // Commit the local control barrier before waiting for the guest or
        // website. A late checkpoint can never undo a participant's stop.
        update(&app, id, |w| {
            w.generation += 1;
            w.state = if action == "pause" {
                "paused"
            } else {
                "stopped"
            }
            .into();
            w.stage = "Stopping investigation; progress saved".into();
        })
        .await?;
        let _execution = execution_gate(&app, id).await.lock_owned().await;
        worker = read(&app, id).await?;
        guest::abort_agent(&app, &worker).await?;
        let result=crate::market::swarm_account_request(reqwest::Method::POST,&format!("/api/swarm/workers/{remote}/control"),Some(&json!({"action":if action=="delete"{"stop"}else{action},"reason":"Participant requested this action"}))).await;
        if action != "pause" {
            guest::stop_owned(&app, &worker, action == "delete").await?;
        }
        worker = update(&app, id, |w| {
            w.stage = "Progress saved".into();
            if action == "leave" {
                w.policy = Value::Null;
                w.membership = Value::Null;
                w.session_id = None;
            }
        })
        .await?;
        if action == "pause" {
            model_lifecycle::release_while_waiting(&app, &worker).await?;
        } else {
            model_lifecycle::schedule_unused_cleanup(&app, &worker);
            model_lifecycle::stop_if_unused(&app, &worker).await?;
        }
        if action == "delete" {
            let m = app.state::<Swarm>();
            let mut i = m.inner.lock().await;
            i.rows.remove(id);
            save(&app, &i)?;
            cleanup_deleted_worker(&app, &worker)?;
        }
        result?;
        return Ok(json!({"worker":worker.view(),"deleted":action=="delete"}));
    }
    if action == "resume" {
        if !worker.policy.is_null() {
            direct_source_policy(&worker.policy)?;
        }
        let body = if request["budgetMinutes"].is_null() {
            json!({"action":"resume"})
        } else {
            json!({"action":"resume","budgetMinutes":request["budgetMinutes"]})
        };
        crate::market::swarm_account_request(
            reqwest::Method::POST,
            &format!("/api/swarm/workers/{remote}/control"),
            Some(&body),
        )
        .await?;
        worker = update_if_current(&app, id, worker.generation, |w| {
            w.generation += 1;
            w.state = if w.policy.is_null() {
                "ready_waiting"
            } else {
                "running"
            }
            .into();
            w.error = None;
        })
        .await?;
        launch(&app, id.into(), false);
        return Ok(json!({"worker":worker.view()}));
    }
    Err("This Swarm Mining operation is not available in the current worker state".into())
}

async fn prepare_lock<'a>(
    lock: &'a Mutex<()>,
    cancel: &CancellationToken,
) -> Option<tokio::sync::MutexGuard<'a, ()>> {
    tokio::select! {_=cancel.cancelled()=>None,guard=lock.lock()=>Some(guard)}
}

async fn prepare(app: &AppHandle, id: &str, cancel: &CancellationToken) -> Result<(), String> {
    let manager = app.state::<Swarm>();
    let Some(_serial) = prepare_lock(&manager.prepare, cancel).await else {
        return Ok(());
    };
    if cancel.is_cancelled() {
        return Ok(());
    }
    let mut worker = read(app, id).await?;
    if worker.state != "preparing" {
        return Ok(());
    }
    // Check availability and account credentials before allocating disk/GPU or
    // downloading weights for a platform that has not enabled the pilot.
    let config = tokio::select! {_=cancel.cancelled()=>return Ok(()),result=crate::market::swarm_account_request(reqwest::Method::GET,"/api/swarm/config",None)=>result?};
    if config["enabled"] != true {
        return Err("Swarm Mining is not enabled on this platform yet. Your worker can be resumed after it is enabled.".into());
    }
    if config["currency"] != "USDC"
        || config["scopeMode"] != "local_source_only"
        || config["paymentMode"] != "publisher_direct_external"
    {
        return Err(
            "This Swarm platform does not provide the supported publisher direct-payment USDC source-authorization contract"
                .into(),
        );
    }
    let preflight = tokio::select! {_=cancel.cancelled()=>return Ok(()),result=crate::model_runner::model_preflight(worker.model.clone(),worker.quant.clone(),None)=>result?};
    if preflight["runner"] != "yougori-llama-cpp" {
        return Err("Swarm workers currently require a supported GGUF model with agent tool calling. Paste its Hugging Face GGUF repository.".into());
    }
    // Implicit and explicitly selected defaults refer to the same verified
    // quantization, so reuse compares the resolved preflight selection.
    worker.quant = preflight["quant"].as_str().map(str::to_owned);
    if cancel.is_cancelled() {
        return Ok(());
    }
    write(app, worker.clone()).await?;
    let existing = if worker.model_environment_id.is_none() {
        model_lifecycle::find_reusable_model(app, &worker, &preflight).await?
    } else {
        None
    };
    if cancel.is_cancelled() {
        return Ok(());
    }
    if worker.model_environment_id.is_some() {
        let model = worker.model_environment_id.clone().unwrap();
        if app.state::<PlatformStore>().environment(&model)?.status
            != crate::models::EnvironmentStatus::Running
        {
            crate::model_runner::start_model(model, app.clone()).await?;
        }
    } else if let Some(model) = existing {
        worker.model_environment_id = Some(model);
    } else {
        let mut resources: crate::model_runner::ModelResources =
            serde_json::from_value(worker.resources.clone())
                .map_err(|e| format!("Invalid worker resources: {e}"))?;
        resources.cpu = Some(resources.cpu.unwrap_or(4.) - 2.);
        resources.memory_gb = Some(resources.memory_gb.unwrap_or(8.) - 4.);
        resources.cpu_only = worker.gpu == "cpu";
        resources.agent_api = true;
        let result = crate::model_runner::run_model_with_resources(
            worker.model.clone(),
            None,
            Some(resources),
            worker.quant.clone(),
            app.clone(),
        )
        .await?;
        worker.model_environment_id = Some(string(&result, "id")?.into());
        worker.owned_model = true;
        if !model_lifecycle::record_created_model(app, &mut worker, cancel).await? {
            return Ok(());
        }
    }
    model_lifecycle::tag_owned_model(app, &worker)?;
    worker.stage = "Downloading and loading your selected model".into();
    write(app, worker.clone()).await?;
    let model_id = worker
        .model_environment_id
        .clone()
        .ok_or("Missing model environment")?;
    if app.state::<PlatformStore>().environment(&model_id)?.status
        != crate::models::EnvironmentStatus::Running
    {
        crate::model_runner::start_model(model_id.clone(), app.clone()).await?;
    }
    if cancel.is_cancelled() {
        model_lifecycle::stop_if_unused(app, &worker).await?;
        return Ok(());
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3600);
    loop {
        if cancel.is_cancelled() {
            return Ok(());
        }
        if let Ok(health) = crate::model_runner::model_status(model_id.clone(), app.clone()).await {
            if health["status"] == "ready" {
                break;
            }
            if health["status"] == "error" {
                return Err(health["error"]
                    .as_str()
                    .unwrap_or("Model could not load")
                    .into());
            }
            if matches!(health["status"].as_str(), Some("idle" | "queued")) {
                model_lifecycle::ensure_ready(app, &worker, cancel).await?;
                break;
            }
            let stage = health["status"].as_str().unwrap_or("starting");
            worker.stage = format!("Model: {stage}");
            write(app, worker.clone()).await?;
        }
        if tokio::time::Instant::now() > deadline {
            return Err(
                "Model setup exceeded one hour. Verified downloaded files are preserved.".into(),
            );
        }
        tokio::select! {_=cancel.cancelled()=>return Ok(()),_=tokio::time::sleep(Duration::from_secs(2))=>{}}
    }
    model_lifecycle::ensure_ready(app, &worker, cancel).await?;
    worker.stage = "Checking your model's agent tool calling".into();
    write(app, worker.clone()).await?;
    let check = tokio::select! {_=cancel.cancelled()=>return Ok(()),result=crate::model_runner::model_request(app,&model_id,"/v1/chat/completions",Some(json!({"model":worker.model,"messages":[{"role":"user","content":"Use the worker_ready function once with ready=true. Do not perform any other task."}],"tools":[{"type":"function","function":{"name":"worker_ready","description":"Confirm the harmless agent tool check.","parameters":{"type":"object","properties":{"ready":{"type":"boolean"}},"required":["ready"],"additionalProperties":false}}}],"tool_choice":{"type":"function","function":{"name":"worker_ready"}},"max_tokens":128,"temperature":0})))=>result?};
    if !guest::tool_check(&check) {
        return Err("The model loaded, but did not complete the agent tool check. Choose a GGUF model that supports tool calling.".into());
    }
    worker.stage = "Preparing OpenCode and its private model connection".into();
    write(app, worker.clone()).await?;
    guest::prepare_agent(app, &mut worker, cancel).await?;
    let result=crate::market::swarm_account_request(reqwest::Method::POST,"/api/swarm/workers",Some(&json!({"name":worker.name,"model":worker.model,"environmentId":worker.environment_id,"capabilities":{"localOnly":true,"gpu":worker.gpu=="nvidia","toolCalling":true},"idempotencyKey":format!("worker-register-{}",worker.id)}))).await?;
    worker.server_id = Some(string(&result["worker"], "id")?.into());
    store_credential(&mut worker, &result)?;
    worker.state = "ready_waiting".into();
    worker.stage = "Worker ready. Waiting for bounty offers.".into();
    write(app, worker.clone()).await?;
    model_lifecycle::release_while_waiting(app, &worker).await
}
