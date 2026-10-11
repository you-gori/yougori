//! RunPod from start to finish: the account, GPUs, templates and Hub repos, pods that
//! Yougori reaches over SSH on its own, serverless endpoints, network volumes and
//! registry logins. Mutations use runpodctl; filtered stock uses RunPod GraphQL.
mod availability;
use super::{accounts, install, Deployment};
use crate::{models::*, runtime::RuntimeManager, store::PlatformStore, AppHandle};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashSet},
    path::PathBuf,
    process::Stdio,
    sync::Mutex,
    time::{Duration, Instant},
};
use tauri::{Emitter, Manager, State};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PROVIDER: &str = "runpod";
const CONSOLE: &str = "https://console.runpod.io";
const TIMED_OUT: &str = "Neocloud did not answer in time";

/// Pods currently watched until their SSH works, so a pod never gets two watchers.
static WATCHING: Mutex<Option<HashSet<String>>> = Mutex::new(None);

/// Only Yougori's own reviewed copy receives the account key, never another `runpodctl`
/// found on PATH or in the current folder.
fn executable() -> Result<PathBuf, String> {
    install::installed_program(PROVIDER)
        .ok_or_else(|| "Neocloud is not set up on this PC yet. Connect your account to set it up.".to_string())
}

fn installed() -> bool {
    install::installed_program(PROVIDER).is_some()
}

struct Output {
    success: bool,
    stdout: String,
    stderr: String,
}

/// Runs runpodctl with the saved key (or its own `~/.runpod/config.toml`). `input` is
/// written to stdin, so registry passwords never enter the arguments. runpodctl has no other
/// input for pod and endpoint environment values (including JUPYTER_PASSWORD): those are
/// arguments, visible to same-user processes and process auditing while the command runs.
async fn cli_output(args: &[String], seconds: u64, input: Option<&str>) -> Result<Output, String> {
    let key = accounts::saved_key(PROVIDER)?;
    let mut command = tokio::process::Command::new(executable()?);
    if let Some(key) = &key {
        command.env("RUNPOD_API_KEY", key);
    }
    command
        .env("NO_COLOR", "1")
        .env("TERM", "dumb")
        .args(args)
        .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(windows)]
    command.creation_flags(0x08000000);
    let mut child = command
        .spawn()
        .map_err(|_| "Neocloud is not set up on this PC yet. Connect your account to set it up.".to_string())?;
    if let (Some(text), Some(mut stdin)) = (input, child.stdin.take()) {
        stdin.write_all(text.as_bytes()).await.map_err(|e| e.to_string())?;
        drop(stdin);
    }
    let mut out = child.stdout.take().ok_or("Neocloud output unavailable")?.take(4 * 1024 * 1024);
    let mut err = child.stderr.take().ok_or("Neocloud output unavailable")?.take(1024 * 1024);
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    let result = tokio::time::timeout(Duration::from_secs(seconds), async {
        tokio::try_join!(out.read_to_end(&mut stdout), err.read_to_end(&mut stderr), child.wait())
    })
    .await;
    let status = match result {
        Ok(Ok((_, _, status))) => status,
        Ok(Err(error)) => return Err(error.to_string()),
        Err(_) => {
            let _ = child.kill().await;
            return Err(format!("{TIMED_OUT}. Check your connection and try again."));
        }
    };
    let redact = |text: Vec<u8>| {
        let text = String::from_utf8_lossy(&text).into_owned();
        match &key {
            Some(key) => text.replace(key.as_str(), "[redacted]"),
            None => text,
        }
    };
    Ok(Output {
        success: status.success(),
        stdout: redact(stdout),
        stderr: redact(stderr),
    })
}

/// runpodctl reports failures as `{"error": "..."}`; that message is shown as it is.
fn failure(output: &Output) -> String {
    for text in [&output.stdout, &output.stderr] {
        if let Ok(value) = serde_json::from_str::<Value>(text.trim()) {
            if let Some(message) = value["error"].as_str().filter(|m| !m.is_empty()) {
                return friendly(message);
            }
        }
    }
    let text = if output.stderr.trim().is_empty() { &output.stdout } else { &output.stderr };
    friendly(text.trim().lines().last().unwrap_or("Neocloud rejected the request"))
}

fn friendly(message: &str) -> String {
    let lower = message.to_ascii_lowercase();
    let message: String = message.chars().take(600).collect();
    if lower.contains("api key") && (lower.contains("invalid") || lower.contains("unauthorized") || lower.contains("not set") || lower.contains("missing"))
        || lower.contains("401")
    {
        "Neocloud did not accept the API key. Connect your account again with a key that has read and write access.".into()
    } else if lower.contains("insufficient") && lower.contains("balance") || lower.contains("not enough") && lower.contains("fund") {
        format!("Your Neocloud balance is too low for this. Add funds at {CONSOLE}/user/billing, then try again.")
    } else if lower.contains("no longer any instances available") || lower.contains("no available") || lower.contains("out of stock") {
        "Neocloud has no free machine with this GPU right now. Choose another GPU or location, or try again in a few minutes.".into()
    } else {
        message
    }
}

fn cli(args: &[&str], seconds: u64) -> impl std::future::Future<Output = Result<Value, String>> {
    let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
    async move { cli_args(&args, seconds).await }
}

async fn cli_args(args: &[String], seconds: u64) -> Result<Value, String> {
    let output = cli_output(args, seconds, None).await?;
    if !output.success {
        return Err(failure(&output));
    }
    let text = output.stdout.trim();
    if text.is_empty() {
        return Ok(Value::Null);
    }
    let value = serde_json::from_str::<Value>(text).unwrap_or_else(|_| Value::String(text.into()));
    if let Some(message) = value.get("error").and_then(Value::as_str).filter(|m| !m.is_empty()) {
        return Err(friendly(message));
    }
    Ok(value)
}

fn emit(app: &AppHandle, state: &PlatformState) {
    let _ = app.emit("yougori-platform-state", state);
}

fn text(value: &Value) -> String {
    value.as_str().unwrap_or_default().to_owned()
}

fn number(value: &Value) -> Option<f64> {
    value.as_f64().filter(|n| n.is_finite())
}

fn array(value: &Value) -> Vec<Value> {
    value.as_array().cloned().unwrap_or_default()
}

fn safe_id(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && !value.starts_with('-')
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || b" -_.:/@".contains(&b))
}

fn valid_name(name: &str) -> Result<(), String> {
    if !(2..=40).contains(&name.len())
        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("Use a name of 2–40 letters, numbers, hyphens or underscores".into());
    }
    Ok(())
}

// ---------------------------------------------------------------- account

fn account(user: &Value) -> Value {
    json!({
        "email": user["email"],
        "balance": number(&user["clientBalance"]),
        "spendPerHour": number(&user["currentSpendPerHr"]),
        "spendLimit": number(&user["spendLimit"]),
    })
}

/// Whether the tools are installed and the account answers, with its balance.
#[tauri::command]
pub async fn runpod_status() -> Result<Value, String> {
    if !installed() {
        return Ok(json!({"installed":false,"connected":false,"message":"Neocloud is not set up on this PC yet."}));
    }
    Ok(match cli(&["user"], 30).await {
        Ok(user) if user.is_object() => json!({"installed":true,"connected":true,"account":account(&user)}),
        Ok(_) => json!({"installed":true,"connected":false,"message":"Neocloud did not return your account. Connect again."}),
        Err(message) => json!({"installed":true,"connected":false,"message":message}),
    })
}

/// Installs runpodctl when needed and, with a key, verifies and saves it.
#[tauri::command]
pub async fn runpod_connect(api_key: Option<String>) -> Result<Value, String> {
    if !installed() {
        install::neocloud_install(PROVIDER.into()).await?;
    }
    if let Some(key) = api_key.filter(|k| !k.trim().is_empty()) {
        accounts::neocloud_authenticate(PROVIDER.into(), key, None).await.map_err(|e| friendly(&e))?;
    }
    runpod_status().await
}

#[tauri::command]
pub async fn runpod_disconnect() -> Result<Value, String> {
    accounts::neocloud_forget_account(PROVIDER.into())?;
    runpod_status().await
}

// ---------------------------------------------------------------- catalogue

/// Stock for the CLI's model pod, including GPU count, public SSH and disk needs.
#[tauri::command]
pub async fn runpod_gpu_offers(container_disk_gb: Option<u32>, gpu_count: Option<u32>) -> Result<Value, String> {
    let disk = container_disk_gb.unwrap_or(40);
    let count = gpu_count.unwrap_or(1);
    if !(1..=8).contains(&count) {
        return Err("Choose 1–8 GPUs per pod".into());
    }
    if !(5..=4000).contains(&disk) {
        return Err("Container disk must be 5–4000 GB".into());
    }
    availability::read(None, json!({"gpuCount":count,"minDisk":disk,"supportPublicIp":true})).await
}

fn gpu(row: &Value) -> Value {
    let locations: Vec<Value> = array(&row["dataCenterAvailability"])
        .iter()
        .map(|dc| json!({"id":dc["dataCenterId"],"stock":stock(&dc["stockStatus"])}))
        .collect();
    let secure = number(&row["securePricePerHr"]).filter(|_| row["secureCloud"] != false);
    let community = number(&row["communityPricePerHr"]).filter(|_| row["communityCloud"] != false);
    json!({
        "id": row["gpuId"],
        "name": row["displayName"].as_str().or(row["gpuId"].as_str()),
        "vramGb": number(&row["memoryInGb"]),
        "securePrice": secure,
        "communityPrice": community,
        "available": row["available"] == true,
        "stock": stock(&row["stockStatus"]),
        "locations": locations,
        "amd": row["gpuId"].as_str().is_some_and(|id| id.starts_with("AMD")),
    })
}

/// RunPod's stock words, as `high`, `medium`, `low` or `none`.
fn stock(value: &Value) -> &'static str {
    match value.as_str().unwrap_or("").to_ascii_lowercase().as_str() {
        "high" => "high",
        "medium" => "medium",
        "low" => "low",
        _ => "none",
    }
}

fn template(row: &Value, own: bool) -> Value {
    let image = text(&row["imageName"]);
    let category = text(&row["category"]);
    json!({
        "id": row["id"],
        "name": row["name"],
        "image": image,
        "kind": match category.as_str() { "CPU" => "cpu", "AMD" => "amd", _ => "gpu" },
        "containerDiskGb": row["containerDiskInGb"].as_u64(),
        "volumeGb": row["volumeInGb"].as_u64(),
        "mountPath": row["volumeMountPath"].as_str().unwrap_or("/workspace"),
        "own": own,
        "official": row["isRunpod"] == true,
    })
}

fn volume(row: &Value) -> Value {
    json!({"id":row["id"],"name":row["name"],"sizeGb":row["size"],"location":row["dataCenterId"]})
}

/// Everything the creation screen needs, loaded in parallel. A failed part is reported
/// in `issues` and the rest is still shown.
#[tauri::command]
pub async fn runpod_catalog() -> Result<Value, String> {
    let (gpus, centers, official, own, volumes, registries, user) = tokio::join!(
        cli(&["gpu", "list", "--include-unavailable"], 40),
        cli(&["datacenter", "list"], 40),
        cli(&["template", "list", "--type", "official"], 40),
        cli(&["template", "list", "--type", "user"], 40),
        cli(&["network-volume", "list"], 40),
        cli(&["registry", "list"], 40),
        cli(&["user"], 40),
    );
    let mut issues = Vec::new();
    let mut take = |label: &str, result: Result<Value, String>| match result {
        Ok(value) => value,
        Err(error) => {
            issues.push(format!("{label}: {error}"));
            Value::Null
        }
    };
    let gpus = take("GPUs", gpus);
    let centers = take("Locations", centers);
    let official = take("Templates", official);
    let own = take("Your templates", own);
    let volumes = take("Network volumes", volumes);
    let registries = take("Registry logins", registries);
    let user = take("Account", user);
    let mut gpus: Vec<Value> = array(&gpus).iter().map(gpu).collect();
    gpus.sort_by(|a, b| {
        let price = |g: &Value| number(&g["securePrice"]).or(number(&g["communityPrice"])).unwrap_or(f64::MAX);
        price(a).total_cmp(&price(b))
    });
    let mut templates: Vec<Value> = array(&official).iter().map(|t| template(t, false)).collect();
    templates.extend(array(&own).iter().map(|t| template(t, true)));
    Ok(json!({
        "checkedAt": chrono::Utc::now().to_rfc3339(),
        "account": if user.is_object() { account(&user) } else { Value::Null },
        "gpus": gpus,
        "locations": array(&centers).iter().map(|dc| json!({"id":dc["id"],"country":dc["location"]})).collect::<Vec<_>>(),
        "templates": templates,
        "volumes": array(&volumes).iter().map(volume).collect::<Vec<_>>(),
        "registries": array(&registries).iter().map(|r| json!({"id":r["id"],"name":r["name"]})).collect::<Vec<_>>(),
        "issues": issues,
    }))
}

fn ports(template: &Value) -> Vec<Value> {
    let names: BTreeMap<String, String> = array(&template["portsConfig"])
        .iter()
        .filter_map(|p| Some((p["port"].as_str()?.to_owned(), p["name"].as_str()?.to_owned())))
        .collect();
    array(&template["ports"])
        .iter()
        .filter_map(|p| {
            let (port, kind) = p.as_str()?.split_once('/')?;
            let number = port.parse::<u16>().ok()?;
            Some(json!({"port":number,"kind":kind,"name":names.get(port).cloned().unwrap_or_else(|| default_port_name(number, kind))}))
        })
        .collect()
}

fn default_port_name(port: u16, kind: &str) -> String {
    match (port, kind) {
        (22, _) => "SSH".into(),
        (8888, _) => "Jupyter".into(),
        (8188, _) => "ComfyUI".into(),
        (7860, _) => "Web UI".into(),
        (3000, _) => "Web app".into(),
        _ => format!("Port {port}"),
    }
}

/// A template's ports and readme.
#[tauri::command]
pub async fn runpod_template(id: String) -> Result<Value, String> {
    if !safe_id(&id, 128) {
        return Err("Invalid template".into());
    }
    let value = cli(&["template", "get", &id], 40).await?;
    let mut summary = template(&value, false);
    summary["ports"] = json!(ports(&value));
    summary["readme"] = json!(value["readme"].as_str().unwrap_or("").chars().take(6000).collect::<String>());
    Ok(summary)
}

/// Official, community and your own templates matching `term`.
#[tauri::command]
pub async fn runpod_search_templates(term: String) -> Result<Value, String> {
    let term = term.trim();
    if term.is_empty() || term.len() > 80 || term.starts_with('-') {
        return Ok(json!([]));
    }
    let found = cli(&["template", "search", term, "--limit", "30"], 40).await?;
    Ok(json!(array(&found).iter().map(|t| template(t, false)).collect::<Vec<_>>()))
}

fn hub_summary(row: &Value) -> Value {
    json!({
        "id": row["id"], "title": row["title"], "description": row["description"],
        "category": row["category"], "owner": row["repoOwner"], "repo": row["repoName"],
        "deploys": row["deploys"], "stars": row["stars"], "tags": row["tags"],
    })
}

/// Serverless repos from the RunPod Hub, most deployed first.
#[tauri::command]
pub async fn runpod_hub(search: Option<String>) -> Result<Value, String> {
    let search = search.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty());
    let found = match &search {
        Some(term) if term.len() <= 80 && !term.starts_with('-') => {
            cli(&["hub", "search", term, "--type", "SERVERLESS", "--limit", "40", "--order-by", "deploys"], 40).await?
        }
        Some(_) => return Ok(json!([])),
        None => cli(&["hub", "list", "--type", "SERVERLESS", "--limit", "60", "--order-by", "deploys"], 40).await?,
    };
    Ok(json!(array(&found).iter().filter(|r| r["type"] == "SERVERLESS").map(hub_summary).collect::<Vec<_>>()))
}

/// One Hub repo with the settings its endpoint asks for.
#[tauri::command]
pub async fn runpod_hub_repo(id: String) -> Result<Value, String> {
    if !safe_id(&id, 64) {
        return Err("Invalid Hub repo".into());
    }
    let value = cli(&["hub", "get", &id], 40).await?;
    let config: Value = value["listedRelease"]["config"]
        .as_str()
        .and_then(|c| serde_json::from_str(c).ok())
        .unwrap_or(Value::Null);
    let inputs: Vec<Value> = array(&config["env"])
        .iter()
        .filter_map(|env| {
            let key = env["key"].as_str()?;
            let input = &env["input"];
            Some(json!({
                "key": key,
                "name": input["name"].as_str().unwrap_or(key),
                "type": input["type"].as_str().unwrap_or("string"),
                "description": input["description"],
                "required": input["required"] == true,
                "advanced": input["advanced"] == true,
                "default": input["default"],
                "options": array(&input["options"]),
                "secret": secret_key(key),
            }))
        })
        .collect();
    let mut summary = hub_summary(&value);
    summary["gpuPools"] = json!(config["gpuIds"].as_str().unwrap_or("").split(',').filter(|s| !s.is_empty()).collect::<Vec<_>>());
    summary["gpuCount"] = json!(config["gpuCount"].as_u64().unwrap_or(1));
    summary["runsOn"] = json!(config["runsOn"].as_str().unwrap_or("GPU"));
    summary["containerDiskGb"] = config["containerDiskInGb"].clone();
    summary["inputs"] = json!(inputs);
    summary["presets"] = json!(array(&config["presets"]));
    summary["ready"] = json!(value["listedRelease"]["build"]["imageName"].is_string());
    Ok(summary)
}

fn secret_key(key: &str) -> bool {
    let key = key.to_ascii_uppercase();
    ["TOKEN", "SECRET", "PASSWORD", "API_KEY", "ACCESS_KEY"].iter().any(|s| key.contains(s))
}

// ---------------------------------------------------------------- SSH key

/// Yougori's own key for RunPod pods, made once and added to the RunPod account, so pods
/// open in Yougori without any SSH setup. Returns the private key path and public key.
async fn ssh_key() -> Result<(PathBuf, String), String> {
    let dir = install::data_dir()?.join("runpod-ssh");
    let private = dir.join("yougori_ed25519");
    let public_path = dir.join("yougori_ed25519.pub");
    if !private.is_file() || !public_path.is_file() {
        std::fs::create_dir_all(&dir).map_err(|e| format!("Prepare the Neocloud SSH key: {e}"))?;
        let _ = std::fs::remove_file(&private);
        let _ = std::fs::remove_file(&public_path);
        let status = crate::runtime::cloud::command("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "yougori-runpod", "-f"])
            .arg(&private)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map_err(|_| "OpenSSH is needed to reach Neocloud pods. Install the Windows OpenSSH client, then try again.".to_string())?;
        if !status.success() {
            return Err("Could not create an SSH key for Neocloud".into());
        }
    }
    let public = std::fs::read_to_string(&public_path).map_err(|e| format!("Read the Neocloud SSH key: {e}"))?;
    let public = crate::runtime::cloud::public_identity(public.trim())?
        .ok_or("The Neocloud SSH key is damaged; delete it to make a new one")?;
    Ok((private, public))
}

fn key_body(key: &str) -> &str {
    key.split_whitespace().nth(1).unwrap_or("")
}

/// Adds Yougori's key to the account when it is missing and returns every account key.
async fn account_keys(public: &str) -> Result<Vec<String>, String> {
    let listed = cli(&["ssh", "list-keys"], 40).await?;
    let mut keys: Vec<String> = array(&listed["keys"])
        .iter()
        .filter_map(|k| k["key"].as_str().map(|k| k.trim().to_owned()))
        .collect();
    if !keys.iter().any(|k| key_body(k) == key_body(public)) {
        cli_args(&["ssh".into(), "add-key".into(), "--key".into(), format!("{public} yougori")], 40).await?;
        keys.push(public.to_owned());
    }
    Ok(keys)
}

// ---------------------------------------------------------------- pods

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PodRequest {
    pub name: String,
    /// `gpu` or `cpu`.
    pub compute: String,
    #[serde(default)]
    pub gpu_id: String,
    #[serde(default = "one")]
    pub gpu_count: u32,
    /// `secure` or `community`.
    #[serde(default = "secure")]
    pub cloud: String,
    /// A data centre ID, or empty for anywhere.
    #[serde(default)]
    pub location: String,
    #[serde(default)]
    pub template_id: String,
    #[serde(default)]
    pub image: String,
    pub container_disk_gb: u32,
    #[serde(default)]
    pub volume_gb: u32,
    #[serde(default)]
    pub volume_mount_path: String,
    #[serde(default)]
    pub network_volume_id: String,
    #[serde(default)]
    pub registry_auth_id: String,
    #[serde(default)]
    pub http_ports: Vec<u16>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub max_hourly_usd: Option<f64>,
    #[serde(default)]
    pub public_ip: bool,
    #[serde(default)]
    pub global_networking: bool,
    #[serde(default)]
    pub compliance: Vec<String>,
    #[serde(default)]
    pub min_cuda: String,
}

fn one() -> u32 {
    1
}

fn secure() -> String {
    "secure".into()
}

fn valid_env(env: &BTreeMap<String, String>) -> Result<(), String> {
    if env.len() > 64 {
        return Err("Use at most 64 environment variables".into());
    }
    for (key, value) in env {
        let mut chars = key.chars();
        let first = chars.next().unwrap_or('0');
        if key.len() > 128
            || !(first.is_ascii_alphabetic() || first == '_')
            || !chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(format!("{key} is not a valid environment variable name"));
        }
        if value.len() > 32 * 1024 || value.contains('\0') {
            return Err(format!("{key} is too long"));
        }
    }
    Ok(())
}

fn validate_pod(r: &PodRequest) -> Result<(), String> {
    valid_name(&r.name)?;
    match r.compute.as_str() {
        "gpu" => {
            if r.gpu_id.is_empty() || r.gpu_id.len() > 128 || r.gpu_id.starts_with('-')
                || !r.gpu_id.bytes().all(|b| b.is_ascii_alphanumeric() || b" -_.".contains(&b))
            {
                return Err("Choose a GPU".into());
            }
            if !(1..=8).contains(&r.gpu_count) {
                return Err("Choose 1 to 8 GPUs".into());
            }
            if !matches!(r.cloud.as_str(), "secure" | "community") {
                return Err("Choose Secure or Community Cloud".into());
            }
            if !r.max_hourly_usd.is_some_and(|p| p.is_finite() && p > 0.0 && p < 10_000.0) {
                return Err("Review the hourly price before creating the pod".into());
            }
        }
        "cpu" => {
            if !r.gpu_id.is_empty() {
                return Err("A CPU pod has no GPU".into());
            }
        }
        _ => return Err("Choose a GPU or CPU pod".into()),
    }
    if r.template_id.is_empty() == r.image.is_empty() {
        return Err("Choose a template or an image".into());
    }
    if !r.template_id.is_empty() && !safe_id(&r.template_id, 128) {
        return Err("Choose a valid template".into());
    }
    if !r.image.is_empty() && !safe_id(&r.image, 512) || r.image.contains(' ') {
        return Err("Enter a valid container image, for example runpod/pytorch:latest".into());
    }
    if !r.location.is_empty() && !safe_id(&r.location, 64) {
        return Err("Choose a valid location".into());
    }
    if !(5..=4000).contains(&r.container_disk_gb) || r.volume_gb > 4000 {
        return Err("Container disk must be 5–4000 GB and the volume at most 4000 GB".into());
    }
    if !r.volume_mount_path.is_empty()
        && (!r.volume_mount_path.starts_with('/') || !safe_id(&r.volume_mount_path, 200) || r.volume_mount_path.contains(".."))
    {
        return Err("The volume folder must be an absolute path such as /workspace".into());
    }
    for id in [&r.network_volume_id, &r.registry_auth_id] {
        if !id.is_empty() && !safe_id(id, 128) {
            return Err("Invalid network volume or registry login".into());
        }
    }
    if r.http_ports.len() > 10 || r.http_ports.iter().any(|p| *p == 0 || *p == 22) {
        return Err("Add at most 10 web ports, other than 22".into());
    }
    if r.compliance.iter().any(|c| !matches!(c.as_str(), "SOC_2_TYPE_2" | "HIPAA" | "ISO_27001" | "GDPR")) {
        return Err("Unknown compliance requirement".into());
    }
    if !r.min_cuda.is_empty() && !r.min_cuda.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return Err("Enter a CUDA version such as 12.4".into());
    }
    valid_env(&r.env)
}

/// RunPod-side pod name: the chosen name plus this node's ID, so reconciling a create never
/// adopts an unrelated pod that happens to share the name.
fn provider_pod_name(name: &str, environment_id: &str) -> String {
    let suffix: String = environment_id
        .trim_start_matches("env-")
        .chars()
        .filter(char::is_ascii_hexdigit)
        .take(8)
        .collect();
    format!("{name}-yg{suffix}")
}

fn pod_args(r: &PodRequest, name: &str, ports: &[String], env: &BTreeMap<String, String>) -> Vec<String> {
    let mut args: Vec<String> = vec!["pod".into(), "create".into(), "--name".into(), name.into()];
    if r.template_id.is_empty() {
        args.extend(["--image".into(), r.image.clone()]);
    } else {
        args.extend(["--template-id".into(), r.template_id.clone()]);
    }
    if r.compute == "cpu" {
        args.extend(["--compute-type".into(), "CPU".into()]);
    } else {
        args.extend([
            "--compute-type".into(), "GPU".into(),
            "--gpu-id".into(), r.gpu_id.clone(),
            "--gpu-count".into(), r.gpu_count.to_string(),
            "--cloud-type".into(), r.cloud.to_ascii_uppercase(),
        ]);
        if r.cloud == "community" && r.public_ip {
            args.push("--public-ip".into());
        }
        if r.cloud == "secure" && r.global_networking {
            args.push("--global-networking".into());
        }
        if !r.min_cuda.is_empty() {
            args.extend(["--min-cuda-version".into(), r.min_cuda.clone()]);
        }
    }
    if !r.location.is_empty() {
        args.extend(["--data-center-ids".into(), r.location.clone()]);
    }
    args.extend(["--container-disk-in-gb".into(), r.container_disk_gb.to_string()]);
    if r.network_volume_id.is_empty() && r.volume_gb > 0 {
        args.extend(["--volume-in-gb".into(), r.volume_gb.to_string()]);
    }
    if r.network_volume_id.is_empty() && r.volume_gb > 0 || !r.network_volume_id.is_empty() {
        let path = if r.volume_mount_path.is_empty() { "/workspace" } else { &r.volume_mount_path };
        args.extend(["--volume-mount-path".into(), path.into()]);
    }
    if !r.network_volume_id.is_empty() {
        args.extend(["--network-volume-id".into(), r.network_volume_id.clone()]);
    }
    if !r.registry_auth_id.is_empty() {
        args.extend(["--registry-auth-id".into(), r.registry_auth_id.clone()]);
    }
    if !r.compliance.is_empty() {
        args.extend(["--compliance".into(), r.compliance.join(",")]);
    }
    if !ports.is_empty() {
        args.extend(["--ports".into(), ports.join(",")]);
    }
    if !env.is_empty() {
        args.extend(["--env".into(), serde_json::to_string(env).unwrap_or_default()]);
    }
    args
}

fn empty_range() -> ResourceRange {
    ResourceRange { min: 0.0, preferred: 0.0, max: 0.0, current: 0.0 }
}

fn node(id: &str, name: &str, runtime: &str, gpu: bool, description: &str) -> Environment {
    Environment {
        id: id.into(),
        name: name.into(),
        kind: EnvironmentKind::Cloud,
        status: EnvironmentStatus::Provisioning,
        runtime: runtime.into(),
        provider: Some(RuntimeProviderKind::CloudSsh),
        runtime_id: None,
        runtime_path: None,
        control_endpoint: None,
        console_endpoint: None,
        container_command: None,
        network_access: false,
        gpu_access: gpu,
        sandbox_policy: None,
        last_error: None,
        description: description.into(),
        branch_type: None,
        created_at: chrono::Utc::now().to_rfc3339(),
        last_opened_at: None,
        cpu_usage: 0.0,
        memory_usage_gb: 0.0,
        storage_delta_gb: 0.0,
        storage_limit_gb: None,
        storage_drive: None,
        network_rx_mbps: 0.0,
        resource_policy: ResourcePolicy {
            cpu: empty_range(),
            memory_gb: empty_range(),
            priority: Priority::Normal,
            dynamic: true,
        },
    }
}

fn deployment(product: &str, name: &str, image: &str, offer: &str, location: &str, extra: Value) -> Deployment {
    Deployment {
        provider: PROVIDER.into(),
        product: product.into(),
        name: name.into(),
        resource_id: String::new(),
        state: "Creating".into(),
        image: image.into(),
        offer: offer.into(),
        disk_gb: 0,
        location: location.into(),
        address: String::new(),
        ssh_hint: String::new(),
        request_id: uuid::Uuid::new_v4().to_string(),
        last_error: None,
        extra,
    }
}

fn insert(store: &PlatformStore, environment: Environment, deployment: Deployment) -> Result<PlatformState, String> {
    store.mutate(|state| {
        if state.environments.iter().any(|e| e.name.eq_ignore_ascii_case(&environment.name)) {
            return Err("An environment with this name already exists. Choose another name.".into());
        }
        state.neocloud_deployments.insert(environment.id.clone(), deployment);
        state.environments.push(environment);
        Ok(())
    })
}

fn update(
    store: &PlatformStore,
    id: &str,
    change: impl FnOnce(&mut Environment, &mut Deployment),
) -> Result<PlatformState, String> {
    store.mutate(|state| {
        let deployment = state.neocloud_deployments.get_mut(id).ok_or("Neocloud resource not found")?;
        let environment = state.environments.iter_mut().find(|e| e.id == id).ok_or("Environment not found")?;
        change(environment, deployment);
        Ok(())
    })
}

/// Removes a node whose RunPod request was refused, so nothing exists behind it.
fn forget(store: &PlatformStore, id: &str) -> Result<PlatformState, String> {
    store.mutate(|state| {
        state.neocloud_deployments.remove(id);
        state.environments.retain(|e| e.id != id);
        Ok(())
    })
}

fn jupyter_entry(environment_id: &str) -> Result<keyring::Entry, String> {
    keyring::Entry::new("Yougori.Neocloud.v1", &format!("runpod-jupyter:{environment_id}"))
        .map_err(|_| "System credential store is unavailable".into())
}

/// Creates a GPU or CPU pod. Yougori's SSH key goes with it, and a watcher connects the
/// node as soon as the pod answers, so the pod opens like any other environment.
#[tauri::command]
pub async fn runpod_create_pod(
    request: PodRequest,
    app: AppHandle,
    store: State<'_, PlatformStore>,
) -> Result<PlatformState, String> {
    validate_pod(&request)?;
    if store.snapshot()?.environments.iter().any(|e| e.name.eq_ignore_ascii_case(&request.name)) {
        return Err("An environment with this name already exists. Choose another name.".into());
    }
    let hourly = if request.compute == "gpu" {
        Some(availability::quote(&request).await?)
    } else {
        None
    };
    // Template ports are kept when web ports are added; an image gets SSH plus its web ports.
    // An unreadable template could hide a public Jupyter port, so creation stops instead.
    let mut ports: Vec<Value> = if request.template_id.is_empty() {
        vec![json!({"port":22,"kind":"tcp","name":"SSH"})]
    } else {
        runpod_template(request.template_id.clone())
            .await
            .map(|t| array(&t["ports"]))
            .map_err(|error| format!("Cannot read this template's ports ({error}). No pod was created; try again."))?
    };
    for port in &request.http_ports {
        if !ports.iter().any(|p| p["port"] == *port) {
            ports.push(json!({"port":port,"kind":"http","name":default_port_name(*port, "http")}));
        }
    }
    if !ports.iter().any(|p| p["port"] == 22) {
        ports.push(json!({"port":22,"kind":"tcp","name":"SSH"}));
    }
    let explicit_ports = if request.template_id.is_empty() || !request.http_ports.is_empty() {
        ports.iter().map(|p| format!("{}/{}", p["port"], text(&p["kind"]))).collect()
    } else {
        Vec::new()
    };
    let mut env = request.env.clone();
    let id = format!("env-{}", uuid::Uuid::new_v4());
    let provider_name = provider_pod_name(&request.name, &id);
    // Jupyter gets a private token instead of running open to anyone with the link. Without a
    // place to keep that token, no pod is created rather than one with an open notebook.
    let jupyter = ports.iter().any(|p| p["port"] == 8888);
    if jupyter && !env.contains_key("JUPYTER_PASSWORD") {
        let token = uuid::Uuid::new_v4().simple().to_string();
        jupyter_entry(&id)?
            .set_password(&token)
            .map_err(|_| "Cannot save this pod's Jupyter password in the system credential store. No pod was created.".to_string())?;
        env.insert("JUPYTER_PASSWORD".into(), token);
    }
    let mut ssh_note = None;
    match ssh_key().await {
        Ok((_, public)) => match account_keys(&public).await {
            // CPU pods are created without RunPod-managed SSH, so the keys travel with the pod.
            Ok(keys) if request.compute == "cpu" && !env.contains_key("PUBLIC_KEY") => {
                env.insert("PUBLIC_KEY".into(), keys.join("\n"));
            }
            Ok(_) => {}
            Err(error) => ssh_note = Some(format!("Yougori's SSH key could not be added to Neocloud ({error}); terminals may need manual setup.")),
        },
        Err(error) => ssh_note = Some(error),
    }
    let args = pod_args(&request, &provider_name, &explicit_ports, &env);
    // Template and key lookups take time; the reviewed price must still hold when the pod is created.
    let hourly = if request.compute == "gpu" {
        match availability::quote(&request).await {
            Ok(price) => Some(price),
            Err(error) => {
                let _ = jupyter_entry(&id).map(|e| e.delete_credential());
                return Err(error);
            }
        }
    } else {
        hourly
    };
    let (label, description) = if request.compute == "gpu" {
        (format!("{} × {}", request.gpu_count, request.gpu_id), "Neocloud GPU pod · opens in Yougori over SSH")
    } else {
        ("CPU".to_owned(), "Neocloud CPU pod · opens in Yougori over SSH")
    };
    let extra = json!({
        "kind": "pod",
        "compute": request.compute,
        "gpuId": request.gpu_id,
        "gpuCount": request.gpu_count,
        "cloud": request.cloud,
        "hourlyUsd": hourly,
        "template": request.template_id,
        "containerDiskGb": request.container_disk_gb,
        "volumeGb": request.volume_gb,
        "mountPath": if request.volume_mount_path.is_empty() { "/workspace" } else { &request.volume_mount_path },
        "networkVolumeId": request.network_volume_id,
        "ports": ports,
        "jupyter": jupyter && env.contains_key("JUPYTER_PASSWORD") && !request.env.contains_key("JUPYTER_PASSWORD"),
        "sshReady": false,
        "sshNote": ssh_note,
        "providerName": provider_name,
    });
    let image = if request.image.is_empty() { &request.template_id } else { &request.image };
    let mut environment = node(&id, &request.name, &format!("Neocloud · {label}"), request.compute == "gpu", description);
    environment.status = EnvironmentStatus::Provisioning;
    let mut record = deployment("pod", &request.name, image, &request.gpu_id, &request.location, extra);
    record.disk_gb = request.volume_gb;
    let state = insert(&store, environment, record)?;
    emit(&app, &state);
    let result = cli_args(&args, 240).await;
    let state = update(&store, &id, |environment, deployment| match &result {
        Ok(value) => match value["id"].as_str().or(value["pod"]["id"].as_str()) {
            Some(pod) => {
                deployment.resource_id = pod.into();
                deployment.state = "Starting".into();
                environment.status = EnvironmentStatus::Stopped;
            }
            None => {
                deployment.state = "Needs inspection".into();
                deployment.last_error = Some("Neocloud accepted the pod but did not return its ID. Check your Neocloud pods before trying again; it may be billing.".into());
                environment.status = EnvironmentStatus::Error;
                environment.last_error = deployment.last_error.clone();
            }
        },
        Err(error) => {
            deployment.state = "Needs inspection".into();
            deployment.last_error = Some(format!("{error} Check your Neocloud pods before trying again; one may have been created."));
            environment.status = EnvironmentStatus::Error;
            environment.last_error = deployment.last_error.clone();
        }
    })?;
    if let Err(error) = result {
        // An error does not prove nothing was created: a failed or garbled response can still
        // leave a billing pod. Only a confirmed absence removes the node; an unanswered or
        // unverifiable request is kept for checking.
        if !error.starts_with(TIMED_OUT) {
            match created_pod(&provider_name).await {
                Ok(None) => {
                    let _ = jupyter_entry(&id).map(|e| e.delete_credential());
                    emit(&app, &forget(&store, &id)?);
                }
                Ok(Some(pod)) => {
                    let state = update(&store, &id, |environment, deployment| {
                        deployment.resource_id = pod.clone();
                        deployment.state = "Starting".into();
                        deployment.last_error = None;
                        environment.status = EnvironmentStatus::Stopped;
                        environment.last_error = None;
                    })?;
                    emit(&app, &state);
                    watch(app, id);
                    return Ok(state);
                }
                Err(_) => emit(&app, &state),
            }
        } else {
            emit(&app, &state);
        }
        return Err(error);
    }
    emit(&app, &state);
    watch(app, id);
    Ok(state)
}

/// The live pod created under this node's unique RunPod name, if any.
async fn created_pod(provider_name: &str) -> Result<Option<String>, String> {
    Ok(array(&cli(&["pod", "list", "--all", "--name", provider_name], 40).await?)
        .into_iter()
        .find(|p| p["name"] == provider_name && p["desiredStatus"] != "TERMINATED")
        .and_then(|p| p["id"].as_str().map(str::to_owned)))
}

/// Follows a pod until SSH answers (or it stops), then saves the connection so the
/// node opens directly. Addresses change when a pod restarts, so this runs on every start.
pub(crate) fn watch(app: AppHandle, id: String) {
    {
        let mut watching = WATCHING.lock().unwrap();
        if !watching.get_or_insert_with(HashSet::new).insert(id.clone()) {
            return;
        }
    }
    tauri::async_runtime::spawn(async move {
        let result = follow(&app, &id).await;
        if let Err(error) = result {
            let store = app.state::<PlatformStore>();
            if let Ok(state) = update(&store, &id, |_, d| {
                d.extra["sshNote"] = json!(error);
            }) {
                emit(&app, &state);
            }
        }
        WATCHING.lock().unwrap().get_or_insert_with(HashSet::new).remove(&id);
    });
}

/// After a restart, keeps following pods that were still starting.
pub(crate) fn resume(app: &AppHandle) {
    let Ok(state) = app.state::<PlatformStore>().snapshot() else { return };
    for (id, d) in &state.neocloud_deployments {
        if d.provider == PROVIDER && d.product == "pod" && !d.resource_id.is_empty()
            && matches!(d.state.as_str(), "Starting" | "Running") && d.extra["sshReady"] != true
        {
            watch(app.clone(), id.clone());
        }
    }
}

async fn follow(app: &AppHandle, id: &str) -> Result<(), String> {
    let started = Instant::now();
    let mut attempts_after_ready = 0;
    loop {
        if started.elapsed() > Duration::from_secs(45 * 60) {
            return Err("The pod did not become reachable within 45 minutes. Check its logs.".into());
        }
        let store = app.state::<PlatformStore>();
        let Some(deployment) = store.snapshot()?.neocloud_deployments.get(id).cloned() else {
            return Ok(());
        };
        if deployment.resource_id.is_empty() || deployment.state == "Deleted" || deployment.product != "pod" {
            return Ok(());
        }
        let value = match cli(&["pod", "get", &deployment.resource_id], 40).await {
            Ok(value) => value,
            Err(error) => {
                if let Ok(state) = update(&store, id, |_, d| {
                    d.extra["sshNote"] = json!(format!("Cannot refresh RunPod status: {error}. Retrying."));
                }) { emit(app, &state); }
                tokio::time::sleep(Duration::from_secs(10)).await;
                continue;
            }
        };
        let status = pod_status(&value);
        let ip = text(&value["ssh"]["ip"]);
        let port = value["ssh"]["port"].as_u64().and_then(|p| u16::try_from(p).ok());
        let state = update(&store, id, |_, d| describe_pod(d, &value))?;
        emit(app, &state);
        match status.as_str() {
            "stopped" | "terminated" | "exited" => return Ok(()),
            "running" if !ip.is_empty() && port.is_some() => {
                match connect_ssh(app, id, &ip, port.unwrap_or(22)).await {
                    Ok(()) => return Ok(()),
                    Err(error) if error.contains("Python 3") => return Err(error),
                    // sshd usually starts a little after the container reports running.
                    Err(error) if attempts_after_ready >= 30 => return Err(error),
                    Err(error) => {
                        attempts_after_ready += 1;
                        let state = update(&store, id, |_, d| {
                            d.extra["sshNote"] = json!(format!("Pod created; SSH is not ready: {error} Retrying."));
                        })?;
                        emit(app, &state);
                    }
                }
            }
            _ => {}
        }
        tokio::time::sleep(Duration::from_secs(if started.elapsed() < Duration::from_secs(180) { 6 } else { 12 })).await;
    }
}

fn pod_status(value: &Value) -> String {
    value["runtimeStatus"]
        .as_str()
        .filter(|s| !s.is_empty() && *s != "unknown")
        .or(value["desiredStatus"].as_str())
        .unwrap_or("unknown")
        .to_ascii_lowercase()
}

fn describe_pod(d: &mut Deployment, value: &Value) {
    let status = pod_status(value);
    d.state = match status.as_str() {
        "running" => "Running",
        "initializing" | "created" => "Starting",
        "stopped" | "exited" => "Stopped",
        "terminated" => "Deleted",
        _ => "Starting",
    }
    .into();
    if let Some(cost) = number(&value["costPerHr"]).filter(|c| *c > 0.0) {
        d.extra["hourlyUsd"] = json!(cost);
    }
    d.extra["statusReason"] = value["runtimeStatusReason"].clone();
    let ip = text(&value["ssh"]["ip"]);
    if status == "running" && !ip.is_empty() {
        d.address = ip;
        d.ssh_hint = text(&value["ssh"]["ssh_command"]);
    } else if status != "running" {
        d.extra["sshReady"] = json!(false);
    }
    if let Some(machine) = value["machine"].as_object() {
        if let Some(location) = machine.get("dataCenterId").and_then(Value::as_str) {
            d.location = location.into();
        }
    }
    d.last_error = None;
}

/// Trusts the host key the pod presents at the address RunPod reported for it, checks
/// the login, and saves the connection for the node.
async fn connect_ssh(app: &AppHandle, id: &str, host: &str, port: u16) -> Result<(), String> {
    let (private, _) = ssh_key().await?;
    let store = app.state::<PlatformStore>();
    let runtime = app.state::<RuntimeManager>();
    let name = store
        .snapshot()?
        .environments
        .iter()
        .find(|e| e.id == id)
        .map(|e| e.name.clone())
        .ok_or("Environment not found")?;
    if let Ok(saved) = runtime.cloud.profile(id) {
        if saved.host == host && saved.port == port && runtime.cloud.connected(id).await {
            return mark_ready(app, id, host, port);
        }
    }
    let profile = crate::runtime::cloud::Profile {
        name,
        vendor: "other".into(),
        host: host.into(),
        port,
        username: "root".into(),
        identity_file: private.to_string_lossy().into_owned(),
        host_key: String::new(),
    };
    let checked = crate::runtime::cloud::test_connection(profile).await?;
    runtime.cloud.disconnect(id).await;
    runtime.cloud.save(id, &checked)?;
    mark_ready(app, id, host, port)
}

fn mark_ready(app: &AppHandle, id: &str, host: &str, port: u16) -> Result<(), String> {
    let store = app.state::<PlatformStore>();
    let state = update(&store, id, |environment, d| {
        environment.runtime = format!("Neocloud · root@{host}:{port}");
        environment.last_error = None;
        if environment.status == EnvironmentStatus::Error || environment.status == EnvironmentStatus::Provisioning {
            environment.status = EnvironmentStatus::Stopped;
        }
        d.extra["sshReady"] = json!(true);
        d.extra["sshNote"] = Value::Null;
        d.extra["statusReason"] = Value::Null;
        d.state = "Running".into();
    })?;
    emit(app, &state);
    Ok(())
}

/// Web links for a pod's HTTP ports, with its private Jupyter token.
#[tauri::command]
pub async fn runpod_links(environment_id: String, store: State<'_, PlatformStore>) -> Result<Value, String> {
    let deployment = store
        .snapshot()?
        .neocloud_deployments
        .get(&environment_id)
        .cloned()
        .ok_or("Neocloud resource not found")?;
    let pod = &deployment.resource_id;
    let token = jupyter_entry(&environment_id).ok().and_then(|e| e.get_password().ok());
    let links: Vec<Value> = array(&deployment.extra["ports"])
        .iter()
        .filter(|p| p["kind"] == "http" && !pod.is_empty())
        .map(|p| {
            let port = p["port"].as_u64().unwrap_or(0);
            let mut url = format!("https://{pod}-{port}.proxy.runpod.net/");
            if port == 8888 {
                if let Some(token) = &token {
                    url.push_str(&format!("lab?token={token}"));
                }
            }
            json!({"name":p["name"],"port":port,"url":url})
        })
        .collect();
    Ok(json!({"links":links,"console":format!("{CONSOLE}/pods?id={pod}")}))
}

/// The pod's recent container and platform log lines.
#[tauri::command]
pub async fn runpod_logs(environment_id: String, store: State<'_, PlatformStore>) -> Result<Value, String> {
    let deployment = store
        .snapshot()?
        .neocloud_deployments
        .get(&environment_id)
        .cloned()
        .ok_or("Neocloud resource not found")?;
    if deployment.resource_id.is_empty() {
        return Ok(json!([]));
    }
    let args: Vec<String> = if deployment.product == "serverless" {
        vec!["serverless".into(), "logs".into(), deployment.resource_id.clone()]
    } else {
        vec!["pod".into(), "logs".into(), deployment.resource_id.clone(), "--tail".into(), "200".into()]
    };
    let output = cli_output(&args, 30, None).await?;
    if !output.success {
        return Err(failure(&output));
    }
    Ok(json!(output
        .stdout
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .map(|l| json!({"source":l["source"],"line":l["line"].as_str().or(l["message"].as_str()).unwrap_or(""),"time":l["ts"].as_str().or(l["timestamp"].as_str())}))
        .collect::<Vec<_>>()))
}

// ---------------------------------------------------------------- serverless

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointRequest {
    pub name: String,
    pub hub_id: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub gpu_id: String,
    #[serde(default)]
    pub gpu_count: u32,
    #[serde(default)]
    pub workers_min: u32,
    #[serde(default = "one")]
    pub workers_max: u32,
    #[serde(default = "idle")]
    pub idle_timeout: u32,
    #[serde(default)]
    pub network_volume_id: String,
    #[serde(default)]
    pub location: String,
}

fn idle() -> u32 {
    5
}

fn validate_endpoint(r: &EndpointRequest) -> Result<(), String> {
    valid_name(&r.name)?;
    if r.name.len() < 3 {
        return Err("Endpoint names need at least 3 characters".into());
    }
    if !safe_id(&r.hub_id, 64) {
        return Err("Choose a Hub repo".into());
    }
    if !r.gpu_id.is_empty() && (!r.gpu_id.bytes().all(|b| b.is_ascii_alphanumeric() || b" -_.".contains(&b)) || r.gpu_id.len() > 128) {
        return Err("Choose a valid GPU".into());
    }
    if r.gpu_count > 8 || r.workers_max == 0 || r.workers_max > 100 || r.workers_min > r.workers_max {
        return Err("Use 1–100 workers, with the always-on count no higher than the maximum".into());
    }
    if !(1..=3600).contains(&r.idle_timeout) {
        return Err("Idle time must be 1–3600 seconds".into());
    }
    for id in [&r.network_volume_id, &r.location] {
        if !id.is_empty() && !safe_id(id, 128) {
            return Err("Invalid network volume or location".into());
        }
    }
    if r.title.len() > 200 || r.category.len() > 40 {
        return Err("Invalid Hub repo details".into());
    }
    valid_env(&r.env)
}

fn endpoint_args(r: &EndpointRequest) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "serverless".into(), "create".into(),
        "--hub-id".into(), r.hub_id.clone(),
        "--name".into(), r.name.clone(),
        "--workers-min".into(), r.workers_min.to_string(),
        "--workers-max".into(), r.workers_max.to_string(),
        "--idle-timeout".into(), r.idle_timeout.to_string(),
    ];
    if !r.gpu_id.is_empty() {
        args.extend(["--gpu-id".into(), r.gpu_id.clone()]);
    }
    if r.gpu_count > 0 {
        args.extend(["--gpu-count".into(), r.gpu_count.to_string()]);
    }
    if !r.network_volume_id.is_empty() {
        args.extend(["--network-volume-id".into(), r.network_volume_id.clone()]);
    }
    if !r.location.is_empty() {
        args.extend(["--data-center-ids".into(), r.location.clone()]);
    }
    for (key, value) in &r.env {
        args.extend(["--env".into(), format!("{key}={value}")]);
    }
    args
}

fn invoke_urls(id: &str, category: &str) -> Value {
    let base = format!("https://api.runpod.ai/v2/{id}");
    json!({
        "run": format!("{base}/run"),
        "runsync": format!("{base}/runsync"),
        "health": format!("{base}/health"),
        "openai": (category == "language").then(|| format!("{base}/openai/v1")),
    })
}

/// Deploys a Hub repo as a serverless endpoint. With no always-on workers it costs
/// nothing while idle.
#[tauri::command]
pub async fn runpod_create_endpoint(
    request: EndpointRequest,
    app: AppHandle,
    store: State<'_, PlatformStore>,
) -> Result<PlatformState, String> {
    validate_endpoint(&request)?;
    if store.snapshot()?.environments.iter().any(|e| e.name.eq_ignore_ascii_case(&request.name)) {
        return Err("An environment with this name already exists. Choose another name.".into());
    }
    let id = format!("env-{}", uuid::Uuid::new_v4());
    let title = if request.title.is_empty() { "Hub repo" } else { &request.title };
    let extra = json!({
        "kind": "endpoint",
        "title": title,
        "category": request.category,
        "workersMin": request.workers_min,
        "workersMax": request.workers_max,
        "idleTimeout": request.idle_timeout,
        "gpuId": request.gpu_id,
        "networkVolumeId": request.network_volume_id,
    });
    let environment = node(&id, &request.name, &format!("Neocloud · serverless · {title}"), true, "Neocloud serverless endpoint · scales to zero when idle");
    let state = insert(&store, environment, deployment("serverless", &request.name, &request.hub_id, &request.gpu_id, &request.location, extra))?;
    emit(&app, &state);
    let result = cli_args(&endpoint_args(&request), 180).await;
    let state = update(&store, &id, |environment, d| match &result {
        Ok(value) => match value["id"].as_str().or(value["endpoint"]["id"].as_str()) {
            Some(endpoint) => {
                d.resource_id = endpoint.into();
                d.state = "Ready".into();
                d.extra["urls"] = invoke_urls(endpoint, &request.category);
                d.address = format!("https://api.runpod.ai/v2/{endpoint}/run");
                environment.status = EnvironmentStatus::Stopped;
            }
            None => {
                d.state = "Needs inspection".into();
                d.last_error = Some("Neocloud accepted the endpoint but did not return its ID. Check your serverless endpoints before trying again.".into());
                environment.status = EnvironmentStatus::Error;
                environment.last_error = d.last_error.clone();
            }
        },
        Err(error) => {
            d.state = "Needs inspection".into();
            d.last_error = Some(format!("{error} Check your serverless endpoints before trying again; one may have been created."));
            environment.status = EnvironmentStatus::Error;
            environment.last_error = d.last_error.clone();
        }
    })?;
    if let Err(error) = result {
        if !error.starts_with(TIMED_OUT) {
            emit(&app, &forget(&store, &id)?);
        } else {
            emit(&app, &state);
        }
        return Err(error);
    }
    emit(&app, &state);
    Ok(state)
}

/// Serverless controls: `stop` pauses by allowing no workers (the URL is kept),
/// `start` restores the worker limit, `delete` removes the endpoint.
pub(super) async fn endpoint_action(
    environment_id: &str,
    action: &str,
    store: &PlatformStore,
) -> Result<PlatformState, String> {
    let deployment = store
        .snapshot()?
        .neocloud_deployments
        .get(environment_id)
        .cloned()
        .ok_or("Neocloud resource not found")?;
    let endpoint = deployment.resource_id.clone();
    if endpoint.is_empty() {
        return Err("This endpoint has no Neocloud ID. Remove the node and create it again.".into());
    }
    let workers_max = deployment.extra["workersMax"].as_u64().filter(|n| *n > 0).unwrap_or(1);
    let workers_min = deployment.extra["workersMin"].as_u64().unwrap_or(0);
    let result = match action {
        "inspect" => {
            let (details, health) = tokio::join!(cli(&["serverless", "get", &endpoint], 40), cli(&["serverless", "health", &endpoint], 40));
            details.map(|details| json!({"details":details,"health":health.unwrap_or(Value::Null)}))
        }
        "stop" => cli(&["serverless", "update", &endpoint, "--workers-min", "0", "--workers-max", "0"], 60).await,
        "start" => {
            cli_args(&[
                "serverless".into(), "update".into(), endpoint.clone(),
                "--workers-min".into(), workers_min.to_string(),
                "--workers-max".into(), workers_max.to_string(),
            ], 60).await
        }
        "delete" => match cli(&["serverless", "delete", &endpoint], 60).await {
            Ok(value) => Ok(value),
            Err(error) if error.to_ascii_lowercase().contains("not found") => Ok(Value::Null),
            Err(error) => Err(error),
        },
        _ => return Err("Unsupported endpoint action".into()),
    };
    let failed = result.as_ref().err().cloned();
    let state = store.mutate(|state| {
        let d = state.neocloud_deployments.get_mut(environment_id).ok_or("Neocloud resource not found")?;
        match (&result, action) {
            (Ok(value), "inspect") => {
                let details = &value["details"];
                let max = details["workersMax"].as_u64().unwrap_or(workers_max);
                d.state = if max == 0 { "Paused" } else { "Ready" }.into();
                if max > 0 {
                    d.extra["workersMax"] = json!(max);
                    d.extra["workersMin"] = json!(details["workersMin"].as_u64().unwrap_or(workers_min));
                }
                if let Some(idle) = details["idleTimeout"].as_u64() {
                    d.extra["idleTimeout"] = json!(idle);
                }
                d.extra["health"] = value["health"].clone();
                d.extra["urls"] = invoke_urls(&endpoint, d.extra["category"].as_str().unwrap_or(""));
            }
            (Ok(_), "stop") => d.state = "Paused".into(),
            (Ok(_), "start") => d.state = "Ready".into(),
            (Ok(_), "delete") => {
                d.state = "Deleted".into();
                d.resource_id.clear();
            }
            _ => {}
        }
        d.last_error = failed.clone();
        if let Some(env) = state.environments.iter_mut().find(|e| e.id == environment_id) {
            env.status = if failed.is_some() { EnvironmentStatus::Error } else { EnvironmentStatus::Stopped };
            env.last_error = failed.clone();
        }
        Ok(())
    })?;
    match failed {
        Some(error) => Err(error),
        None => Ok(state),
    }
}

/// Sends one request to an endpoint and waits for its answer.
#[tauri::command]
pub async fn runpod_endpoint_run(
    environment_id: String,
    input: Value,
    store: State<'_, PlatformStore>,
) -> Result<Value, String> {
    let deployment = store
        .snapshot()?
        .neocloud_deployments
        .get(&environment_id)
        .cloned()
        .ok_or("Neocloud resource not found")?;
    if deployment.product != "serverless" || deployment.resource_id.is_empty() {
        return Err("This is not a serverless endpoint".into());
    }
    if !input.is_object() {
        return Err("The request must be a JSON object".into());
    }
    let payload = serde_json::to_string(&input).map_err(|e| e.to_string())?;
    if payload.len() > 512 * 1024 {
        return Err("Keep test requests under 512 KB".into());
    }
    let args: Vec<String> = vec![
        "serverless".into(), "run".into(), deployment.resource_id.clone(),
        "--input".into(), "-".into(), "--wait".into(), "4m".into(),
    ];
    let output = cli_output(&args, 270, Some(&payload)).await?;
    let value = serde_json::from_str::<Value>(output.stdout.trim()).unwrap_or(Value::Null);
    if value.is_null() {
        return Err(failure(&output));
    }
    Ok(json!({"ok":output.success,"job":value}))
}

// ---------------------------------------------------------------- pod and endpoint controls

/// Start, stop, restart, refresh or delete a RunPod node. Starting reconnects SSH on
/// the pod's new address.
#[tauri::command]
pub async fn runpod_action(
    environment_id: String,
    action: String,
    confirmation: Option<String>,
    app: AppHandle,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
) -> Result<PlatformState, String> {
    let deployment = store
        .snapshot()?
        .neocloud_deployments
        .get(&environment_id)
        .cloned()
        .ok_or("Neocloud resource not found")?;
    if deployment.provider != PROVIDER {
        return super::neocloud_action(environment_id, action, confirmation, store, runtime).await;
    }
    if action == "delete" && confirmation.as_deref() != Some(&deployment.name) {
        return Err("Type the name to delete it".into());
    }
    if deployment.resource_id.is_empty() && deployment.state != "Deleted" {
        let state = reconcile(&environment_id, &deployment, &store).await?;
        emit(&app, &state);
        if state.neocloud_deployments.get(&environment_id).is_some_and(|d| d.product == "pod" && !d.resource_id.is_empty()) {
            watch(app, environment_id);
        }
        return Ok(state);
    }
    if deployment.product == "serverless" {
        let state = endpoint_action(&environment_id, &action, &store).await?;
        emit(&app, &state);
        return Ok(state);
    }
    if deployment.resource_id.is_empty() {
        return Err("This pod has no Neocloud ID. Check your Neocloud pods, then remove this node.".into());
    }
    let pod = deployment.resource_id.clone();
    let state = match action.as_str() {
        "delete" => {
            let state = super::neocloud_action(environment_id.clone(), action.clone(), confirmation, store.clone(), runtime).await?;
            let _ = jupyter_entry(&environment_id).map(|e| e.delete_credential());
            state
        }
        "start" | "restart" => {
            runtime.cloud.disconnect(&environment_id).await;
            cli(&["pod", if action == "start" { "start" } else { "restart" }, &pod], 90).await?;
            update(&store, &environment_id, |_, d| {
                d.state = "Starting".into();
                d.extra["sshReady"] = json!(false);
                d.last_error = None;
            })?
        }
        "stop" => {
            runtime.cloud.disconnect(&environment_id).await;
            cli(&["pod", "stop", &pod], 90).await?;
            let mut state = update(&store, &environment_id, |_, d| {
                d.state = "Stopping".into();
                d.extra["sshReady"] = json!(false);
            })?;
            for _ in 0..8 {
                tokio::time::sleep(Duration::from_secs(3)).await;
                if let Ok(value) = cli(&["pod", "get", &pod], 40).await {
                    state = update(&store, &environment_id, |_, d| describe_pod(d, &value))?;
                    if pod_status(&value) != "running" {
                        break;
                    }
                }
            }
            state
        }
        "inspect" => {
            let value = cli(&["pod", "get", &pod], 40).await?;
            update(&store, &environment_id, |environment, d| {
                describe_pod(d, &value);
                if environment.status == EnvironmentStatus::Error {
                    environment.status = EnvironmentStatus::Stopped;
                    environment.last_error = None;
                }
            })?
        }
        _ => return Err("Unsupported pod action".into()),
    };
    emit(&app, &state);
    let current = state.neocloud_deployments.get(&environment_id);
    if current.is_some_and(|d| d.extra["sshReady"] != true && matches!(d.state.as_str(), "Starting" | "Running")) {
        watch(app, environment_id);
    }
    Ok(state)
}

/// A create that went unanswered: find the pod or endpoint by its name. Found, it is
/// attached; absent, nothing was created and the node can be removed.
async fn reconcile(environment_id: &str, deployment: &Deployment, store: &PlatformStore) -> Result<PlatformState, String> {
    let found = if deployment.product == "serverless" {
        array(&cli(&["serverless", "list"], 40).await?)
            .into_iter()
            .find(|e| e["name"] == deployment.name.as_str())
    } else {
        // Nodes created before unique pod names recorded only the chosen name.
        let name = deployment.extra["providerName"].as_str().unwrap_or(&deployment.name);
        array(&cli(&["pod", "list", "--all", "--name", name], 40).await?)
            .into_iter()
            .find(|p| p["name"] == name && p["desiredStatus"] != "TERMINATED")
    };
    update(store, environment_id, |environment, d| {
        environment.last_error = None;
        environment.status = EnvironmentStatus::Stopped;
        d.last_error = None;
        match found.as_ref().and_then(|f| f["id"].as_str()) {
            Some(id) => {
                d.resource_id = id.into();
                d.state = if d.product == "serverless" { "Ready" } else { "Starting" }.into();
                if d.product == "serverless" {
                    d.extra["urls"] = invoke_urls(id, d.extra["category"].as_str().unwrap_or(""));
                }
            }
            None => d.state = "Deleted".into(),
        }
    })
}

// ---------------------------------------------------------------- account resources

/// Pods and endpoints in the RunPod account, marking those already in Yougori.
#[tauri::command]
pub async fn runpod_resources(store: State<'_, PlatformStore>) -> Result<Value, String> {
    let (pods, endpoints) = tokio::join!(cli(&["pod", "list", "--all"], 40), cli(&["serverless", "list"], 40));
    let attached: HashSet<String> = store
        .snapshot()?
        .neocloud_deployments
        .values()
        .filter(|d| d.provider == PROVIDER && d.state != "Deleted")
        .map(|d| d.resource_id.clone())
        .collect();
    let pods = array(&pods?)
        .iter()
        .map(|p| json!({"id":p["id"],"name":p["name"],"status":p["desiredStatus"],"gpu":p["gpuTypeId"],"gpuCount":p["gpuCount"],"hourlyUsd":p["costPerHr"],"image":p["imageName"],"attached":attached.contains(p["id"].as_str().unwrap_or(""))}))
        .collect::<Vec<_>>();
    let endpoints = array(&endpoints.unwrap_or(Value::Null))
        .iter()
        .map(|e| json!({"id":e["id"],"name":e["name"],"workersMax":e["workersMax"],"workersMin":e["workersMin"],"attached":attached.contains(e["id"].as_str().unwrap_or(""))}))
        .collect::<Vec<_>>();
    Ok(json!({"pods":pods,"endpoints":endpoints}))
}

/// Adds a pod or endpoint that already exists in RunPod as a Yougori node.
#[tauri::command]
pub async fn runpod_attach(
    kind: String,
    resource_id: String,
    app: AppHandle,
    store: State<'_, PlatformStore>,
) -> Result<PlatformState, String> {
    if !safe_id(&resource_id, 64) || resource_id.contains(' ') {
        return Err("Invalid Neocloud ID".into());
    }
    if store.snapshot()?.neocloud_deployments.values().any(|d| d.provider == PROVIDER && d.resource_id == resource_id && d.state != "Deleted") {
        return Err("This is already in Yougori".into());
    }
    let taken: Vec<String> = store.snapshot()?.environments.iter().map(|e| e.name.to_ascii_lowercase()).collect();
    let unique = |base: &str| {
        let base: String = base.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').take(36).collect();
        let base = if base.len() < 3 { format!("runpod-{base}") } else { base };
        (1..).map(|n| if n == 1 { base.clone() } else { format!("{base}-{n}") }).find(|n| !taken.contains(&n.to_ascii_lowercase())).unwrap_or(base)
    };
    let id = format!("env-{}", uuid::Uuid::new_v4());
    match kind.as_str() {
        "pod" => {
            let value = cli(&["pod", "get", &resource_id], 40).await?;
            let name = unique(value["name"].as_str().unwrap_or("runpod-pod"));
            let gpu = text(&value["gpuTypeId"]);
            let compute = if gpu.is_empty() { "cpu" } else { "gpu" };
            let ports: Vec<Value> = array(&value["ports"])
                .iter()
                .filter_map(|p| {
                    let (port, kind) = p.as_str()?.split_once('/')?;
                    let port = port.parse::<u16>().ok()?;
                    Some(json!({"port":port,"kind":kind,"name":default_port_name(port, kind)}))
                })
                .collect();
            let extra = json!({"kind":"pod","compute":compute,"gpuId":gpu,"gpuCount":value["gpuCount"],"containerDiskGb":value["containerDiskInGb"],"volumeGb":value["volumeInGb"],"mountPath":value["volumeMountPath"],"networkVolumeId":value["networkVolumeId"],"ports":ports,"sshReady":false,"attached":true});
            let label = if gpu.is_empty() { "CPU".to_owned() } else { format!("{} × {gpu}", value["gpuCount"].as_u64().unwrap_or(1)) };
            let mut environment = node(&id, &name, &format!("Neocloud · {label}"), compute == "gpu", "Neocloud pod added from your account · opens in Yougori over SSH");
            environment.status = EnvironmentStatus::Stopped;
            let mut record = deployment("pod", &name, &text(&value["imageName"]), &gpu, "", extra);
            record.resource_id = resource_id;
            describe_pod(&mut record, &value);
            let state = insert(&store, environment, record)?;
            emit(&app, &state);
            // Pods created elsewhere may not carry Yougori's key yet; it is added for their next start.
            if let Ok((_, public)) = ssh_key().await {
                let _ = account_keys(&public).await;
            }
            watch(app, id);
            Ok(state)
        }
        "endpoint" => {
            let value = cli(&["serverless", "get", &resource_id], 40).await?;
            let name = unique(value["name"].as_str().unwrap_or("runpod-endpoint"));
            let extra = json!({"kind":"endpoint","title":value["name"],"category":"","workersMin":value["workersMin"],"workersMax":value["workersMax"],"idleTimeout":value["idleTimeout"],"urls":invoke_urls(&resource_id, ""),"attached":true});
            let mut environment = node(&id, &name, "Neocloud · serverless", true, "Neocloud serverless endpoint added from your account");
            environment.status = EnvironmentStatus::Stopped;
            let mut record = deployment("serverless", &name, "", "", "", extra);
            record.state = if value["workersMax"].as_u64() == Some(0) { "Paused" } else { "Ready" }.into();
            record.address = format!("https://api.runpod.ai/v2/{resource_id}/run");
            record.resource_id = resource_id;
            let state = insert(&store, environment, record)?;
            emit(&app, &state);
            Ok(state)
        }
        _ => Err("Choose a pod or an endpoint".into()),
    }
}

/// Network volumes: `create`, `resize` (grow only) and `delete`.
#[tauri::command]
pub async fn runpod_volume(
    action: String,
    id: Option<String>,
    name: Option<String>,
    location: Option<String>,
    size_gb: Option<u32>,
) -> Result<Value, String> {
    let size = size_gb.unwrap_or(0);
    match action.as_str() {
        "create" => {
            let name = name.unwrap_or_default();
            valid_name(&name)?;
            let location = location.filter(|l| safe_id(l, 64)).ok_or("Choose where the volume lives")?;
            if !(1..=4000).contains(&size) {
                return Err("Volumes hold 1–4000 GB".into());
            }
            let created = cli(&["network-volume", "create", "--name", &name, "--data-center-id", &location, "--size", &size.to_string()], 60).await?;
            Ok(volume(&created))
        }
        "resize" | "delete" => {
            let id = id.filter(|i| safe_id(i, 64) && !i.contains(' ')).ok_or("Choose a volume")?;
            if action == "resize" {
                if !(1..=4000).contains(&size) {
                    return Err("Volumes hold 1–4000 GB".into());
                }
                cli(&["network-volume", "update", &id, "--size", &size.to_string()], 60).await
            } else {
                cli(&["network-volume", "delete", &id], 60).await
            }
        }
        _ => Err("Unknown volume action".into()),
    }
}

/// Saves a private container registry login; the password goes through stdin.
#[tauri::command]
pub async fn runpod_registry(
    action: String,
    id: Option<String>,
    name: Option<String>,
    username: Option<String>,
    password: Option<String>,
) -> Result<Value, String> {
    match action.as_str() {
        "create" => {
            let name = name.unwrap_or_default();
            valid_name(&name)?;
            let username = username.filter(|u| safe_id(u, 200) && !u.contains(' ')).ok_or("Enter the registry user name")?;
            let password = password.filter(|p| !p.is_empty() && p.len() <= 8192 && !p.contains(['\n', '\r', '\0'])).ok_or("Enter the registry password or token")?;
            let args: Vec<String> = ["registry", "create", "--name", &name, "--username", &username, "--password-stdin"].iter().map(|s| (*s).to_owned()).collect();
            let output = cli_output(&args, 60, Some(&password)).await?;
            if !output.success {
                return Err(failure(&output));
            }
            Ok(serde_json::from_str(output.stdout.trim()).unwrap_or(Value::Null))
        }
        "delete" => {
            let id = id.filter(|i| safe_id(i, 64) && !i.contains(' ')).ok_or("Choose a registry login")?;
            cli(&["registry", "delete", &id], 60).await
        }
        _ => Err("Unknown registry action".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "Read-only RunPod availability diagnostic using the saved account"]
    async fn live_gpu_availability_diagnostic() {
        let catalog = runpod_gpu_offers(Some(40), None).await.unwrap();
        let gpus = catalog["gpus"].as_array().unwrap();
        assert!(gpus.len() > 10);
        for row in gpus.iter().filter(|g| matches!(g["id"].as_str(), Some("NVIDIA GeForce RTX 3090" | "NVIDIA RTX A4500" | "NVIDIA RTX A5000"))) {
            println!("{row}");
        }
    }

    fn pod() -> PodRequest {
        serde_json::from_value(json!({
            "name":"pytorch-4090","compute":"gpu","gpuId":"NVIDIA GeForce RTX 4090","gpuCount":1,"cloud":"secure",
            "templateId":"runpod-torch-v280","containerDiskGb":30,"volumeGb":50,"maxHourlyUsd":0.74
        }))
        .unwrap()
    }

    #[test]
    fn pods_are_argument_arrays_with_the_chosen_template_gpu_and_storage() {
        let request = pod();
        validate_pod(&request).unwrap();
        let args = pod_args(&request, "pytorch-4090", &[], &BTreeMap::new());
        assert_eq!(args[..4], ["pod", "create", "--name", "pytorch-4090"]);
        assert_eq!(provider_pod_name("pytorch-4090", "env-3f9a12c4-0000-4000-8000-000000000000"), "pytorch-4090-yg3f9a12c4");
        assert!(args.windows(2).any(|w| w == ["--template-id", "runpod-torch-v280"]));
        assert!(args.windows(2).any(|w| w == ["--gpu-id", "NVIDIA GeForce RTX 4090"]));
        assert!(args.windows(2).any(|w| w == ["--cloud-type", "SECURE"]));
        assert!(args.windows(2).any(|w| w == ["--volume-in-gb", "50"]));
        assert!(!args.iter().any(|a| a == "--ports" || a == "--data-center-ids"));
        for count in [2, 4, 8] {
            let mut multiple = pod();
            multiple.gpu_count = count;
            validate_pod(&multiple).unwrap();
            assert!(pod_args(&multiple, &multiple.name, &[], &BTreeMap::new()).windows(2)
                .any(|w| w[0] == "--gpu-count" && w[1] == count.to_string()));
        }
        let mut bad = pod();
        bad.name = "x; rm -rf /".into();
        assert!(validate_pod(&bad).is_err());
        let mut both = pod();
        both.image = "ubuntu:22.04".into();
        assert!(validate_pod(&both).is_err());
        let mut cpu = pod();
        cpu.compute = "cpu".into();
        assert!(validate_pod(&cpu).is_err(), "a CPU pod cannot carry a GPU");
        cpu.gpu_id.clear();
        cpu.env.insert("bad key".into(), "x".into());
        assert!(validate_pod(&cpu).is_err());
    }

    #[tokio::test]
    async fn gpu_offer_counts_are_validated_before_querying_runpod() {
        for count in [0, 9, u32::MAX] {
            assert!(runpod_gpu_offers(Some(40), Some(count)).await.unwrap_err().contains("1–8"));
        }
    }

    #[test]
    fn endpoints_keep_hub_defaults_and_pass_only_the_chosen_settings() {
        let mut request: EndpointRequest = serde_json::from_value(json!({
            "name":"qwen-chat","hubId":"cm8h09d9n000008jvh2rqdsmb","category":"language","env":{"MODEL_NAME":"Qwen/Qwen2.5-0.5B-Instruct"}
        }))
        .unwrap();
        validate_endpoint(&request).unwrap();
        let args = endpoint_args(&request);
        assert!(args.windows(2).any(|w| w == ["--env", "MODEL_NAME=Qwen/Qwen2.5-0.5B-Instruct"]));
        assert!(args.windows(2).any(|w| w == ["--workers-min", "0"]));
        assert!(!args.iter().any(|a| a == "--gpu-id"), "the Hub's own GPU choice applies");
        assert_eq!(invoke_urls("abc", "language")["openai"], "https://api.runpod.ai/v2/abc/openai/v1");
        request.workers_min = 3;
        assert!(validate_endpoint(&request).is_err());
    }

    #[test]
    fn catalogue_rows_are_plain_and_pod_state_is_read_from_the_runtime() {
        let g = gpu(&json!({"gpuId":"NVIDIA GeForce RTX 4090","displayName":"RTX 4090",
            "securePricePerHr":0.74,"communityPricePerHr":0.34,"secureCloud":true,"communityCloud":true,
            "available":true,"dataCenterAvailability":[{"dataCenterId":"US-KS-2","stockStatus":"Low"},{"dataCenterId":"EU-RO-1","stockStatus":"none"}]}));
        assert_eq!(g["securePrice"], 0.74);
        assert_eq!(g["locations"][1]["stock"], "none");
        let template = json!({"ports":["8888/http","22/tcp"],"portsConfig":[{"name":"Jupyter Notebook","port":"8888"}]});
        assert_eq!(ports(&template)[0]["name"], "Jupyter Notebook");
        assert_eq!(ports(&template)[1]["name"], "SSH");
        let mut d = deployment("pod", "p", "i", "g", "", json!({}));
        d.extra["statusReason"] = json!("awaiting_container");
        describe_pod(&mut d, &json!({"runtimeStatus":"running","costPerHr":0.74,"ssh":{"ip":"1.2.3.4","port":22101,"ssh_command":"ssh root@1.2.3.4 -p 22101"}}));
        assert!(d.extra["statusReason"].is_null());
        assert_eq!((d.state.as_str(), d.address.as_str()), ("Running", "1.2.3.4"));
        describe_pod(&mut d, &json!({"desiredStatus":"EXITED"}));
        assert_eq!(d.state, "Stopped");
        assert_eq!(d.extra["sshReady"], false);
    }

    /// Reads the live account through the installed CLI; nothing is created.
    #[tokio::test]
    #[ignore = "Read-only diagnostic; set YOUGORI_DIAGNOSTIC_POD to an existing RunPod pod ID"]
    async fn live_pod_startup_diagnostic() {
        let id = std::env::var("YOUGORI_DIAGNOSTIC_POD").expect("Set YOUGORI_DIAGNOSTIC_POD");
        assert!(safe_id(&id, 128));
        let value = cli(&["pod", "get", &id], 40).await.unwrap();
        println!("{}", json!({"id":value["id"],"runtimeStatus":value["runtimeStatus"],"desiredStatus":value["desiredStatus"],"reason":value["runtimeStatusReason"],"ssh":value["ssh"]}));
        let args = ["pod", "logs", &id, "--tail", "25", "--source", "both"].map(String::from);
        let output = cli_output(&args, 30, None).await.unwrap();
        assert!(output.success, "{}", failure(&output));
        for line in output.stdout.lines() {
            let lower = line.to_ascii_lowercase();
            if !["token", "password", "secret", "api_key"].iter().any(|word| lower.contains(word)) {
                println!("{line}");
            }
        }
        let host = value["ssh"]["ip"].as_str().unwrap();
        let port = value["ssh"]["port"].as_u64().unwrap() as u16;
        let keys = crate::runtime::cloud::scan(host.into(), port).await.unwrap();
        println!("Scanned host keys: {}", serde_json::to_string(&keys).unwrap());
    }

    #[tokio::test]
    #[ignore = "Needs runpodctl signed in to a RunPod account"]
    async fn live_catalogue_hub_and_templates_are_read() {
        let status = runpod_status().await.unwrap();
        assert_eq!(status["connected"], true, "{status}");
        let catalog = runpod_catalog().await.unwrap();
        assert!(catalog["issues"].as_array().unwrap().is_empty(), "{}", catalog["issues"]);
        assert!(catalog["gpus"].as_array().unwrap().len() > 10);
        let hub = runpod_hub(None).await.unwrap();
        let vllm = hub.as_array().unwrap().iter().find(|r| r["title"] == "vLLM").expect("vLLM repo").clone();
        let repo = runpod_hub_repo(vllm["id"].as_str().unwrap().into()).await.unwrap();
        assert!(repo["inputs"].as_array().unwrap().iter().any(|i| i["key"] == "MODEL_NAME" && i["required"] == true));
        let template = runpod_template("runpod-torch-v280".into()).await.unwrap();
        assert!(template["ports"].as_array().unwrap().iter().any(|p| p["port"] == 8888));
        println!("{}", serde_json::to_string_pretty(&json!({"account":catalog["account"],"gpu":catalog["gpus"][0],"template":catalog["templates"][0],"repo":{"gpuPools":repo["gpuPools"],"presets":repo["presets"],"inputs":repo["inputs"].as_array().unwrap().iter().filter(|i| i["advanced"] != true).collect::<Vec<_>>()}})).unwrap());
    }

    #[test]
    fn api_key_failures_are_explained() {
        assert!(friendly("Error: invalid api key").contains("did not accept the API key"));
        assert!(friendly("There are no longer any instances available with the requested specifications").contains("no free machine"));
    }
}
