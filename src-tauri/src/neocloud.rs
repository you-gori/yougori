//! Provider-owned compute created with an installed, authenticated provider CLI.
//! A durable intent is saved before the paid create call; ambiguous failures are
//! never retried automatically because they may have created a billable resource.
use crate::{models::*, runtime::RuntimeManager, store::PlatformStore};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{process::Stdio, time::Duration};
use tauri::State;
use tokio::io::AsyncReadExt;

pub(crate) mod accounts;
pub(crate) mod catalog;
#[cfg(test)]
mod contracts;
pub(crate) mod install;
mod pricing;
mod provider_commands;
pub(crate) mod runpod;
pub use accounts::{neocloud_account, neocloud_authenticate, neocloud_forget_account};
pub use catalog::neocloud_catalog;
pub use install::neocloud_install;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Deployment {
    pub provider: String,
    pub product: String,
    pub name: String,
    pub resource_id: String,
    pub state: String,
    pub image: String,
    pub offer: String,
    #[serde(default)]
    pub disk_gb: u32,
    #[serde(default)]
    pub location: String,
    pub address: String,
    #[serde(default)]
    pub ssh_hint: String,
    pub request_id: String,
    pub last_error: Option<String>,
    /// Provider details shown on the node, such as a RunPod pod's GPU, ports and price.
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub extra: Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateRequest {
    pub provider: String,
    pub product: String,
    pub name: String,
    pub image: String,
    pub offer: String,
    #[serde(default)]
    pub location: String,
    pub disk_gb: u32,
    #[serde(default)]
    pub subnet_id: String,
    #[serde(default)]
    pub platform: String,
    #[serde(default)]
    pub ssh_public_key: String,
    #[serde(default)]
    pub firewall: String,
    #[serde(default)]
    pub cpu_cores: u32,
    #[serde(default)]
    pub memory_gb: u32,
    #[serde(default = "one_gpu")]
    pub gpu_count: u32,
    #[serde(default)]
    pub max_hourly_usd: Option<f64>,
}

fn one_gpu() -> u32 {
    1
}

#[tauri::command]
pub fn neocloud_providers() -> Vec<Value> {
    accounts::metadata()
}

fn program(provider: &str) -> Result<&'static str, String> {
    match provider {
        "runpod" => Ok("runpodctl"),
        "vast" => Ok("vastai"),
        "crusoe" => Ok("crusoe"),
        "jarvis" => Ok("jl"),
        "civo" => Ok("civo"),
        "nebius" => Ok("nebius"),
        "prime" => Ok("prime"),
        "thunder" => Ok("tnr"),
        "latitude" => Ok("lsh"),
        "e2e" => Ok("e2e_cli"),
        _ => Err("This provider is not ready for managed creation in Yougori".into()),
    }
}

fn token(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:/@".contains(&b))
}

fn ssh_public_key(value: &str) -> Option<String> {
    let mut parts = value.split_whitespace();
    let kind = parts.next()?;
    if !matches!(
        kind,
        "ssh-ed25519"
            | "ssh-rsa"
            | "ecdsa-sha2-nistp256"
            | "ecdsa-sha2-nistp384"
            | "ecdsa-sha2-nistp521"
    ) {
        return None;
    }
    let encoded = parts.next()?;
    if encoded.len() > 8192 {
        return None;
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    if !(32..=4096).contains(&bytes.len()) {
        return None;
    }
    // An SSH public-key blob starts with a length-prefixed algorithm name.
    // Plain base64 (including an arbitrary 32-byte string) is not a key.
    let name_length = u32::from_be_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
    if name_length != kind.len() || bytes.get(4..4 + name_length)? != kind.as_bytes() {
        return None;
    }
    if bytes.len() <= 4 + name_length + 4 {
        return None;
    }
    Some(format!("{kind} {encoded}"))
}

fn validate(request: &CreateRequest) -> Result<(), String> {
    program(&request.provider)?;
    if request.name.len() < 2
        || request.name.len() > 40
        || !request
            .name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("Name must be 2–40 letters, numbers, hyphens or underscores".into());
    }
    if !token(&request.image, 512) {
        return Err("Choose a valid image".into());
    }
    if !request.location.is_empty() && !token(&request.location, 128) {
        return Err("Choose a valid region or project ID".into());
    }
    if !matches!(request.provider.as_str(), "latitude" | "e2e")
        && request.provider != "crusoe"
        && request.provider != "civo"
        && !(request.provider == "runpod" && request.product == "serverless")
        && !(10..=2048).contains(&request.disk_gb)
    {
        return Err("Disk must be 10–2048 GB".into());
    }
    match (request.provider.as_str(), request.product.as_str()) {
        ("runpod", "cpu") if request.offer.is_empty() => Ok(()),
        ("runpod", "gpu")
            if !request.offer.is_empty()
                && token(&request.location, 128)
                && request.max_hourly_usd.is_some_and(|price| {
                    price.is_finite() && price > 0.0 && price <= 1_000_000.0
                })
                && request.gpu_count == 1
                && request.offer.len() <= 128
                && !request.offer.starts_with('-')
                && request
                    .offer
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b" -_.".contains(&b)) =>
        {
            Ok(())
        }
        ("runpod", "serverless")
            if request.name.len() >= 3
                && token(&request.image, 128)
                && !request.offer.is_empty()
                && request.offer.len() <= 128
                && request
                    .offer
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b" -_.".contains(&b)) =>
        {
            Ok(())
        }
        ("vast", "gpu") if request.offer.parse::<u64>().is_ok_and(|id| id > 0) => Ok(()),
        ("crusoe", "cpu" | "gpu")
            if token(&request.offer, 128) && token(&request.location, 128) =>
        {
            Ok(())
        }
        ("jarvis", "gpu") if token(&request.offer, 128) && token(&request.image, 128) => Ok(()),
        ("jarvis", "cpu")
            if request.offer.is_empty()
                || provider_commands::cpu_size(&request.offer).is_some() =>
        {
            Ok(())
        }
        ("prime", "gpu")
            if token(&request.offer, 128)
                && (1..=1024).contains(&request.cpu_cores)
                && (1..=16384).contains(&request.memory_gb) =>
        {
            Ok(())
        }
        ("thunder", "gpu")
            if token(&request.offer, 128)
                && (1..=1024).contains(&request.cpu_cores)
                && (1..=8).contains(&request.gpu_count)
                && request.disk_gb >= request.gpu_count * 100 =>
        {
            Ok(())
        }
        ("latitude", "cpu" | "gpu")
            if token(&request.offer, 128)
                && token(&request.location, 128)
                && token(&request.platform, 128)
                && token(&request.subnet_id, 128) =>
        {
            Ok(())
        }
        ("e2e", "cpu" | "gpu")
            if token(&request.offer, 128)
                && provider_commands::e2e_context(&request.location).is_ok()
                && request.firewall.parse::<u64>().is_ok()
                && ssh_public_key(&request.ssh_public_key).is_some() =>
        {
            Ok(())
        }
        ("jarvis", "serverless")
            if token(&request.offer, 128)
                && token(&request.location, 128)
                && token(&request.image, 256) =>
        {
            Ok(())
        }
        ("civo", "cpu" | "gpu")
            if token(&request.offer, 128)
                && token(&request.location, 128)
                && token(&request.platform, 128)
                && token(&request.firewall, 128)
                && request.offer.to_ascii_lowercase().contains("gpu")
                    == (request.product == "gpu") =>
        {
            Ok(())
        }
        ("nebius", "cpu" | "gpu")
            if token(&request.offer, 128)
                && token(&request.location, 128)
                && token(&request.subnet_id, 128)
                && token(&request.platform, 128)
                && ssh_public_key(&request.ssh_public_key).is_some() =>
        {
            Ok(())
        }
        _ => Err("Choose a supported provider, compute type, and GPU or offer ID".into()),
    }
}

async fn read_limited(reader: impl tokio::io::AsyncRead + Unpin) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(2 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|e| e.to_string())?;
    if bytes.len() > 2 * 1024 * 1024 {
        return Err("Provider output exceeded 2 MiB".into());
    }
    Ok(bytes)
}

async fn run_with_timeout(provider: &str, args: &[String], seconds: u64) -> Result<Value, String> {
    run_authenticated(provider, args, seconds, None).await
}

async fn run_authenticated(
    provider: &str,
    args: &[String],
    seconds: u64,
    supplied_key: Option<&str>,
) -> Result<Value, String> {
    let binary = program(provider)?;
    let wsl = cfg!(windows) && matches!(provider, "latitude" | "nebius");
    let executable = if wsl {
        std::path::PathBuf::from("wsl.exe")
    } else {
        install::installed_program(provider).unwrap_or_else(|| std::path::PathBuf::from(binary))
    };
    let mut command = tokio::process::Command::new(&executable);
    if wsl {
        command.args([
            "--exec",
            "bash",
            "-lc",
            "export PATH=\"$HOME/.nebius/bin:$HOME/.lsh:$HOME/.local/bin:$PATH\"; exec \"$@\"",
            "yougori",
            binary,
        ]);
    }
    let saved = if supplied_key.is_none() && args != ["--help"] && args != ["--version"] {
        accounts::saved_key(provider)?
    } else {
        None
    };
    let credential = supplied_key.or(saved.as_deref());
    if let (Some(key), Some(variable)) = (credential, accounts::key_variable(provider)) {
        command.env(variable, key);
        if provider == "latitude" {
            command.env("LATITUDESH_AUTH_TOKEN", key);
        }
        if wsl {
            let existing = std::env::var("WSLENV").unwrap_or_default();
            command.env(
                "WSLENV",
                format!(
                    "{existing}:{variable}{}",
                    if provider == "latitude" {
                        ":LATITUDESH_AUTH_TOKEN"
                    } else {
                        ""
                    }
                ),
            );
        }
    }
    command.env("NO_COLOR", "1").env("TERM", "dumb");
    command
        .args(args)
        .stdin(if provider == "e2e" && args.iter().any(|a| a == "delete") {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(windows)]
    {
        command.creation_flags(0x08000000);
    }
    let mut child = command.spawn().map_err(|e| {
        format!("Install and sign in to the official {binary} CLI, then check the connection: {e}")
    })?;
    // E2E's official delete command requires a prompt even with every argument
    // supplied. This path is reached only after our name-confirmed deletion.
    if let Some(mut input) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        input
            .write_all(b"y\n")
            .await
            .map_err(|_| "Cannot confirm provider deletion")?;
    }
    let out = child.stdout.take().ok_or("Provider stdout unavailable")?;
    let err = child.stderr.take().ok_or("Provider stderr unavailable")?;
    let result = tokio::time::timeout(Duration::from_secs(seconds), async {
        tokio::try_join!(read_limited(out), read_limited(err), async { child.wait().await.map_err(|e| e.to_string()) })
    }).await.map_err(|_| "Provider operation timed out; inspect the account before retrying because a billable resource may exist".to_string());
    let (stdout, stderr, status) = match result {
        Ok(Ok(value)) => value,
        Ok(Err(error)) | Err(error) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err(error);
        }
    };
    if !status.success() {
        let detail = String::from_utf8_lossy(if stderr.is_empty() { &stdout } else { &stderr });
        let detail = if let Some(key) = credential {
            detail.replace(key, "[redacted]")
        } else {
            detail.into_owned()
        };
        return Err(format!(
            "{binary}: {}",
            detail.chars().take(4000).collect::<String>()
        ));
    }
    let output = String::from_utf8_lossy(&stdout);
    if output.trim().is_empty() {
        return Ok(Value::Null);
    }
    // Some lifecycle commands acknowledge success with plain text. Creation
    // still requires a structured ID, enforced by `identifier` below.
    parse_output(provider, output.trim())
}

fn parse_output(provider: &str, output: &str) -> Result<Value, String> {
    // Some lsh commands print an API error on stdout and exit successfully.
    if provider == "latitude"
        && output
            .lines()
            .any(|line| line.trim().starts_with("✗ Error:"))
    {
        return Err(
            if output.contains("[404]") || output.to_ascii_lowercase().contains("not found") {
                "Latitude resource not found (404)"
            } else {
                "Latitude rejected the request; check account permissions and configuration"
            }
            .into(),
        );
    }
    let parsed = serde_json::from_str(output)
        .ok()
        .or_else(|| {
            if provider != "e2e" {
                return None;
            }
            output
                .char_indices()
                .filter(|(_, c)| *c == '{')
                .find_map(|(i, _)| serde_json::from_str(&output[i..]).ok())
        })
        .unwrap_or_else(|| Value::String(output.into()));
    if let Some(errors) = parsed["errors"].as_array().filter(|e| !e.is_empty()) {
        if errors
            .iter()
            .any(|e| e["status"] == "404" || e["status"] == 404)
        {
            return Err("Provider resource not found (404)".into());
        }
        return Err("Provider rejected the request; check its account and permissions".into());
    }
    if parsed
        .get("error")
        .is_some_and(|e| !e.is_null() && e != false && e != "")
    {
        return Err("Provider rejected the request; check its account and permissions".into());
    }
    if provider == "e2e" && parsed["code"].as_u64() == Some(404) {
        return Err("E2E resource not found (404)".into());
    }
    if provider == "e2e"
        && (parsed["code"].as_u64().is_some_and(|c| c >= 400) || parsed["status"] == false)
    {
        return Err(
            "E2E rejected the request. Check the selected alias, project, region and permissions."
                .into(),
        );
    }
    Ok(parsed)
}

async fn run(provider: &str, args: &[String]) -> Result<Value, String> {
    run_with_timeout(provider, args, 120).await
}

fn create_args(request: &CreateRequest) -> Vec<String> {
    if let Some(args) = provider_commands::create(request) {
        return args;
    }
    if request.provider == "runpod" {
        if request.product == "serverless" {
            return vec![
                "serverless".into(),
                "create".into(),
                "--hub-id".into(),
                request.image.clone(),
                "--name".into(),
                request.name.clone(),
                "--gpu-id".into(),
                request.offer.clone(),
                "--workers-min".into(),
                "0".into(),
                "--workers-max".into(),
                "1".into(),
                "--idle-timeout".into(),
                "600".into(),
            ];
        }
        let mut args = vec![
            "pod",
            "create",
            "--name",
            &request.name,
            "--image",
            &request.image,
            "--volume-in-gb",
        ]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
        args.push(request.disk_gb.to_string());
        args.extend(["--container-disk-in-gb", "20", "--ports", "22/tcp"].map(str::to_string));
        if request.product == "cpu" {
            args.extend(["--compute-type", "cpu"].map(str::to_string));
        } else {
            args.extend(["--gpu-id".to_string(), request.offer.clone()]);
        }
        if !request.location.is_empty() {
            args.extend(["--data-center-ids".into(), request.location.clone()]);
        }
        args
    } else if request.provider == "vast" {
        vec![
            "create".into(),
            "instance".into(),
            request.offer.clone(),
            "--image".into(),
            request.image.clone(),
            "--disk".into(),
            request.disk_gb.to_string(),
            "--ssh".into(),
            "--direct".into(),
            "--label".into(),
            request.name.clone(),
            "--raw".into(),
        ]
    } else if request.provider == "jarvis" {
        if request.product == "serverless" {
            return vec![
                "deploy".into(),
                "create".into(),
                "--name".into(),
                request.name.clone(),
                "--region".into(),
                request.location.clone(),
                "--framework".into(),
                "vllm".into(),
                "--gpu".into(),
                request.offer.clone(),
                "--gpus-per-worker".into(),
                "1".into(),
                "--min-workers".into(),
                "0".into(),
                "--max-workers".into(),
                "1".into(),
                "--idle-timeout".into(),
                "600".into(),
                "--wait-time".into(),
                "60".into(),
                "--storage".into(),
                request.disk_gb.to_string(),
                "--model".into(),
                request.image.clone(),
                "--detach".into(),
                "--yes".into(),
                "--json".into(),
            ];
        }
        let mut args = vec!["create".into()];
        if request.product == "cpu" {
            args.extend(["--vm".into(), "--cpu".into()]);
            if let Some((cpu, ram)) = provider_commands::cpu_size(&request.offer) {
                args.extend([
                    "--vcpus".into(),
                    cpu.to_string(),
                    "--ram".into(),
                    ram.to_string(),
                ]);
            }
        } else {
            args.extend(["--gpu".into(), request.offer.clone()]);
        }
        args.extend([
            "--name".into(),
            request.name.clone(),
            "--storage".into(),
            request.disk_gb.to_string(),
        ]);
        if request.product == "gpu" {
            args.extend(["--template".into(), request.image.clone()]);
        }
        if !request.location.is_empty() {
            args.extend(["--region".into(), request.location.clone()]);
        }
        args.extend(["--yes".into(), "--json".into()]);
        args
    } else if request.provider == "civo" {
        vec![
            "instance".into(),
            "create".into(),
            "--hostname".into(),
            request.name.clone(),
            "--size".into(),
            request.offer.clone(),
            "--diskimage".into(),
            request.image.clone(),
            "--sshkey".into(),
            request.platform.clone(),
            "--firewall".into(),
            request.firewall.clone(),
            "--region".into(),
            request.location.clone(),
            "--output".into(),
            "json".into(),
        ]
    } else if request.provider == "nebius" {
        let key = ssh_public_key(&request.ssh_public_key).expect("validated SSH public key");
        vec![
            "compute".into(),
            "instance".into(),
            "create".into(),
            "--name".into(),
            request.name.clone(),
            "--parent-id".into(),
            request.location.clone(),
            "--resources-platform".into(),
            request.platform.clone(),
            "--resources-preset".into(),
            request.offer.clone(),
            "--boot-disk-attach-mode".into(),
            "read_write".into(),
            "--boot-disk-managed-disk-type".into(),
            "network_ssd".into(),
            "--boot-disk-managed-disk-size-gibibytes".into(),
            request.disk_gb.to_string(),
            "--boot-disk-managed-disk-source-image-id".into(),
            request.image.clone(),
            "--cloud-init-user-data".into(),
            format!("#cloud-config\nusers:\n  - name: ubuntu\n    groups: sudo\n    shell: /bin/bash\n    sudo: ALL=(ALL) NOPASSWD:ALL\n    ssh_authorized_keys:\n      - {key}\n"),
            "--network-interfaces".into(),
            json!([{
                "name": "eth0", "subnet_id": request.subnet_id,
                "ip_address": {}, "public_ip_address": {}
            }])
            .to_string(),
            "--format".into(),
            "json".into(),
        ]
    } else {
        vec![
            "compute".into(),
            "vms".into(),
            "create".into(),
            "--name".into(),
            request.name.clone(),
            "--type".into(),
            request.offer.clone(),
            "--location".into(),
            request.location.clone(),
            "--image".into(),
            request.image.clone(),
            "--json".into(),
        ]
    }
}

fn identifier(provider: &str, value: &Value) -> Option<String> {
    if matches!(provider, "prime" | "thunder" | "latitude" | "e2e") {
        return provider_commands::id(provider, value);
    }
    if provider == "jarvis_serverless" {
        value["deployment_id"]
            .as_str()
            .or(value["id"].as_str())
            .map(str::to_owned)
    } else if provider == "runpod_serverless" {
        value["id"]
            .as_str()
            .or(value["endpoint"]["id"].as_str())
            .map(str::to_owned)
    } else if provider == "nebius" {
        value["metadata"]["id"]
            .as_str()
            .or(value["id"].as_str())
            .map(str::to_owned)
    } else if provider == "crusoe" {
        value["name"].as_str().map(str::to_owned)
    } else if provider == "jarvis" {
        value["machine_id"].as_u64().map(|id| id.to_string())
    } else if provider == "vast" {
        value["new_contract"]
            .as_u64()
            .map(|id| id.to_string())
            .or_else(|| value["new_contract"].as_str().map(str::to_owned))
    } else {
        value["id"]
            .as_str()
            .or_else(|| value["pod"]["id"].as_str())
            .map(str::to_owned)
    }
}

fn empty_range() -> ResourceRange {
    ResourceRange {
        min: 0.0,
        preferred: 0.0,
        max: 0.0,
        current: 0.0,
    }
}

async fn preflight(request: &CreateRequest) -> Result<(), String> {
    let provider = request.provider.as_str();
    if provider == "runpod" && request.product == "gpu" {
        let inventory = run_with_timeout(
            "runpod",
            &["gpu".into(), "list".into(), "--include-unavailable".into()],
            35,
        )
        .await?;
        pricing::runpod_secure_quote(
            &inventory,
            &request.offer,
            &request.location,
            request.max_hourly_usd.ok_or("Choose a priced RunPod GPU")?,
        )?;
    }
    if matches!(provider, "prime" | "thunder" | "latitude" | "e2e") {
        let value = run(
            provider,
            &accounts::check_args(provider, Some(&request.location))?,
        )
        .await?;
        return if value.is_object() || value.is_array() {
            Ok(())
        } else {
            Err("Provider CLI did not verify account access; no resource was created".into())
        };
    }
    let args: Vec<String> = match provider {
        "runpod" => vec!["user".into()],
        "vast" => vec!["show".into(), "user".into(), "--raw".into()],
        "crusoe" => vec![
            "compute".into(),
            "vms".into(),
            "types".into(),
            "--json".into(),
        ],
        "jarvis" => vec!["status".into(), "--json".into()],
        "civo" => vec![
            "instance".into(),
            "list".into(),
            "--output".into(),
            "json".into(),
        ],
        "nebius" => vec![
            "compute".into(),
            "instance".into(),
            "list".into(),
            "--parent-id".into(),
            request.location.clone(),
            "--format".into(),
            "json".into(),
        ],
        _ => return Err("Unsupported provider".into()),
    };
    run(provider, &args)
        .await
        .and_then(|value| {
            if value.is_object() || value.is_array() {
                Ok(())
            } else {
                Err("The CLI did not return structured account data".into())
            }
        })
        .map_err(|error| format!("Provider CLI is not ready; no resource was created: {error}"))
}

#[tauri::command]
pub async fn neocloud_discover(
    provider: String,
    location: Option<String>,
) -> Result<Value, String> {
    catalog::discover_raw(&provider, location.as_deref()).await
}

/// Compare fresh provider-CLI quotes. Unpriced or differently denominated
/// offers remain visible but never enter the USD ranking.
#[tauri::command]
pub async fn neocloud_prices(
    provider: Option<String>,
    product: Option<String>,
    offer: Option<String>,
    location: Option<String>,
    hours: Option<f64>,
    max_hourly: Option<f64>,
    min_vram_gb: Option<f64>,
    limit: Option<usize>,
) -> Result<Value, String> {
    pricing::compare(
        provider,
        product,
        offer,
        location,
        hours,
        max_hourly,
        min_vram_gb,
        limit,
    )
    .await
}

/// Validate a proposed provider resource without contacting the provider or
/// creating anything. Account readiness and live cost are separate checks.
#[tauri::command]
pub fn neocloud_plan(request: CreateRequest) -> Result<Value, String> {
    validate(&request)?;
    let serverless = request.product == "serverless";
    // Only these provider image fields are OCI images. Other integrations use
    // provider templates, VM image IDs or model IDs and must not be passed to
    // `yougori run` as if they were OCI references.
    let local_image_is_oci = !serverless && matches!(request.provider.as_str(), "runpod" | "vast");
    let local_model =
        serverless && request.provider == "jarvis" && request.image.starts_with("hf.co/");
    let mut local_run_args = if local_image_is_oci {
        Some(vec![
            "run".to_owned(),
            "-d".into(),
            "--name".into(),
            format!("{}-trial", request.name),
        ])
    } else if local_model {
        Some(vec!["model".to_owned(), "run".into()])
    } else {
        None
    };
    if let Some(args) = local_run_args.as_mut() {
        if !local_model && request.product == "gpu" {
            args.extend(["--gpu".into(), "nvidia".into()]);
        }
        args.push(request.image.clone());
    }
    let quote_args = if !serverless && !request.offer.is_empty() {
        Some(vec![
            "neocloud",
            "quote",
            "--provider",
            &request.provider,
            "--offer",
            &request.offer,
            "--product",
            &request.product,
        ])
    } else {
        None
    };
    Ok(json!({
        "validRequest": true,
        "provider": request.provider,
        "product": request.product,
        "name": request.name,
        "offer": request.offer,
        "location": request.location,
        "image": request.image,
        "diskGb": request.disk_gb,
        "providerCli": program(&request.provider)?,
        "accountChecked": false,
        "priceChecked": false,
        "createsBillableResource": true,
        "guestShell": !serverless,
        "fileTransferAfterSsh": !serverless,
        "quoteArgs": quote_args,
        "localTrial": {
            "recommendedType": if serverless { "gpu-model" } else if request.product == "gpu" { "gpu-container" } else { "container" },
            "requiresNvidiaGpu": request.product == "gpu" || serverless,
            "readinessArgs": if request.product == "gpu" || serverless { vec!["gpu","status"] } else { vec!["agent","inventory"] },
            "providerImageIsOci": local_image_is_oci,
            "runArgs": local_run_args,
            "requiresEquivalentLocalImage": !local_image_is_oci && !local_model,
            "checks": [["inspect","TRIAL_ENV_ID"],["logs","TRIAL_ENV_ID"],["exec","TRIAL_ENV_ID","YOUR_CHECK_COMMAND"]],
            "note": "Ask whether to run a local trial first. For provider templates, VM image IDs or non-Hugging Face serverless models, choose a separate equivalent local image. A local trial checks workload behavior, not cloud capacity, pricing, networking or exact disk state."
        },
        "promotion": {
            "automaticDiskClone": false,
            "requiresUserChoice": true,
            "steps": ["Review trial exit status and logs; fix failures before paying for cloud compute", "Compare live Neocloud offers and confirm provider account and total charges", "Create the selected provider resource only after user authorization", "Configure and verify SSH for guest access; transfer only explicitly selected files after creation", "Re-run checks in the cloud environment and stop or delete it according to provider billing rules"]
        },
        "next": "Offer a local trial first. After reviewing its results, use neocloud prices/discover/quote to check cloud options. Create only the user's chosen billable resource and inspect it after creation."
    }))
}

#[tauri::command]
pub async fn create_neocloud_environment(
    request: CreateRequest,
    cost_acknowledged: bool,
    store: State<'_, PlatformStore>,
) -> Result<PlatformState, String> {
    if request.provider != "runpod" || !matches!(request.product.as_str(), "gpu" | "cpu") {
        return Err(
            "Only RunPod GPU and CPU pods are available for new Neocloud deployments right now"
                .into(),
        );
    }
    if !cost_acknowledged {
        return Err("Review and acknowledge provider charges before creation".into());
    }
    validate(&request)?;
    preflight(&request).await?;
    let id = format!("env-{}", uuid::Uuid::new_v4());
    let name = request.name.clone();
    let mut deployment = Deployment {
        provider: request.provider.clone(),
        product: request.product.clone(),
        name: name.clone(),
        resource_id: String::new(),
        state: "Creating".into(),
        image: request.image.clone(),
        offer: request.offer.clone(),
        disk_gb: request.disk_gb,
        location: request.location.clone(),
        address: String::new(),
        ssh_hint: String::new(),
        request_id: uuid::Uuid::new_v4().to_string(),
        last_error: None,
        extra: Value::Null,
    };
    let environment = Environment {
        id: id.clone(),
        name,
        kind: EnvironmentKind::Cloud,
        status: EnvironmentStatus::Provisioning,
        runtime: format!("Neocloud · {} {}", request.provider, request.product),
        provider: Some(RuntimeProviderKind::CloudSsh),
        runtime_id: None,
        runtime_path: None,
        control_endpoint: None,
        console_endpoint: None,
        container_command: None,
        network_access: false,
        gpu_access: request.product == "gpu" || request.product == "serverless",
        sandbox_policy: None,
        last_error: None,
        description: if request.product == "serverless" {
            "Provider-managed model endpoint. No SSH terminal or guest file system.".into()
        } else {
            "Provider-managed compute. Configure SSH after provisioning to use terminals and files."
                .into()
        },
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
    };
    store.mutate(|state| {
        if state
            .environments
            .iter()
            .any(|e| e.name.eq_ignore_ascii_case(&environment.name))
        {
            return Err("An environment with this name already exists".into());
        }
        state.environments.push(environment);
        state
            .neocloud_deployments
            .insert(id.clone(), deployment.clone());
        Ok(())
    })?;
    match run_with_timeout(&request.provider, &create_args(&request), 900).await {
        Ok(value) => {
            let resource_id = if request.provider == "crusoe" {
                // Crusoe uses the VM name for later actions. Verify that the VM
                // exists even if create returned only an operation acknowledgement.
                run(
                    "crusoe",
                    &[
                        "compute".into(),
                        "vms".into(),
                        "get".into(),
                        request.name.clone(),
                        "--json".into(),
                    ],
                )
                .await
                .ok()
                .map(|_| request.name.clone())
            } else if request.provider == "civo" {
                identifier("civo", &value).or_else(|| {
                    // The CLI may print only an acknowledgement on create.
                    // The hostname is a supported identifier for `instance show`.
                    Some(request.name.clone())
                })
            } else {
                identifier(
                    if request.product == "serverless" {
                        if request.provider == "jarvis" {
                            "jarvis_serverless"
                        } else {
                            "runpod_serverless"
                        }
                    } else {
                        &request.provider
                    },
                    &value,
                )
            };
            match resource_id {
                Some(resource_id) => {
                    deployment.resource_id = resource_id;
                    deployment.state = "Created — inspect to verify".into();
                    if request.provider == "crusoe" {
                        match run("crusoe", &action_args(&deployment, "start")?).await {
                            Ok(_) => deployment.state = "start accepted — inspect to verify".into(),
                            Err(error) => {
                                deployment.state = "Needs inspection".into();
                                deployment.last_error =
                                    Some(format!("VM was created but did not start: {error}"));
                            }
                        }
                    }
                    if deployment.last_error.is_none() {
                        if let Err(error) = inspect(&mut deployment).await {
                            deployment.state = "Needs inspection".into();
                            deployment.last_error = Some(format!("Provider resource was created, but its state could not be read: {error}"));
                        }
                    }
                }
                None => {
                    deployment.state = "Needs inspection".into();
                    deployment.last_error = Some("Provider accepted the create command but did not return a verifiable resource ID. Check the provider account before retrying; this resource may be billable.".into());
                }
            }
        }
        Err(error) => {
            deployment.state = "Needs inspection".into();
            deployment.last_error = Some(format!("{error}. Check the provider account before retrying; this resource may be billable."));
        }
    }
    store.mutate(|state| {
        if let Some(env) = state.environments.iter_mut().find(|e| e.id == id) {
            env.status = if deployment.last_error.is_some() {
                EnvironmentStatus::Error
            } else {
                // Cloud environment status describes SSH connectivity. The
                // provider's compute state is tracked separately above.
                EnvironmentStatus::Stopped
            };
            env.last_error = deployment.last_error.clone();
        }
        state.neocloud_deployments.insert(id, deployment);
        Ok(())
    })
}

fn action_args(deployment: &Deployment, action: &str) -> Result<Vec<String>, String> {
    if !token(&deployment.resource_id, 128) {
        return Err("Invalid provider resource ID".into());
    }
    if let Some(args) = provider_commands::action(deployment, action) {
        return args;
    }
    if deployment.resource_id.is_empty() {
        return Err("Inspect the provider account and recover the resource ID first".into());
    }
    let id = deployment.resource_id.clone();
    match (deployment.provider.as_str(), action) {
        ("runpod", "inspect") if deployment.product == "serverless" => {
            Ok(vec!["serverless".into(), "get".into(), id])
        }
        ("runpod", "stop" | "delete") if deployment.product == "serverless" => {
            Ok(vec!["serverless".into(), "delete".into(), id])
        }
        ("jarvis", "inspect") if deployment.product == "serverless" => {
            Ok(vec!["deploy".into(), "get".into(), id, "--json".into()])
        }
        ("jarvis", "stop" | "delete") if deployment.product == "serverless" => Ok(vec![
            "deploy".into(),
            "delete".into(),
            id,
            "--yes".into(),
            "--json".into(),
        ]),
        ("crusoe", "inspect" | "start" | "stop") => Ok(vec![
            "compute".into(),
            "vms".into(),
            action.replace("inspect", "get"),
            id,
            "--json".into(),
        ]),
        ("crusoe", "delete") => Ok(vec![
            "compute".into(),
            "vms".into(),
            "delete".into(),
            id,
            "--yes".into(),
            "--json".into(),
        ]),
        ("runpod", "inspect") => Ok(vec!["pod".into(), "get".into(), id]),
        ("runpod", "start" | "stop" | "delete") => Ok(vec!["pod".into(), action.into(), id]),
        ("vast", "inspect") => Ok(vec!["show".into(), "instance".into(), id, "--raw".into()]),
        ("vast", "start" | "stop") => {
            Ok(vec![action.into(), "instance".into(), id, "--raw".into()])
        }
        ("vast", "delete") => Ok(vec![
            "destroy".into(),
            "instance".into(),
            id,
            "-y".into(),
            "--raw".into(),
        ]),
        ("jarvis", "inspect") => Ok(vec!["get".into(), id, "--json".into()]),
        ("jarvis", "start") => Ok(vec!["resume".into(), id, "--yes".into(), "--json".into()]),
        ("jarvis", "stop") => Ok(vec!["pause".into(), id, "--yes".into(), "--json".into()]),
        ("jarvis", "delete") => Ok(vec!["destroy".into(), id, "--yes".into(), "--json".into()]),
        ("civo", "inspect") => Ok(vec![
            "instance".into(),
            "show".into(),
            id,
            "--region".into(),
            deployment.location.clone(),
            "--output".into(),
            "json".into(),
        ]),
        ("civo", "start" | "stop") => Ok(vec![
            "instance".into(),
            action.into(),
            id,
            "--region".into(),
            deployment.location.clone(),
            "--output".into(),
            "json".into(),
        ]),
        ("civo", "delete") => Ok(vec![
            "instance".into(),
            "remove".into(),
            id,
            "--region".into(),
            deployment.location.clone(),
            "--yes".into(),
            "--output".into(),
            "json".into(),
        ]),
        ("nebius", "inspect" | "start" | "stop" | "delete") => Ok(vec![
            "compute".into(),
            "instance".into(),
            action.replace("inspect", "get"),
            id,
            "--format".into(),
            "json".into(),
        ]),
        _ => Err("Unsupported provider action".into()),
    }
}

fn provider_state(provider: &str, value: &Value) -> String {
    if provider == "nebius" {
        value["status"]["state"]
            .as_str()
            .or(value["state"].as_str())
            .unwrap_or("Unknown")
            .to_owned()
    } else if matches!(
        provider,
        "crusoe" | "jarvis" | "civo" | "prime" | "thunder" | "latitude" | "e2e"
    ) {
        value["state"]
            .as_str()
            .or(value["status"].as_str())
            .unwrap_or("Unknown")
            .to_owned()
    } else if provider == "vast" {
        value["actual_status"]
            .as_str()
            .unwrap_or("Unknown")
            .to_owned()
    } else {
        value["runtimeStatus"]
            .as_str()
            .or(value["desiredStatus"].as_str())
            .unwrap_or("Unknown")
            .to_owned()
    }
}

fn provider_resource_name<'a>(provider: &str, value: &'a Value) -> Option<&'a str> {
    match provider {
        "nebius" => value["metadata"]["name"]
            .as_str()
            .or(value["name"].as_str()),
        "civo" | "latitude" => value["hostname"].as_str(),
        "vast" => value["label"].as_str(),
        _ => value["name"].as_str(),
    }
}

fn stopped(state: &str) -> bool {
    matches!(
        state.to_ascii_lowercase().as_str(),
        "stopped" | "exited" | "paused" | "shutoff" | "off" | "powered off"
    )
}

fn running(state: &str) -> bool {
    matches!(
        state.to_ascii_lowercase().as_str(),
        "running" | "active" | "on"
    )
}

async fn inspect(deployment: &mut Deployment) -> Result<(), String> {
    let value = run(&deployment.provider, &action_args(deployment, "inspect")?).await?;
    let value = provider_commands::resource(&deployment.provider, &deployment.resource_id, value)?;
    deployment.state = provider_state(&deployment.provider, &value);
    if matches!(
        deployment.provider.as_str(),
        "prime" | "thunder" | "latitude" | "e2e"
    ) {
        deployment.address = value["ip"]
            .as_str()
            .or(value["primary_ipv4"].as_str())
            .or(value["public_ip_address"].as_str())
            .unwrap_or("")
            .into();
        deployment.ssh_hint = value["ssh"].as_str().unwrap_or("").into();
    } else if deployment.provider == "runpod" && deployment.product == "serverless" {
        deployment.state = value["status"].as_str().unwrap_or("Unknown").to_owned();
        deployment.address = format!("https://api.runpod.ai/v2/{}/run", deployment.resource_id);
        deployment.ssh_hint.clear();
    } else if deployment.provider == "runpod" {
        deployment.address = value["ssh"]["ip"].as_str().unwrap_or("").into();
        deployment.ssh_hint = value["ssh"]["ssh_command"].as_str().unwrap_or("").into();
    } else if deployment.provider == "vast" {
        deployment.address = value["ssh_host"].as_str().unwrap_or("").into();
        if let (Some(host), Some(port)) = (value["ssh_host"].as_str(), value["ssh_port"].as_u64()) {
            deployment.ssh_hint = format!("ssh -p {port} root@{host}");
        }
    } else if deployment.provider == "crusoe" {
        deployment.address = value["public_ip"]
            .as_str()
            .or(value["publicIp"].as_str())
            .unwrap_or("")
            .into();
    } else if deployment.provider == "jarvis" && deployment.product == "serverless" {
        deployment.ssh_hint.clear();
        deployment.address = value["openai_base_url"].as_str().unwrap_or("").into();
    } else if deployment.provider == "jarvis" {
        deployment.ssh_hint = value["ssh_command"].as_str().unwrap_or("").into();
        deployment.address = value["public_ip"].as_str().unwrap_or("").into();
    } else if deployment.provider == "civo" {
        deployment.address = value["public_ip"].as_str().unwrap_or("").into();
        if let Some(user) = value["initial_user"].as_str() {
            if !deployment.address.is_empty() {
                deployment.ssh_hint = format!("ssh {user}@{}", deployment.address);
            }
        }
    } else if deployment.provider == "nebius" {
        deployment.address = value["status"]["network_interfaces"][0]["public_ip_address"]
            ["address"]
            .as_str()
            .or(value["status"]["networkInterfaces"][0]["publicIpAddress"]["address"].as_str())
            .unwrap_or("")
            .into();
        deployment.ssh_hint = if deployment.address.is_empty() {
            String::new()
        } else {
            format!("ssh ubuntu@{}", deployment.address)
        };
    }
    Ok(())
}

/// Reconcile an ambiguous create with an ID copied from the provider account.
/// Inspect first: a guessed ID is never attached to a Yougori node.
#[tauri::command]
pub async fn neocloud_recover_id(
    environment_id: String,
    resource_id: String,
    store: State<'_, PlatformStore>,
) -> Result<PlatformState, String> {
    let lock = crate::commands::environment_network_lock(&environment_id).await;
    let _guard = lock.lock().await;
    let state = store.snapshot()?;
    let mut deployment = state
        .neocloud_deployments
        .get(&environment_id)
        .cloned()
        .ok_or("Neocloud deployment not found")?;
    if !deployment.resource_id.is_empty() {
        return Err("This node already has a provider resource ID".into());
    }
    if deployment.provider == "vast" {
        if !resource_id.parse::<u64>().is_ok_and(|id| id > 0) {
            return Err("Enter a numeric Vast.ai instance ID".into());
        }
    } else if !token(&resource_id, 128) {
        return Err("Enter a valid provider resource ID".into());
    }
    if state.neocloud_deployments.iter().any(|(id, other)| {
        id != &environment_id
            && other.provider == deployment.provider
            && other.resource_id == resource_id
    }) {
        return Err("This provider resource is already attached to another Neocloud node".into());
    }
    deployment.resource_id = resource_id;
    let details = run(&deployment.provider, &action_args(&deployment, "inspect")?).await?;
    let details =
        provider_commands::resource(&deployment.provider, &deployment.resource_id, details)?;
    if let Some(name) = provider_resource_name(&deployment.provider, &details)
        .filter(|_| deployment.provider != "thunder")
    {
        if name != deployment.name {
            return Err(format!("This provider resource is named {name}, not {}. Attach the resource created for this node.", deployment.name));
        }
    }
    inspect(&mut deployment).await?;
    deployment.last_error = None;
    store.mutate(|state| {
        if let Some(env) = state
            .environments
            .iter_mut()
            .find(|e| e.id == environment_id)
        {
            env.status = EnvironmentStatus::Stopped;
            env.last_error = None;
        }
        state
            .neocloud_deployments
            .insert(environment_id, deployment);
        Ok(())
    })
}

fn contains_resource_id(value: &Value, id: &str) -> bool {
    match value {
        Value::Array(items) => items.iter().any(|item| contains_resource_id(item, id)),
        Value::Object(fields) => {
            fields.iter().any(|(key, value)| {
                (key == "id" || key == "deployment_id") && value.as_str() == Some(id)
            }) || fields.values().any(|value| contains_resource_id(value, id))
        }
        _ => false,
    }
}

async fn serverless_absent(provider: &str, id: &str) -> Result<bool, String> {
    let args = if provider == "jarvis" {
        vec!["deploy".into(), "list".into(), "--json".into()]
    } else {
        vec!["serverless".into(), "list".into()]
    };
    let list = run(provider, &args).await?;
    if !list.is_object() && !list.is_array() {
        return Err("The provider did not return a structured deployment list".into());
    }
    Ok(!contains_resource_id(&list, id))
}

fn listed_resource(value: &Value, id: &str, provider: &str) -> bool {
    match value {
        Value::Array(items) => items.iter().any(|item| listed_resource(item, id, provider)),
        Value::Object(fields) => fields.iter().any(|(key, value)| {
            let identity = matches!(key.as_str(), "id" | "machine_id" | "pod_id" | "resource_id")
                || (provider == "crusoe" && key == "name");
            let matched = identity
                && (value.as_str() == Some(id)
                    || value
                        .as_u64()
                        .is_some_and(|number| number.to_string() == id));
            matched || listed_resource(value, id, provider)
        }),
        _ => false,
    }
}

async fn provider_resource_absent(deployment: &Deployment) -> Result<bool, String> {
    if deployment.provider == "thunder" {
        let list = run("thunder", &["status".into(), "--json".into()]).await?;
        if !list.is_array() {
            return Err("Thunder did not return an instance list".into());
        }
        return Ok(!listed_resource(&list, &deployment.resource_id, "thunder"));
    }
    let list_args: Vec<String> = match deployment.provider.as_str() {
        "prime" => vec![
            "pods".into(),
            "list".into(),
            "--output".into(),
            "json".into(),
        ],
        "latitude" => vec!["servers".into(), "list".into(), "-o".into(), "json".into()],
        "e2e" => {
            let (project, region) = provider_commands::e2e_context(&deployment.location)?;
            vec![
                "--project_id".into(),
                project.into(),
                "--location".into(),
                region.into(),
                "node".into(),
                "list".into(),
            ]
        }
        "runpod" => vec!["pod".into(), "list".into(), "--all".into()],
        "vast" => vec!["show".into(), "instances".into(), "--raw".into()],
        "crusoe" => vec![
            "compute".into(),
            "vms".into(),
            "list".into(),
            "--json".into(),
        ],
        "jarvis" => vec!["list".into(), "--json".into()],
        "civo" => vec![
            "instance".into(),
            "list".into(),
            "--region".into(),
            deployment.location.clone(),
            "--output".into(),
            "json".into(),
        ],
        "nebius" => vec![
            "compute".into(),
            "instance".into(),
            "list".into(),
            "--parent-id".into(),
            deployment.location.clone(),
            "--all".into(),
            "--format".into(),
            "json".into(),
        ],
        _ => return Err("Unsupported provider".into()),
    };
    let get_result = run(&deployment.provider, &action_args(deployment, "inspect")?).await;
    if get_result.is_ok() {
        return Ok(false);
    }
    let error = get_result.err().unwrap_or_default().to_ascii_lowercase();
    if !(error.contains("not found") || error.contains("no such") || error.contains("404")) {
        return Err(
            "The provider could not confirm deletion; check its account before removing this node"
                .into(),
        );
    }
    let list = run(&deployment.provider, &list_args).await?;
    if !list.is_object() && !list.is_array() {
        return Err(
            "The provider did not return a structured resource list to verify deletion".into(),
        );
    }
    Ok(!listed_resource(
        &list,
        &deployment.resource_id,
        &deployment.provider,
    ))
}

async fn serverless_action(
    environment_id: &str,
    action: &str,
    mut deployment: Deployment,
    store: &PlatformStore,
) -> Result<PlatformState, String> {
    if !matches!(action, "inspect" | "start" | "stop" | "delete") {
        return Err("Unsupported serverless action".into());
    }
    if matches!(action, "stop" | "delete")
        && (deployment.state.starts_with("Stop requested")
            || deployment.state.starts_with("Delete requested"))
    {
        return Err("Refresh the provider state before sending another delete request".into());
    }
    if action == "start" {
        if !deployment.resource_id.is_empty() || deployment.state != "Stopped" {
            return Err(
                "Verify that the previous serverless deployment is gone before starting another"
                    .into(),
            );
        }
        deployment.state = "Creating".into();
        deployment.last_error = None;
        store.mutate(|state| {
            state
                .neocloud_deployments
                .insert(environment_id.to_owned(), deployment.clone());
            Ok(())
        })?;
        let request = CreateRequest {
            cpu_cores: 0,
            memory_gb: 0,
            gpu_count: 1,
            max_hourly_usd: None,
            provider: deployment.provider.clone(),
            product: "serverless".into(),
            name: deployment.name.clone(),
            image: deployment.image.clone(),
            offer: deployment.offer.clone(),
            location: deployment.location.clone(),
            disk_gb: deployment.disk_gb,
            subnet_id: String::new(),
            platform: String::new(),
            ssh_public_key: String::new(),
            firewall: String::new(),
        };
        match run_with_timeout(&deployment.provider, &create_args(&request), 900).await {
            Ok(value) => {
                let provider_kind = if deployment.provider == "jarvis" {
                    "jarvis_serverless"
                } else {
                    "runpod_serverless"
                };
                if let Some(id) = identifier(provider_kind, &value) {
                    deployment.resource_id = id;
                    deployment.state = "Creating — inspect to verify".into();
                    if let Err(error) = inspect(&mut deployment).await {
                        deployment.last_error = Some(format!(
                            "Deployment was created; inspect it at the provider: {error}"
                        ));
                    }
                } else {
                    deployment.state = "Needs inspection".into();
                    deployment.last_error = Some("The provider accepted creation without a deployment ID. Check your account before retrying.".into());
                }
            }
            Err(error) => {
                deployment.state = "Needs inspection".into();
                deployment.last_error = Some(format!(
                    "{error}. Check the provider before retrying; a deployment may exist."
                ));
            }
        }
    } else if deployment.resource_id.is_empty() {
        if action == "delete" && deployment.state == "Stopped" {
            deployment.state = "Deleted".into();
            deployment.last_error = None;
        } else {
            return Err("Recover the provider deployment ID before managing this node".into());
        }
    } else if action == "inspect" {
        let deletion_requested = deployment.state.starts_with("Delete requested");
        let stop_requested = deployment.state.starts_with("Stop requested");
        if deletion_requested || stop_requested {
            match serverless_absent(&deployment.provider, &deployment.resource_id).await {
                Ok(true) => {
                    deployment.resource_id.clear();
                    deployment.address.clear();
                    deployment.state = if deletion_requested {
                        "Deleted"
                    } else {
                        "Stopped"
                    }
                    .into();
                    deployment.last_error = None;
                }
                Ok(false) => {
                    deployment.state = "Needs inspection".into();
                    deployment.last_error = Some("The provider still lists this endpoint. Check whether deletion is in progress, then refresh or retry the action.".into());
                }
                Err(error) => deployment.last_error = Some(error),
            }
        } else {
            match inspect(&mut deployment).await {
                Ok(()) => deployment.last_error = None,
                Err(error) => {
                    match serverless_absent(&deployment.provider, &deployment.resource_id).await {
                        Ok(true) => {
                            deployment.resource_id.clear();
                            deployment.address.clear();
                            deployment.state = "Stopped".into();
                            deployment.last_error = None;
                        }
                        Ok(false) | Err(_) => deployment.last_error = Some(error),
                    }
                }
            }
        }
    } else {
        let intent = if action == "delete" {
            "Delete requested"
        } else {
            "Stop requested"
        };
        deployment.state = intent.into();
        deployment.last_error = None;
        store.mutate(|state| {
            state
                .neocloud_deployments
                .insert(environment_id.to_owned(), deployment.clone());
            Ok(())
        })?;
        match run(&deployment.provider, &action_args(&deployment, action)?).await {
            Ok(_) => match serverless_absent(&deployment.provider, &deployment.resource_id).await {
                Ok(true) => {
                    deployment.resource_id.clear();
                    deployment.address.clear();
                    deployment.state = if action == "delete" {
                        "Deleted"
                    } else {
                        "Stopped"
                    }
                    .into();
                }
                Ok(false) => {
                    deployment.state = "Needs inspection".into();
                    deployment.last_error = Some("The provider still lists this endpoint. Check whether deletion is in progress, then refresh or retry the action.".into());
                }
                Err(error) => {
                    deployment.last_error = Some(format!(
                        "{intent}; provider list could not verify completion: {error}"
                    ))
                }
            },
            Err(error) => {
                deployment.last_error = Some(format!(
                    "{intent}; check the provider before retrying: {error}"
                ))
            }
        }
    }
    let error = deployment.last_error.clone();
    let result = store.mutate(|state| {
        if let Some(env) = state
            .environments
            .iter_mut()
            .find(|env| env.id == environment_id)
        {
            env.status = if error.is_some() {
                EnvironmentStatus::Error
            } else {
                EnvironmentStatus::Stopped
            };
            env.last_error = error.clone();
        }
        state
            .neocloud_deployments
            .insert(environment_id.to_owned(), deployment);
        Ok(())
    })?;
    if let Some(error) = error {
        Err(error)
    } else {
        Ok(result)
    }
}

fn finish_provider_deletion(
    store: &PlatformStore,
    environment_id: &str,
    mut deployment: Deployment,
    verification: Result<bool, String>,
) -> Result<PlatformState, String> {
    deployment.last_error = verification.as_ref().err().cloned();
    if let Ok(gone) = &verification {
        if *gone {
            deployment.state = "Deleted".into();
        } else {
            deployment.state = "Needs inspection".into();
            deployment.last_error = Some("The provider still lists this resource. Deletion may be in progress; refresh its state or retry deletion after checking the provider account.".into());
        }
    }
    let result = store.mutate(|state| {
        if let Some(env) = state.environments.iter_mut().find(|e| e.id == environment_id) {
            env.status = if deployment.last_error.is_some() {
                EnvironmentStatus::Error
            } else {
                EnvironmentStatus::Stopped
            };
            env.last_error = deployment.last_error.clone();
        }
        state.neocloud_deployments.insert(environment_id.to_owned(), deployment);
        Ok(())
    })?;
    verification.map(|_| result)
}

#[tauri::command]
pub async fn neocloud_action(
    environment_id: String,
    action: String,
    confirmation: Option<String>,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
) -> Result<PlatformState, String> {
    let lock = crate::commands::environment_network_lock(&environment_id).await;
    let _guard = lock.lock().await;
    let mut deployment = store
        .snapshot()?
        .neocloud_deployments
        .get(&environment_id)
        .cloned()
        .ok_or("Neocloud deployment not found")?;
    if deployment.state == "Deleted" {
        return Err("This provider resource was deleted".into());
    }
    if action == "delete" && confirmation.as_deref() != Some(&deployment.name) {
        return Err("Type the exact resource name to delete it".into());
    }
    if deployment.provider == "runpod" && deployment.product == "serverless" {
        return runpod::endpoint_action(&environment_id, &action, &store).await;
    }
    if deployment.product == "serverless" {
        return serverless_action(&environment_id, &action, deployment, &store).await;
    }
    if deployment.state.starts_with("Delete requested") {
        if action != "inspect" {
            return Err("Refresh deletion status before sending another provider action".into());
        }
        let verification = provider_resource_absent(&deployment).await;
        return finish_provider_deletion(&store, &environment_id, deployment, verification);
    }
    let args = action_args(&deployment, &action)?;
    if action == "delete" {
        deployment.state = "Delete requested — verification pending".into();
        deployment.last_error = None;
        store.mutate(|state| {
            state
                .neocloud_deployments
                .insert(environment_id.clone(), deployment.clone());
            Ok(())
        })?;
        runtime.cloud.disconnect(&environment_id).await;
        let operation = run(&deployment.provider, &args).await;
        let verification = match operation {
            Ok(_) => provider_resource_absent(&deployment).await,
            Err(error) => Err(format!("Delete command could not be verified: {error}. Check the provider account before retrying.")),
        };
        return finish_provider_deletion(&store, &environment_id, deployment, verification);
    }
    if matches!(action.as_str(), "stop" | "delete") {
        runtime.cloud.disconnect(&environment_id).await;
    }
    let result = if action == "inspect" {
        inspect(&mut deployment).await.map(|_| json!({}))
    } else {
        run(&deployment.provider, &args).await
    };
    match result {
        Ok(value) => {
            deployment.last_error = None;
            if action == "inspect" { /* `inspect` populated the verified state above. */
            } else {
                // JarvisLabs may allocate a different machine ID on resume.
                if deployment.provider == "jarvis" && action == "start" {
                    if let Some(id) = identifier("jarvis", &value) {
                        deployment.resource_id = id;
                    }
                }
                // An accepted power command is not proof that billing stopped.
                // Poll briefly, then keep an explicit pending state for the user.
                let mut verified = false;
                for attempt in 0..6 {
                    if attempt > 0 {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                    match inspect(&mut deployment).await {
                        Ok(())
                            if (action == "stop" && stopped(&deployment.state))
                                || (action == "start" && running(&deployment.state)) =>
                        {
                            verified = true;
                            break;
                        }
                        Ok(()) => {}
                        Err(_) => {}
                    }
                }
                if !verified {
                    deployment.state = format!(
                        "{} pending — not verified",
                        if action == "stop" {
                            "Stop"
                        } else if action == "start" {
                            "Start"
                        } else {
                            "Inspect"
                        }
                    );
                    // The CLI accepted the power operation; a transition can
                    // take longer than our short poll. Keep it pending rather
                    // than reporting a false failure or a verified stop.
                }
            }
        }
        Err(error) => {
            deployment.state = "Needs inspection".into();
            deployment.last_error = Some(format!("{action} could not be verified: {error}"));
        }
    }
    let failed = deployment.last_error.is_some();
    let result = store.mutate(|state| {
        if let Some(env) = state
            .environments
            .iter_mut()
            .find(|e| e.id == environment_id)
        {
            if !failed && (action == "stop" || action == "delete") {
                env.status = EnvironmentStatus::Stopped;
            } else if !failed && env.status == EnvironmentStatus::Error {
                env.status = EnvironmentStatus::Stopped;
            }
            if failed {
                env.status = EnvironmentStatus::Error;
            }
            env.last_error = deployment.last_error.clone();
        }
        state
            .neocloud_deployments
            .insert(environment_id.clone(), deployment.clone());
        Ok(())
    })?;
    if failed {
        return Err(deployment.last_error.unwrap_or_default());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn test_ssh_key() -> String {
        let mut blob = Vec::new();
        blob.extend_from_slice(&11_u32.to_be_bytes());
        blob.extend_from_slice(b"ssh-ed25519");
        blob.extend_from_slice(&32_u32.to_be_bytes());
        blob.extend_from_slice(&[7_u8; 32]);
        format!(
            "ssh-ed25519 {}",
            base64::engine::general_purpose::STANDARD.encode(blob)
        )
    }

    #[test]
    fn plans_are_argument_arrays_and_reject_untrusted_values() {
        let request = CreateRequest {
            cpu_cores: 0,
            memory_gb: 0,
            gpu_count: 1,
            max_hourly_usd: None,
            provider: "vast".into(),
            product: "gpu".into(),
            name: "training-1".into(),
            image: "vastai/pytorch:latest".into(),
            offer: "12345".into(),
            location: String::new(),
            disk_gb: 40,
            subnet_id: String::new(),
            platform: String::new(),
            ssh_public_key: String::new(),
            firewall: String::new(),
        };
        validate(&request).unwrap();
        assert_eq!(create_args(&request)[..3], ["create", "instance", "12345"]);
        assert!(validate(&CreateRequest {
            name: "bad name; rm -rf /".into(),
            ..request
        })
        .is_err());
    }

    #[test]
    fn runpod_pod_and_vast_instance_ids_are_parsed() {
        assert_eq!(
            identifier("runpod", &json!({"id":"pod-1"})).as_deref(),
            Some("pod-1")
        );
        assert_eq!(
            identifier("vast", &json!({"new_contract":123})).as_deref(),
            Some("123")
        );
        assert_eq!(
            identifier("jarvis", &json!({"machine_id":456})).as_deref(),
            Some("456")
        );
        assert!(stopped("Paused"));
        assert!(!stopped("Stop pending — not verified"));
        assert!(running("RUNNING"));
        assert!(!running("initializing"));
    }

    #[test]
    fn agent_plan_uses_real_provider_validation_without_creating_compute() {
        let request = CreateRequest {
            cpu_cores: 0,
            memory_gb: 0,
            gpu_count: 1,
            max_hourly_usd: None,
            provider: "vast".into(),
            product: "gpu".into(),
            name: "training-1".into(),
            image: "vastai/pytorch:latest".into(),
            offer: "12345".into(),
            location: String::new(),
            disk_gb: 40,
            subnet_id: String::new(),
            platform: String::new(),
            ssh_public_key: String::new(),
            firewall: String::new(),
        };
        let plan = neocloud_plan(request).unwrap();
        assert_eq!(plan["validRequest"], true);
        assert_eq!(plan["accountChecked"], false);
        assert_eq!(plan["priceChecked"], false);
        assert_eq!(plan["quoteArgs"][5], "12345");
        assert!(plan["guestShell"].as_bool().unwrap());
        assert_eq!(plan["localTrial"]["recommendedType"], "gpu-container");
        assert_eq!(
            plan["localTrial"]["runArgs"],
            json!([
                "run",
                "-d",
                "--name",
                "training-1-trial",
                "--gpu",
                "nvidia",
                "vastai/pytorch:latest"
            ])
        );
        let trial_args = plan["localTrial"]["runArgs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|arg| arg.as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        let local = yougori_cli::public::parse_run(&trial_args[1..], false).unwrap();
        assert_eq!(local.request["provider"], "yougoriCuda");
        assert_eq!(local.request["runtime"], "vastai/pytorch:latest");
        assert_eq!(plan["promotion"]["automaticDiskClone"], false);
        let invalid: CreateRequest = serde_json::from_value(json!({
            "provider":"vast", "product":"gpu", "name":"bad name", "image":"ubuntu:24.04",
            "offer":"12345", "diskGb":20
        }))
        .unwrap();
        assert!(neocloud_plan(invalid).is_err());
    }

    #[test]
    fn provider_vm_images_are_not_misrepresented_as_local_oci_trials() {
        let request: CreateRequest = serde_json::from_value(json!({
            "provider":"civo", "product":"cpu", "name":"web", "image":"ubuntu-jammy",
            "offer":"g4s.kube.small", "location":"LON1", "diskGb":0,
            "platform":"ssh-key", "firewall":"firewall-id"
        }))
        .unwrap();
        let plan = neocloud_plan(request).unwrap();
        assert_eq!(plan["localTrial"]["recommendedType"], "container");
        assert_eq!(plan["localTrial"]["providerImageIsOci"], false);
        assert_eq!(plan["localTrial"]["runArgs"], Value::Null);
        assert_eq!(plan["localTrial"]["requiresEquivalentLocalImage"], true);
    }

    #[test]
    fn jarvis_resume_uses_the_current_machine_id_and_noninteractive_json() {
        let request = CreateRequest {
            cpu_cores: 0,
            memory_gb: 0,
            gpu_count: 1,
            max_hourly_usd: None,
            provider: "jarvis".into(),
            product: "gpu".into(),
            name: "trainer".into(),
            image: "pytorch".into(),
            offer: "A100".into(),
            location: String::new(),
            disk_gb: 40,
            subnet_id: String::new(),
            platform: String::new(),
            ssh_public_key: String::new(),
            firewall: String::new(),
        };
        validate(&request).unwrap();
        assert_eq!(
            create_args(&request),
            vec![
                "create",
                "--gpu",
                "A100",
                "--name",
                "trainer",
                "--storage",
                "40",
                "--template",
                "pytorch",
                "--yes",
                "--json"
            ]
        );
        let deployment = Deployment {
            provider: "jarvis".into(),
            product: "gpu".into(),
            name: "trainer".into(),
            resource_id: "51".into(),
            state: "Paused".into(),
            image: "pytorch".into(),
            offer: "A100".into(),
            disk_gb: 40,
            location: String::new(),
            address: String::new(),
            ssh_hint: String::new(),
            request_id: String::new(),
            last_error: None,
            extra: Value::Null,
        };
        assert_eq!(
            action_args(&deployment, "start").unwrap(),
            vec!["resume", "51", "--yes", "--json"]
        );
        assert_eq!(
            action_args(&deployment, "stop").unwrap(),
            vec!["pause", "51", "--yes", "--json"]
        );
    }

    #[test]
    fn cpu_and_vm_providers_use_noninteractive_verified_plans() {
        let cpu = CreateRequest {
            cpu_cores: 0,
            memory_gb: 0,
            gpu_count: 1,
            max_hourly_usd: None,
            provider: "jarvis".into(),
            product: "cpu".into(),
            name: "build-vm".into(),
            image: "cpu-vm".into(),
            offer: String::new(),
            location: String::new(),
            disk_gb: 40,
            subnet_id: String::new(),
            platform: String::new(),
            ssh_public_key: String::new(),
            firewall: String::new(),
        };
        validate(&cpu).unwrap();
        let args = create_args(&cpu);
        assert!(args.windows(2).any(|pair| pair == ["--vm", "--cpu"]));
        assert!(!args.contains(&"--template".to_owned()));

        let civo = CreateRequest {
            cpu_cores: 0,
            memory_gb: 0,
            gpu_count: 1,
            max_hourly_usd: None,
            provider: "civo".into(),
            product: "cpu".into(),
            name: "build-vm".into(),
            image: "ubuntu-noble".into(),
            offer: "g4s.small".into(),
            location: "LON1".into(),
            disk_gb: 0,
            subnet_id: String::new(),
            platform: "my-key".into(),
            ssh_public_key: String::new(),
            firewall: "my-firewall".into(),
        };
        validate(&civo).unwrap();
        assert!(create_args(&civo)
            .windows(2)
            .any(|pair| pair == ["--output", "json"]));
        assert!(stopped(&provider_state(
            "civo",
            &json!({"status":"SHUTOFF"})
        )));

        let nebius = CreateRequest {
            cpu_cores: 0,
            memory_gb: 0,
            gpu_count: 1,
            max_hourly_usd: None,
            provider: "nebius".into(),
            product: "gpu".into(),
            name: "train-vm".into(),
            image: "image-1".into(),
            offer: "gpu-preset".into(),
            location: "project-1".into(),
            disk_gb: 100,
            subnet_id: "subnet-1".into(),
            platform: "gpu-platform".into(),
            ssh_public_key: test_ssh_key(),
            firewall: String::new(),
        };
        validate(&nebius).unwrap();
        let args = create_args(&nebius);
        let network = args
            .iter()
            .position(|arg| arg == "--network-interfaces")
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&args[network + 1]).unwrap()[0]["subnet_id"],
            "subnet-1"
        );
        assert_eq!(
            identifier("nebius", &json!({"metadata":{"id":"instance-1"}})).as_deref(),
            Some("instance-1")
        );
        assert!(validate(&CreateRequest {
            subnet_id: String::new(),
            ..nebius
        })
        .is_err());
        assert!(
            ssh_public_key("ssh-ed25519 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").is_none()
        );
        assert!(ssh_public_key(&test_ssh_key()).is_some());
    }

    #[test]
    fn jarvis_serverless_uses_detached_zero_minimum_workers_and_requires_verified_id() {
        let request = CreateRequest {
            cpu_cores: 0,
            memory_gb: 0,
            gpu_count: 1,
            max_hourly_usd: None,
            provider: "jarvis".into(),
            product: "serverless".into(),
            name: "qwen-api".into(),
            image: "Qwen/Qwen3-0.6B".into(),
            offer: "L4".into(),
            location: "IN2".into(),
            disk_gb: 50,
            subnet_id: String::new(),
            platform: String::new(),
            ssh_public_key: String::new(),
            firewall: String::new(),
        };
        validate(&request).unwrap();
        let args = create_args(&request);
        assert_eq!(&args[..2], ["deploy", "create"]);
        assert!(args.windows(2).any(|pair| pair == ["--min-workers", "0"]));
        assert!(args.contains(&"--detach".into()));
        assert_eq!(
            identifier("jarvis_serverless", &json!({"deployment_id":"deploy-1"})).as_deref(),
            Some("deploy-1")
        );
        assert!(contains_resource_id(
            &json!({"deployments":[{"id":"deploy-1"}]}),
            "deploy-1"
        ));
        assert!(!contains_resource_id(
            &json!({"deployments":[{"id":"deploy-2"}]}),
            "deploy-1"
        ));
    }

    #[test]
    fn runpod_serverless_requires_a_hub_id_and_zero_minimum_workers() {
        let request = CreateRequest {
            cpu_cores: 0,
            memory_gb: 0,
            gpu_count: 1,
            max_hourly_usd: None,
            provider: "runpod".into(),
            product: "serverless".into(),
            name: "model-api".into(),
            image: "cm8h09d9n000008jvh2rqdsmb".into(),
            offer: "NVIDIA A40".into(),
            location: String::new(),
            disk_gb: 0,
            subnet_id: String::new(),
            platform: String::new(),
            ssh_public_key: String::new(),
            firewall: String::new(),
        };
        validate(&request).unwrap();
        let args = create_args(&request);
        assert_eq!(&args[..2], ["serverless", "create"]);
        assert!(args
            .windows(2)
            .any(|pair| pair == ["--hub-id", "cm8h09d9n000008jvh2rqdsmb"]));
        assert!(args.windows(2).any(|pair| pair == ["--workers-min", "0"]));
        assert_eq!(
            identifier("runpod_serverless", &json!({"endpoint":{"id":"ep-1"}})).as_deref(),
            Some("ep-1")
        );
        assert!(validate(&CreateRequest {
            name: "ab".into(),
            ..request
        })
        .is_err());
    }

    #[test]
    fn deletion_verification_finds_provider_resource_ids_in_structured_lists() {
        assert!(listed_resource(
            &json!({"instances":[{"id":"vm-1"}]}),
            "vm-1",
            "civo"
        ));
        assert!(listed_resource(
            &json!({"instances":[{"machine_id":51}]}),
            "51",
            "jarvis"
        ));
        assert!(listed_resource(
            &json!({"vms":[{"name":"training-1"}]}),
            "training-1",
            "crusoe"
        ));
        assert!(!listed_resource(
            &json!({"instances":[{"id":"vm-2"}]}),
            "vm-1",
            "civo"
        ));
    }
}
