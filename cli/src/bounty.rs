//! Swarm Mining's human CLI. Worker credentials and private agent channels stay in the engine.
use crate::{cli_ui as ui, model_invocation, public::call};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use serde_json::{json, Value};
use std::{collections::BTreeSet, future::Future, time::Duration};

pub const HELP: &str = r#"Swarm Mining — your model, your worker, your choice of bounty.

  yougori start bounty [--model hf.co/OWNER/MODEL] [OPTIONS]
  yougori bounty workers
  yougori bounty bounties [WORKER]
  yougori bounty apply WORKER BOUNTY --version N --terms-digest DIGEST --yes
  yougori bounty status|offers|chat|messages|pause|resume|stop WORKER
  yougori bounty details WORKER OFFER
  yougori bounty accept WORKER OFFER --version N --terms-digest DIGEST
                         --authorization-digest DIGEST --report-policy automatic|review
                         --budget-minutes N --accept-rules --accept-authorization
                         --accept-direct-payment --yes
  yougori bounty skip WORKER OFFER
  yougori bounty chat WORKER --message "Suggest a direction"
  yougori bounty submit WORKER REPORT_ID --yes
  yougori bounty leave WORKER --yes
  yougori bounty delete WORKER --yes
  yougori bounty reports|rewards [WORKER]
  yougori bounty doctor [WORKER]

Setup options:
  --cpu CORES --memory GB --gpu nvidia|cpu --storage-drive PATH
  --workspace-quota GB --name NAME --quant VARIANT --release-memory
  --worker WORKER (resume the saved model and resources)
  --platform-url HTTPS_URL (HTTP loopback supported for local development)
  --yes --no-wait (scripted start: prints the worker at once; never accepts a bounty)
  --dry-run (validate and show requests without contacting the engine)

Without --gpu the worker uses an NVIDIA GPU only when this PC passes the CUDA
checks of yougori gpu status; otherwise the processor runs the model.

Paste a Hugging Face model first. Yougori prepares a private local model API and
OpenCode, then waits for offers without agent inference. Once online it offers a
safe, offline practice bounty you can try while you wait. Review the company,
objective, exact source authorization and publisher payment promise before accepting.
With report policy review, a finished draft shows as report ready: read it with
bounty reports, then send it with bounty submit. Leaving ends the accepted bounty.
An engine restart pauses every worker until you resume it.
The publisher pays a qualifying winner externally from its own wallet. Payment is
not prefunded, verified or guaranteed by Yougori. No Swarm withdrawal or transfer
command is provided. Never supply a wallet private key or seed phrase.
Humans chat only with
their own agent; private agent channels have no human CLI command.
Authorized local defensive research only. Do not use this service maliciously,
bypass safeguards, or falsify evidence. Open source modification rights remain.
Read https://yougori.com/swarm/rules and the exact rules in your offer.
Publisher assertions do not grant rights over third parties or live systems.

Ctrl+C opens Cancel / Pause / Stop / Stop and delete. Ctrl+] detaches and keeps
the engine's worker running. Deletion keeps submitted reports and reward records.
An environment named bounty can still start with: yougori env start bounty
or: yougori start --environment bounty
"#;

#[derive(Clone, Debug)]
pub struct Invocation {
    pub request: Value,
    pub dry_run: bool,
    pub yes: bool,
    pub no_wait: bool,
    pub interactive_start: bool,
}

fn clean(value: &str, name: &str, max: usize) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(format!(
            "{name} must contain 1 to {max} bytes and no control characters"
        ));
    }
    Ok(value.into())
}

fn number(value: &str, name: &str, min: f64, max: f64) -> Result<f64, String> {
    let raw = value.trim_end_matches(['G', 'B', 'g', 'b']);
    let value = raw
        .parse::<f64>()
        .map_err(|_| format!("{name} must be a number"))?;
    if !value.is_finite() || value < min || value > max {
        return Err(format!("{name} must be between {min} and {max}"));
    }
    Ok(value)
}

pub fn model(value: &str) -> Result<String, String> {
    let value = model_invocation::model_id(value)?;
    if !value.starts_with("hf.co/") {
        return Err("Paste a Hugging Face model: hf.co/OWNER/MODEL".into());
    }
    Ok(value)
}

/// The engine's rule for worker and report IDs.
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
}

fn sha256_hex(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|s| s.len() == 64 && s.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

pub fn source_authorization_digest(document: &Value) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    fn canonical(value: &Value) -> Value {
        match value {
            Value::Object(object) => {
                let mut keys = object.keys().collect::<Vec<_>>();
                keys.sort();
                let mut sorted = serde_json::Map::new();
                for key in keys {
                    sorted.insert(key.clone(), canonical(&object[key]));
                }
                Value::Object(sorted)
            }
            Value::Array(values) => Value::Array(values.iter().map(canonical).collect()),
            _ => value.clone(),
        }
    }
    Ok(format!(
        "{:x}",
        Sha256::digest(
            serde_json::to_vec(&canonical(document)).map_err(|error| error.to_string())?
        )
    ))
}

/// Both CLI consent and the native supervisor verify the same immutable source
/// authorization. This validates its bindings, not the publisher's legal rights.
pub fn validate_source_authorization(
    document: &Value,
    digest: &Value,
    revision: &Value,
    source_digest: &Value,
    version: &Value,
) -> Result<(), String> {
    for field in [
        "publisherLegalName",
        "publisherDisplayName",
        "signerName",
        "signerCapacity",
        "rightsStatement",
        "defensivePurpose",
        "permittedOfflineTests",
    ] {
        let limit = if matches!(field, "rightsStatement" | "permittedOfflineTests") {
            32 * 1024
        } else {
            8 * 1024
        };
        if document[field]
            .as_str()
            .is_none_or(|text| text.trim().is_empty() || text.len() > limit)
        {
            return Err(format!(
                "This offer has no complete publisher source authorization: {field}"
            ));
        }
    }
    if !sha256_hex(digest)
        || !sha256_hex(source_digest)
        || revision
            .as_str()
            .is_none_or(|value| value.trim().is_empty() || value.len() > 256)
        || version.as_u64().is_none_or(|value| value == 0)
        || document["sourceRevision"] != *revision
        || document["sourceDigest"] != *source_digest
        || document["termsVersion"] != *version
        || document["thirdPartyExcluded"] != true
        || document["liveSystemsExcluded"] != true
        || document["noProductionSecrets"] != true
    {
        return Err("The publisher authorization must bind the exact accepted source snapshot/version and exclude live systems, third parties and production secrets".into());
    }
    let minimum = &document["minimumRules"];
    if minimum["mode"] != "local_source_only"
        || minimum["remoteTargetsAllowed"] != false
        || minimum["thirdPartyRightsGranted"] != false
        || minimum["sourceInspectionDoesNotVerifyOwnership"] != true
        || minimum["productionSecretsAllowed"] != false
        || minimum["purpose"] != "defensive_source_review"
    {
        return Err(
            "This authorization does not provide the supported defensive offline source-only rules"
                .into(),
        );
    }
    if digest.as_str() != Some(source_authorization_digest(document)?.as_str()) {
        return Err(
            "The publisher source authorization does not match its immutable digest".into(),
        );
    }
    Ok(())
}

fn offer_authorization(offer: &Value) -> Result<&Value, String> {
    let bounty = &offer["bounty"];
    let reward = if offer["reward"].is_object() {
        &offer["reward"]
    } else {
        &bounty["reward"]
    };
    if reward["paymentMode"] != "publisher_direct_external"
        || offer["legacyResolutionRequired"] == true
        || bounty["legacyResolutionRequired"] == true
        || reward["prefunded"] != false
        || reward["guaranteed"] != false
        || reward["verifiedFunding"] != false
        || reward["currency"] != "USDC"
    {
        return Err("This offer is not a supported unverified publisher direct-payment promise. Legacy platform-funded obligations require manual resolution; existing reports and records are retained.".into());
    }
    let document = &bounty["terms"]["authorization"];
    validate_source_authorization(
        document,
        &offer["authorizationDigest"],
        &offer["sourceRevision"],
        &bounty["terms"]["sourceDigest"],
        &offer["termsVersion"],
    )?;
    Ok(document)
}

fn platform(value: &str) -> Result<String, String> {
    let url = reqwest::Url::parse(value).map_err(|_| "--platform-url requires an HTTPS URL")?;
    let loopback = matches!(
        url.host_str(),
        Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
    );
    if !(url.scheme() == "https" || (url.scheme() == "http" && loopback))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
        || url.host_str().is_none()
    {
        return Err("--platform-url must be an HTTPS origin, or HTTP loopback for local development, without credentials or a path".into());
    }
    Ok(url.as_str().trim_end_matches('/').into())
}

/// Recognize only Swarm commands; existing environment starts remain unclaimed.
pub fn parse(args: &[String]) -> Result<Option<Invocation>, String> {
    let tail = if args.len() >= 2 && args[0] == "start" && args[1] == "bounty" {
        let mut tail = vec!["start".to_string()];
        tail.extend_from_slice(&args[2..]);
        tail
    } else if args.first().is_some_and(|a| a == "bounty") {
        args[1..].to_vec()
    } else {
        return Ok(None);
    };
    if tail.is_empty() {
        return Err(HELP.into());
    }
    let action = tail[0].as_str();
    if !matches!(
        action,
        "start"
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
            | "leave"
            | "delete"
            | "submit"
            | "reports"
            | "rewards"
            | "doctor"
            | "bounties"
            | "apply"
    ) {
        return Err(format!(
            "Unknown bounty command {action}. Run yougori bounty --help."
        ));
    }
    let mut request = json!({"action":match action {
        "start" => "prepare",
        "submit" => "submitReport",
        _ => action,
    }});
    let mut positional = Vec::new();
    let mut seen = BTreeSet::new();
    let mut dry_run = false;
    let mut yes = false;
    let mut no_wait = false;
    let mut i = 1;
    while i < tail.len() {
        let flag = tail[i].as_str();
        if !flag.starts_with('-') {
            positional.push(clean(flag, "Identifier", 256)?);
            i += 1;
            continue;
        }
        if !seen.insert(flag.to_string()) {
            return Err(format!("{flag} supplied twice"));
        }
        match flag {
            "--dry-run" => dry_run = true,
            "--yes" => yes = true,
            "--no-wait" if action == "start" => no_wait = true,
            "--release-memory" if action == "start" => request["keepResident"] = false.into(),
            "--model" | "--cpu" | "--memory" | "--gpu" | "--storage-drive"
            | "--workspace-quota" | "--name" | "--quant" | "--worker" | "--platform-url"
                if action == "start" =>
            {
                i += 1;
                let value = tail
                    .get(i)
                    .filter(|v| !v.starts_with('-'))
                    .ok_or_else(|| format!("{flag} requires a value"))?;
                match flag {
                    "--model" => request["model"] = model(value)?.into(),
                    "--cpu" | "--memory" => {
                        if request["resources"].is_null() {
                            request["resources"] = json!({});
                        }
                        request["resources"][if flag == "--cpu" { "cpu" } else { "memoryGb" }] =
                            number(
                                value,
                                flag,
                                if flag == "--cpu" { 4.0 } else { 8.0 },
                                if flag == "--cpu" { 255.0 } else { 1024.0 },
                            )?
                            .into();
                    }
                    "--gpu" => {
                        if !matches!(value.as_str(), "nvidia" | "cpu") {
                            return Err("--gpu must be nvidia or cpu".into());
                        }
                        request["gpu"] = value.clone().into();
                    }
                    "--storage-drive" => {
                        if request["resources"].is_null() {
                            request["resources"] = json!({});
                        }
                        request["resources"]["storageDrive"] =
                            clean(value, "Storage drive", 1024)?.into();
                    }
                    "--workspace-quota" => {
                        request["workspaceQuotaGb"] = number(value, flag, 4.0, 1024.0)?.into()
                    }
                    "--platform-url" => request["platformUrl"] = platform(value)?.into(),
                    _ => {
                        request[match flag {
                            "--name" => "name",
                            "--quant" => "quant",
                            _ => "workerId",
                        }] = clean(value, flag, if flag == "--name" { 64 } else { 256 })?.into()
                    }
                }
            }
            "--message" if action == "chat" => {
                i += 1;
                request["content"] = clean(
                    tail.get(i).ok_or("--message requires text")?,
                    "Message",
                    8192,
                )?
                .into();
            }
            "--accept-rules" if action == "accept" => {
                request["rulesAccepted"] = true.into();
            }
            "--accept-authorization" if action == "accept" => {
                request["authorizationAccepted"] = true.into()
            }
            "--accept-direct-payment" if action == "accept" => {
                request["directPaymentAccepted"] = true.into()
            }
            "--version"
            | "--terms-digest"
            | "--authorization-digest"
            | "--report-policy"
            | "--budget-minutes"
                if action == "accept"
                    || action == "apply" && matches!(flag, "--version" | "--terms-digest") =>
            {
                i += 1;
                let value = tail
                    .get(i)
                    .ok_or_else(|| format!("{flag} requires a value"))?;
                match flag {
                    "--version" => {
                        let n = value
                            .parse::<u64>()
                            .map_err(|_| "--version requires a positive integer")?;
                        if n == 0 {
                            return Err("--version requires a positive integer".into());
                        }
                        request["termsVersion"] = n.into();
                    }
                    "--terms-digest" => {
                        request["termsDigest"] = clean(value, "Terms digest", 128)?.into()
                    }
                    "--authorization-digest" => {
                        request["authorizationDigest"] =
                            clean(value, "Authorization digest", 64)?.into();
                        if !sha256_hex(&request["authorizationDigest"]) {
                            return Err("--authorization-digest requires the exact 64-character SHA-256 from the offer".into());
                        }
                    }
                    "--report-policy" => {
                        if !matches!(value.as_str(), "automatic" | "review") {
                            return Err("--report-policy must be automatic or review".into());
                        }
                        request["reportPolicy"] = value.clone().into();
                    }
                    _ => {
                        let n = value
                            .parse::<u64>()
                            .map_err(|_| "--budget-minutes requires an integer")?;
                        if !(1..=1440).contains(&n) {
                            return Err("--budget-minutes must be between 1 and 1440".into());
                        }
                        request["budgetMinutes"] = n.into();
                    }
                }
            }
            _ => return Err(format!("Unknown option {flag} for bounty {action}")),
        }
        i += 1;
    }
    let limits = match action {
        "start" | "workers" => (0, 0),
        "details" | "accept" | "skip" | "apply" | "submit" => (2, 2),
        "reports" | "rewards" | "doctor" | "bounties" => (0, 1),
        _ => (1, 1),
    };
    if positional.len() < limits.0 || positional.len() > limits.1 {
        return Err(format!(
            "Wrong arguments for bounty {action}. Run yougori bounty --help."
        ));
    }
    if let Some(worker) = positional.first() {
        request["workerId"] = worker.clone().into();
    }
    if let Some(report) = positional.get(1).filter(|_| action == "submit") {
        if !identifier(report) {
            return Err("REPORT_ID is the id of a draft listed by yougori bounty reports WORKER".into());
        }
        request["reportId"] = report.clone().into();
    } else if let Some(offer) = positional.get(1) {
        request["offerId"] = offer.clone().into();
        request["bountyId"] = offer.clone().into();
    }
    if action == "start" {
        if request["workerId"].is_string()
            && (request["model"].is_string()
                || request["resources"].is_object()
                || request["gpu"].is_string()
                || request["name"].is_string()
                || request["quant"].is_string()
                || request["workspaceQuotaGb"].is_number()
                || request["keepResident"].is_boolean())
        {
            return Err("--worker resumes saved model and resources; do not combine it with creation options".into());
        }
        if request["workerId"].is_string() {
            request["action"] = "resume".into();
        }
    }
    if action == "accept" {
        if request["rulesAccepted"] != true {
            return Err(
                "Read the offer's responsible use rules and explicitly supply --accept-rules"
                    .into(),
            );
        }
        if request["authorizationAccepted"] != true {
            return Err("Review the publisher's exact immutable source authorization and explicitly supply --accept-authorization".into());
        }
        if request["directPaymentAccepted"] != true {
            return Err("Review publisher counterparty/non-payment risk and explicitly supply --accept-direct-payment. Yougori does not prefund or guarantee the promised USDC.".into());
        }
        for key in [
            "termsVersion",
            "termsDigest",
            "authorizationDigest",
            "reportPolicy",
            "budgetMinutes",
        ] {
            if request[key].is_null() {
                return Err(format!(
                    "Explicit bounty acceptance requires {key}; view the offer first"
                ));
            }
        }
        if !yes && !dry_run {
            return Err(
                "Explicit bounty acceptance requires --yes after reviewing the offer".into(),
            );
        }
        request["confirmed"] = true.into();
    }
    if action == "delete" && !yes && !dry_run {
        return Err("Deletion requires --yes. Submitted reports remain; local workspace and unsent drafts are removed.".into());
    }
    if action == "submit" && !yes && !dry_run {
        return Err("Submitting requires --yes after you have read the draft in yougori bounty reports WORKER. It sends the report privately to the publisher for review.".into());
    }
    if action == "leave" && !yes && !dry_run {
        return Err("Leaving requires --yes. The worker stops work on its accepted bounty and stops its sandboxes; reports, drafts and reward records remain.".into());
    }
    if action == "apply" {
        if request["termsVersion"].is_null()
            || request["termsDigest"].as_str().is_none_or(str::is_empty)
        {
            return Err(
                "An access application requires the exact published --version and --terms-digest"
                    .into(),
            );
        }
        if !yes && !dry_run {
            return Err("An access application requires --yes; it grants no source access or research authorization".into());
        }
        request["confirmed"] = true.into();
    }
    if yes && !matches!(action, "start" | "accept" | "apply" | "delete" | "stop" | "submit" | "leave") {
        return Err(format!("--yes is not used by bounty {action}"));
    }
    if action == "delete" {
        request["confirmed"] = yes.into();
    }
    Ok(Some(Invocation {
        request,
        dry_run,
        yes,
        no_wait,
        interactive_start: action == "start",
    }))
}

/// Publisher and server text becomes one plain line: newlines and other controls could fake
/// extra accept-screen lines, and bidirectional or zero-width characters can disguise text.
pub(crate) fn safe(value: &str) -> String {
    value
        .chars()
        .filter(|c| !invisible_format(*c))
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(16000)
        .collect()
}
fn invisible_format(c: char) -> bool {
    matches!(c as u32,
        0x00AD | 0x061C | 0x180E | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064
            | 0x2066..=0x206F | 0xFEFF | 0xFFF9..=0xFFFB | 0xE0000..=0xE007F)
}
fn field(value: &Value, key: &str, fallback: &str) -> String {
    match &value[key] {
        Value::String(s) => safe(s),
        Value::Number(n) => n.to_string(),
        _ => fallback.into(),
    }
}

fn worker_id(result: &Value) -> Result<String, String> {
    result["worker"]["id"]
        .as_str()
        .or(result["id"].as_str())
        .or(result["workerId"].as_str())
        .map(str::to_string)
        .ok_or_else(|| {
            "The engine did not return a worker ID; inspect yougori bounty workers before retrying"
                .into()
        })
}

pub async fn dispatch(request: Value) -> Result<Value, String> {
    call("swarm_dispatch", json!({"request":request})).await.map_err(engine_error)
}

fn engine_error(error: String) -> String {
    if error.contains("Unknown method") || error.contains("unknown method") {
        "This running engine does not support Swarm Mining. Start the updated source engine or install the matching Yougori release.".into()
    } else {
        error
    }
}

async fn activity(label: &str, request: Value) -> Result<Value, String> {
    let mut task = ui::loading_task(label);
    let result = crate::public::call_with_progress(
        "swarm_dispatch",
        json!({"request":request}),
        |progress| {
            if let Some(stage) = progress["stage"].as_str().or(progress["message"].as_str()) {
                task.set(&safe(stage));
            }
            if let (Some(done), Some(total)) = (
                progress["bytesDone"].as_u64(),
                progress["bytesTotal"].as_u64(),
            ) {
                task.progress("Downloading", done, total, "bytes");
            }
        },
    )
    .await;
    match result {
        Ok(value) => {
            task.done(label);
            Ok(value)
        }
        Err(e) => {
            task.fail("Could not complete this step");
            Err(e)
        }
    }
}

fn worker_value(result: &Value) -> &Value {
    if result["worker"].is_object() {
        &result["worker"]
    } else {
        result
    }
}
fn prepared_state(state: &str, bounty: bool) -> bool {
    if bounty {
        matches!(state, "running" | "working" | "awaiting_review")
    } else {
        matches!(
            state,
            "ready_waiting" | "waiting" | "ready" | "running" | "working" | "awaiting_review"
        )
    }
}

async fn preparation_interrupt(worker: &str) -> Result<bool, String> {
    ui::take_interrupt();
    let selected = ui::select_required(
        "What would you like to do?",
        &["Preparation belongs to this worker. Saved downloads can be resumed.".into()],
        &[
            ui::Choice::new("Cancel", "return to preparation; keep it running"),
            ui::Choice::new(
                "Stop preparation",
                "stop this worker's setup; preserve downloaded files",
            ),
            ui::Choice::new(
                "Back to terminal",
                "detach; keep setup running in the engine",
            ),
        ],
    )?;
    if selected == 0 {
        return Ok(false);
    }
    if selected == 1 {
        dispatch(json!({"action":"cancelPrepare","workerId":worker})).await?;
        ui::info("Preparation stopped. Saved downloads remain available for retry.");
    } else {
        ui::info(&format!(
            "Preparation continues. Reconnect: yougori start bounty --worker {}",
            safe(worker)
        ));
    }
    Ok(true)
}

/// Mutations return a stable owned worker promptly. Preparation runs in the
/// engine and remains inspectable/cancellable if this terminal disconnects.
async fn wait_prepared(worker: &str, bounty: bool) -> Result<bool, String> {
    let mut task = ui::loading_task(if bounty {
        "Preparing the accepted bounty"
    } else {
        "Preparing your worker"
    });
    let _raw = if ui::can_prompt() {
        Some(ui::Raw::on()?)
    } else {
        None
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3600);
    loop {
        let result = dispatch(json!({"action":"status","workerId":worker})).await?;
        let data = worker_value(&result);
        let state = data["state"].as_str().unwrap_or("");
        if prepared_state(state, bounty) {
            task.done(if bounty {
                "Your agent is ready to work."
            } else {
                "Your worker is ready."
            });
            return Ok(true);
        }
        if matches!(
            state,
            "failed" | "error" | "preparation_failed" | "failed_prepare" | "failed_bounty"
        ) {
            task.fail("Worker preparation failed");
            let reason = data["error"]
                .as_str()
                .or(result["error"].as_str())
                .map(safe)
                .unwrap_or_else(|| "Preparation failed.".into());
            return Err(format!(
                "{reason}\nCheck it: yougori bounty doctor {0}\nTry again: yougori start bounty --worker {0}",
                safe(worker)
            ));
        }
        if state == "paused" && data["error"].is_string() {
            task.fail("Worker needs attention");
            return Err(safe(data["error"].as_str().unwrap()));
        }
        if matches!(state, "stopped" | "paused" | "cancelled") {
            task.done("Worker preparation is paused or stopped");
            return Ok(false);
        }
        if let Some(stage) = data["stage"].as_str().or(result["stage"].as_str()) {
            task.set(&safe(stage));
        }
        if let (Some(done), Some(total)) = (data["bytesDone"].as_u64(), data["bytesTotal"].as_u64())
        {
            task.progress("Downloading", done, total, "bytes");
        }
        if tokio::time::Instant::now() >= deadline {
            task.done("Preparation continues in the engine");
            ui::info(&format!(
                "The terminal stopped waiting after 60 minutes. Inspect: yougori bounty status {}",
                safe(worker)
            ));
            return Ok(false);
        }
        let tick = tokio::time::Instant::now() + Duration::from_secs(2);
        while tokio::time::Instant::now() < tick {
            if ui::can_prompt() && event::poll(Duration::ZERO).map_err(|e| e.to_string())? {
                match event::read().map_err(|e| e.to_string())? {
                    Event::Key(key) => match key_action(key) {
                        WorkerKey::Interrupt => {
                            if preparation_interrupt(worker).await? {
                                task.done("Left preparation view");
                                return Ok(false);
                            }
                        }
                        WorkerKey::Detach => {
                            task.done("Preparation continues in the engine");
                            return Ok(false);
                        }
                        _ => {} // Discard setup-time Enter/typing; never accept a later prompt.
                    },
                    Event::Resize(..) => ui::refresh(),
                    _ => {}
                }
            }
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
    }
}

/// Plain words for a worker state, shared by the live view, its log and tables.
pub fn state_label(state: &str) -> &'static str {
    match state {
        "ready_waiting" | "waiting" | "ready" => "live",
        "preparing" => "preparing",
        "preparing_bounty" => "preparing bounty",
        "running" | "working" => "working",
        "awaiting_review" => "report ready",
        "paused" => "paused",
        "stopped" => "stopped",
        "failed" | "error" | "preparation_failed" | "failed_prepare" | "failed_bounty" => "needs attention",
        _ => "unknown",
    }
}

fn state_sentence(name: &str, state: &str) -> String {
    match state_label(state) {
        "live" => format!("{name} is live and waiting for bounty offers"),
        "needs attention" => format!("{name} needs attention"),
        "report ready" => format!("{name} has a report ready for your review"),
        label => format!("{name} is {label}"),
    }
}

/// What the participant can do next when a worker waits for them: work that an engine
/// restart paused, or a report draft to read and send.
fn state_hint(worker: &Value, id: &str) -> Option<String> {
    let id = safe(id);
    if worker["state"] == "paused" && worker["restored"] == true {
        return Some(format!(
            "The engine restarted, so this worker paused; nothing runs until you resume it. Press P, or run: yougori bounty resume {id}"
        ));
    }
    if worker["state"] != "awaiting_review" {
        return None;
    }
    let report = worker["reviewReports"]
        .as_array()
        .and_then(|drafts| drafts.last())
        .and_then(Value::as_str)
        .map_or_else(|| "REPORT_ID".into(), safe);
    Some(format!(
        "Read the draft with yougori bounty reports {id}, then send it: yougori bounty submit {id} {report} --yes"
    ))
}

/// NVIDIA only when this PC passes the CUDA checks behind `yougori gpu status`. AMD or Intel
/// graphics, a missing driver or WSL, or an engine that could not check, mean the processor.
fn gpu_choice(cuda: &Value) -> &'static str {
    if cuda["supported"] == true {
        "nvidia"
    } else {
        "cpu"
    }
}

async fn cuda_checks<F, Fut>(rpc: &mut F) -> Value
where
    F: FnMut(&'static str, Value) -> Fut,
    Fut: Future<Output = Result<Value, String>>,
{
    rpc("get_cuda_runtime_status", json!({})).await.unwrap_or(Value::Null)
}

/// `--yes` settings: the documented defaults, and the NVIDIA GPU only when CUDA works here.
async fn scripted_settings<F, Fut>(request: &mut Value, rpc: &mut F)
where
    F: FnMut(&'static str, Value) -> Fut,
    Fut: Future<Output = Result<Value, String>>,
{
    if request["gpu"].is_null() {
        request["gpu"] = gpu_choice(&cuda_checks(rpc).await).into();
    }
    defaults(request);
}

/// Settings for the one-screen setup, or none when the command line already chose some.
fn recommended_settings(request: &Value, host: &Value, cuda: &Value) -> Result<Option<Value>, String> {
    if ["gpu", "workspaceQuotaGb", "name", "keepResident"].iter().any(|key| !request[*key].is_null())
        || ["cpu", "memoryGb", "storageDrive"].iter().any(|key| !request["resources"][*key].is_null())
    {
        return Ok(None);
    }
    let mut recommended = request.clone();
    recommended["resources"] = json!({});
    for slider in resource_sliders(request, host)? {
        recommended["resources"][if slider.label == "CPU" { "cpu" } else { "memoryGb" }] = slider.value.into();
    }
    // The drive with the most free space keeps model files off a full system drive.
    let free = |drive: &&Value| drive["freeGb"].as_f64().unwrap_or(0.0);
    if let Some(drive) = host["storageDrives"].as_array().into_iter().flatten()
        .filter(|drive| drive["path"].is_string() && drive["readOnly"] != true && drive["removable"] != true)
        .max_by(|a, b| free(a).total_cmp(&free(b)))
    {
        recommended["resources"]["storageDrive"] = drive["path"].clone();
    }
    // Windows reports GPU use for any vendor; only the CUDA checks show an NVIDIA GPU works.
    recommended["gpu"] = gpu_choice(cuda).into();
    defaults(&mut recommended);
    Ok(Some(recommended))
}

fn setup_notes(request: &Value, cuda: &Value) -> Vec<String> {
    let resources = &request["resources"];
    let mut notes = vec![
        format!("{} · {}", field(request, "name", "Bounty worker"), field(request, "model", "")),
        format!(
            "{} · {} CPU cores · {} GB memory",
            if request["gpu"] == "cpu" { "Runs on the processor" } else { "Runs on your NVIDIA GPU" },
            field(resources, "cpu", "4"),
            field(resources, "memoryGb", "8")
        ),
    ];
    if request["gpu"] == "cpu" && cuda["supported"] != true {
        notes.push("No NVIDIA GPU passed the CUDA checks on this PC; yougori gpu status shows why.".into());
    }
    notes.extend([
        format!(
            "Files on {} · {} GB for bounty workspaces · {}",
            field(resources, "storageDrive", "the default drive"),
            field(request, "workspaceQuotaGb", "20"),
            if request["keepResident"] == false { "model memory released while waiting" } else { "model kept loaded while waiting" }
        ),
        "The engine checks disk space, downloads, model tools and context before readiness.".into(),
        "Your model API stays private. No bounty is accepted during setup.".into(),
    ]);
    notes
}

fn defaults(request: &mut Value) {
    if request["resources"].is_null() {
        request["resources"] = json!({});
    }
    if request["resources"]["cpu"].is_null() {
        request["resources"]["cpu"] = 4.into();
    }
    if request["resources"]["memoryGb"].is_null() {
        request["resources"]["memoryGb"] = 8.into();
    }
    // Callers choose the GPU from the CUDA checks; never assume NVIDIA without them.
    if request["gpu"].is_null() {
        request["gpu"] = "cpu".into();
    }
    if request["workspaceQuotaGb"].is_null() {
        request["workspaceQuotaGb"] = 20.into();
    }
    if request["keepResident"].is_null() {
        request["keepResident"] = true.into();
    }
    if request["name"].is_null() {
        request["name"] = "Bounty worker".into();
    }
}

fn resource_sliders(request: &Value, host: &Value) -> Result<Vec<ui::Slider>, String> {
    let mut sliders = Vec::new();
    for (key, host_key, label, unit, default, ceiling) in [
        ("cpu", "totalCpu", "CPU", "cores", 4, 255),
        ("memoryGb", "totalMemoryGb", "Memory", "GB", 8, 1024),
    ] {
        if !request["resources"][key].is_null() {
            continue;
        }
        let total = host[host_key].as_f64().unwrap_or(default as f64);
        if !total.is_finite() || total < default as f64 {
            return Err(format!(
                "This computer does not have enough {label} for a worker"
            ));
        }
        let max = total.floor().min(ceiling as f64) as u32;
        sliders.push(ui::Slider {
            label,
            unit,
            min: default,
            max,
            default: default.min(max),
            value: default.min(max),
        });
    }
    Ok(sliders)
}

/// What `--no-wait` prints: the worker as the engine returned it, and how to follow it.
fn started(result: &Value) -> Result<Value, String> {
    let id = worker_id(result)?;
    let worker = worker_value(result);
    let next = match worker["state"].as_str() {
        Some("preparing") => format!("Preparation continues in the engine. Follow it with `yougori bounty status {id}`; the worker is ready when its state is ready_waiting."),
        Some("paused") => format!("The worker stays paused. Resume it with `yougori bounty resume {id}`."),
        _ => format!("Follow it with `yougori bounty status {id}`."),
    };
    let mut shown = json!({"worker":worker,"next":next});
    if result["background"] == true {
        shown["background"] = true.into();
    }
    Ok(shown)
}

/// Scripted `start bounty --yes --no-wait`: no prompts, no progress lines and no waiting.
/// One request starts preparation (or resumes `--worker`) in the engine, which keeps
/// working after this process ends; `bounty status` follows the worker.
async fn start_detached<F, Fut>(mut request: Value, mut rpc: F) -> Result<Value, String>
where
    F: FnMut(&'static str, Value) -> Fut,
    Fut: Future<Output = Result<Value, String>>,
{
    if request["action"] == "prepare" {
        scripted_settings(&mut request, &mut rpc).await;
    }
    rpc("swarm_dispatch", json!({"request":request}))
        .await
        .map_err(engine_error)
}

/// Registering a new worker needs the account. Scripts stop here; people can sign in now.
async fn sign_in(interactive: bool) -> Result<(), String> {
    if crate::network::signed_in().await? {
        return Ok(());
    }
    if !interactive {
        return Err("Connect your account first with yougori login. No worker was created.".into());
    }
    ui::intro(
        "Connect this worker to your Yougori account",
        "The engine stores credentials securely on this computer.",
    );
    crate::network::login(|code, address| {
        ui::info(&format!("Approve this sign-in: {}", safe(address)));
        ui::info(&format!("Code: {}", safe(code)));
    })
    .await
    .map(|_| ())
}

/// Starts or reconnects a worker and returns the engine's result for it, after it is
/// ready unless `--no-wait` was given. None means the person cancelled or detached.
async fn setup(invocation: &mut Invocation) -> Result<Option<Value>, String> {
    let interactive = ui::can_prompt();
    let resume = invocation.request["action"] == "resume";
    if !resume && invocation.request["model"].is_null() {
        invocation.request["model"] = ui::input_prefilled(
            "Which Hugging Face model should power your worker?",
            "hf.co/",
            &model,
        )?
        .into();
    }
    crate::client::start(None).await?;
    if invocation.yes && invocation.no_wait {
        if !resume {
            sign_in(interactive).await?;
        }
        return start_detached(invocation.request.clone(), |method, params| call(method, params))
            .await
            .map(Some);
    }
    if resume {
        let worker = invocation.request["workerId"].as_str().unwrap().to_string();
        // Reconnecting opens the worker; it continues paused work only with explicit consent.
        let current = dispatch(json!({"action":"status","workerId":worker})).await?;
        if current["worker"]["state"] == "paused" {
            let note = if current["worker"]["restored"] == true {
                "The engine restarted, so this worker paused. Reconnecting does not resume work by itself."
            } else {
                "Reconnecting does not resume work by itself."
            };
            let resume = invocation.yes
                || interactive
                    && ui::select_required(
                        "This worker is paused. Resume it?",
                        &[note.into()],
                        &[
                            ui::Choice::new("Stay paused", "open the worker without resuming"),
                            ui::Choice::new("Resume", "recheck authorization and continue"),
                        ],
                    )? == 1;
            if !resume {
                ui::info(&format!(
                    "The worker stays paused. Press P in its view, or run: yougori bounty resume {}",
                    safe(&worker)
                ));
                return Ok(Some(current));
            }
        }
        let result = activity(
            "Resuming worker and synchronizing notes",
            invocation.request.clone(),
        )
        .await?;
        if !invocation.no_wait && !wait_prepared(&worker, false).await? {
            return Ok(None);
        }
        return Ok(Some(result));
    }
    let mut rpc = |method: &'static str, params: Value| call(method, params);
    if interactive && !invocation.yes {
        let state = activity(
            "Checking your model and hardware",
            json!({"action":"doctor","model":invocation.request["model"]}),
        )
        .await?;
        let preflight = loop {
            let result=activity("Checking the selected model revision",json!({"action":"doctor","model":invocation.request["model"],"quant":invocation.request["quant"],"preflightModel":true})).await;
            match result {
                Ok(value) if value["preflight"].is_object() => break value["preflight"].clone(),
                Ok(_) => break Value::Null,
                Err(error) => {
                    let choices=[ui::Choice::new("Choose another model","paste a supported Hugging Face GGUF repository"),ui::Choice::new("Sign in to Hugging Face","save a read token securely; gated terms must be accepted on Hugging Face"),ui::Choice::new("Cancel","return without creating a worker")];
                    match ui::select("This model needs attention", &[safe(&error)], &choices, 0)? {
                        0 => {
                            invocation.request["model"] = ui::input_prefilled(
                                "Which Hugging Face model should power your worker?",
                                "hf.co/",
                                &model,
                            )?
                            .into()
                        }
                        1 => {
                            let token = ui::input("Hugging Face read token", "", true, &|value| {
                                if !value.starts_with("hf_")
                                    || !(12..=1024).contains(&value.len())
                                    || !value
                                        .bytes()
                                        .all(|b| b.is_ascii_alphanumeric() || b == b'_')
                                {
                                    return Err("Enter a valid Hugging Face read token. Its value is withheld.".into());
                                }
                                Ok(value.into())
                            })?;
                            call(
                                "set_deployment_secret",
                                json!({"name":crate::model_auth::REFERENCE,"value":token}),
                            )
                            .await?;
                            ui::info("Read token saved in the OS credential vault. Accept any gated model's terms on Hugging Face before retrying.");
                        }
                        _ => return Ok(None),
                    }
                }
            }
        };
        if !preflight.is_null() {
            for line in [
                format!(
                    "Model revision: {}",
                    field(&preflight, "revision", "Unknown")
                ),
                format!(
                    "Selected variant: {} · Weights: {}",
                    field(&preflight, "quant", "GGUF"),
                    preflight["resources"]["weightsBytes"]
                        .as_u64()
                        .map(ui::bytes)
                        .unwrap_or_else(|| "See model metadata".into())
                ),
            ] {
                ui::info(&line);
            }
            if invocation.request["quant"].is_null() && preflight["quant"].is_string() {
                invocation.request["quant"] = preflight["quant"].clone();
            }
        }
        let host = if state["host"].is_object() {
            &state["host"]
        } else {
            &state
        };
        let cuda = if invocation.request["gpu"].is_null() {
            let task = ui::loading_task("Checking for a compatible NVIDIA GPU");
            let cuda = cuda_checks(&mut rpc).await;
            task.done(if gpu_choice(&cuda) == "nvidia" {
                "This PC passed the NVIDIA CUDA checks"
            } else {
                "No compatible NVIDIA GPU; the processor will run the model"
            });
            cuda
        } else {
            Value::Null
        };
        // One screen with recommended settings instead of six questions; Customize keeps them.
        let mut chosen = false;
        if let Some(recommended) = recommended_settings(&invocation.request, host, &cuda)? {
            match ui::select(
                "Prepare this worker?",
                &setup_notes(&recommended, &cuda),
                &[
                    ui::Choice::new("Prepare", "download and verify the model with these settings"),
                    ui::Choice::new("Customize", "choose GPU or CPU, cores, memory, drive, space and name"),
                    ui::Choice::new("Cancel", "return without creating a worker"),
                ],
                0,
            )? {
                0 => {
                    invocation.request = recommended;
                    chosen = true;
                }
                1 => {}
                _ => return Ok(None),
            }
        }
        if !chosen {
            if invocation.request["gpu"].is_null() {
                let choices = [
                    ui::Choice::new("Compatible local GPU", "use this computer's NVIDIA GPU"),
                    ui::Choice::new("CPU", "use this computer's processor"),
                ];
                let detected = gpu_choice(&cuda);
                let note = if detected == "nvidia" {
                    "This PC passed the NVIDIA CUDA checks. Compatibility is checked again before the worker is marked ready."
                } else {
                    "No NVIDIA GPU passed the CUDA checks (yougori gpu status shows why), so CPU is recommended."
                };
                let gpu = ui::select(
                    "Where should your worker run the model?",
                    &[note.into()],
                    &choices,
                    usize::from(detected == "cpu"),
                )?;
                invocation.request["gpu"] = if gpu == 0 { "nvidia" } else { "cpu" }.into();
            }
            let mut sliders = resource_sliders(&invocation.request, host)?;
            if !sliders.is_empty() {
                ui::sliders(
                    "Size your bounty worker",
                    "Choose CPU cores and RAM. Existing workloads keep their allocations.",
                    &mut sliders,
                )?;
            }
            if invocation.request["resources"].is_null() {
                invocation.request["resources"] = json!({});
            }
            for slider in sliders {
                invocation.request["resources"][if slider.label == "CPU" {
                    "cpu"
                } else {
                    "memoryGb"
                }] = slider.value.into();
            }
            if invocation.request["resources"]["storageDrive"].is_null() {
                let drives = host["storageDrives"]
                    .as_array()
                    .map(Vec::as_slice)
                    .unwrap_or(&[]);
                if !drives.is_empty() {
                    let choices = drives
                        .iter()
                        .map(|d| {
                            ui::Choice::new(
                                field(d, "path", "Unknown drive"),
                                format!("{} GB free", field(d, "freeGb", "unknown")),
                            )
                        })
                        .collect::<Vec<_>>();
                    let at = ui::select(
                        "Where should model and workspace files be stored?",
                        &[],
                        &choices,
                        0,
                    )?;
                    invocation.request["resources"]["storageDrive"] = drives[at]["path"].clone();
                }
            }
            if invocation.request["workspaceQuotaGb"].is_null() {
                let value = ui::input(
                    "How much space can bounty workspaces use?",
                    "20",
                    false,
                    &|v| number(v, "Workspace quota", 4.0, 1024.0).map(|n| n.to_string()),
                )?;
                invocation.request["workspaceQuotaGb"] =
                    number(&value, "Workspace quota", 4.0, 1024.0)?.into();
            }
            if invocation.request["name"].is_null() {
                invocation.request["name"] =
                    ui::input("Name this worker", "Bounty worker", false, &|v| {
                        clean(v, "Worker name", 64)
                    })?
                    .into();
            }
            if invocation.request["keepResident"].is_null() {
                let choices = [
                    ui::Choice::new(
                        "Keep it loaded",
                        "uses memory while waiting; no agent inference",
                    ),
                    ui::Choice::new(
                        "Release model memory while waiting",
                        "reload for accepted work or your private prompts",
                    ),
                ];
                invocation.request["keepResident"] =
                    json!(ui::select("Keep the model ready while waiting?", &[], &choices, 0)? == 0);
            }
            defaults(&mut invocation.request);
            let notes = vec![
                format!("Model: {}", field(&invocation.request, "model", "")),
                format!(
                    "{} · CPU: {} · Memory: {} GB · Workspace quota: {} GB",
                    if invocation.request["gpu"] == "cpu" { "Runs on the processor" } else { "Runs on your NVIDIA GPU" },
                    field(&invocation.request["resources"], "cpu", ""),
                    field(&invocation.request["resources"], "memoryGb", ""),
                    field(&invocation.request, "workspaceQuotaGb", "")
                ),
                "The engine checks disk space, downloads, model tools and context before readiness."
                    .into(),
                "Your model API stays private. No bounty is accepted during setup.".into(),
            ];
            if ui::select(
                "Prepare this worker?",
                &notes,
                &[
                    ui::Choice::new("Cancel", "return without creating a worker"),
                    ui::Choice::new("Prepare", "download and verify the selected local model"),
                ],
                0,
            )? != 1
            {
                return Ok(None);
            }
        }
    } else {
        scripted_settings(&mut invocation.request, &mut rpc).await;
    }
    sign_in(interactive).await?;
    let result = activity("Preparing your worker", invocation.request.clone()).await?;
    let id = worker_id(&result)?;
    if invocation.no_wait {
        return Ok(Some(result));
    }
    ui::info(&format!("Reconnect: yougori start bounty --worker {id}"));
    if !wait_prepared(&id, false).await? {
        return Ok(None);
    }
    Ok(Some(result))
}

/// Every printed value from a remote project/company passes terminal sanitization.
pub fn offer_lines(offer: &Value, detailed: bool) -> Vec<String> {
    let bounty = if offer["bounty"].is_object() {
        &offer["bounty"]
    } else {
        offer
    };
    let company = bounty["company"]["name"]
        .as_str()
        .or(bounty["organization"]["name"].as_str())
        .or(bounty["companyName"].as_str())
        .unwrap_or("Company");
    let terms = if bounty["terms"].is_object() {
        &bounty["terms"]
    } else {
        bounty
    };
    let reward = if offer["reward"].is_object() {
        &offer["reward"]
    } else {
        &bounty["reward"]
    };
    let mut lines = vec![
        format!("New bounty from {}", safe(company)),
        field(bounty, "title", "Untitled bounty"),
        format!("Objective: {}", field(terms, "objective", "Review details")),
        format!(
            "Publisher promise: {} {} to the qualifying winner{}",
            field(reward, "amount", "Not specified"),
            field(reward, "currency", ""),
            if reward["simulated"] == true {
                " · simulated test reward"
            } else {
                ""
            }
        ),
        format!(
            "Rules: {}",
            field(
                terms,
                "winnerRule",
                "First complete qualifying submission, subsequently verified"
            )
        ),
        format!("Testing closes: {}", field(terms, "closesAt", "See terms")),
        format!(
            "Source access: {}",
            field(terms, "sourceAccess", "See terms")
        ),
        "Payment: publisher pays externally from its own wallet; Yougori does not prefund, verify funding or guarantee payment.".into(),
        "Counterparty risk: the publisher may not pay. No Swarm balance credit or withdrawal is created.".into(),
        format!("Terms version: {}", field(offer, "termsVersion", "Unknown")),
    ];
    if detailed {
        let authorization = &terms["authorization"];
        for (key, label) in [
            ("publisherLegalName", "Publisher legal identity"),
            ("publisherDisplayName", "Publisher display name"),
            ("signerName", "Authorization signer"),
            ("signerCapacity", "Signer capacity"),
            (
                "rightsStatement",
                "Publisher's authority statement (not independently verified)",
            ),
            ("defensivePurpose", "Defensive research purpose"),
            ("permittedOfflineTests", "Permitted offline checks"),
        ] {
            lines.push(format!(
                "{label}: {}",
                field(authorization, key, "Not supplied")
            ));
        }
        lines.push("Authorization covers only the exact supplied source snapshot and approved offline checks. Publisher assertions grant no third-party rights or live-system permission and do not establish global legality.".into());
        for (key, label) in [
            ("qualifyingCriteria", "Qualifying solution"),
            ("exclusions", "Exclusions"),
            ("scope", "Permitted testing scope"),
            ("inScope", "Included components"),
            ("outOfScope", "Excluded components"),
            ("prohibitedActions", "Prohibited actions"),
            ("confidentialityTerms", "Confidentiality"),
            ("confidentiality", "Confidentiality terms"),
            ("resourceLimits", "Resource limits"),
            ("evidenceRequirements", "Required evidence"),
            ("knownIssues", "Known issues"),
            ("setupCommand", "Project setup command"),
            ("testCommand", "Test command"),
            ("reviewDays", "Review period (days)"),
            ("appealDays", "Appeal period (days)"),
            ("paymentSchedule", "Payment schedule"),
            ("duplicatePolicy", "Duplicate findings"),
            ("reviewDeadline", "Review deadline"),
            ("appealPolicy", "Appeals"),
        ] {
            if !terms[key].is_null() {
                let text = if let Some(s) = terms[key].as_str() {
                    s.to_owned()
                } else {
                    serde_json::to_string(&terms[key]).unwrap_or_default()
                };
                lines.push(format!("{label}: {}", safe(&text)));
            }
        }
        lines.push(format!(
            "Source revision: {}",
            field(
                offer,
                "sourceRevision",
                &field(terms, "sourceRevision", "See manifest")
            )
        ));
        lines.push(format!(
            "Terms digest: {}",
            field(offer, "termsDigest", "Unknown")
        ));
        lines.push(format!(
            "Source digest: {}",
            field(terms, "sourceDigest", "Unknown")
        ));
        lines.push(format!(
            "Authorization digest: {}",
            field(offer, "authorizationDigest", "Unknown")
        ));
        if let Err(error) = offer_authorization(offer) {
            lines.push(error);
        }
        lines.push("Each accepted participant receives local project files. No automatic reward split is implied.".into());
        lines.push(if terms["agentChannelVisibility"] == "agents_and_publisher" {
            "Shared coordination: agents and this bounty's publisher (read-only). Your private agent conversation is excluded.".into()
        } else {
            "Shared coordination: agents-only under this accepted version; no publisher read access.".into()
        });
        if let Ok(rules) = offer_rules(offer) {
            lines.push(format!(
                "Responsible use rules: {} · {}",
                field(rules, "version", "Unknown"),
                field(rules, "digest", "Unknown")
            ));
            for section in rules["sections"].as_array().unwrap() {
                lines.push(format!(
                    "{}: {}",
                    field(section, "title", "Rule"),
                    field(section, "text", "Read the published rules")
                ));
            }
        } else {
            lines.push("This offer must be republished with valid responsible use rules before acceptance.".into());
        }
    }
    lines
}

pub fn reward_lines(result: &Value) -> Vec<String> {
    let mut lines =
        vec!["Publisher direct payments · no Swarm balance credit, custody or withdrawals.".into()];
    for award in result["directAwards"]
        .as_array()
        .into_iter()
        .flatten()
        .take(100)
    {
        let state = award["state"]
            .as_str()
            .or(award["status"].as_str())
            .unwrap_or_default();
        let label = match state {
            "external_payment_due" => "External payment due; no publisher payment report",
            "publisher_reported_unverified" => {
                "Publisher reported transaction evidence; unverified"
            }
            "winner_acknowledged_receipt" => {
                "Winner acknowledged receipt; not independently chain-verified"
            }
            _ => "Unrecognized direct-payment record; inspect its terms",
        };
        let first = |keys: &[&str], fallback: &str| {
            keys.iter()
                .find(|key| award[**key].is_string() || award[**key].is_number())
                .map(|key| field(award, key, fallback))
                .unwrap_or_else(|| fallback.into())
        };
        lines.push(format!(
            "{} · {} {} · network: {} · recipient: {} · due: {} · {label}",
            field(award, "id", "Award"),
            field(award, "amount", "See terms"),
            first(&["currency", "token"], "(token not stated; check the terms)"),
            first(&["network", "chain"], "not stated"),
            first(&["recipient", "recipientAddress", "walletAddress"], "not stated"),
            first(&["dueAt", "dueDate", "due"], "not stated"),
        ));
    }
    if result["legacyAwards"]
        .as_array()
        .is_some_and(|values| !values.is_empty())
        || result["legacyReserves"]
            .as_array()
            .is_some_and(|values| !values.is_empty())
    {
        lines.push("Historic platform-funded obligations are retained for manual resolution. They are not new direct-payment credits.".into());
    }
    lines
}

fn offer_id(offer: &Value) -> Result<String, String> {
    offer["id"]
        .as_str()
        .or(offer["bounty"]["id"].as_str())
        .map(str::to_string)
        .ok_or_else(|| "Offer has no identifier".into())
}

pub fn acceptance(
    worker: &str,
    offer: &Value,
    report_policy: &str,
    budget: u64,
) -> Result<Value, String> {
    if !matches!(report_policy, "automatic" | "review") || !(1..=1440).contains(&budget) {
        return Err("Invalid submission policy or work budget".into());
    }
    let version = offer["termsVersion"]
        .as_u64()
        .filter(|v| *v > 0)
        .ok_or("Offer has no valid terms version; refresh offers before accepting")?;
    let digest = offer["termsDigest"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or("Offer has no terms digest; refresh offers before accepting")?;
    let id = offer_id(offer)?;
    let rules = offer_rules(offer)?;
    offer_authorization(offer)?;
    let bounty = offer["bounty"]["id"]
        .as_str()
        .or(offer["bountyId"].as_str())
        .unwrap_or(&id);
    Ok(
        json!({"action":"accept","workerId":worker,"offerId":id,"bountyId":bounty,"termsVersion":version,"termsDigest":digest,"sourceRevision":offer["sourceRevision"],"sourceDigest":offer["bounty"]["terms"]["sourceDigest"],"authorizationDigest":offer["authorizationDigest"],"authorizationAccepted":true,"directPaymentAccepted":true,"reportPolicy":report_policy,"budgetMinutes":budget,"confirmed":true,"rulesAccepted":true,"rulesVersion":rules["version"],"rulesDigest":rules["digest"]}),
    )
}

fn bind_offer(request: &mut Value, offer: &Value) -> Result<(), String> {
    if request["termsVersion"] != offer["termsVersion"]
        || request["termsDigest"] != offer["termsDigest"]
        || request["authorizationDigest"] != offer["authorizationDigest"]
    {
        return Err(
            "The offer changed. Review its current scope and reward terms before accepting.".into(),
        );
    }
    offer_authorization(offer)?;
    if request["authorizationAccepted"] != true || request["directPaymentAccepted"] != true {
        return Err("Explicit source authorization and publisher direct-payment risk acceptance are required".into());
    }
    request["bountyId"] = offer["bounty"]["id"]
        .as_str()
        .or(offer["bountyId"].as_str())
        .ok_or("Offer has no bounty ID")?
        .into();
    request["sourceRevision"] = offer["sourceRevision"].clone();
    request["sourceDigest"] = offer["bounty"]["terms"]["sourceDigest"].clone();
    let rules = offer_rules(offer)?;
    request["rulesVersion"] = rules["version"].clone();
    request["rulesDigest"] = rules["digest"].clone();
    Ok(())
}

fn offer_rules(offer: &Value) -> Result<&Value, String> {
    let rules = &offer["bounty"]["terms"]["serviceRules"];
    if rules["version"].as_str().is_none_or(str::is_empty)
        || !rules["digest"]
            .as_str()
            .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        || !rules["sections"].is_array()
    {
        return Err("This offer has no valid responsible use rules. Ask the publisher to publish a new version.".into());
    }
    Ok(rules)
}

async fn browse_bounties(worker: &str) -> Result<(), String> {
    let result = activity(
        "Browsing published bounty metadata",
        json!({"action":"bounties","workerId":worker}),
    )
    .await?;
    let bounties = result["bounties"]
        .as_array()
        .ok_or("Invalid published bounty response")?;
    if bounties.is_empty() {
        ui::info("No published bounties are available. Your worker keeps waiting.");
        return Ok(());
    }
    let mut choices = bounties
        .iter()
        .map(|bounty| {
            ui::Choice::new(
                field(bounty, "title", "Published bounty"),
                format!(
                    "version {} · publisher access approval required",
                    field(bounty, "termsVersion", "Unknown")
                ),
            )
        })
        .collect::<Vec<_>>();
    choices.push(ui::Choice::new("Back", "keep waiting without applying"));
    let selected=ui::select("Choose published metadata to review",&["Applying grants no source access or research permission. A publisher must approve this exact version, followed by your separate offer acceptance.".into()],&choices,0)?;
    if selected >= bounties.len() {
        return Ok(());
    }
    let bounty = &bounties[selected];
    let offer = json!({"id":bounty["id"],"bounty":bounty,"reward":bounty["reward"],"termsVersion":bounty["termsVersion"],"termsDigest":bounty["termsDigest"],"authorizationDigest":bounty["authorizationDigest"],"sourceRevision":bounty["terms"]["sourceRevision"]});
    offer_authorization(&offer)?;
    let confirmed = ui::select(
        "Request publisher approval for this exact version?",
        &offer_lines(&offer, true),
        &[
            ui::Choice::new("Cancel", "no application or source download"),
            ui::Choice::new(
                "Request access",
                "wait for approval; no investigation starts",
            ),
        ],
        0,
    )?;
    if confirmed == 1 {
        activity("Requesting exact-version source access",json!({"action":"apply","workerId":worker,"bountyId":bounty["id"],"termsVersion":bounty["termsVersion"],"termsDigest":bounty["termsDigest"],"confirmed":true})).await?;
        ui::info("Access application sent. Keep waiting for an approved offer; review and accept it separately before any source is downloaded.");
    }
    Ok(())
}

async fn offers(worker: &str) -> Result<(), String> {
    loop {
        let result = activity(
            "Checking bounty offers",
            json!({"action":"offers","workerId":worker}),
        )
        .await?;
        let offers = result["offers"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        if offers.is_empty() {
            ui::info(
                "No approved bounty offers yet. Your worker waits without inference; source access requires publisher approval.",
            );
            let choice = ui::select(
                "Request access to a published bounty?",
                &[],
                &[
                    ui::Choice::new("Keep waiting", "no application or source download"),
                    ui::Choice::new(
                        "Browse published bounties",
                        "view metadata and request exact-version approval",
                    ),
                ],
                0,
            )?;
            if choice == 1 {
                browse_bounties(worker).await?;
            }
            return Ok(());
        }
        let mut choices = offers
            .iter()
            .map(|o| {
                ui::Choice::new(
                    field(&o["bounty"], "title", "Bounty"),
                    format!(
                        "{} {}",
                        field(&o["reward"], "amount", ""),
                        field(&o["reward"], "currency", "")
                    ),
                )
            })
            .collect::<Vec<_>>();
        choices.push(ui::Choice::new("Keep waiting", "return to your worker"));
        let at = ui::select(
            "Choose a bounty to review",
            &[],
            &choices,
            choices.len() - 1,
        )?;
        if at == offers.len() {
            return Ok(());
        }
        let offer = &offers[at];
        let selection = ui::select(
            "Would you like to work on this bounty?",
            &offer_lines(offer, false),
            &[
                ui::Choice::new("View details", "review complete scope and reward terms"),
                ui::Choice::new("Accept bounty", "review submission and work budget"),
                ui::Choice::new("Skip", "hide this offer for this worker"),
                ui::Choice::new("Keep waiting", "leave without accepting"),
            ],
            0,
        )?;
        if selection == 3 {
            return Ok(());
        }
        if selection == 2 {
            dispatch(json!({"action":"skip","workerId":worker,"offerId":offer_id(offer)?,"bountyId":offer["bounty"]["id"]})).await?;
            continue;
        }
        let detailed =
            dispatch(json!({"action":"details","workerId":worker,"offerId":offer_id(offer)?}))
                .await?;
        let offer = if detailed["offer"].is_object() {
            &detailed["offer"]
        } else if detailed["termsVersion"].is_number() {
            &detailed
        } else {
            offer
        };
        for line in offer_lines(offer, true) {
            ui::info(&line);
        }
        let policy=ui::select("How should your agent submit a supported finding?",&["Priority uses server receipt of a complete report. Waiting for review can affect priority.".into()],&[ui::Choice::new("Ask me to review first","keep a private draft until you submit"),ui::Choice::new("Submit privately when ready","submit evidence automatically")],0)?;
        let budget = ui::input(
            "How long may your agent work before checking in?",
            "60",
            false,
            &|s| {
                let n = s
                    .parse::<u64>()
                    .map_err(|_| "Enter minutes between 1 and 1440")?;
                if !(1..=1440).contains(&n) {
                    return Err("Enter minutes between 1 and 1440".into());
                }
                Ok(n.to_string())
            },
        )?
        .parse::<u64>()
        .map_err(|_| "Invalid work budget")?;
        let request = acceptance(
            worker,
            offer,
            if policy == 0 { "review" } else { "automatic" },
            budget,
        )?;
        let mut notes = offer_lines(offer, true);
        notes.push(format!(
            "Work budget: {budget} minutes · Submission: {}",
            if policy == 0 {
                "review first"
            } else {
                "automatic private submission"
            }
        ));
        let confirmed = ui::select(
            "Accept exact source authorization, rules and direct-payment risk?",
            &notes,
            &[
                ui::Choice::new("Cancel", "keep waiting; no source download"),
                ui::Choice::new(
                    "Accept and prepare",
                    "accept publisher's unguaranteed payment promise and exact offline source scope",
                ),
            ],
            0,
        )?;
        if confirmed != 1 {
            return Ok(());
        }
        activity("Preparing the accepted bounty", request).await?;
        wait_prepared(worker, true).await?;
        return Ok(());
    }
}

async fn show_messages(worker: &str, last: &mut BTreeSet<String>) -> Result<(), String> {
    let result = dispatch(json!({"action":"messages","workerId":worker})).await?;
    for message in result["messages"].as_array().into_iter().flatten() {
        let id = message["id"]
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| {
                format!(
                    "{}:{}",
                    field(message, "createdAt", ""),
                    field(message, "content", "")
                )
            });
        if last.insert(id) {
            ui::info(&format!(
                "{}: {}",
                field(message, "role", "Agent"),
                field(message, "content", "")
            ));
        }
    }
    while last.len() > 1000 {
        let Some(first) = last.first().cloned() else {
            break;
        };
        last.remove(&first);
    }
    Ok(())
}

async fn chat(worker: &str) -> Result<(), String> {
    ui::intro(
        "Your agent",
        "This is your private conversation. Agent-channel messages are unavailable here.",
    );
    ui::info("/pause pauses work · /resume resumes · /status shows your worker · /back returns");
    let mut seen = BTreeSet::new();
    loop {
        show_messages(worker, &mut seen).await?;
        let content = match ui::input(
            "Ask your agent about progress or suggest a direction…",
            "",
            false,
            &|v| clean(v, "Message", 8192),
        ) {
            Ok(content) => content,
            Err(e) if e == ui::CANCELLED => {
                if ui::take_interrupt() && !interrupt(worker).await? {
                    continue;
                }
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        match content.as_str() {
            "/back" => return Ok(()),
            "/pause" | "/resume" => {
                let action = if content == "/pause" {
                    "pause"
                } else {
                    "resume"
                };
                activity(
                    "Updating your worker",
                    json!({"action":action,"workerId":worker}),
                )
                .await?;
                continue;
            }
            "/status" => {
                let value = dispatch(json!({"action":"status","workerId":worker})).await?;
                let worker = worker_value(&value);
                ui::info(&format!(
                    "{} · {}",
                    field(worker, "state", "Unknown"),
                    field(worker, "summary", "No completed attempts yet")
                ));
                continue;
            }
            _ => {}
        }
        let result = activity(
            "Sending your suggestion",
            json!({"action":"chat","workerId":worker,"content":content}),
        )
        .await?;
        ui::info(if result["delivered"] == true {
            "Your agent received the message."
        } else {
            "Message saved. Your agent will handle it at a task checkpoint."
        });
        show_messages(worker, &mut seen).await?;
        let choices = [
            ui::Choice::new(
                "Write another message",
                "suggest a direction or ask about progress",
            ),
            ui::Choice::new("Refresh replies", "check your agent's conversation"),
            ui::Choice::new("Back to worker", "keep the agent running"),
        ];
        loop {
            let selected = match ui::select("Your agent conversation", &[], &choices, 1) {
                Ok(selected) => selected,
                Err(error) if error == ui::CANCELLED => {
                    if ui::take_interrupt() && !interrupt(worker).await? {
                        continue;
                    }
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            match selected {
                0 => break,
                1 => show_messages(worker, &mut seen).await?,
                _ => return Ok(()),
            }
        }
    }
}

fn interrupt_choice(index: usize) -> &'static str {
    match index {
        1 => "pause",
        2 => "stop",
        3 => "delete",
        _ => "cancel",
    }
}

async fn interrupt(worker: &str) -> Result<bool, String> {
    ui::take_interrupt();
    let choices = [
        ui::Choice::new("Cancel", "return; keep everything running"),
        ui::Choice::new("Pause bounty work", "checkpoint and stop new tasks"),
        ui::Choice::new("Stop sandbox", "keep model and workspace files"),
        ui::Choice::new("Stop and delete", "remove this worker's local workspace"),
    ];
    let action = interrupt_choice(ui::select_required(
        "What would you like to do?",
        &[safe(worker)],
        &choices,
    )?);
    if action == "cancel" {
        return Ok(false);
    }
    if action == "delete" {
        let confirm=ui::select_required("Delete this bounty workspace?",&["Local project files and unsent drafts will be removed. Submitted reports and reward records stay in your account.".into()],&[ui::Choice::new("Cancel","keep the worker and its files"),ui::Choice::new("Delete workspace","permanently delete only this worker's workspace")])?;
        if confirm != 1 {
            return Ok(false);
        }
    }
    activity(
        "Updating worker",
        json!({"action":action,"workerId":worker,"confirmed":action=="delete"}),
    )
    .await?;
    Ok(action != "pause")
}

#[derive(Debug, PartialEq)]
enum WorkerKey {
    None,
    Offers,
    Chat,
    TogglePause,
    Refresh,
    Detach,
    Interrupt,
}
fn key_action(key: KeyEvent) -> WorkerKey {
    if key.kind == KeyEventKind::Release {
        return WorkerKey::None;
    }
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        return match key.code {
            KeyCode::Char('c') => WorkerKey::Interrupt,
            KeyCode::Char(']') => WorkerKey::Detach,
            _ => WorkerKey::None,
        };
    }
    match key.code {
        KeyCode::Char('o' | 'O') => WorkerKey::Offers,
        KeyCode::Char('c' | 'C') => WorkerKey::Chat,
        KeyCode::Char('p' | 'P') => WorkerKey::TogglePause,
        KeyCode::Char('r' | 'R') => WorkerKey::Refresh,
        KeyCode::Char('q' | 'Q') | KeyCode::Esc => WorkerKey::Detach,
        _ => WorkerKey::None,
    }
}

async fn dashboard(worker: &str) -> Result<(), String> {
    // The live map lists the keys; this stays in the log above it.
    ui::info(
        "Ctrl+C opens lifecycle choices. Ctrl+] detaches; the engine keeps your worker running.",
    );
    let screen = crate::bounty_map::Screen::start(worker);
    let mut last_snapshot = String::new();
    let mut offer_count = usize::MAX;
    let _raw = ui::Raw::on()?;
    loop {
        let result = dispatch(json!({"action":"status","workerId":worker})).await?;
        let state = worker_value(&result);
        if state["state"] == "stopped" {
            drop(screen);
            ui::outro("Worker stopped. Saved files remain available.");
            return Ok(());
        }
        screen.worker(state);
        let paused = state["state"] == "paused";
        // The map shows the details; the log keeps one plain line per change, and the exact
        // command when the worker waits for the participant.
        let sentence = state_sentence(&field(state, "name", worker), state["state"].as_str().unwrap_or(""));
        let hint = state_hint(state, worker);
        let snapshot = format!("{sentence}\n{}", hint.as_deref().unwrap_or_default());
        if last_snapshot != snapshot {
            ui::step(&sentence);
            if let Some(hint) = &hint {
                ui::info(hint);
            }
            last_snapshot = snapshot;
        }
        let result = dispatch(json!({"action":"offers","workerId":worker})).await?;
        let count = result["offers"].as_array().map_or(0, Vec::len);
        screen.offers(count);
        if count != offer_count {
            offer_count = count;
            if count > 0 {
                ui::step(&format!(
                    "{count} bounty offer{} available · press O to review company, objective and reward",
                    if count == 1 { "" } else { "s" }
                ));
            }
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let action = if event::poll(Duration::ZERO).map_err(|e| e.to_string())? {
                match event::read().map_err(|e| e.to_string())? {
                    Event::Key(key) => key_action(key),
                    Event::Resize(..) => {
                        ui::refresh();
                        WorkerKey::None
                    }
                    _ => WorkerKey::None,
                }
            } else {
                WorkerKey::None
            };
            match action {
                WorkerKey::Offers => {
                    // Menus and chat own the screen; the map steps aside meanwhile.
                    screen.show(false);
                    match offers(worker).await {
                        Err(e) if e == ui::CANCELLED => {
                            if ui::take_interrupt() && interrupt(worker).await? {
                                return Ok(());
                            }
                        }
                        Err(e) => ui::warn(&safe(&e)),
                        _ => {}
                    }
                    screen.show(true);
                    break;
                }
                WorkerKey::Chat => {
                    screen.show(false);
                    match chat(worker).await {
                        Err(e) if e == ui::CANCELLED => {
                            if ui::take_interrupt() && interrupt(worker).await? {
                                return Ok(());
                            }
                        }
                        Err(e) => ui::warn(&safe(&e)),
                        _ => {}
                    }
                    screen.show(true);
                    break;
                }
                WorkerKey::TogglePause => {
                    activity(
                        if paused {
                            "Resuming worker"
                        } else {
                            "Pausing worker"
                        },
                        json!({"action":if paused{"resume"}else{"pause"},"workerId":worker}),
                    )
                    .await?;
                    break;
                }
                WorkerKey::Refresh => break,
                WorkerKey::Detach => {
                    drop(screen);
                    ui::outro(&format!(
                        "Detached. Reconnect: yougori start bounty --worker {}",
                        safe(worker)
                    ));
                    return Ok(());
                }
                WorkerKey::Interrupt => {
                    screen.show(false);
                    if interrupt(worker).await? {
                        return Ok(());
                    }
                    screen.show(true);
                    break;
                }
                WorkerKey::None => {}
            }
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
    }
}

pub async fn run(args: &[String]) -> Result<Option<Value>, String> {
    if !args.first().is_some_and(|a| a == "bounty")
        && !(args.len() >= 2 && args[0] == "start" && args[1] == "bounty")
    {
        return Ok(None);
    }
    if args.iter().any(|a| matches!(a.as_str(), "--help" | "-h")) {
        println!("{HELP}");
        return Ok(Some(json!({"help":true})));
    }
    let Some(mut invocation) = parse(args)? else {
        return Ok(None);
    };
    if invocation.dry_run {
        return Ok(Some(
            json!({"dryRun":true,"request":invocation.request,"modelInputFirst":true,"privateModelApi":true,"autoAccept":false,"idleInference":false,"agentChannelHumanAccess":false,"interactiveRequired":invocation.interactive_start&&!invocation.yes,"terminal":"current"}),
        ));
    }
    if invocation.interactive_start && !ui::can_prompt() {
        if !invocation.yes
            || !invocation.no_wait
            || invocation.request["model"].is_null() && invocation.request["workerId"].is_null()
        {
            return Err("Starting a bounty worker requires an interactive terminal. For scripts supply --model, --yes and --no-wait; this never accepts an offer.".into());
        }
    }
    if invocation.request["action"] == "chat"
        && invocation.request["content"].is_null()
        && !ui::can_prompt()
    {
        return Err(
            "Chat requires an interactive terminal, or --message with a complete prompt".into(),
        );
    }
    // The wordmark belongs to the guided flows, not to one-line lookups such as `bounty workers`.
    let guided = invocation.interactive_start
        || invocation.request["action"] == "chat" && invocation.request["content"].is_null();
    let _session = if ui::can_prompt() && guided {
        Some(ui::Session::start(
            "Swarm Mining",
            "your model, your worker, your choice of bounty",
        ))
    } else {
        None
    };
    let result = async {
        if invocation.interactive_start {
            let Some(started_worker) = setup(&mut invocation).await? else {
                return Ok(json!({"cancelled":true}));
            };
            // Waiting for readiness belongs to `bounty status`, not to this process.
            if invocation.no_wait {
                return started(&started_worker);
            }
            let worker = worker_id(&started_worker)?;
            // Now online and waiting for offers: offer a safe practice run first.
            crate::bounty_practice::offer_practice_when_waiting(&worker).await?;
            dashboard(&worker).await?;
            Ok(json!({"detached":true,"workerId":worker}))
        } else {
            crate::client::start(None).await?;
            if invocation.request["action"] == "chat" && invocation.request["content"].is_null() {
                chat(invocation.request["workerId"].as_str().unwrap()).await?;
                Ok(json!({"detached":true}))
            } else {
                if invocation.request["action"]=="accept" {
                    let detail=dispatch(json!({"action":"details","workerId":invocation.request["workerId"],"offerId":invocation.request["offerId"]})).await?;
                    bind_offer(&mut invocation.request,&detail["offer"])?;
                }
                let rewards=invocation.request["action"]=="rewards";
                let mut result=dispatch(invocation.request).await?;
                if rewards {
                    let lines=reward_lines(&result);
                    if ui::can_prompt(){for line in &lines {ui::info(line);}}
                    if result.is_object(){result["paymentStatusLabels"]=json!(lines);}
                }
                Ok(result)
            }
        }
    }
    .await;
    match result {
        Err(e) if e == ui::CANCELLED => {
            ui::take_interrupt();
            Ok(Some(json!({"cancelled":true})))
        }
        Ok(v) => Ok(Some(v)),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn direct_offer(mut offer: Value) -> Value {
        let document = json!({"publisherLegalName":"Fixture publisher","publisherDisplayName":"Fixture company","signerName":"Fixture signer","signerCapacity":"Authorized maintainer","rightsStatement":"I may authorize review of this supplied fixture snapshot","defensivePurpose":"Defensive offline source review","permittedOfflineTests":"Read the supplied source and run only its declared offline checks","thirdPartyExcluded":true,"liveSystemsExcluded":true,"noProductionSecrets":true,"sourceRevision":offer["sourceRevision"],"sourceDigest":"b".repeat(64),"termsVersion":offer["termsVersion"],"minimumRules":{"mode":"local_source_only","remoteTargetsAllowed":false,"thirdPartyRightsGranted":false,"sourceInspectionDoesNotVerifyOwnership":true,"productionSecretsAllowed":false,"purpose":"defensive_source_review"}});
        offer["authorizationDigest"] = source_authorization_digest(&document).unwrap().into();
        offer["bounty"]["terms"]["authorization"] = document;
        offer["bounty"]["terms"]["sourceDigest"] = json!("b".repeat(64));
        offer["bounty"]["terms"]["sourceRevision"] = offer["sourceRevision"].clone();
        for (key, value) in [
            ("paymentMode", json!("publisher_direct_external")),
            ("prefunded", json!(false)),
            ("guaranteed", json!(false)),
            ("verifiedFunding", json!(false)),
            ("currency", json!("USDC")),
        ] {
            offer["reward"][key] = value;
        }
        offer
    }
    fn words(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_string).collect()
    }
    #[test]
    fn worker_setup_is_model_first_private_and_has_no_implicit_bounty() {
        let i=parse(&words("start bounty --model https://huggingface.co/Owner/Model --cpu 4.5 --memory 12GB --gpu cpu --workspace-quota 30 --dry-run")).unwrap().unwrap();
        assert_eq!(i.request["model"], "hf.co/Owner/Model");
        assert_eq!(i.request["resources"]["cpu"], 4.5);
        assert_eq!(i.request["resources"]["memoryGb"], 12.0);
        assert!(i.request["bountyId"].is_null());
        assert!(i.request["confirmed"].is_null());
    }
    #[test]
    fn start_environment_collision_is_explicit() {
        for args in [
            "start ordinary",
            "start --environment bounty",
            "env start bounty",
        ] {
            assert!(parse(&words(args)).unwrap().is_none());
        }
        assert!(
            parse(&words("start bounty --dry-run"))
                .unwrap()
                .unwrap()
                .interactive_start
        );
    }
    #[test]
    fn invalid_setup_is_rejected_before_any_engine_work() {
        for args in [
            "start bounty --model owner/model;bad",
            "start bounty --model yg/user/model",
            "start bounty --cpu NaN",
            "start bounty --memory inf",
            "start bounty --gpu all",
            "start bounty --cpu 2 --cpu 3",
            "start bounty --worker saved --memory 8",
            "start bounty --nowfree",
            "start bounty --model",
            "start bounty --platform-url http://remote.example",
            "start bounty --platform-url https://user:secret@example.com",
            "start bounty --platform-url https://example.com/api",
        ] {
            assert!(parse(&words(args)).is_err(), "{args}");
        }
        assert!(parse(&words(
            "start bounty --platform-url http://127.0.0.1:3000 --dry-run"
        ))
        .is_ok());
    }
    #[test]
    fn scripted_acceptance_requires_reviewed_terms_and_explicit_confirmation() {
        for args in ["bounty accept worker offer --yes","bounty accept worker offer --version 1 --terms-digest digest --report-policy review --budget-minutes 60","bounty accept worker offer --version 0 --terms-digest digest --report-policy review --budget-minutes 60 --yes","bounty accept worker offer --version 1 --terms-digest digest --report-policy automatic --budget-minutes 0 --yes"]{assert!(parse(&words(args)).is_err(),"{args}");}
        let command=format!("bounty accept worker offer --version 2 --terms-digest digest --authorization-digest {} --report-policy review --budget-minutes 30 --accept-rules --accept-authorization --accept-direct-payment --yes","a".repeat(64));
        let i = parse(&words(&command)).unwrap().unwrap();
        assert_eq!(i.request["termsVersion"], 2);
        assert_eq!(i.request["confirmed"], true);
        assert_eq!(i.request["rulesAccepted"], true);
        assert_eq!(i.request["authorizationAccepted"], true);
        assert_eq!(i.request["directPaymentAccepted"], true);
        for flag in [
            " --accept-rules",
            " --accept-authorization",
            " --accept-direct-payment",
        ] {
            assert!(parse(&words(&command.replace(flag, ""))).is_err(), "{flag}");
        }
        assert!(parse(&words("bounty accept worker offer --version 2 --terms-digest digest --report-policy review --budget-minutes 30 --yes")).is_err());
    }
    #[test]
    fn acceptance_binds_the_exact_offer_without_fallback_versions() {
        let mut offer = json!({"id":"offer","bounty":{"id":"bounty"},"termsVersion":3,"termsDigest":"abc","sourceRevision":"commit"});
        assert!(acceptance("worker", &offer, "review", 60).is_err());
        offer["bounty"]["terms"] = json!({"serviceRules":{"version":"fixture-1","digest":"a".repeat(64),"sections":[{"title":"Defensive use","text":"Do not bypass scope."}]}});
        offer = direct_offer(offer);
        let r = acceptance("worker", &offer, "review", 60).unwrap();
        assert_eq!(r["bountyId"], "bounty");
        assert_eq!(r["termsVersion"], 3);
        assert_eq!(r["sourceRevision"], "commit");
        assert_eq!(r["rulesVersion"], "fixture-1");
        assert_eq!(r["rulesDigest"], "a".repeat(64));
        assert_eq!(r["authorizationDigest"], offer["authorizationDigest"]);
        assert_eq!(r["sourceDigest"], "b".repeat(64));
        offer["termsDigest"] = Value::Null;
        assert!(acceptance("worker", &offer, "review", 60).is_err());
    }
    #[test]
    fn human_chat_never_requests_agent_channels_and_keeps_complete_text() {
        let args = vec![
            "bounty".into(),
            "chat".into(),
            "worker".into(),
            "--message".into(),
            "Please try this component next".into(),
        ];
        let i = parse(&args).unwrap().unwrap();
        assert_eq!(i.request["action"], "chat");
        assert_eq!(i.request["content"], "Please try this component next");
        for cmd in [
            "bounty channel worker",
            "bounty events worker",
            "bounty chat worker --channel secret",
        ] {
            assert!(parse(&words(cmd)).is_err());
        }
    }
    #[test]
    fn terminal_keys_do_not_turn_repeated_interrupts_into_delete() {
        assert_eq!(interrupt_choice(0), "cancel");
        assert_eq!(interrupt_choice(3), "delete");
        assert_eq!(
            key_action(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            WorkerKey::Interrupt
        );
        assert_eq!(
            key_action(KeyEvent::new(KeyCode::Char(']'), KeyModifiers::CONTROL)),
            WorkerKey::Detach
        );
        assert_eq!(
            key_action(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
            WorkerKey::None
        );
    }
    #[test]
    fn remote_offer_text_cannot_print_terminal_escape_sequences() {
        let lines = offer_lines(
            &json!({"bounty":{"company":{"name":"evil\u{1b}[2J"},"title":"Test"},"reward":{"amount":"100","currency":"TEST","simulated":true},"termsVersion":1}),
            true,
        );
        assert!(lines.iter().all(|line| !line.contains('\u{1b}')));
        assert!(lines.iter().any(|l| l.contains("simulated test reward")));
    }
    #[test]
    fn resource_sliders_fit_host_and_explicit_limits_are_preserved() {
        let r = json!({"resources":{"cpu":4.5}});
        let s = resource_sliders(&r, &json!({"totalCpu":16,"totalMemoryGb":12.5})).unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].max, 12);
        assert_eq!(s[0].value, 8);
        assert_eq!(r["resources"]["cpu"], 4.5);
        assert!(resource_sliders(&json!({}), &json!({"totalCpu":0})).is_err());
    }
    #[test]
    fn background_preparation_never_announces_readiness_while_loading() {
        for state in [
            "preparing",
            "downloading",
            "verifying",
            "preparing_bounty",
            "pending_approval",
            "failed",
            "stopped",
            "paused",
        ] {
            assert!(!prepared_state(state, false));
            assert!(!prepared_state(state, true));
        }
        assert!(prepared_state("ready_waiting", false));
        assert!(!prepared_state("ready_waiting", true));
        assert!(prepared_state("running", false));
        assert!(prepared_state("running", true));
    }
    #[test]
    fn server_offer_terms_are_visible_and_scripted_acceptance_resolves_the_bounty() {
        let offer = direct_offer(
            json!({"id":"bounty_example:2","bounty":{"id":"bounty_example","title":"Review local fixture","companyName":"Fixture company","terms":{"serviceRules":{"version":"fixture-1","digest":"a".repeat(64),"sections":[{"title":"Defensive use","text":"Do not bypass scope."}]},"objective":"Check local permissions","inScope":"Supplied source only","outOfScope":"All external services","qualifyingCriteria":"Reproduce the fixture issue","winnerRule":"First complete qualifying report"}},"reward":{"amount":"100.5","currency":"USDC","simulated":true,"status":"publisher_promise_unverified"},"termsVersion":2,"termsDigest":"digest","sourceRevision":"commit"}),
        );
        let lines = offer_lines(&offer, true).join("\n");
        for text in [
            "Fixture company",
            "Check local permissions",
            "Supplied source only",
            "All external services",
            "100.5 USDC",
            "simulated test reward",
            "Do not bypass scope.",
        ] {
            assert!(lines.contains(text), "{text}");
        }
        let mut request = json!({"termsVersion":2,"termsDigest":"digest","authorizationDigest":offer["authorizationDigest"],"authorizationAccepted":true,"directPaymentAccepted":true});
        bind_offer(&mut request, &offer).unwrap();
        assert_eq!(request["bountyId"], "bounty_example");
        assert_eq!(request["sourceRevision"], "commit");
        request["termsVersion"] = 1.into();
        assert!(bind_offer(&mut request, &offer).is_err());
    }
    #[test]
    fn publisher_promise_and_source_authorization_are_required_without_inventing_legal_rights() {
        let offer = direct_offer(
            json!({"id":"offer","bounty":{"id":"bounty","terms":{"serviceRules":{"version":"fixture","digest":"a".repeat(64),"sections":[]}}},"reward":{},"sourceRevision":"snapshot-1","termsVersion":1,"termsDigest":"exact"}),
        );
        assert!(acceptance("worker", &offer, "review", 20).is_ok());
        for (field, value) in [
            ("thirdPartyExcluded", json!(false)),
            ("liveSystemsExcluded", json!(false)),
            ("noProductionSecrets", json!(false)),
            ("sourceDigest", json!("c".repeat(64))),
            ("publisherLegalName", json!("")),
            (
                "rightsStatement",
                json!("Changed assertion without republishing"),
            ),
        ] {
            let mut bad = offer.clone();
            bad["bounty"]["terms"]["authorization"][field] = value;
            assert!(acceptance("worker", &bad, "review", 20).is_err(), "{field}");
        }
        let mut legacy = offer.clone();
        legacy["reward"]["paymentMode"] = json!("legacy_platform_funded");
        assert!(acceptance("worker", &legacy, "review", 20).is_err());
        let display = offer_lines(&offer, true).join("\n");
        for text in [
            "Publisher promise",
            "may not pay",
            "Publisher legal identity",
            "Signer capacity",
            "not independently verified",
            "third-party rights",
            "global legality",
            "Permitted offline checks",
        ] {
            assert!(display.contains(text), "{text}");
        }
    }
    #[test]
    fn valid_long_unicode_and_multiline_publisher_declarations_match_server_character_limits() {
        let mut offer = direct_offer(
            json!({"id":"offer","bounty":{"id":"bounty","terms":{"serviceRules":{"version":"fixture","digest":"a".repeat(64),"sections":[]}}},"reward":{},"sourceRevision":"snapshot","termsVersion":1,"termsDigest":"exact"}),
        );
        let document = &mut offer["bounty"]["terms"]["authorization"];
        document["rightsStatement"] = json!(format!(
            "{}\nAuthority for the supplied fixture only.",
            "界".repeat(7900)
        ));
        document["permittedOfflineTests"] = json!(format!(
            "{}\nDeclared offline checks only.",
            "ț".repeat(7900)
        ));
        document["publisherLegalName"] = json!("界".repeat(1990));
        offer["authorizationDigest"] =
            json!(source_authorization_digest(&offer["bounty"]["terms"]["authorization"]).unwrap());
        assert!(offer_authorization(&offer).is_ok());
        let mut altered = offer.clone();
        altered["bounty"]["terms"]["authorization"]["permittedOfflineTests"] =
            json!("An unaccepted new check");
        assert!(offer_authorization(&altered).is_err());
        let mut revision = offer.clone();
        revision["sourceRevision"] = json!("界".repeat(86));
        assert!(offer_authorization(&revision).is_err());
    }
    #[test]
    fn publisher_text_cannot_fake_lines_or_hide_direction_changes() {
        assert_eq!(safe("Title\nTerms digest: forged\u{202E}gpj.exe\u{200B}"), "Title Terms digest: forgedgpj.exe");
        let line = reward_lines(&json!({"directAwards":[{"state":"external_payment_due","amount":"5"}]}))[1].clone();
        assert!(line.contains("token not stated") && !line.contains("USDC"), "{line}");
        assert!(line.contains("network: not stated") && line.contains("recipient: not stated") && line.contains("due: not stated"));
        let line = reward_lines(&json!({"directAwards":[{"state":"external_payment_due","amount":"5","currency":"USDC","network":"Base","recipient":"0xabc","dueAt":"2026-11-01"}]}))[1].clone();
        assert!(line.contains("5 USDC · network: Base · recipient: 0xabc · due: 2026-11-01"), "{line}");
    }
    #[test]
    fn payment_records_distinguish_due_reported_evidence_and_receipt_without_balance_credit() {
        let text=reward_lines(&json!({"directAwards":[{"state":"external_payment_due","amount":"12"},{"state":"publisher_reported_unverified","amount":"12"},{"state":"winner_acknowledged_receipt","amount":"12"}],"legacyAwards":[{"state":"reserved"}]})).join("\n");
        for label in [
            "External payment due",
            "transaction evidence; unverified",
            "Winner acknowledged receipt",
            "not independently chain-verified",
            "manual resolution",
            "no Swarm balance credit",
        ] {
            assert!(text.contains(label), "{label}");
        }
        for command in [
            "bounty withdraw worker",
            "bounty transfer worker",
            "bounty rewards worker --private-key secret",
            "bounty rewards worker --seed-phrase secret",
        ] {
            assert!(parse(&words(command)).is_err());
        }
    }
    #[test]
    fn approval_applications_bind_published_scope_and_do_not_accept_an_offer() {
        let application = parse(&words(
            "bounty apply worker bounty --version 2 --terms-digest scope --yes",
        ))
        .unwrap()
        .unwrap();
        assert_eq!(application.request["action"], "apply");
        assert_eq!(application.request["confirmed"], true);
        assert!(application.request["authorizationAccepted"].is_null());
        assert!(application.request["directPaymentAccepted"].is_null());
        assert!(parse(&words(
            "bounty apply worker bounty --version 2 --terms-digest scope"
        ))
        .is_err());
        assert!(parse(&words("bounty apply worker bounty --yes")).is_err());
        assert!(parse(&words("bounty bounties")).is_ok());
    }

    #[test]
    fn plain_states_and_recommended_setup() {
        assert_eq!(state_label("ready_waiting"), "live");
        assert_eq!(state_label("failed"), "needs attention");
        assert_eq!(state_sentence("ToA", "running"), "ToA is working");
        assert_eq!(state_sentence("ToA", "ready_waiting"), "ToA is live and waiting for bounty offers");
        let host = json!({"totalCpu":24,"totalMemoryGb":63.4,"gpuUsagePercent":3.9,"storageDrives":[
            {"path":"C:\\","freeGb":18.7},{"path":"E:\\","freeGb":900.0,"removable":true},{"path":"D:\\","freeGb":583.1}]});
        let request = json!({"action":"prepare","model":"hf.co/owner/model"});
        let nvidia = json!({"supported":true,"checks":[{"name":"NVIDIA GPU and driver","passed":true}]});
        let recommended = recommended_settings(&request, &host, &nvidia).unwrap().unwrap();
        assert_eq!(recommended["resources"]["storageDrive"], "D:\\", "most free fixed drive");
        assert_eq!((recommended["resources"]["cpu"].as_u64(), recommended["resources"]["memoryGb"].as_u64()), (Some(4), Some(8)));
        assert_eq!(recommended["gpu"], "nvidia");
        assert_eq!(recommended["model"], "hf.co/owner/model");
        let notes = setup_notes(&recommended, &nvidia).join("\n");
        assert!(notes.contains("Runs on your NVIDIA GPU · 4 CPU cores · 8 GB memory"), "{notes}");
        assert!(notes.contains("Files on D:\\ · 20 GB for bounty workspaces · model kept loaded"), "{notes}");
        // Windows reports GPU use for AMD and Intel graphics too; only the CUDA checks count.
        let amd = json!({"supported":false,"checks":[{"name":"NVIDIA GPU and driver","passed":false}]});
        let cpu_only = recommended_settings(&request, &host, &amd).unwrap().unwrap();
        assert_eq!(cpu_only["gpu"], "cpu");
        let notes = setup_notes(&cpu_only, &amd).join("\n");
        assert!(notes.contains("Runs on the processor") && notes.contains("yougori gpu status"), "{notes}");
        let unchecked = recommended_settings(&request, &host, &Value::Null).unwrap().unwrap();
        assert_eq!(unchecked["gpu"], "cpu", "an engine that could not check");
        // Any setting given on the command line keeps the step-by-step questions.
        assert!(recommended_settings(&json!({"model":"m","name":"Mine"}), &host, &nvidia).unwrap().is_none());
        assert!(recommended_settings(&json!({"model":"m","resources":{"cpu":6}}), &host, &nvidia).unwrap().is_none());
        assert!(recommended_settings(&request, &json!({"totalCpu":2,"totalMemoryGb":4}), &nvidia).is_err());
    }

    #[tokio::test]
    async fn scripted_setup_uses_the_gpu_only_after_the_cuda_checks_pass() {
        for (cuda, expected) in [
            (Ok(json!({"supported":true})), "nvidia"),
            (Ok(json!({"supported":false,"detail":"No compatible NVIDIA WDDM device was verified."})), "cpu"),
            (Err("Unknown method get_cuda_runtime_status".to_string()), "cpu"),
        ] {
            let mut request = json!({"action":"prepare","model":"hf.co/owner/model"});
            let mut calls = Vec::new();
            scripted_settings(&mut request, &mut |method, _| {
                calls.push(method);
                std::future::ready(cuda.clone())
            })
            .await;
            assert_eq!(request["gpu"], expected);
            assert_eq!(calls, ["get_cuda_runtime_status"]);
            assert_eq!((request["resources"]["cpu"].as_u64(), request["workspaceQuotaGb"].as_u64()), (Some(4), Some(20)));
        }
        // An explicit choice is kept without checking.
        let mut request = json!({"action":"prepare","model":"hf.co/owner/model","gpu":"nvidia"});
        scripted_settings(&mut request, &mut |_, _| {
            panic!("--gpu skips the CUDA checks");
            #[allow(unreachable_code)]
            std::future::ready(Ok(Value::Null))
        })
        .await;
        assert_eq!(request["gpu"], "nvidia");
        let mut bare = json!({});
        defaults(&mut bare);
        assert_eq!(bare["gpu"], "cpu", "defaults never assume NVIDIA");
    }

    #[tokio::test]
    async fn scripted_no_wait_starts_the_worker_with_one_request_and_never_polls() {
        let script = parse(&words("start bounty --model hf.co/owner/model --yes --no-wait")).unwrap().unwrap();
        assert!(script.yes && script.no_wait);
        let mut calls = Vec::new();
        let result = start_detached(script.request, |method, params| {
            calls.push((method, params["request"]["action"].clone(), params["request"]["gpu"].clone()));
            std::future::ready(Ok(match method {
                "get_cuda_runtime_status" => json!({"supported":false}),
                _ => json!({"worker":{"id":"worker-new","state":"preparing","stage":"Checking your model and resources"},"background":true}),
            }))
        })
        .await
        .unwrap();
        assert_eq!(calls, [("get_cuda_runtime_status", Value::Null, Value::Null), ("swarm_dispatch", json!("prepare"), json!("cpu"))]);
        let shown = started(&result).unwrap();
        assert_eq!((shown["worker"]["id"].as_str(), shown["worker"]["state"].as_str(), shown["background"].as_bool()), (Some("worker-new"), Some("preparing"), Some(true)));
        assert!(shown["next"].as_str().unwrap().contains("yougori bounty status worker-new"), "{shown}");
        // Reconnecting a saved worker sends only its resume request.
        let script = parse(&words("start bounty --worker worker-old --yes --no-wait")).unwrap().unwrap();
        let mut actions = Vec::new();
        let result = start_detached(script.request, |_, params| {
            actions.push(params["request"]["action"].clone());
            std::future::ready(Ok(json!({"worker":{"id":"worker-old","state":"ready_waiting"}})))
        })
        .await
        .unwrap();
        assert_eq!(actions, [json!("resume")]);
        assert!(started(&result).unwrap()["next"].as_str().unwrap().contains("bounty status worker-old"));
        let paused = started(&json!({"worker":{"id":"worker-old","state":"paused"}})).unwrap();
        assert!(paused["next"].as_str().unwrap().contains("yougori bounty resume worker-old") && paused["background"].is_null());
        assert!(started(&json!({"background":true})).is_err(), "a result without a worker ID is an error");
    }

    #[test]
    fn submitting_a_draft_and_leaving_a_bounty_need_explicit_confirmation() {
        let submit = parse(&words("bounty submit worker-1 report_9 --yes")).unwrap().unwrap();
        assert_eq!(submit.request, json!({"action":"submitReport","workerId":"worker-1","reportId":"report_9"}));
        let leave = parse(&words("bounty leave worker-1 --yes")).unwrap().unwrap();
        assert_eq!(leave.request, json!({"action":"leave","workerId":"worker-1"}));
        for args in [
            "bounty submit worker-1 report_9",
            "bounty submit worker-1 --yes",
            "bounty submit worker-1 ../report_9 --yes",
            "bounty submit worker-1 report_9 extra --yes",
            "bounty submitReport worker-1 report_9 --yes",
            "bounty leave worker-1",
            "bounty leave --yes",
        ] {
            assert!(parse(&words(args)).is_err(), "{args}");
        }
        assert!(parse(&words("bounty submit worker-1 report_9 --dry-run")).is_ok());
        assert!(parse(&words("bounty messages worker-1")).is_ok());
        for usage in ["chat|messages|pause", "bounty submit WORKER REPORT_ID --yes", "bounty leave WORKER --yes"] {
            assert!(HELP.contains(usage), "{usage}");
        }
    }

    #[test]
    fn restarted_and_review_states_say_exactly_what_to_run() {
        let hint = state_hint(&json!({"state":"paused","restored":true}), "worker-1").unwrap();
        assert!(hint.contains("engine restarted") && hint.contains("yougori bounty resume worker-1"), "{hint}");
        assert!(state_hint(&json!({"state":"paused"}), "worker-1").is_none(), "a pause the participant chose needs no hint");
        let review = json!({"state":"awaiting_review","reviewReports":["report_1","report_2"]});
        let hint = state_hint(&review, "worker-1").unwrap();
        assert!(hint.contains("yougori bounty reports worker-1") && hint.contains("yougori bounty submit worker-1 report_2 --yes"), "{hint}");
        let forged = state_hint(&json!({"state":"awaiting_review","reviewReports":["x\u{1b}[2J"]}), "w").unwrap();
        assert!(!forged.contains('\u{1b}'), "{forged}");
        assert_eq!(state_label("awaiting_review"), "report ready");
        assert!(prepared_state("awaiting_review", true));
    }
}
