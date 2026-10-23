//! Swarm Mining's human CLI. Worker credentials and private agent channels stay in the engine.
use crate::{cli_ui as ui, model_invocation, public::call};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    future::Future,
    time::{Duration, Instant},
};

pub const DEFAULT_MODEL: &str = "hf.co/thesamgodson/Gemma-4-12B-Hephaestus-GGUF:Q4_K_M";

/// The setup's model question and the line under it.
const MODEL_QUESTION: &str = "Which Hugging Face GGUF model should power your worker?";
const MODEL_NOTE: &str =
    "Use a GGUF repository, for example hf.co/OWNER/MODEL-GGUF. Add :Q4_K_M to choose a quantization.";
/// Workers run GGUF models only, through the engine's llama.cpp runner.
const GGUF_ONLY: &str = "Swarm Mining workers run only GGUF models (the llama.cpp format). Choose a Hugging Face repository with .gguf files; its name usually ends in -GGUF.";

pub const HELP: &str = r#"Swarm Mining runs a bounty worker on this computer with your own model. It works only on
bounties you accept.

  yougori start bounty [--change] [--model hf.co/OWNER/MODEL-GGUF[:QUANT]] [OPTIONS]
  yougori bounty workers
  yougori bounty bounties [WORKER]
  yougori bounty apply WORKER BOUNTY --version N --terms-digest DIGEST --yes
  yougori bounty status|offers|chat|messages|pause|resume|stop WORKER
  yougori bounty resume WORKER [--budget-minutes N]
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
  yougori bounty practice WORKER [--stop]
  yougori bounty memory WORKER release|keep

WORKER is the name to type for a worker, such as keen-heron. A new worker gets a name
no other worker on this computer answers to, with -2 or -3 added when needed. Every
hint uses it and yougori bounty workers lists it; a worker's short name, the name
you gave it, its ID or the first digits of its ID work too.

Setup options:
  --change (set up a new worker: choose the model, drive and resources again)
  --cpu CORES --memory GB --gpu nvidia|metal|cpu --storage-drive PATH
  --workspace-quota GB --name NAME --quant VARIANT --release-memory|--keep-loaded
  --worker WORKER (resume the saved model and resources)
  --platform-url HTTPS_URL (HTTP loopback supported for local development)
  --yes --no-wait (scripted start: prints the worker at once; never accepts a bounty)
  --dry-run (validate and show requests without contacting the engine)

Without options, start bounty reconnects to the worker set up last on this computer
and reuses its downloaded model and sandbox. A worker whose preparation failed asks
before retrying. --change, --model or another creation option (--cpu, --memory,
--gpu, --storage-drive, --workspace-quota, --name, --quant, --release-memory,
--keep-loaded, --platform-url) sets up a new worker instead.

The model loads only for work: an accepted bounty, your chat, or the practice. While
the worker waits it is unloaded, so it holds no GPU or model memory; the next job
loads it from disk again. --keep-loaded, or bounty memory WORKER keep, keeps it
loaded for faster starts; bounty memory WORKER release unloads it again.
bounty practice WORKER, or T in the waiting view, opens a live console where the
worker's own model attacks a safe offline target: the runtime starts a flawed
login service and plants a flag, and the model breaks in over the network and
captures it. Its requests, the responses and its tries stream as they happen;
typing stops it and it goes on with your message. A finding qualifies only when
its flag matches the planted one. Nothing is paid; /endpractice leaves. Without a
terminal it stops after 5 rejected findings or 30 minutes; --stop ends it. Press L (or Enter) in the waiting view
to watch an accepted bounty the same way; there /stop pauses or leaves it.

Without --gpu, native Mac builds probe Metal first. Other hosts use an NVIDIA GPU only when this PC passes the CUDA
checks of yougori gpu status; otherwise the processor runs the model.

Workers run GGUF models (the llama.cpp format) that support tool calling. Interactive
setup suggests Gemma-4-12B-Hephaestus-GGUF at Q4_K_M. Paste another Hugging Face
GGUF repository to change it; :IQ4_XS also selects the quantization. A repository
without GGUF files is refused before anything downloads. Setup then asks which drive
stores the model and the worker's sandboxes, preselecting the fixed drive with the
most free space. A model already downloaded on that drive with the same settings is
reused; another drive downloads it again. Esc goes back to the previous question,
and Ctrl+C stops waiting at any step. Memory is suggested from the selected weights
plus space for the agent and test sandbox.
Yougori prepares a private local model API and
OpenCode, then waits for offers without agent inference. Once online it offers a
safe, offline practice bounty you can try while you wait. Review the company,
objective, exact source authorization and publisher payment promise before accepting.
Each acceptance question offers Back, and nothing is accepted until Accept and prepare.
With report policy review, a finished draft shows as report ready: read it with
bounty reports, then send it with bounty submit. Leaving ends the accepted bounty.
An engine restart pauses every worker until you resume it. Once the work budget
is spent, resume with --budget-minutes N (1-1440): work continues N more minutes
from now, never past the bounty's deadline.
The publisher pays a qualifying winner externally from its own wallet. Payment is
not prefunded, verified or guaranteed by Yougori. No Swarm withdrawal or transfer
command is provided. Never supply a wallet private key or seed phrase.
Humans chat only with
their own agent; private agent channels have no human CLI command.
Authorized local defensive research only. Do not use this service maliciously,
bypass safeguards, or falsify evidence. Open source modification rights remain.
Read https://yougori.com/swarm/rules and the exact rules in your offer.
Publisher assertions do not grant rights over third parties or live systems.

The waiting view: O offers, C chat, P pause/resume, T practice, R refresh, Q detach.
Ctrl+C opens Cancel / Pause / Stop / Stop and delete. Ctrl+] detaches and keeps
the engine's worker running. Deletion keeps submitted reports and reward records.
An environment named bounty can still start with: yougori start --environment bounty
"#;

#[derive(Clone, Debug)]
pub struct Invocation {
    pub request: Value,
    pub dry_run: bool,
    pub yes: bool,
    pub no_wait: bool,
    pub interactive_start: bool,
    /// `--change`: set up a new worker instead of reconnecting to the saved one.
    pub change: bool,
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

/// The usage line of one bounty command, from [`HELP`], naming only that command.
fn usage(action: &str) -> String {
    if action == "start" {
        return "Usage: yougori start bounty [OPTIONS]".into();
    }
    HELP.lines()
        .filter_map(|line| line.trim().strip_prefix("yougori bounty "))
        .find_map(|rest| {
            let (verbs, words) = rest.split_once(' ').unwrap_or((rest, ""));
            verbs.split('|').any(|verb| verb == action).then(|| format!("Usage: yougori bounty {action} {words}").trim_end().to_owned())
        })
        .unwrap_or_else(|| format!("Usage: yougori bounty {action}"))
}

/// What a value-taking option of the bounty commands expects, for the error that asks for it.
fn flag_value(flag: &str) -> &'static str {
    match flag {
        "--model" => "a Hugging Face GGUF model, such as hf.co/OWNER/MODEL-GGUF",
        "--cpu" => "CPU cores, from 4 to 255",
        "--memory" => "memory in GB, from 8 to 1024",
        "--gpu" => "nvidia, metal or cpu",
        "--storage-drive" => "the drive or folder for the model and sandboxes",
        "--workspace-quota" => "GB for bounty workspaces, from 4 to 1024",
        "--name" => "the worker's name",
        "--quant" => "a GGUF quantization, such as Q4_K_M",
        "--worker" => "a worker's name or ID from yougori bounty workers",
        "--platform-url" => "the website's address",
        "--version" => "the offer's terms version",
        "--terms-digest" => "the offer's terms digest",
        "--authorization-digest" => "the offer's authorization digest",
        "--report-policy" => "automatic or review",
        "--budget-minutes" => "minutes from 1 to 1440",
        _ => "a value",
    }
}

/// A worker's own name. The engine refuses names shorter than two bytes.
fn worker_name(value: &str) -> Result<String, String> {
    let name = value.trim();
    if name.len() < 2 || name.len() > 64 || name.chars().any(char::is_control) {
        return Err("Worker name must contain 2 to 64 bytes and no control characters".into());
    }
    Ok(name.into())
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
    let (repository, quant) = match value.trim().rsplit_once(':') {
        Some((repository, quant)) if !quant.contains('/') => {
            if quant.is_empty() || quant.len() > 32 || !quant.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                return Err("Use a GGUF quantization label after ':', for example IQ4_XS or Q4_K_M".into());
            }
            (repository, Some(quant.to_ascii_uppercase()))
        }
        _ => (value, None),
    };
    let value = model_invocation::model_id(repository)?;
    if !value.starts_with("hf.co/") {
        return Err("Paste a Hugging Face GGUF model: hf.co/OWNER/MODEL-GGUF".into());
    }
    Ok(match quant { Some(quant) => format!("{value}:{quant}"), None => value })
}

fn normalize_selection(request: &mut Value) -> Result<(), String> {
    let Some(selected) = request["model"].as_str() else { return Ok(()) };
    let selected = model(selected)?;
    if let Some((repository, quant)) = selected.rsplit_once(':') {
        if request["quant"].as_str().is_some_and(|explicit|!explicit.eq_ignore_ascii_case(quant)) {
            return Err("The model's :QUANT suffix conflicts with --quant; choose one variant".into());
        }
        request["model"] = repository.into();
        request["quant"] = quant.into();
    } else {
        request["model"] = selected.into();
    }
    Ok(())
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
            | "practice"
            | "memory"
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
    let mut change = false;
    let mut i = 1;
    while i < tail.len() {
        let flag = tail[i].as_str();
        if !flag.starts_with('-') {
            positional.push(clean(flag, "Identifier", 256)?);
            i += 1;
            continue;
        }
        if !seen.insert(flag.to_string()) {
            return Err(format!("{flag} is given twice. Give it once."));
        }
        match flag {
            "--dry-run" => dry_run = true,
            "--yes" => yes = true,
            "--no-wait" if action == "start" => no_wait = true,
            "--change" if action == "start" => change = true,
            // Ends a practice that runs in the engine, such as one a stopped script left.
            "--stop" if action == "practice" => request["action"] = "practiceStop".into(),
            "--release-memory" | "--keep-loaded" if action == "start" => {
                if request["keepResident"].is_boolean() {
                    return Err("Choose either --release-memory or --keep-loaded".into());
                }
                request["keepResident"] = (flag == "--keep-loaded").into();
            }
            "--model" | "--cpu" | "--memory" | "--gpu" | "--storage-drive"
            | "--workspace-quota" | "--name" | "--quant" | "--worker" | "--platform-url"
                if action == "start" =>
            {
                i += 1;
                let value = tail
                    .get(i)
                    .filter(|v| !v.starts_with('-'))
                    .ok_or_else(|| format!("{flag} needs a value: {}.", flag_value(flag)))?;
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
                        if !matches!(value.as_str(), "nvidia" | "metal" | "cpu") {
                            return Err("--gpu must be nvidia, metal or cpu".into());
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
                    "--name" => request["name"] = worker_name(value)?.into(),
                    _ => {
                        request[if flag == "--quant" { "quant" } else { "workerId" }] =
                            clean(value, flag, 256)?.into()
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
                    || action == "apply" && matches!(flag, "--version" | "--terms-digest")
                    || action == "resume" && flag == "--budget-minutes" =>
            {
                i += 1;
                let value = tail
                    .get(i)
                    .ok_or_else(|| format!("{flag} needs a value: {}.", flag_value(flag)))?;
                match flag {
                    "--version" => {
                        let n = value
                            .parse::<u64>()
                            .map_err(|_| "--version must be a whole number above 0, the offer's terms version.")?;
                        if n == 0 {
                            return Err("--version must be a whole number above 0, the offer's terms version.".into());
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
                            return Err("--authorization-digest must be the exact 64-character SHA-256 from the offer.".into());
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
                            .map_err(|_| "--budget-minutes must be a whole number from 1 to 1440.")?;
                        if !(1..=1440).contains(&n) {
                            return Err("--budget-minutes must be a whole number from 1 to 1440.".into());
                        }
                        request["budgetMinutes"] = n.into();
                    }
                }
            }
            _ => {
                let command = if action == "start" { "yougori start bounty".to_owned() } else { format!("yougori bounty {action}") };
                return Err(format!("Unknown option {flag} for {command}. See its options with yougori bounty --help."));
            }
        }
        i += 1;
    }
    let limits = match action {
        "start" | "workers" => (0, 0),
        "details" | "accept" | "skip" | "apply" | "submit" | "memory" => (2, 2),
        "reports" | "rewards" | "doctor" | "bounties" => (0, 1),
        _ => (1, 1),
    };
    if positional.len() < limits.0 || positional.len() > limits.1 {
        return Err(format!("{}. See every option with yougori bounty --help.", usage(action)));
    }
    if let Some(worker) = positional.first() {
        request["workerId"] = worker.clone().into();
    }
    if action == "memory" {
        request["keepResident"] = match positional[1].as_str() {
            "release" => false,
            "keep" => true,
            _ => return Err("bounty memory WORKER takes release (unload while waiting) or keep".into()),
        }
        .into();
    } else if let Some(report) = positional.get(1).filter(|_| action == "submit") {
        if !identifier(report) {
            return Err("REPORT_ID is the id of a draft listed by yougori bounty reports WORKER".into());
        }
        request["reportId"] = report.clone().into();
    } else if let Some(offer) = positional.get(1) {
        request["offerId"] = offer.clone().into();
        request["bountyId"] = offer.clone().into();
    }
    if action == "start" {
        normalize_selection(&mut request)?;
        if request["workerId"].is_string() && (change || creation_options(&request)) {
            return Err("--worker resumes saved model and resources; do not combine it with --change or creation options".into());
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
        for (key, flag) in [
            ("termsVersion", "--version N"),
            ("termsDigest", "--terms-digest DIGEST"),
            ("authorizationDigest", "--authorization-digest DIGEST"),
            ("reportPolicy", "--report-policy automatic|review"),
            ("budgetMinutes", "--budget-minutes N"),
        ] {
            if request[key].is_null() {
                return Err(format!(
                    "Accepting a bounty needs {flag}. The offer's values are in yougori bounty details WORKER OFFER."
                ));
            }
        }
        if !yes && !dry_run {
            return Err(
                "Accepting binds your worker to this offer's terms and starts its work. Repeat with --yes after reviewing the offer.".into(),
            );
        }
        request["confirmed"] = true.into();
    }
    if action == "delete" && !yes && !dry_run {
        return Err("Deleting removes the worker's local workspace and unsent drafts; submitted reports stay. Repeat with --yes to go ahead.".into());
    }
    if action == "submit" && !yes && !dry_run {
        return Err("Submitting sends the report privately to the publisher for review. Read the draft with yougori bounty reports WORKER, then repeat with --yes.".into());
    }
    if action == "leave" && !yes && !dry_run {
        return Err("Leaving stops work on the accepted bounty and stops its sandboxes; reports, drafts and reward records stay. Repeat with --yes to go ahead.".into());
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
            return Err("Applying asks the publisher for access; it grants no source access or research authorization by itself. Repeat with --yes to go ahead.".into());
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
        change,
    }))
}

/// Settings that describe a new worker, so `start bounty` does not reconnect to the saved one.
/// A platform URL is one too: a worker keeps the platform it was prepared for, and only a new
/// worker's preparation checks the URL.
fn creation_options(request: &Value) -> bool {
    request["model"].is_string()
        || request["resources"].is_object()
        || request["gpu"].is_string()
        || request["name"].is_string()
        || request["quant"].is_string()
        || request["workspaceQuotaGb"].is_number()
        || request["keepResident"].is_boolean()
        || request["platformUrl"].is_string()
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

/// A long note for a prompt, such as a problem to fix, as lines that fit this terminal:
/// prompts cut every note line at the screen's edge.
fn note_lines(text: &str) -> Vec<String> {
    let columns = crossterm::terminal::size().map_or(80, |(columns, _)| usize::from(columns));
    // The rail before each note line takes three columns; the last one stays free.
    wrapped(text, columns.saturating_sub(4))
}

/// At most five lines, so the question and its choices stay on screen.
fn wrapped(text: &str, columns: usize) -> Vec<String> {
    let mut lines: Vec<String> = ui::wrap(text, columns.max(20))
        .into_iter()
        .map(|(line, _)| line.trim_end().to_owned())
        .collect();
    if lines.len() > 5 {
        lines.truncate(5);
        lines[4].push('…');
    }
    lines
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

/// Words for worker short names: plain, friendly, easy to type and harmless in any pairing
/// (no word that reads as slang next to another). Changing either list renames existing workers.
const HANDLE_ADJECTIVES: [&str; 100] = [
    "able", "agile", "amber", "ample", "apt", "azure", "bold", "brave", "breezy", "bright",
    "brisk", "calm", "candid", "cheery", "civic", "clever", "cosmic", "cozy", "crisp", "curious",
    "dapper", "daring", "deft", "eager", "early", "earnest", "elated", "epic", "fair", "fancy",
    "fleet", "fluent", "fresh", "frosty", "gentle", "glad", "golden", "grand", "happy", "hardy",
    "hearty", "honest", "humble", "jolly", "jovial", "keen", "kind", "lively", "lucid", "lucky",
    "lunar", "mellow", "merry", "mighty", "misty", "modest", "neat", "nimble", "noble", "novel",
    "polar", "polite", "proud", "quick", "quiet", "rapid", "ready", "regal", "rosy", "royal",
    "rustic", "sage", "scenic", "serene", "sharp", "shiny", "silent", "silver", "sleek", "smart",
    "snowy", "solar", "sonic", "spry", "steady", "stellar", "sturdy", "sunny", "swift", "tidy",
    "tranquil", "true", "trusty", "upbeat", "valiant", "vivid", "warm", "wise", "witty", "zesty",
];
const HANDLE_NOUNS: [&str; 100] = [
    "alpaca", "badger", "bear", "bee", "beetle", "bison", "bobcat", "canary", "caribou", "cheetah",
    "condor", "corgi", "coyote", "crane", "cricket", "deer", "dingo", "dolphin", "dove", "eagle",
    "egret", "elk", "falcon", "ferret", "finch", "fox", "gazelle", "gecko", "gibbon", "gopher",
    "grouse", "hare", "hawk", "heron", "ibex", "ibis", "impala", "jaguar", "kestrel", "kite",
    "kiwi", "koala", "lark", "lemur", "leopard", "lion", "llama", "lynx", "magpie", "marmot",
    "marten", "meerkat", "mink", "moose", "narwhal", "newt", "ocelot", "okapi", "orca", "osprey",
    "otter", "owl", "panda", "panther", "parrot", "pelican", "penguin", "petrel", "pika", "plover",
    "puffin", "puma", "quail", "quokka", "rabbit", "raven", "robin", "salmon", "seal", "sparrow",
    "starling", "stork", "swan", "tapir", "teal", "tern", "thrush", "tiger", "toucan", "trout",
    "turtle", "vole", "walrus", "warbler", "whale", "wolf", "wombat", "wren", "yak", "zebra",
];

/// The short name people use for a worker, such as keen-heron: derived from the whole ID, so
/// an ID keeps its name forever. Two workers rarely share one; their IDs then tell them apart.
pub fn worker_handle(id: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(id.as_bytes());
    let n = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) as usize;
    format!("{}-{}", HANDLE_ADJECTIVES[n % 100], HANDLE_NOUNS[n / 100 % 100])
}

/// How a command compares what people type with workers' names: in any case, with spaces for
/// hyphens, so " Keen Heron " is keen-heron.
fn name_key(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join("-").to_lowercase()
}

/// Whether `name` is a memorable worker name, as new workers are given: two words from the
/// short-name lists, such as keen-heron, with -2, -3 and so on after a collision.
pub fn memorable_name(name: &str) -> bool {
    let key = name_key(name);
    let mut words = key.split('-');
    let (Some(adjective), Some(noun), number, None) = (words.next(), words.next(), words.next(), words.next()) else {
        return false;
    };
    HANDLE_ADJECTIVES.contains(&adjective)
        && HANDLE_NOUNS.contains(&noun)
        && number.is_none_or(|n| !n.starts_with('0') && n.parse::<u32>().is_ok_and(|n| n >= 2))
}

/// Whether a command reads `text` as the first digits of a worker ID rather than as a name.
fn id_digits(text: &str) -> bool {
    let wanted = text.trim().to_lowercase();
    let digits = wanted.strip_prefix("worker-").unwrap_or(&wanted);
    digits.len() >= 4 && digits.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// The workers of a `workers` listing.
fn listed_workers(listed: &Value) -> impl Iterator<Item = &Value> {
    listed["workers"].as_array().into_iter().flatten().filter(|worker| worker["id"].is_string())
}

/// Every name a worker answers to in a command, as [`name_key`] compares them: its ID, its
/// short name and its own name.
fn answers_to(worker: &Value) -> Vec<String> {
    let id = worker["id"].as_str().unwrap_or_default();
    let mut names = vec![id.to_lowercase(), worker_handle(id)];
    names.extend(worker["name"].as_str().map(name_key));
    names
}

/// The name for a new worker: `base`, such as keen-heron, or keen-heron-2, keen-heron-3 and so
/// on when a worker in the `workers` listing already answers to it by its ID, short name or own
/// name. A name a command would read as ID digits is never given. So in a command the new
/// name always means the new worker; existing workers keep their names.
pub fn new_worker_name(base: &str, listed: &Value) -> String {
    let taken: BTreeSet<String> = listed_workers(listed).flat_map(answers_to).collect();
    let base = name_key(base);
    let mut name = base.clone();
    let mut number = 1;
    while taken.contains(&name) || id_digits(&name) {
        number += 1;
        name = format!("{base}-{number}");
    }
    name
}

/// A memorable two-word name picked at random, such as keen-heron.
fn fresh_worker_name() -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
    hasher.write_u128(now.map_or(0, |since| since.as_nanos()));
    let n = hasher.finish() as usize;
    format!("{}-{}", HANDLE_ADJECTIVES[n % HANDLE_ADJECTIVES.len()], HANDLE_NOUNS[n / HANDLE_ADJECTIVES.len() % HANDLE_NOUNS.len()])
}

/// What to type for `worker` in a command, among `workers`: its memorable name when no other of
/// them answers to it, else its short name when no other answers to that, else its full ID.
fn typed_among(worker: &Value, workers: &[&Value]) -> String {
    let id = worker["id"].as_str().unwrap_or_default();
    let others: BTreeSet<String> = workers
        .iter()
        .filter(|other| other["id"].as_str() != Some(id))
        .flat_map(|other| answers_to(other))
        .collect();
    let name = worker["name"].as_str().map(name_key).unwrap_or_default();
    if memorable_name(&name) && !others.contains(&name) {
        return name;
    }
    let handle = worker_handle(id);
    if others.contains(&handle) {
        field(worker, "id", "worker")
    } else {
        handle
    }
}

/// What to type for each of these workers in a command, as [`typed_among`] picks it.
pub fn worker_names(workers: &[&Value]) -> Vec<String> {
    workers.iter().map(|worker| typed_among(worker, workers)).collect()
}

/// Whether another worker in a `workers` listing answers to the short name of the worker `id`.
fn handle_shared(id: &str, listed: &Value) -> bool {
    let handle = worker_handle(id);
    listed_workers(listed)
        .filter(|worker| worker["id"].as_str() != Some(id))
        .any(|worker| answers_to(worker).contains(&handle))
}

/// What to type for the worker `id` in a command, as [`worker_names`] picks it from the
/// `workers` listing; its short name, or its ID when that is shared, if it is not listed.
pub fn typed_name(id: &str, listed: &Value) -> String {
    let workers: Vec<&Value> = listed_workers(listed).collect();
    match workers.iter().find(|worker| worker["id"].as_str() == Some(id)) {
        Some(worker) => typed_among(worker, &workers),
        None if handle_shared(id, listed) => safe(id),
        None => worker_handle(id),
    }
}

/// What to type for the worker in an engine result that [`with_handles`] marked: its memorable
/// name, else its short name, or its ID when another worker shares that.
pub fn typed_in_result(worker: &Value) -> String {
    let name = worker["name"].as_str().map(name_key).unwrap_or_default();
    if memorable_name(&name) {
        name
    } else if worker["handleShared"] == true {
        field(worker, "id", "worker")
    } else {
        worker["id"].as_str().map(worker_handle).unwrap_or_else(|| "—".into())
    }
}

/// [`typed_name`] from the engine's current listing, for a command printed as a hint. The
/// short name when the listing does not come at once, such as after Ctrl+C stopped a slow
/// request.
pub(crate) async fn typed(id: &str) -> String {
    match tokio::time::timeout(Duration::from_secs(2), dispatch(json!({"action":"workers"}))).await {
        Ok(Ok(listed)) => typed_name(id, &listed),
        _ => worker_handle(id),
    }
}

/// Workers listed for people to choose from: what to type, with each one's name and state.
fn worker_choices(workers: &[&Value]) -> String {
    workers
        .iter()
        .zip(worker_names(workers))
        .map(|(worker, typed)| {
            let state = state_label(worker["state"].as_str().unwrap_or(""));
            let name = field(worker, "name", "Bounty worker");
            if name_key(&name) == typed {
                format!("{typed} ({state})")
            } else {
                format!("{typed} ({name}, {state})")
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// The full ID of the worker that `input` names, from a `workers` listing: its ID, its short
/// name or its own name in any case, or the first digits of its ID (at least four).
pub fn resolve_worker(input: &str, listed: &Value) -> Result<String, String> {
    let workers: Vec<&Value> = listed["workers"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|worker| worker["id"].is_string())
        .collect();
    let id = |worker: &Value| worker["id"].as_str().unwrap_or_default().to_owned();
    let input = input.trim();
    if let Some(worker) = workers.iter().find(|worker| worker["id"].as_str() == Some(input)) {
        return Ok(id(worker));
    }
    let wanted = input.to_lowercase();
    let digits = wanted.strip_prefix("worker-").unwrap_or(&wanted);
    let prefix = id_digits(input);
    let shown = ui::clip(&safe(input), 80);
    // "keen heron" names keen-heron too.
    let typed = name_key(input);
    // A short name and a worker's own name count alike, so a name one worker has as its short
    // name and another as its own is never taken as either of them.
    let by_name = |worker: &Value| {
        worker_handle(&id(worker)) == typed || worker["name"].as_str().is_some_and(|name| name_key(name) == typed)
    };
    let by_prefix = |worker: &Value| {
        let full = id(worker).to_lowercase();
        prefix && full.strip_prefix("worker-").unwrap_or(&full).starts_with(digits)
    };
    let tiers: [&dyn Fn(&Value) -> bool; 2] = [&by_name, &by_prefix];
    for matches in tiers {
        let found: Vec<&Value> = workers.iter().copied().filter(|worker| matches(worker)).collect();
        match found.len() {
            0 => {}
            1 => return Ok(id(found[0])),
            _ => {
                return Err(format!(
                    "{shown} matches more than one worker: {}. Name one of them as listed, such as {}.",
                    worker_choices(&found),
                    worker_names(&found)[0]
                ))
            }
        }
    }
    if workers.is_empty() {
        return Err(format!(
            "No bounty worker matches {shown}: this computer has none yet. Set one up with yougori start bounty."
        ));
    }
    Err(format!(
        "No bounty worker matches {shown}. Workers on this computer: {}.",
        worker_choices(&workers)
    ))
}

/// The engine names workers by their full ID. Anything else the person typed is looked up.
async fn resolve(request: &mut Value) -> Result<(), String> {
    let Some(input) = request["workerId"].as_str().map(str::to_owned) else { return Ok(()) };
    let full = input.strip_prefix("worker-").is_some_and(|digits| {
        digits.len() == 32 && digits.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    });
    if !full {
        let listed = ui::busy("Finding your workers", dispatch(json!({"action":"workers"}))).await?;
        request["workerId"] = resolve_worker(&input, &listed)?.into();
    }
    Ok(())
}

/// Adds the short name of each worker in an engine result, next to its ID. A worker that
/// shares it with another worker in the `listed` workers is marked `handleShared`: commands
/// name that one by its ID.
fn with_handles(result: &mut Value, listed: &Value) {
    let add = |worker: &mut Value| {
        let Some(id) = worker["id"].as_str().map(str::to_owned) else { return };
        let shared = handle_shared(&id, listed);
        if let Some(worker) = worker.as_object_mut() {
            worker.insert("handle".into(), worker_handle(&id).into());
            if shared {
                worker.insert("handleShared".into(), true.into());
            }
        }
    };
    if let Some(result) = result.as_object_mut() {
        if let Some(worker) = result.get_mut("worker") {
            add(worker);
        }
        if let Some(Value::Array(workers)) = result.get_mut("workers") {
            workers.iter_mut().for_each(add);
        }
    }
}

/// The command that opens this worker again: plain `start bounty` when it picks this worker,
/// otherwise with the name to type for it.
fn reconnect_command(id: &str, listed: &Value, environments: &[Value]) -> String {
    if saved_worker(listed, environments).is_some_and(|saved| saved["id"] == id) {
        "yougori start bounty".into()
    } else {
        format!("yougori start bounty --worker {}", typed_name(id, listed))
    }
}

pub(crate) async fn reconnect_line(id: &str) -> String {
    let (listed, environments) = workers_listing().await.unwrap_or_default();
    format!("Reconnect: {}", reconnect_command(id, &listed, &environments))
}

/// The workers, and the environments that tell which of them was set up last.
async fn workers_listing() -> Result<(Value, Vec<Value>), String> {
    let listed = dispatch(json!({"action":"workers"})).await?;
    // Older engines record no creation time; the workers' environments stand in for it.
    let environments = call("get_platform_state", json!({}))
        .await
        .ok()
        .and_then(|mut state| serde_json::from_value(state["environments"].take()).ok())
        .unwrap_or_default();
    Ok((listed, environments))
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

/// A finished step's line, as a task leaves it: what was done and how long it took.
fn finished(text: &str, started: Instant) {
    let elapsed = started.elapsed();
    let time = if elapsed >= Duration::from_millis(100) {
        format!("  {}", ui::muted(&ui::clock(elapsed)))
    } else {
        String::new()
    };
    ui::line(&format!("{}  {text}{time}", ui::paint("◇", ui::GREEN)));
}

/// One engine request shown as a step. Ctrl+C stops waiting (the engine may still finish a
/// request it received); keys typed meanwhile are dropped.
async fn activity(label: &str, request: Value) -> Result<Value, String> {
    let started = Instant::now();
    match ui::busy(label, dispatch(request)).await {
        Ok(value) => {
            finished(label, started);
            Ok(value)
        }
        Err(error) if error == ui::CANCELLED => Err(error),
        Err(error) => {
            ui::line(&format!("{}  Could not complete this step", ui::paint("■", ui::RED)));
            Err(error)
        }
    }
}

/// A change the person asked for, shown as a step. Ctrl+C stops waiting, but the engine may
/// still finish a request it received, so the person is told where to check instead of
/// hearing that nothing changed.
async fn change(label: &str, request: Value) -> Result<Value, String> {
    let worker = request["workerId"].as_str().map(str::to_owned);
    match activity(label, request).await {
        Err(error) if error == ui::CANCELLED => {
            ui::take_interrupt();
            Err(stopped_waiting(&status_command(worker.as_deref()).await))
        }
        result => result,
    }
}

/// The command that shows what became of a change to this worker, or of the workers.
async fn status_command(worker: Option<&str>) -> String {
    match worker {
        Some(id) => format!("yougori bounty status {}", typed(id).await),
        None => "yougori bounty workers".into(),
    }
}

fn stopped_waiting(check: &str) -> String {
    format!("Stopped waiting. Yougori may still finish this change; check it with {check}.")
}

fn worker_value(result: &Value) -> &Value {
    if result["worker"].is_object() {
        &result["worker"]
    } else {
        result
    }
}
/// The engine is already preparing or running this worker. Reconnecting only watches it:
/// a resume request would restart its preparation.
fn active_state(state: &str) -> bool {
    matches!(state, "preparing" | "preparing_bounty") || prepared_state(state, false)
}
fn failed_state(state: &str) -> bool {
    matches!(state, "failed" | "error" | "preparation_failed" | "failed_prepare" | "failed_bounty")
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

/// What Ctrl+C offers during a preparation. An accepted bounty's preparation runs inside the
/// waiting view, so leaving it goes back there; a worker's setup ends the command instead.
fn preparation_choices(bounty: bool) -> [ui::Choice; 3] {
    [
        ui::Choice::new("Cancel", "return to preparation; keep it running"),
        ui::Choice::new(
            "Stop preparation",
            "stop this worker's setup; preserve downloaded files",
        ),
        if bounty {
            ui::Choice::new("Back to the waiting view", "keep preparing the bounty in the engine")
        } else {
            ui::Choice::new("Back to terminal", "detach; keep setup running in the engine")
        },
    ]
}

async fn preparation_interrupt(worker: &str, bounty: bool) -> Result<bool, String> {
    ui::take_interrupt();
    let selected = ui::select_required(
        "What would you like to do?",
        &["Preparation belongs to this worker. Saved downloads can be resumed.".into()],
        &preparation_choices(bounty),
    )?;
    if selected == 0 {
        return Ok(false);
    }
    if selected == 1 {
        change("Stopping preparation", json!({"action":"cancelPrepare","workerId":worker})).await?;
        ui::info("Preparation stopped. Saved downloads remain available for retry.");
    } else if bounty {
        ui::info("Preparation continues in the engine.");
    } else {
        ui::info(&format!("Preparation continues. {}", reconnect_line(worker).await));
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
            task.done(&if bounty {
                "Your agent is ready to work.".to_owned()
            } else {
                format!("Your worker {} is ready.", typed(worker).await)
            });
            return Ok(true);
        }
        if failed_state(state) {
            task.fail("Worker preparation failed");
            let reason = data["error"]
                .as_str()
                .or(result["error"].as_str())
                .map(safe)
                .unwrap_or_else(|| "Preparation failed.".into());
            let name = typed(worker).await;
            return Err(format!(
                "{reason}\nCheck it: yougori bounty doctor {name}\nTry again: yougori start bounty --worker {name}\nChoose another model or drive: yougori start bounty --change"
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
                "The terminal stopped waiting after 60 minutes. Inspect: {}",
                status_command(Some(worker)).await
            ));
            return Ok(false);
        }
        let tick = tokio::time::Instant::now() + Duration::from_secs(2);
        while tokio::time::Instant::now() < tick {
            if ui::can_prompt() && event::poll(Duration::ZERO).map_err(|e| e.to_string())? {
                match event::read().map_err(|e| e.to_string())? {
                    Event::Key(key) => match key_action(key) {
                        WorkerKey::Interrupt => {
                            if preparation_interrupt(worker, bounty).await? {
                                task.done("Left preparation view");
                                return Ok(false);
                            }
                        }
                        WorkerKey::Detach => {
                            task.done("Preparation continues in the engine");
                            if !bounty {
                                ui::info(&reconnect_line(worker).await);
                            }
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
/// restart paused, or a report draft to read and send. `id` is what to type for the worker
/// ([`typed_name`]).
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
    if cuda["metalSupported"] == true && cuda["available"] == true {
        "metal"
    } else if cuda["supported"] == true {
        "nvidia"
    } else {
        "cpu"
    }
}

#[test]
fn metal_requires_a_successful_native_runtime_probe() {
    assert_eq!(gpu_choice(&json!({"available":true,"metalSupported":true})), "metal");
    assert_eq!(gpu_choice(&json!({"available":false,"metalSupported":true})), "cpu");
    assert_eq!(gpu_choice(&json!({"available":true,"metalSupported":false})), "cpu");
}

const COMPUTE_STATUS_METHOD: &str = if cfg!(target_os="macos") {"model_compute_status"} else {"get_cuda_runtime_status"};

async fn cuda_checks<F, Fut>(rpc: &mut F) -> Value
where
    F: FnMut(&'static str, Value) -> Fut,
    Fut: Future<Output = Result<Value, String>>,
{
    rpc(COMPUTE_STATUS_METHOD, json!({})).await.unwrap_or(Value::Null)
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
    let automatic_memory = request["resources"]["memoryGb"].is_null() && request["rentedGpu"].is_null();
    defaults(request);
    // The engine resolves omitted RAM after preflight, using the selected weights.
    if automatic_memory { request["resources"].as_object_mut().unwrap().remove("memoryGb"); }
}

/// Settings for the one-screen setup, or none when the command line already chose some.
fn recommended_settings(request: &Value, host: &Value, cuda: &Value) -> Result<Option<Value>, String> {
    // The drive is asked separately, so a chosen drive keeps this screen.
    if ["gpu", "workspaceQuotaGb", "name", "keepResident"].iter().any(|key| !request[*key].is_null())
        || ["cpu", "memoryGb"].iter().any(|key| !request["resources"][*key].is_null())
    {
        return Ok(None);
    }
    let mut recommended = request.clone();
    recommended["resources"] = json!({});
    for slider in resource_sliders(request, host)? {
        recommended["resources"][if slider.label == "CPU" { "cpu" } else { "memoryGb" }] = slider.value.into();
    }
    if let Some(drive) = request["resources"]["storageDrive"].as_str() {
        recommended["resources"]["storageDrive"] = drive.into();
    } else if let Some(drive) = roomiest_drive(host) {
        recommended["resources"]["storageDrive"] = drive["path"].clone();
    }
    // Windows reports GPU use for any vendor; only the CUDA checks show an NVIDIA GPU works.
    recommended["gpu"] = gpu_choice(cuda).into();
    defaults(&mut recommended);
    Ok(Some(recommended))
}

fn free_gb(drive: &Value) -> f64 {
    drive["freeGb"].as_f64().filter(|gb| gb.is_finite()).unwrap_or(0.0)
}

/// The drive with the most free space keeps model files off a full system drive.
fn roomiest_drive(host: &Value) -> Option<&Value> {
    host["storageDrives"].as_array().into_iter().flatten()
        .filter(|drive| drive["path"].is_string() && drive["readOnly"] != true && drive["removable"] != true)
        .max_by(|a, b| free_gb(a).total_cmp(&free_gb(b)))
}

/// Which drive stores the model download, its runtime and the worker's sandboxes, and whether
/// that was asked. One drive needs no question, and without a drive list the engine uses its
/// default.
fn choose_drive(request: &Value, host: &Value, preflight: &Value, preferred: Option<&str>) -> Result<(Option<String>, bool), String> {
    let drives = host["storageDrives"].as_array().into_iter().flatten()
        .filter(|drive| drive["path"].is_string())
        .collect::<Vec<_>>();
    let path = |drive: &Value| drive["path"].as_str().unwrap_or_default().to_owned();
    if drives.len() < 2 {
        return Ok((drives.first().map(|drive| path(drive)), false));
    }
    // The model volume holds at least 20 GB; both sandboxes share the workspace quota.
    let needed = preflight["resources"]["storageGbRecommended"].as_f64().unwrap_or(0.0).max(20.0)
        + request["workspaceQuotaGb"].as_f64().unwrap_or(20.0);
    let recommended = roomiest_drive(host).map(path);
    let writable = |drive: &Value| drive["readOnly"] != true;
    let mut choices = drives
        .iter()
        .map(|drive| {
            let label = match drive["name"].as_str().map(str::trim).filter(|name| !name.is_empty()) {
                Some(name) => format!("{} {}", safe(&path(drive)), safe(name)),
                None => safe(&path(drive)),
            };
            let free = free_gb(drive);
            let mut hint = if !writable(drive) {
                "read-only".to_string()
            } else if free < needed {
                format!("{} free; needs about {needed:.0} GB", ui::size_gb(free))
            } else {
                format!("{} free", ui::size_gb(free))
            };
            if drive["removable"] == true {
                hint.push_str(" · removable");
            }
            let choice = ui::Choice::new(label, hint).recommended(recommended == Some(path(drive)));
            if writable(drive) { choice } else { choice.disabled() }
        })
        .collect::<Vec<_>>();
    choices.push(ui::Choice::new("Cancel", "return without creating a worker"));
    let initial = preferred
        .and_then(|preferred| drives.iter().position(|drive| writable(drive) && crate::storage::same_drive(&path(drive), preferred)))
        .or_else(|| drives.iter().position(|drive| recommended == Some(path(drive))))
        .or_else(|| drives.iter().position(|drive| writable(drive)))
        .unwrap_or(drives.len());
    let weights = preflight["resources"]["weightsBytes"].as_u64().map(|bytes| format!(" ({})", ui::bytes(bytes))).unwrap_or_default();
    let picked = ui::select(
        "Where should your worker's files be stored?",
        &[
            format!("The model download{weights}, its runtime and the worker's sandboxes need about {needed:.0} GB."),
            "A model already downloaded on a drive with the same settings is reused there.".into(),
        ],
        &choices,
        initial,
    )?;
    if picked >= drives.len() {
        return Err(ui::CANCELLED.into());
    }
    Ok((Some(path(drives[picked])), true))
}

/// When a worker's environments were created, standing in for the creation time that older
/// releases did not record: its agent sandbox first, then its model. The test sandbox is made
/// when the worker accepts its first bounty, long after setup, so it stands in only for a
/// worker that records no agent sandbox. Environments deleted since count for nothing, so a
/// worker whose files are gone ranks below one that still has them.
fn environments_created<'a>(worker: &Value, environments: &'a [Value]) -> (&'a str, &'a str) {
    let created = |key: &str| {
        worker[key]
            .as_str()
            .and_then(|id| environments.iter().find(|environment| environment["id"] == id))
            .and_then(|environment| environment["createdAt"].as_str())
            .unwrap_or("")
    };
    let sandbox = if worker["environmentId"].is_string() {
        created("environmentId")
    } else {
        created("testEnvironmentId")
    };
    (sandbox, created("modelEnvironmentId"))
}

/// The worker `start bounty` reconnects to: the newest. Workers from releases without a
/// creation time rank by when their environments were created, then by state and by how far
/// their preparation got.
fn saved_worker<'a>(listed: &'a Value, environments: &[Value]) -> Option<&'a Value> {
    listed["workers"].as_array()?.iter()
        .filter(|worker| worker["id"].as_str().is_some_and(identifier))
        .max_by_key(|worker| {
            let state = worker["state"].as_str().unwrap_or("");
            let rank = if active_state(state) { 3 } else if state == "paused" { 2 } else if failed_state(state) { 1 } else { 0 };
            (
                worker["createdAt"].as_i64().unwrap_or(0),
                environments_created(worker, environments),
                rank,
                worker["serverId"].is_string(),
                worker["environmentId"].is_string(),
                worker["modelEnvironmentId"].is_string(),
            )
        })
}

/// The saved worker's model and quantization, suggested again by `--change`.
fn saved_model(saved: &Value) -> Option<String> {
    let name = saved["model"].as_str()?;
    let name = if name.starts_with("hf.co/") { name.to_owned() } else { format!("hf.co/{name}") };
    model(&match saved["quant"].as_str() {
        Some(quant) => format!("{name}:{quant}"),
        None => name,
    })
    .ok()
}

/// A suggested model with the variant `quant` (--quant) in place of its own :QUANT. A
/// --quant that is no GGUF label leaves the suggestion without one; --quant still applies.
fn with_variant(suggested: String, quant: Option<&str>) -> String {
    let Some(quant) = quant else { return suggested };
    let repository = match suggested.rsplit_once(':') {
        Some((repository, label)) if !label.contains('/') => repository.to_owned(),
        _ => suggested,
    };
    model(&format!("{repository}:{quant}")).unwrap_or(repository)
}

/// The model question's check of an answer, against the command line's request `base`.
fn model_entry(base: &Value, value: &str) -> Result<String, String> {
    let chosen = model(value)?;
    let mut request = base.clone();
    request["model"] = chosen.as_str().into();
    normalize_selection(&mut request)?;
    Ok(chosen)
}

/// The saved worker as `start bounty` introduces it before reconnecting, with what to type for
/// it among the `listed` workers.
fn saved_line(saved: &Value, listed: &Value) -> String {
    let name = field(saved, "name", "Bounty worker");
    let typed = typed_name(saved["id"].as_str().unwrap_or_default(), listed);
    format!(
        "Your worker: {} · {} · files on {}",
        if name_key(&name) == typed { typed } else { format!("{name} ({typed})") },
        saved_model(saved).unwrap_or_else(|| field(saved, "model", "")),
        field(&saved["resources"], "storageDrive", "the default drive")
    )
}

/// The newest worker besides `saved` that did not fail, which a failed saved worker's
/// screen offers to open instead.
fn other_worker(listed: &Value, saved: &Value, environments: &[Value]) -> Value {
    let others: Vec<Value> = listed["workers"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|worker| worker["id"] != saved["id"] && !failed_state(worker["state"].as_str().unwrap_or("")))
        .cloned()
        .collect();
    saved_worker(&json!({"workers":others}), environments).cloned().unwrap_or(Value::Null)
}

pub fn model_memory_recommendation(preflight: &Value) -> u32 {
    let weights = preflight["resources"]["weightsBytes"].as_u64().unwrap_or(0) as f64 / 1_073_741_824.;
    // Keep four GiB for Hermes/test sandboxes, plus weight/context overhead.
    (((weights * 1.15 + 1.5 + 4.) / 4.).ceil() * 4.).clamp(8., 1024.) as u32
}

fn recommended_model_settings(request: &Value, host: &Value, cuda: &Value, memory: u32) -> Result<Option<Value>, String> {
    let Some(mut settings) = recommended_settings(request, host, cuda)? else { return Ok(None) };
    for slider in resource_sliders_with_memory(request, host, memory)? {
        settings["resources"][if slider.label == "CPU" { "cpu" } else { "memoryGb" }] = slider.value.into();
    }
    Ok(Some(settings))
}

fn setup_notes(request: &Value, cuda: &Value) -> Vec<String> {
    let resources = &request["resources"];
    let mut notes = vec![
        format!("{} · {}", field(request, "name", "Bounty worker"), field(request, "model", "")),
        format!(
            "{} · {} CPU cores · {} GB memory",
            runs_on(request),
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
            if request["keepResident"] == true { "model kept loaded while waiting" } else { "model loaded only for work" }
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
    // The model loads for work only, unless the participant keeps it loaded.
    if request["keepResident"].is_null() {
        request["keepResident"] = false.into();
    }
}

fn resource_sliders(request: &Value, host: &Value) -> Result<Vec<ui::Slider>, String> {
    resource_sliders_with_memory(request, host, 8)
}

fn resource_sliders_with_memory(request: &Value, host: &Value, memory: u32) -> Result<Vec<ui::Slider>, String> {
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
        let suggested = if key == "memoryGb" { memory.max(default) } else { default };
        if suggested > max {
            return Err(format!("This selected model needs about {suggested} GB for the worker. Choose a smaller GGUF or a lower quantization."));
        }
        sliders.push(ui::Slider {
            label,
            unit,
            min: default,
            max,
            default: suggested,
            value: suggested,
        });
    }
    Ok(sliders)
}

/// What `--no-wait` prints: the worker as the engine returned it, with its short name, and how
/// to follow it.
fn started(result: &Value) -> Result<Value, String> {
    let id = worker_id(result)?;
    let mut worker = worker_value(result).clone();
    if let Some(shown) = worker.as_object_mut() {
        shown.insert("handle".into(), worker_handle(&id).into());
    }
    let name = typed_in_result(&worker);
    let next = match worker["state"].as_str() {
        Some("preparing") => format!("Preparation continues in the engine. Follow it with `yougori bounty status {name}`; the worker is ready when its state is ready_waiting."),
        Some("paused") => format!("The worker stays paused. Resume it with `yougori bounty resume {name}`."),
        _ => format!("Follow it with `yougori bounty status {name}`."),
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

/// [`start_detached`] for a setup's request. A worker the engine already prepares or runs is
/// returned as it is, never restarted: a resume request would restart its preparation or its
/// agent's turn. `saved` is the listed worker plain `start bounty` reconnects to; a worker
/// named with --worker is looked up first.
async fn start_scripted<F, Fut>(request: Value, saved: &Value, mut rpc: F) -> Result<Value, String>
where
    F: FnMut(&'static str, Value) -> Fut,
    Fut: Future<Output = Result<Value, String>>,
{
    if request["action"] == "resume" {
        let current = if saved.is_object() && request["workerId"] == saved["id"] {
            json!({"worker":saved})
        } else {
            let status = json!({"action":"status","workerId":request["workerId"]});
            rpc("swarm_dispatch", json!({"request":status}))
                .await
                .map_err(engine_error)?
        };
        if active_state(worker_value(&current)["state"].as_str().unwrap_or("")) {
            return Ok(current);
        }
    }
    start_detached(request, rpc).await
}

/// Registering a new worker needs the account. Scripts stop here; people can sign in now.
async fn sign_in(interactive: bool) -> Result<(), String> {
    if ui::busy("Checking your Yougori account", crate::network::signed_in()).await? {
        return Ok(());
    }
    if !interactive {
        return Err("Connect your account first with yougori login. No worker was created.".into());
    }
    ui::intro(
        "Connect this worker to your Yougori account",
        "The engine stores credentials securely on this computer.",
    );
    let login = crate::network::login(|code, address| {
        ui::info(&format!("Approve this sign-in: {}", safe(address)));
        ui::info(&format!("Code: {}", safe(code)));
    });
    ui::busy("Waiting for you to approve the sign-in", login).await.map(|_| ())
}

/// Saves a Hugging Face read token in the OS credential vault, for gated and private models.
async fn save_token() -> Result<(), String> {
    let token = ui::input("Hugging Face read token", "", true, &|value| {
        if !value.starts_with("hf_")
            || !(12..=1024).contains(&value.len())
            || !value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err("Enter a valid Hugging Face read token. Its value is withheld.".into());
        }
        Ok(value.into())
    })?;
    ui::busy(
        "Saving the token",
        call("set_deployment_secret", json!({"name":crate::model_auth::REFERENCE,"value":token})),
    )
    .await?;
    ui::info("Read token saved in the OS credential vault. Accept any gated model's terms on Hugging Face before retrying.");
    Ok(())
}

/// Why a checked model cannot power a worker, or None when it can. An engine that reports no
/// preflight leaves the decision to preparation.
fn gguf_problem(preflight: &Value) -> Option<String> {
    if !preflight.is_object() || preflight["runner"] == "yougori-llama-cpp" {
        return None;
    }
    if preflight["format"] != "gguf" {
        return Some(format!("This repository has no GGUF files. {GGUF_ONLY}"));
    }
    // The engine's reasons end without a full stop.
    let reason = field(preflight, "reason", "Yougori cannot run this GGUF repository on a worker");
    Some(format!("{}. Choose another GGUF repository.", reason.trim_end().trim_end_matches('.')))
}

/// The model's memory need when this computer cannot give a worker that much. A --memory
/// given on the command line is the person's own choice.
fn too_big(request: &Value, host: &Value, memory: u32) -> Option<String> {
    if !request["resources"]["memoryGb"].is_null() {
        return None;
    }
    let total = host["totalMemoryGb"].as_f64().filter(|total| total.is_finite())?;
    let needed = memory.max(8);
    (f64::from(needed) > total.floor().min(1024.0)).then(|| format!(
        "This model needs about {needed} GB of memory for the worker, more than this computer has. Choose a smaller GGUF model or a lower quantization, such as :IQ4_XS."
    ))
}

/// A failed model check as the attention screen shows it. The engine words a repository
/// without GGUF files for --quant; people get the rule instead.
fn model_problem(error: &str) -> String {
    if error.contains("has no GGUF files") {
        format!("This repository has no GGUF files. {GGUF_ONLY}")
    } else {
        safe(error)
    }
}

/// Where the worker runs its model, in words.
fn runs_on(request: &Value) -> &'static str {
    match request["gpu"].as_str() {
        Some("cpu") => "Runs on the processor",
        Some("metal") => "Runs natively on Apple Metal",
        _ => "Runs on your NVIDIA GPU",
    }
}

/// The questions of an interactive setup, in order. Back returns to the last one that asked.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Step {
    /// The saved worker failed: Retry, Set up again, open another worker, or Cancel.
    Attention,
    /// The model, then its checks.
    Model,
    Drive,
    /// Prepare with the recommended settings, or Customize.
    Summary,
    Gpu,
    Size,
    Quota,
    Name,
    Memory,
    Confirm,
}

const STEPS: [Step; 10] = [
    Step::Attention,
    Step::Model,
    Step::Drive,
    Step::Summary,
    Step::Gpu,
    Step::Size,
    Step::Quota,
    Step::Name,
    Step::Memory,
    Step::Confirm,
];

/// An interactive setup. The command line's request stays as given and each answer is kept on
/// its own, so a question asked again after Back starts from the earlier answer; the request
/// is put together at the end.
#[derive(Default)]
struct Setup {
    /// The request from the command line.
    given: Value,
    /// The worker set up last on this computer, or null.
    saved: Value,
    /// A worker that did not fail, offered when the saved one did.
    other: Value,
    /// The saved worker failed, so the setup first asks what to do with it.
    attention: bool,
    attention_choice: usize,
    /// The model is checked and the setup questions follow (no --yes).
    checks: bool,
    /// The worker to open instead of setting up a new one.
    reopen: Option<String>,
    /// The engine's `workers` listing, for the names commands use.
    listed: Value,
    /// The name a new worker gets when none is given or entered: memorable, and one no other
    /// worker on this computer answers to.
    fresh_name: String,
    /// The model question is asked: no model was given, or a model needed attention.
    enter_model: bool,
    model: Option<String>,
    /// The chosen model passed its checks, which found `preflight`.
    checked: bool,
    preflight: Value,
    host: Option<Value>,
    cuda: Option<Value>,
    drive: Option<String>,
    /// Prepare with the recommended settings (true) or Customize (false).
    quick: Option<bool>,
    gpu: Option<&'static str>,
    sizes: Vec<u32>,
    quota: Option<f64>,
    name: Option<String>,
    keep: Option<bool>,
}

impl Setup {
    /// Steps that ask nothing with the choices made so far.
    fn skips(&self, step: Step) -> bool {
        let customize = self.checks && self.quick != Some(true);
        match step {
            Step::Attention => !self.attention,
            Step::Model => !self.enter_model && !self.checks,
            Step::Drive => !self.checks || !self.given["resources"]["storageDrive"].is_null(),
            Step::Summary => !self.checks,
            Step::Gpu => !customize || !self.given["gpu"].is_null(),
            Step::Size | Step::Confirm => !customize,
            Step::Quota => !customize || !self.given["workspaceQuotaGb"].is_null(),
            Step::Name => !customize || !self.given["name"].is_null(),
            Step::Memory => !customize || !self.given["keepResident"].is_null(),
        }
    }

    /// Asks each step in turn until the setup is complete or a worker is opened instead.
    async fn ask(&mut self) -> Result<(), String> {
        let mut steps = ui::Wizard::new();
        while let Some(&step) = STEPS.get(steps.step()) {
            let asked = if self.skips(step) { Ok(false) } else { self.run(step).await };
            steps.next(asked)?;
            if self.reopen.is_some() {
                break;
            }
        }
        Ok(())
    }

    async fn run(&mut self, step: Step) -> Result<bool, String> {
        match step {
            Step::Attention => self.ask_attention(),
            Step::Model => self.ask_model_step().await,
            Step::Drive => self.ask_drive(),
            Step::Summary => self.ask_summary(),
            Step::Gpu => self.ask_gpu(),
            Step::Size => self.ask_size(),
            Step::Quota => self.ask_quota(),
            Step::Name => self.ask_name(),
            Step::Memory => self.ask_memory(),
            Step::Confirm => self.ask_confirm(),
        }
    }

    /// The command line's request without the quantization of a model it gave, for a model
    /// the person enters instead. --quant without --model still applies.
    fn entry_base(&self) -> Value {
        let mut base = self.given.clone();
        if !self.given["model"].is_null() {
            base["quant"] = Value::Null;
        }
        base
    }

    /// The command line's request with the model the person entered.
    fn selection(&self) -> Result<Value, String> {
        let Some(model) = &self.model else { return Ok(self.given.clone()) };
        let mut request = self.entry_base();
        request["model"] = model.as_str().into();
        normalize_selection(&mut request)?;
        Ok(request)
    }

    /// The selection with the variant its checks chose and the chosen drive.
    fn chosen(&self) -> Result<Value, String> {
        let mut request = self.selection()?;
        if request["quant"].is_null() && self.preflight["quant"].is_string() {
            request["quant"] = self.preflight["quant"].clone();
        }
        if let Some(drive) = &self.drive {
            if !request["resources"].is_object() {
                request["resources"] = json!({});
            }
            request["resources"]["storageDrive"] = drive.as_str().into();
        }
        Ok(request)
    }

    fn host(&self) -> &Value {
        self.host.as_ref().unwrap_or(&Value::Null)
    }

    fn cuda(&self) -> &Value {
        self.cuda.as_ref().unwrap_or(&Value::Null)
    }

    fn memory(&self) -> u32 {
        model_memory_recommendation(&self.preflight)
    }

    fn recommended(&self) -> Result<Option<Value>, String> {
        let settings = recommended_model_settings(&self.chosen()?, self.host(), self.cuda(), self.memory())?;
        Ok(settings.map(|settings| self.named(settings)))
    }

    /// `request` with the new worker's fresh name when none was given or entered.
    fn named(&self, mut request: Value) -> Value {
        if request["name"].is_null() && !self.fresh_name.is_empty() {
            request["name"] = self.fresh_name.as_str().into();
        }
        request
    }

    /// The request to prepare: the recommended settings, or the command line's choices with
    /// the customized answers. Without checks (--yes), the scripted defaults follow later.
    fn request(&self) -> Result<Value, String> {
        if !self.checks {
            return self.chosen().map(|request| self.named(request));
        }
        if self.quick == Some(true) {
            if let Some(recommended) = self.recommended()? {
                return Ok(recommended);
            }
        }
        let mut request = self.chosen()?;
        let sliders = resource_sliders_with_memory(&request, self.host(), self.memory())?;
        if !request["resources"].is_object() {
            request["resources"] = json!({});
        }
        for (i, slider) in sliders.iter().enumerate() {
            let value = self.sizes.get(i).copied().unwrap_or(slider.value);
            request["resources"][if slider.label == "CPU" { "cpu" } else { "memoryGb" }] = value.into();
        }
        if let Some(gpu) = self.gpu {
            request["gpu"] = gpu.into();
        }
        if let Some(quota) = self.quota {
            request["workspaceQuotaGb"] = quota.into();
        }
        if let Some(name) = &self.name {
            request["name"] = name.as_str().into();
        }
        if let Some(keep) = self.keep {
            request["keepResident"] = keep.into();
        }
        let mut request = self.named(request);
        defaults(&mut request);
        Ok(request)
    }

    /// The saved worker failed. Retry keeps its model and sandbox, Set up again asks for a
    /// model, and a worker that did not fail can be opened instead.
    fn ask_attention(&mut self) -> Result<bool, String> {
        let other = self.other["id"].as_str().map(str::to_owned);
        let mut choices = vec![
            ui::Choice::new("Retry", "prepare this worker again with its saved settings"),
            ui::Choice::new("Set up again", "choose the model, drive and resources"),
        ];
        if let Some(id) = &other {
            choices.push(ui::Choice::new(
                format!("Open {}", typed_name(id, &self.listed)),
                format!("your other worker · {}", state_label(self.other["state"].as_str().unwrap_or(""))),
            ));
        }
        choices.push(ui::Choice::new("Cancel", "return without changes"));
        let mut note = note_lines(&field(&self.saved, "error", "Preparation failed."));
        note.push("Retrying reuses its downloaded model and sandbox.".into());
        let picked = ui::select("Your worker needs attention", &note, &choices, self.attention_choice)?;
        self.attention_choice = picked;
        self.reopen = match (picked, other) {
            (0, _) => self.saved["id"].as_str().map(str::to_owned),
            (1, _) => None,
            (2, Some(id)) => Some(id),
            _ => return Err(ui::CANCELLED.into()),
        };
        Ok(true)
    }

    /// The model question when it is asked, then the model's checks. Back from a model that
    /// needs attention returns to the model question; once this step asked anything, coming
    /// back to it asks the model question again.
    async fn ask_model_step(&mut self) -> Result<bool, String> {
        let mut asked_any = false;
        let mut steps = ui::Wizard::new();
        loop {
            let asked = match steps.step() {
                0 if self.enter_model => self.ask_model().map(|()| true),
                1 if self.checks => self.check_until_usable().await,
                0 | 1 => Ok(false),
                _ => break,
            };
            asked_any |= matches!(asked, Ok(true));
            steps.next(asked)?;
        }
        if self.checks {
            self.check_compute().await?;
        }
        Ok(asked_any)
    }

    /// Checks the chosen model and asks what to do while it needs attention.
    async fn check_until_usable(&mut self) -> Result<bool, String> {
        self.check_host().await?;
        let mut asked = false;
        while let Some(problem) = self.check_model().await? {
            self.model_attention(&problem).await?;
            asked = true;
        }
        Ok(asked)
    }

    /// What the model question starts with: the last answer, the given model, or the saved
    /// worker's model or the suggested one. --quant without --model chooses the variant, so a
    /// suggestion carries that variant instead of its own.
    fn model_prefill(&self) -> String {
        let given = self.given["model"].as_str().map(|model| match self.given["quant"].as_str() {
            Some(quant) => format!("{model}:{quant}"),
            None => model.to_owned(),
        });
        self.model.clone().or(given).unwrap_or_else(|| {
            let suggested = saved_model(&self.saved).unwrap_or_else(|| DEFAULT_MODEL.into());
            with_variant(suggested, self.given["quant"].as_str())
        })
    }

    /// The model question, prefilled by [`Setup::model_prefill`]. A :QUANT that conflicts with
    /// --quant is refused here.
    fn ask_model(&mut self) -> Result<(), String> {
        let initial = self.model_prefill();
        let base = self.entry_base();
        let answer = ui::input_noted(MODEL_QUESTION, &note_lines(MODEL_NOTE), &initial, &|value| {
            model_entry(&base, value)
        })?;
        if self.model.as_ref() != Some(&answer) {
            self.checked = false;
            self.preflight = Value::Null;
        }
        self.model = Some(answer);
        self.enter_model = true;
        Ok(())
    }

    /// This computer's resources and drives, read once.
    async fn check_host(&mut self) -> Result<(), String> {
        if self.host.is_none() {
            let state = activity(
                "Checking your model and hardware",
                json!({"action":"doctor","model":self.selection()?["model"]}),
            )
            .await?;
            self.host = Some(if state["host"].is_object() { state["host"].clone() } else { state });
        }
        Ok(())
    }

    /// Checks the chosen model once. None when it can power a worker, otherwise what needs
    /// attention.
    async fn check_model(&mut self) -> Result<Option<String>, String> {
        if self.checked {
            return Ok(None);
        }
        let request = self.selection()?;
        let result = activity(
            "Checking the selected model revision",
            json!({"action":"doctor","model":request["model"],"quant":request["quant"],"preflightModel":true}),
        )
        .await;
        let preflight = match result {
            Ok(value) => value["preflight"].clone(),
            Err(error) if error == ui::CANCELLED => return Err(error),
            Err(error) => return Ok(Some(model_problem(&error))),
        };
        if let Some(problem) = gguf_problem(&preflight) {
            return Ok(Some(problem));
        }
        if preflight.is_object() {
            ui::info(&format!("Model revision: {}", field(&preflight, "revision", "Unknown")));
            ui::info(&format!(
                "Selected variant: {} · Weights: {}",
                field(&preflight, "quant", "GGUF"),
                preflight["resources"]["weightsBytes"]
                    .as_u64()
                    .map(ui::bytes)
                    .unwrap_or_else(|| "See model metadata".into())
            ));
        }
        if let Some(problem) = too_big(&request, self.host(), model_memory_recommendation(&preflight)) {
            return Ok(Some(problem));
        }
        self.preflight = preflight;
        self.checked = true;
        Ok(None)
    }

    /// Whether the model can run on this PC's GPU, checked once unless --gpu chose already.
    async fn check_compute(&mut self) -> Result<(), String> {
        if self.cuda.is_some() || !self.given["gpu"].is_null() {
            return Ok(());
        }
        let started = Instant::now();
        let mut rpc = |method: &'static str, params: Value| call(method, params);
        let cuda = ui::busy("Checking local model compute", async {
            Ok::<_, String>(cuda_checks(&mut rpc).await)
        })
        .await?;
        finished(
            match gpu_choice(&cuda) {
                "metal" => "Native Apple Metal is available",
                "nvidia" => "This PC passed the NVIDIA CUDA checks",
                _ => "No compatible NVIDIA GPU; the processor will run the model",
            },
            started,
        );
        self.cuda = Some(cuda);
        Ok(())
    }

    /// "This model needs attention": another model, or a Hugging Face sign-in for gated and
    /// private models. Returns once the person entered another model or saved a token.
    async fn model_attention(&mut self, problem: &str) -> Result<(), String> {
        let choices = [
            ui::Choice::new("Choose another model", "paste a supported Hugging Face GGUF repository"),
            ui::Choice::new(
                "Sign in to Hugging Face",
                "save a read token securely; gated terms must be accepted on Hugging Face",
            ),
            ui::Choice::new("Cancel", "return without creating a worker"),
        ];
        let note = note_lines(problem);
        let mut steps = ui::Wizard::new();
        let mut choice = 0;
        loop {
            let asked = match steps.step() {
                0 => match ui::select("This model needs attention", &note, &choices, choice) {
                    Ok(2) => Err(ui::CANCELLED.into()),
                    Ok(picked) => {
                        choice = picked;
                        Ok(true)
                    }
                    Err(error) => Err(error),
                },
                1 if choice == 0 => self.ask_model().map(|()| true),
                1 => save_token().await.map(|()| true),
                _ => break,
            };
            steps.next(asked)?;
        }
        self.enter_model = true;
        Ok(())
    }

    fn ask_drive(&mut self) -> Result<bool, String> {
        let preferred = self
            .drive
            .clone()
            .or_else(|| self.saved["resources"]["storageDrive"].as_str().map(str::to_owned));
        let (drive, asked) = choose_drive(&self.selection()?, self.host(), &self.preflight, preferred.as_deref())?;
        self.drive = drive;
        Ok(asked)
    }

    /// One screen with the recommended settings instead of six questions; Customize asks them.
    fn ask_summary(&mut self) -> Result<bool, String> {
        let Some(recommended) = self.recommended()? else {
            self.quick = None;
            return Ok(false);
        };
        let picked = ui::select(
            "Prepare this worker?",
            &setup_notes(&recommended, self.cuda()),
            &[
                ui::Choice::new("Prepare", "download and verify the model with these settings"),
                ui::Choice::new("Customize", "choose GPU or CPU, cores, memory, space and name"),
                ui::Choice::new("Cancel", "return without creating a worker"),
            ],
            usize::from(self.quick == Some(false)),
        )?;
        if picked == 2 {
            return Err(ui::CANCELLED.into());
        }
        self.quick = Some(picked == 0);
        Ok(true)
    }

    fn ask_gpu(&mut self) -> Result<bool, String> {
        let detected = gpu_choice(self.cuda());
        let note = if detected == "metal" {
            "The native runtime detected Apple Metal. Model and agent readiness are checked before joining."
        } else if detected == "nvidia" {
            "This PC passed the NVIDIA CUDA checks. Compatibility is checked again before the worker is marked ready."
        } else {
            "No NVIDIA GPU passed the CUDA checks (yougori gpu status shows why), so CPU is recommended."
        };
        let initial = match self.gpu {
            Some("cpu") => 1,
            Some(_) => 0,
            None => usize::from(detected == "cpu"),
        };
        let picked = ui::select(
            "Where should your worker run the model?",
            &[note.into()],
            &[
                ui::Choice::new("Compatible local GPU", "use the detected CUDA or Apple Metal backend"),
                ui::Choice::new("CPU", "use this computer's processor"),
            ],
            initial,
        )?;
        self.gpu = Some(if picked == 1 {
            "cpu"
        } else if detected == "metal" {
            "metal"
        } else {
            "nvidia"
        });
        Ok(true)
    }

    fn ask_size(&mut self) -> Result<bool, String> {
        let mut sliders = resource_sliders_with_memory(&self.chosen()?, self.host(), self.memory())?;
        if sliders.is_empty() {
            return Ok(false);
        }
        for (slider, value) in sliders.iter_mut().zip(&self.sizes) {
            slider.value = (*value).clamp(slider.min, slider.max);
        }
        ui::sliders(
            "Size your bounty worker",
            "Choose CPU cores and RAM. Existing workloads keep their allocations.",
            &mut sliders,
        )?;
        self.sizes = sliders.iter().map(|slider| slider.value).collect();
        Ok(true)
    }

    fn ask_quota(&mut self) -> Result<bool, String> {
        let default = self.quota.map_or_else(|| "20".to_owned(), |gb| gb.to_string());
        let value = ui::input("How much space can bounty workspaces use?", &default, false, &|v| {
            number(v, "Workspace quota", 4.0, 1024.0).map(|n| n.to_string())
        })?;
        self.quota = Some(number(&value, "Workspace quota", 4.0, 1024.0)?);
        Ok(true)
    }

    fn ask_name(&mut self) -> Result<bool, String> {
        let default = self.name.clone().unwrap_or_else(|| self.fresh_name.clone());
        self.name = Some(ui::input("Name this worker", &default, false, &worker_name)?);
        Ok(true)
    }

    fn ask_memory(&mut self) -> Result<bool, String> {
        let choices = [
            ui::Choice::new(
                "Load it only for work",
                "frees GPU and memory while waiting; loads for bounties, chat and practice",
            ),
            ui::Choice::new("Keep it loaded", "faster starts; holds GPU and memory while waiting"),
        ];
        let initial = usize::from(self.keep == Some(true));
        self.keep = Some(ui::select("When should the model be loaded?", &[], &choices, initial)? == 1);
        Ok(true)
    }

    /// The customized settings, confirmed with Cancel preselected.
    fn ask_confirm(&mut self) -> Result<bool, String> {
        let request = self.request()?;
        let notes = vec![
            format!("Model: {}", field(&request, "model", "")),
            format!(
                "{} · CPU: {} · Memory: {} GB · Workspace quota: {} GB",
                runs_on(&request),
                field(&request["resources"], "cpu", ""),
                field(&request["resources"], "memoryGb", ""),
                field(&request, "workspaceQuotaGb", "")
            ),
            format!("Files on {}", field(&request["resources"], "storageDrive", "the default drive")),
            "The engine checks disk space, downloads, model tools and context before readiness.".into(),
            "Your model API stays private. No bounty is accepted during setup.".into(),
        ];
        let picked = ui::select(
            "Prepare this worker?",
            &notes,
            &[
                ui::Choice::new("Cancel", "return without creating a worker"),
                ui::Choice::new("Prepare", "download and verify the selected local model"),
            ],
            0,
        )?;
        if picked != 1 {
            return Err(ui::CANCELLED.into());
        }
        Ok(true)
    }
}

/// Opens a saved worker. A paused one resumes only with consent; a stopped or failed one
/// resumes, restarting a preparation that never finished; an active one is only watched.
async fn reopen(invocation: &Invocation) -> Result<Option<Value>, String> {
    let interactive = ui::can_prompt();
    let worker = invocation.request["workerId"].as_str().unwrap_or_default().to_owned();
    let current =
        ui::busy("Opening your worker", dispatch(json!({"action":"status","workerId":worker}))).await?;
    let active = active_state(current["worker"]["state"].as_str().unwrap_or(""));
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
                typed(&worker).await
            ));
            return Ok(Some(current));
        }
    }
    let result = if active {
        current
    } else {
        change("Resuming worker and synchronizing notes", invocation.request.clone()).await?
    };
    if invocation.no_wait {
        return Ok(Some(result));
    }
    if worker_value(&result)["state"] == "preparing" {
        ui::info(&reconnect_line(&worker).await);
    }
    if !wait_prepared(&worker, false).await? {
        return Ok(Some(left_preparation(&worker)));
    }
    Ok(Some(result))
}

/// The person left a preparation that goes on (or that they stopped); what to do next is
/// already on screen.
fn left_preparation(worker: &str) -> Value {
    json!({"detached":true,"workerId":worker,"handle":worker_handle(worker)})
}

/// Starts or reconnects a worker and returns the engine's result for it, after it is
/// ready unless `--no-wait` was given. None means the person cancelled; a `detached` result
/// means they left a preparation that goes on.
async fn setup(invocation: &mut Invocation) -> Result<Option<Value>, String> {
    let interactive = ui::can_prompt();
    let mut resume = invocation.request["action"] == "resume";
    let (listed, environments) = if resume {
        (Value::Null, Vec::new())
    } else {
        ui::busy("Finding your workers", workers_listing()).await?
    };
    let saved = saved_worker(&listed, &environments).cloned().unwrap_or(Value::Null);
    let reconnecting = !saved.is_null() && !invocation.change && !creation_options(&invocation.request);
    let attention = reconnecting
        && interactive
        && !invocation.yes
        && failed_state(saved["state"].as_str().unwrap_or(""));
    let mut setup = Setup {
        given: invocation.request.clone(),
        fresh_name: new_worker_name(&fresh_worker_name(), &listed),
        listed: listed.clone(),
        saved: saved.clone(),
        other: if attention { other_worker(&listed, &saved, &environments) } else { Value::Null },
        attention,
        checks: interactive && !invocation.yes,
        enter_model: invocation.request["model"].is_null(),
        ..Setup::default()
    };
    if reconnecting {
        if interactive {
            ui::info(&saved_line(&saved, &listed));
        }
        if !attention {
            if interactive {
                ui::info("Choose another model or drive: yougori start bounty --change");
            }
            setup.reopen = saved["id"].as_str().map(str::to_owned);
        }
    } else if !resume && interactive && active_state(saved["state"].as_str().unwrap_or("")) {
        ui::info(&format!(
            "This sets up a new worker. {} keeps running until you stop it: yougori bounty stop {}",
            field(&saved, "name", "Your current worker"),
            typed_name(saved["id"].as_str().unwrap_or_default(), &listed)
        ));
    }
    if !resume && setup.reopen.is_none() {
        if interactive {
            setup.ask().await?;
        } else if invocation.request["model"].is_null() {
            return Err(if saved.is_null() {
                "No saved worker on this computer. Supply --model hf.co/OWNER/MODEL-GGUF to prepare one."
            } else {
                "Supply --model hf.co/OWNER/MODEL-GGUF to set up a new worker without a terminal."
            }
            .into());
        }
    }
    if let Some(id) = &setup.reopen {
        invocation.request = json!({"action":"resume","workerId":id});
        resume = true;
    } else if !resume {
        invocation.request = setup.request()?;
    }
    if invocation.yes && invocation.no_wait {
        if !resume {
            sign_in(interactive).await?;
        }
        return start_scripted(invocation.request.clone(), &saved, call)
            .await
            .map(Some);
    }
    if resume {
        return reopen(invocation).await;
    }
    if !setup.checks {
        // --yes in a terminal: the CUDA checks can take a moment.
        let request = &mut invocation.request;
        ui::busy("Checking local model compute", async {
            scripted_settings(request, &mut |method: &'static str, params: Value| call(method, params)).await;
            Ok(())
        })
        .await?;
    }
    sign_in(interactive).await?;
    let result = change("Preparing your worker", invocation.request.clone()).await?;
    let id = worker_id(&result)?;
    if invocation.no_wait {
        return Ok(Some(result));
    }
    ui::info(&reconnect_line(&id).await);
    if !wait_prepared(&id, false).await? {
        return Ok(Some(left_preparation(&id)));
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

/// How the agent submits a finding, from the answer to the first acceptance question.
fn submission(policy: usize) -> &'static str {
    if policy == 0 { "review" } else { "automatic" }
}

/// The offer's three acceptance questions: how findings are submitted, the work budget, and the
/// final confirmation. Each question is asked with the earlier answer selected. Back returns to
/// the question before, and from the first one leaves with [`ui::BACK`]; it never counts as
/// acceptance. Nothing is accepted unless the last answer is Accept, and Ctrl+C leaves with
/// nothing accepted. Returns the submission choice and budget only when accepted.
fn acceptance_questions(
    mut ask_policy: impl FnMut(usize) -> Result<usize, String>,
    mut ask_budget: impl FnMut(u64) -> Result<u64, String>,
    mut confirm: impl FnMut(usize, u64) -> Result<bool, String>,
) -> Result<Option<(usize, u64)>, String> {
    let (mut policy, mut budget, mut step) = (0usize, 60u64, 0);
    loop {
        let answered = match step {
            0 => ask_policy(policy).map(|picked| policy = picked),
            1 => ask_budget(budget).map(|minutes| budget = minutes),
            _ => match confirm(policy, budget) {
                Ok(accepted) => return Ok(accepted.then_some((policy, budget))),
                Err(error) => Err(error),
            },
        };
        match answered {
            Ok(()) => step += 1,
            Err(error) if error == ui::BACK && step > 0 => step -= 1,
            Err(error) => return Err(error),
        }
    }
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
    let mut selected = 0;
    loop {
        selected=ui::select("Choose published metadata to review",&["Applying grants no source access or research permission. A publisher must approve this exact version, followed by your separate offer acceptance.".into()],&choices,selected)?;
        if selected >= bounties.len() {
            return Ok(());
        }
        let bounty = &bounties[selected];
        let offer = json!({"id":bounty["id"],"bounty":bounty,"reward":bounty["reward"],"termsVersion":bounty["termsVersion"],"termsDigest":bounty["termsDigest"],"authorizationDigest":bounty["authorizationDigest"],"sourceRevision":bounty["terms"]["sourceRevision"]});
        offer_authorization(&offer)?;
        // Back returns to the list; nothing is sent unless the answer is Request access.
        let confirmed = ui::with_back(|| {
            ui::select(
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
            )
        });
        match confirmed {
            Err(e) if e == ui::BACK => continue,
            Ok(1) => {
                change("Requesting exact-version source access",json!({"action":"apply","workerId":worker,"bountyId":bounty["id"],"termsVersion":bounty["termsVersion"],"termsDigest":bounty["termsDigest"],"confirmed":true})).await?;
                ui::info("Access application sent. Keep waiting for an approved offer; review and accept it separately before any source is downloaded.");
            }
            other => {
                other?;
            }
        }
        return Ok(());
    }
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
            let skip = json!({"action":"skip","workerId":worker,"offerId":offer_id(offer)?,"bountyId":offer["bounty"]["id"]});
            ui::busy("Skipping this offer", dispatch(skip)).await?;
            continue;
        }
        let details = json!({"action":"details","workerId":worker,"offerId":offer_id(offer)?});
        let detailed = ui::busy("Loading the offer details", dispatch(details)).await?;
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
        // Every question offers Back; from the first it returns to the offer list.
        let answers = ui::with_back(|| acceptance_questions(
            |current| ui::select("How should your agent submit a supported finding?",&["Priority uses server receipt of a complete report. Waiting for review can affect priority.".into()],&[ui::Choice::new("Ask me to review first","keep a private draft until you submit"),ui::Choice::new("Submit privately when ready","submit evidence automatically")],current),
            |current| {
                ui::input(
                    "How long may your agent work before checking in?",
                    &current.to_string(),
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
                .map_err(|_| "Invalid work budget".to_string())
            },
            |policy, budget| {
                // The offer is checked before the person is asked to accept it.
                acceptance(worker, offer, submission(policy), budget)?;
                let mut notes = offer_lines(offer, true);
                notes.push(format!(
                    "Work budget: {budget} minutes · Submission: {}",
                    if policy == 0 {
                        "review first"
                    } else {
                        "automatic private submission"
                    }
                ));
                ui::select(
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
                )
                .map(|picked| picked == 1)
            },
        ));
        let (policy, budget) = match answers {
            Ok(Some(answers)) => answers,
            Ok(None) => return Ok(()),
            Err(e) if e == ui::BACK => continue,
            Err(e) => return Err(e),
        };
        let request = acceptance(worker, offer, submission(policy), budget)?;
        change("Preparing the accepted bounty", request).await?;
        wait_prepared(worker, true).await?;
        return Ok(());
    }
}

async fn show_messages(worker: &str, last: &mut BTreeSet<String>) -> Result<(), String> {
    let request = json!({"action":"messages","workerId":worker});
    let result = ui::busy("Loading your conversation", dispatch(request)).await?;
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
            "Ask your agent about progress, or suggest a direction",
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
                if let Err(error) = activity("Updating your worker", json!({"action":action,"workerId":worker})).await {
                    if error != ui::CANCELLED {
                        return Err(error);
                    }
                    ui::take_interrupt();
                    ui::warn("Stopped waiting. The change may still go through; /status shows your worker.");
                }
                continue;
            }
            "/status" => {
                let request = json!({"action":"status","workerId":worker});
                let value = ui::busy("Checking your worker", dispatch(request)).await?;
                let worker = worker_value(&value);
                ui::info(&format!(
                    "{} · {}",
                    state_label(worker["state"].as_str().unwrap_or("")),
                    field(worker, "summary", "No completed attempts yet")
                ));
                continue;
            }
            _ => {}
        }
        let result = match activity(
            "Sending your suggestion",
            json!({"action":"chat","workerId":worker,"content":content}),
        )
        .await
        {
            Err(error) if error == ui::CANCELLED => {
                ui::take_interrupt();
                ui::warn("Stopped waiting. Your message may still arrive.");
                continue;
            }
            result => result?,
        };
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

/// `/stop` or Ctrl+C while watching work: pause or leave the accepted bounty. True when left.
pub(crate) async fn console_stop(worker: &str) -> Result<bool, String> {
    ui::take_interrupt();
    let name = typed(worker).await;
    let choice = ui::select_required(
        "Stop working on this bounty?",
        &[format!("Worker {name}")],
        &[
            ui::Choice::new("Keep working", "return to the live view"),
            ui::Choice::new("Pause", "checkpoint and stop new tasks; resume later"),
            ui::Choice::new("Leave the bounty", "stop work and its sandboxes; reports and rewards stay"),
        ],
    )?;
    match choice {
        1 => {
            change("Pausing worker", json!({"action":"pause","workerId":worker})).await?;
            ui::info(&format!("Paused. Resume with: yougori bounty resume {name}"));
            Ok(false)
        }
        2 => {
            change("Leaving the bounty", json!({"action":"leave","workerId":worker})).await?;
            Ok(true)
        }
        _ => Ok(false),
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
        &[format!("Worker {}", typed(worker).await)],
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
    let request = json!({"action":action,"workerId":worker,"confirmed":action=="delete"});
    match activity("Updating worker", request).await {
        // Leave the view: it cannot tell what the engine finished.
        Err(error) if error == ui::CANCELLED => {
            ui::take_interrupt();
            ui::warn(&stopped_waiting(&status_command(Some(worker)).await));
            Ok(true)
        }
        Err(error) => Err(error),
        Ok(_) => Ok(action != "pause"),
    }
}

#[derive(Debug, PartialEq)]
enum WorkerKey {
    None,
    Offers,
    Chat,
    TogglePause,
    Practice,
    Console,
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
        KeyCode::Char('t' | 'T') => WorkerKey::Practice,
        KeyCode::Char('l' | 'L') => WorkerKey::Console,
        KeyCode::Enter => WorkerKey::Console,
        KeyCode::Char('r' | 'R') => WorkerKey::Refresh,
        KeyCode::Char('q' | 'Q') | KeyCode::Esc => WorkerKey::Detach,
        _ => WorkerKey::None,
    }
}

/// How many offers wait for the worker `id`, whose status is `state`. Offers come from the
/// worker's registration, so a worker whose setup never finished (paused, or preparing again)
/// has none and is not asked: the engine would refuse.
async fn count_offers<F, Fut>(id: &str, state: &Value, rpc: F) -> Result<usize, String>
where
    F: FnOnce(Value) -> Fut,
    Fut: Future<Output = Result<Value, String>>,
{
    if !state["serverId"].is_string() {
        return Ok(0);
    }
    let result = rpc(json!({"action":"offers","workerId":id})).await?;
    Ok(result["offers"].as_array().map_or(0, Vec::len))
}

async fn dashboard(worker: &str) -> Result<(), String> {
    // The screen and hints name the worker as commands must.
    let name = typed(worker).await;
    // The live map lists the keys; this stays in the log above it.
    ui::info(
        "Ctrl+C opens lifecycle choices. Ctrl+] detaches; the engine keeps your worker running.",
    );
    let screen = crate::bounty_map::Screen::start(&name, &name);
    let mut last_snapshot = String::new();
    let mut offer_count = usize::MAX;
    // The worker state the practice hint was last shown for; repeated presses add nothing.
    let mut practice_hint = String::new();
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
        let sentence = state_sentence(&field(state, "name", &name), state["state"].as_str().unwrap_or(""));
        let hint = state_hint(state, &name);
        let snapshot = format!("{sentence}\n{}", hint.as_deref().unwrap_or_default());
        if last_snapshot != snapshot {
            ui::step(&sentence);
            if let Some(hint) = &hint {
                ui::info(hint);
            }
            last_snapshot = snapshot;
        }
        let count = count_offers(worker, state, dispatch).await?;
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
                    let label = if paused { "Resuming worker" } else { "Pausing worker" };
                    let request = json!({"action":if paused{"resume"}else{"pause"},"workerId":worker});
                    match activity(label, request).await {
                        // The view shows whether the change went through.
                        Err(error) if error == ui::CANCELLED => {
                            ui::take_interrupt();
                            ui::warn("Stopped waiting. The change may still go through; this view shows the worker's state.");
                        }
                        result => {
                            result?;
                        }
                    }
                    break;
                }
                WorkerKey::Practice => {
                    let current = state["state"].as_str().unwrap_or_default();
                    if !matches!(current, "ready_waiting" | "waiting" | "ready") {
                        if practice_hint != current {
                            ui::info(if paused {
                                "Practice needs a live worker. Press P to resume, then T to practice."
                            } else {
                                "Practice runs once your worker is live and waiting for offers."
                            });
                            practice_hint = current.to_owned();
                        }
                        break;
                    }
                    screen.show(false);
                    match crate::bounty_practice::practice_now(worker).await {
                        Err(e) if e == ui::CANCELLED => {
                            if ui::take_interrupt() && interrupt(worker).await? {
                                return Ok(());
                            }
                        }
                        Err(e) => ui::warn(&format!("The practice bounty could not run: {}", safe(&e))),
                        _ => {}
                    }
                    screen.show(true);
                    break;
                }
                WorkerKey::Console => {
                    if !matches!(state["state"].as_str(), Some("running" | "working" | "preparing_bounty" | "awaiting_review")) {
                        break;
                    }
                    // Watch the agent work the accepted bounty live; /stop pauses or leaves it.
                    screen.show(false);
                    match crate::bounty_console::console(worker, false, true, 0, None).await {
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
                WorkerKey::Refresh => break,
                WorkerKey::Detach => {
                    drop(screen);
                    ui::outro(&format!("Detached. {}", reconnect_line(worker).await));
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
        let reuse = invocation.request["action"] == "prepare" && !invocation.change && !creation_options(&invocation.request);
        return Ok(Some(
            json!({"dryRun":true,"request":invocation.request,"reuseSavedWorker":reuse,"modelInputFirst":true,"privateModelApi":true,"autoAccept":false,"idleInference":false,"agentChannelHumanAccess":false,"interactiveRequired":invocation.interactive_start&&!invocation.yes,"terminal":"current"}),
        ));
    }
    if invocation.interactive_start && !ui::can_prompt() && (!invocation.yes || !invocation.no_wait) {
        return Err("Starting a bounty worker requires an interactive terminal. For scripts supply --yes and --no-wait, plus --model for a new worker; this never accepts an offer.".into());
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
        || invocation.request["action"] == "practice"
        || invocation.request["action"] == "chat" && invocation.request["content"].is_null();
    let _session = if ui::can_prompt() && guided {
        Some(ui::Session::start(
            "Swarm Mining",
            "your own model, on bounties you accept",
        ))
    } else {
        None
    };
    let result = async {
        ui::busy("Starting Yougori engine", crate::client::start(None)).await?;
        resolve(&mut invocation.request).await?;
        if invocation.interactive_start {
            let Some(started_worker) = setup(&mut invocation).await? else {
                return Ok(json!({"cancelled":true}));
            };
            if started_worker["detached"] == true {
                return Ok(started_worker);
            }
            // Waiting for readiness belongs to `bounty status`, not to this process.
            if invocation.no_wait {
                return started(&started_worker);
            }
            let worker = worker_id(&started_worker)?;
            // Newly online and waiting for offers: offer a safe practice run first. A worker that
            // was already live when this command reconnected is not asked again.
            if !prepared_state(worker_value(&started_worker)["state"].as_str().unwrap_or(""), false) {
                crate::bounty_practice::offer_practice_when_waiting(&worker).await?;
            }
            dashboard(&worker).await?;
            Ok(json!({"detached":true,"workerId":worker,"handle":worker_handle(&worker)}))
        } else if invocation.request["action"] == "chat" && invocation.request["content"].is_null() {
            chat(invocation.request["workerId"].as_str().unwrap_or_default()).await?;
            Ok(json!({"detached":true}))
        } else if invocation.request["action"] == "practice" {
            let worker = invocation.request["workerId"].as_str().unwrap_or_default();
            if ui::can_prompt() {
                let summary = crate::bounty_practice::walkthrough(worker, false).await?;
                Ok(practice_shown(summary, worker))
            } else {
                crate::bounty_practice::headless(worker).await
            }
        } else {
            one_shot(invocation.request).await
        }
    }
    .await;
    match result {
        // Back is consumed by the setup's questions; should one ever escape, it cancels.
        Err(e) if e == ui::CANCELLED || e == ui::BACK => {
            ui::take_interrupt();
            Ok(Some(json!({"cancelled":true})))
        }
        Ok(v) => Ok(Some(v)),
        Err(e) => Err(e),
    }
}

/// The result of a practice run in the terminal. Its console already ended with the outcome,
/// so the result is marked as shown (`detached`) and nothing is printed after it; the summary
/// keeps the worker's ID and adds its short name.
fn practice_shown(mut summary: Value, worker: &str) -> Value {
    summary["workerId"] = worker.into();
    summary["handle"] = worker_handle(worker).into();
    summary["detached"] = true.into();
    summary
}

/// What a one-line `bounty` command shows while the engine works on it.
fn waiting_label(action: &str) -> &'static str {
    match action {
        "workers" => "Finding your workers",
        "status" | "doctor" => "Checking your worker",
        "offers" => "Checking bounty offers",
        "details" => "Loading the offer details",
        "bounties" => "Loading published bounties",
        "messages" => "Loading your conversation",
        "reports" => "Loading reports",
        "rewards" => "Loading reward records",
        "pause" => "Pausing your worker",
        "resume" => "Resuming your worker",
        "stop" => "Stopping your worker",
        "delete" => "Deleting your worker",
        "leave" => "Leaving the bounty",
        "submitReport" => "Sending your report",
        "apply" => "Sending your access application",
        "accept" => "Accepting the bounty",
        "skip" => "Skipping the offer",
        "chat" => "Sending your message",
        "practiceStop" => "Stopping the practice",
        _ => "Updating your worker",
    }
}

/// `yougori bounty ACTION`: one request, with a spinner while it runs and each shown worker's
/// short name in the result. Ctrl+C stops waiting; a change the engine already received may
/// still finish, so that is reported rather than called cancelled.
async fn one_shot(mut request: Value) -> Result<Value, String> {
    let action = request["action"].as_str().unwrap_or_default().to_owned();
    if action == "accept" {
        let details = json!({"action":"details","workerId":request["workerId"],"offerId":request["offerId"]});
        let detail = ui::busy("Checking the offer", dispatch(details)).await?;
        bind_offer(&mut request, &detail["offer"])?;
    }
    let reads = matches!(
        action.as_str(),
        "workers" | "status" | "doctor" | "offers" | "details" | "bounties" | "messages" | "reports" | "rewards"
    );
    let worker = request["workerId"].as_str().map(str::to_owned);
    let mut result = match ui::busy(waiting_label(&action), dispatch(request)).await {
        Err(error) if error == ui::CANCELLED && !reads => {
            let check = status_command(worker.as_deref().filter(|_| action != "delete")).await;
            return Err(stopped_waiting(&check));
        }
        result => result?,
    };
    if action == "rewards" {
        let lines = reward_lines(&result);
        if ui::can_prompt() {
            for line in &lines {
                ui::info(line);
            }
        }
        if result.is_object() {
            result["paymentStatusLabels"] = json!(lines);
        }
    }
    // `bounty practice WORKER --stop` answers for the worker it names.
    if let (Some(id), Some(stopped)) = (worker.as_deref().filter(|_| action == "practiceStop"), result.as_object_mut()) {
        stopped.insert("workerId".into(), id.into());
        stopped.insert("handle".into(), worker_handle(id).into());
    }
    // Workers that share a short name with another one are marked, so views name them by ID.
    let listed = if result["workers"].is_array() {
        result.clone()
    } else if result["worker"]["id"].is_string() {
        tokio::time::timeout(Duration::from_secs(2), dispatch(json!({"action":"workers"})))
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or(Value::Null)
    } else {
        Value::Null
    };
    with_handles(&mut result, &listed);
    Ok(result)
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
    fn option_errors_name_the_flag_what_it_needs_and_the_usage() {
        let error = |args: &str| parse(&words(args)).unwrap_err();
        assert_eq!(error("start bounty --cpu"), "--cpu needs a value: CPU cores, from 4 to 255.");
        assert_eq!(error("start bounty --name ab --name cd"), "--name is given twice. Give it once.");
        let unknown = error("bounty status worker-1 --colour");
        assert!(unknown.starts_with("Unknown option --colour for yougori bounty status.") && unknown.ends_with("yougori bounty --help."), "{unknown}");
        assert!(error("start bounty --colour").contains("for yougori start bounty."));
        assert_eq!(error("bounty status"), "Usage: yougori bounty status WORKER. See every option with yougori bounty --help.");
        assert_eq!(error("bounty memory worker-1"), "Usage: yougori bounty memory WORKER release|keep. See every option with yougori bounty --help.");
        assert!(error("bounty workers extra").starts_with("Usage: yougori bounty workers."));
        let missing = error("bounty accept worker offer --accept-rules --accept-authorization --accept-direct-payment --yes");
        assert!(missing.contains("--version N") && missing.contains("yougori bounty details WORKER OFFER"), "{missing}");
        assert!(error("bounty resume worker-1 --budget-minutes 0").contains("from 1 to 1440"));
    }
    #[test]
    fn acceptance_questions_accept_only_on_the_final_answer() {
        // Back from the budget returns to the submission question with its answer selected;
        // Back from the confirmation returns to the budget. Neither counts as acceptance.
        let asked = std::cell::RefCell::new(Vec::new());
        let mut policies = [Ok(1), Ok(0)].into_iter();
        let mut budgets = [Err(ui::BACK.to_string()), Ok(30), Ok(45)].into_iter();
        let mut confirms = [Err(ui::BACK.to_string()), Ok(true)].into_iter();
        let answers = acceptance_questions(
            |current| {
                asked.borrow_mut().push(format!("policy {current}"));
                policies.next().unwrap()
            },
            |current| {
                asked.borrow_mut().push(format!("budget {current}"));
                budgets.next().unwrap()
            },
            |policy, budget| {
                asked.borrow_mut().push(format!("confirm {policy} {budget}"));
                confirms.next().unwrap()
            },
        );
        assert_eq!(answers, Ok(Some((0, 45))));
        assert_eq!(
            asked.into_inner(),
            ["policy 0", "budget 60", "policy 1", "budget 60", "confirm 0 30", "budget 30", "confirm 0 45"]
        );
    }
    #[test]
    fn acceptance_questions_never_accept_on_cancel_back_or_ctrl_c() {
        fn back<T>() -> Result<T, String> {
            Err(ui::BACK.into())
        }
        fn ctrl_c<T>() -> Result<T, String> {
            Err(ui::CANCELLED.into())
        }
        // Cancel on the confirmation accepts nothing.
        assert_eq!(acceptance_questions(|_| Ok(1), |_| Ok(30), |_, _| Ok(false)), Ok(None));
        // Back from the first question leaves for the offer list.
        assert_eq!(acceptance_questions(|_| back(), |_| unreachable!(), |_, _| unreachable!()), back());
        // Ctrl+C on any question leaves at once, without asking the rest.
        assert_eq!(acceptance_questions(|_| ctrl_c(), |_| unreachable!(), |_, _| unreachable!()), ctrl_c());
        assert_eq!(acceptance_questions(|_| Ok(1), |_| ctrl_c(), |_, _| unreachable!()), ctrl_c());
        assert_eq!(acceptance_questions(|_| Ok(1), |_| Ok(30), |_, _| ctrl_c()), ctrl_c());
        // An offer that fails its check before the confirmation stops with its reason.
        let stale = "Offer has no terms digest; refresh offers before accepting";
        assert_eq!(acceptance_questions(|_| Ok(0), |_| Ok(30), |_, _| Err(stale.into())), Err(stale.into()));
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
        // Enter opens the live console; L watches work.
        assert_eq!(key_action(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)), WorkerKey::Console);
        assert_eq!(key_action(KeyEvent::new(KeyCode::Char('l'), KeyModifiers::NONE)), WorkerKey::Console);
        // P stays pause; T practices.
        assert_eq!(key_action(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE)), WorkerKey::TogglePause);
        assert_eq!(key_action(KeyEvent::new(KeyCode::Char('T'), KeyModifiers::SHIFT)), WorkerKey::Practice);
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
    fn model_variants_are_split_without_silently_overriding_an_explicit_quant() {
        let selected = parse(&words("start bounty --model hf.co/HauhauCS/Qwen3.8-27B-Uncensored-HauhauCS-Aggressive-MTP-GGUF:IQ4_XS --dry-run")).unwrap().unwrap();
        assert_eq!(selected.request["quant"], "IQ4_XS");
        assert_eq!(selected.request["model"], "hf.co/HauhauCS/Qwen3.8-27B-Uncensored-HauhauCS-Aggressive-MTP-GGUF");
        for command in ["start bounty --model hf.co/owner/model:IQ4_XS --quant Q4_K_M",
                        "start bounty --quant Q4_K_M --model hf.co/owner/model:IQ4_XS",
                        "start bounty --model hf.co/owner/model:"] {
            assert!(parse(&words(command)).is_err());
        }
        assert!(parse(&words("start bounty --model hf.co/owner/model:iq4_xs --quant IQ4_XS")).is_ok());
        let mut default = json!({"model":DEFAULT_MODEL});
        normalize_selection(&mut default).unwrap();
        assert_eq!(default["quant"], "Q4_K_M");
        assert!(!default["model"].as_str().unwrap().contains(':'));
    }
    #[test]
    fn large_model_recommendations_include_model_and_both_sandboxes() {
        let gemma = model_memory_recommendation(&json!({"resources":{"weightsBytes":7_381_384_864u64}}));
        let qwen = model_memory_recommendation(&json!({"resources":{"weightsBytes":15_705_860_224u64}}));
        assert_eq!((gemma, qwen), (16, 24));
        let host = json!({"totalCpu":16,"totalMemoryGb":64});
        let recommended = recommended_model_settings(&json!({"model":"hf.co/owner/model"}), &host, &Value::Null, gemma).unwrap().unwrap();
        assert_eq!(recommended["resources"]["memoryGb"], 16);
        assert!(resource_sliders_with_memory(&json!({}), &json!({"totalCpu":8,"totalMemoryGb":12}), gemma).is_err());
        let sliders = resource_sliders_with_memory(&json!({"resources":{"memoryGb":32}}), &host, gemma).unwrap();
        assert!(sliders.iter().all(|slider|slider.label != "Memory"));
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
        assert!(notes.contains("Files on D:\\ · 20 GB for bounty workspaces · model loaded only for work"), "{notes}");
        assert_eq!(recommended["keepResident"], false, "the model holds no GPU while waiting");
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
    async fn start_reuses_the_saved_worker_unless_change_or_creation_options() {
        assert!(parse(&words("start bounty --change")).unwrap().unwrap().change);
        for args in ["start bounty --change --worker worker-1", "start bounty --change --change", "bounty status worker-1 --change"] {
            assert!(parse(&words(args)).is_err(), "{args}");
        }
        for (args, reuse) in [
            ("start bounty", true),
            ("start bounty --yes --no-wait", true),
            ("start bounty --change", false),
            ("start bounty --model hf.co/owner/model", false),
            ("start bounty --storage-drive D:\\", false),
            ("start bounty --release-memory", false),
            ("start bounty --worker worker-1", false),
            // A worker keeps the platform it was prepared for; only a new one checks the URL.
            ("start bounty --platform-url http://127.0.0.1:3000", false),
        ] {
            let shown = run(&words(&format!("{args} --dry-run"))).await.unwrap().unwrap();
            assert_eq!(shown["reuseSavedWorker"], reuse, "{args}");
        }
        assert!(parse(&words("start bounty --worker worker-1 --platform-url http://127.0.0.1:3000")).is_err());
        assert!(HELP.contains("--change") && HELP.contains("reconnects to the worker set up last"));
        assert!(HELP.contains("--keep-loaded, --platform-url) sets up a new worker instead"));
    }

    #[test]
    fn the_model_loads_for_work_unless_kept_and_practice_and_memory_name_a_worker() {
        let mut bare = json!({});
        defaults(&mut bare);
        assert_eq!(bare["keepResident"], false);
        assert_eq!(parse(&words("start bounty --keep-loaded")).unwrap().unwrap().request["keepResident"], true);
        assert_eq!(parse(&words("start bounty --release-memory")).unwrap().unwrap().request["keepResident"], false);
        assert!(parse(&words("start bounty --keep-loaded --release-memory")).is_err());
        assert_eq!(parse(&words("bounty memory worker-1 release")).unwrap().unwrap().request, json!({"action":"memory","workerId":"worker-1","keepResident":false}));
        assert_eq!(parse(&words("bounty memory worker-1 keep")).unwrap().unwrap().request, json!({"action":"memory","workerId":"worker-1","keepResident":true}));
        assert_eq!(parse(&words("bounty practice worker-1")).unwrap().unwrap().request, json!({"action":"practice","workerId":"worker-1"}));
        for args in ["bounty memory worker-1", "bounty memory worker-1 off", "bounty memory release", "bounty practice", "bounty practice worker-1 --yes", "bounty memory worker-1 keep --keep-loaded"] {
            assert!(parse(&words(args)).is_err(), "{args}");
        }
        assert!(HELP.contains("yougori bounty practice WORKER") && HELP.contains("yougori bounty memory WORKER release|keep"));
    }

    #[test]
    fn the_newest_worker_is_saved_and_older_releases_rank_by_progress() {
        let listed = json!({"workers":[
            {"id":"worker-old","state":"ready_waiting","createdAt":100},
            {"id":"worker-new","state":"failed","createdAt":200},
            {"id":"../escape","state":"ready_waiting","createdAt":900},
        ]});
        assert_eq!(saved_worker(&listed, &[]).unwrap()["id"], "worker-new", "the worker set up last");
        let legacy = json!({"workers":[
            {"id":"worker-a","state":"failed"},
            {"id":"worker-b","state":"failed","environmentId":"env-1","modelEnvironmentId":"env-2"},
            {"id":"worker-c","state":"stopped","serverId":"remote"},
            {"id":"worker-d","state":"failed","modelEnvironmentId":"env-2"},
        ]});
        assert_eq!(saved_worker(&legacy, &[]).unwrap()["id"], "worker-b");
        // Older releases recorded no creation time: the worker whose sandbox is newest was set up
        // last, and one whose environments were deleted ranks below it.
        let environments = [
            json!({"id":"env-agent-new","createdAt":"2026-10-12T12:35:57.558419800+00:00"}),
            json!({"id":"env-agent-old","createdAt":"2026-10-12T09:01:02.5+00:00"}),
            json!({"id":"env-2","createdAt":"2026-10-12T12:13:04.094877+00:00"}),
        ];
        let machine = json!({"workers":[
            {"id":"worker-gone","state":"failed","environmentId":"env-deleted","modelEnvironmentId":"env-deleted-model"},
            {"id":"worker-latest","state":"failed","environmentId":"env-agent-new","modelEnvironmentId":"env-2"},
            {"id":"worker-earlier","state":"failed","environmentId":"env-agent-old","modelEnvironmentId":"env-2"},
        ]});
        assert_eq!(saved_worker(&machine, &environments).unwrap()["id"], "worker-latest");
        assert_eq!(saved_worker(&machine, &environments[1..]).unwrap()["id"], "worker-earlier");
        // A test sandbox is made when a worker accepts its first bounty, long after its setup: a
        // worker set up first that accepted a bounty later is still the older one.
        let environments = [
            json!({"id":"env-first","createdAt":"2026-09-20T10:00:00+00:00"}),
            json!({"id":"env-first-test","createdAt":"2026-10-10T10:00:00+00:00"}),
            json!({"id":"env-second","createdAt":"2026-10-05T10:00:00+00:00"}),
        ];
        let accepted_later = json!({"workers":[
            {"id":"worker-first","state":"ready_waiting","environmentId":"env-first","testEnvironmentId":"env-first-test"},
            {"id":"worker-second","state":"ready_waiting","environmentId":"env-second"},
        ]});
        assert_eq!(saved_worker(&accepted_later, &environments).unwrap()["id"], "worker-second");
        let deleted = json!({"workers":[
            {"id":"worker-first","state":"ready_waiting","environmentId":"env-deleted","testEnvironmentId":"env-first-test"},
            {"id":"worker-second","state":"ready_waiting","environmentId":"env-second"},
        ]});
        assert_eq!(saved_worker(&deleted, &environments).unwrap()["id"], "worker-second", "a deleted sandbox counts for nothing");
        let unrecorded = json!({"workers":[
            {"id":"worker-first","state":"ready_waiting","testEnvironmentId":"env-first-test"},
            {"id":"worker-second","state":"ready_waiting","environmentId":"env-second"},
        ]});
        assert_eq!(saved_worker(&unrecorded, &environments).unwrap()["id"], "worker-first", "the test sandbox stands in for none");
        let live = json!({"workers":[{"id":"worker-a","state":"failed"},{"id":"worker-b","state":"paused"},{"id":"worker-c","state":"preparing"}]});
        assert_eq!(saved_worker(&live, &[]).unwrap()["id"], "worker-c");
        assert!(saved_worker(&json!({"workers":[]}), &[]).is_none());
        assert!(saved_worker(&json!({}), &[]).is_none());
        let saved = json!({"model":"HauhauCS/Gemma-4-E4B-Uncensored-HauhauCS-Aggressive","quant":"Q4_K_M"});
        assert_eq!(saved_model(&saved).unwrap(), "hf.co/HauhauCS/Gemma-4-E4B-Uncensored-HauhauCS-Aggressive:Q4_K_M");
        assert_eq!(saved_model(&json!({"model":"hf.co/owner/model"})).unwrap(), "hf.co/owner/model");
        assert!(saved_model(&json!({"model":"bad;model"})).is_none());
        for state in ["preparing", "preparing_bounty", "ready_waiting", "running", "awaiting_review"] {
            assert!(active_state(state), "{state}");
        }
        for state in ["paused", "failed", "stopped", ""] {
            assert!(!active_state(state), "{state}");
        }
    }

    #[test]
    fn a_chosen_drive_keeps_the_recommended_screen() {
        let host = json!({"totalCpu":24,"totalMemoryGb":63.4,"storageDrives":[{"path":"C:\\","freeGb":58.9},{"path":"D:\\","freeGb":379.6}]});
        let nvidia = json!({"supported":true});
        assert_eq!(roomiest_drive(&host).unwrap()["path"], "D:\\");
        let chosen = json!({"action":"prepare","model":"hf.co/owner/model","resources":{"storageDrive":"C:\\"}});
        let recommended = recommended_settings(&chosen, &host, &nvidia).unwrap().unwrap();
        assert_eq!(recommended["resources"]["storageDrive"], "C:\\");
        assert_eq!(recommended["resources"]["cpu"], 4);
        assert!(setup_notes(&recommended, &nvidia).join("\n").contains("Files on C:\\"));
        // One drive, or none reported, needs no question.
        let preflight = json!({"resources":{"weightsBytes":5_368_709_120u64,"storageGbRecommended":12}});
        let single = json!({"storageDrives":[{"path":"C:\\","freeGb":58.9}]});
        assert_eq!(choose_drive(&chosen, &single, &preflight, None).unwrap(), (Some("C:\\".to_owned()), false));
        assert_eq!(choose_drive(&chosen, &json!({}), &preflight, None).unwrap(), (None, false));
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
            assert!(request["resources"]["memoryGb"].is_null(), "engine sizes RAM after preflight");
            assert_eq!(calls, [COMPUTE_STATUS_METHOD]);
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
    async fn scripted_setup_keeps_explicit_ram_and_rented_local_budget() {
        for (mut request, expected) in [
            (json!({"gpu":"cpu","resources":{"memoryGb":36}}), 36),
            (json!({"gpu":"cpu","rentedGpu":"pod-fixture"}), 8),
        ] {
            scripted_settings(&mut request, &mut |_, _| std::future::ready(Ok(Value::Null))).await;
            assert_eq!(request["resources"]["memoryGb"], expected);
        }
    }

    #[tokio::test]
    async fn scripted_no_wait_starts_the_worker_with_one_request_and_never_polls() {
        let script = parse(&words("start bounty --model hf.co/owner/model --yes --no-wait")).unwrap().unwrap();
        assert!(script.yes && script.no_wait);
        let mut calls = Vec::new();
        let result = start_detached(script.request, |method, params| {
            calls.push((method, params["request"]["action"].clone(), params["request"]["gpu"].clone()));
            std::future::ready(Ok(match method {
                COMPUTE_STATUS_METHOD => json!({"supported":false}),
                _ => json!({"worker":{"id":"worker-new","state":"preparing","stage":"Checking your model and resources"},"background":true}),
            }))
        })
        .await
        .unwrap();
        assert_eq!(calls, [(COMPUTE_STATUS_METHOD, Value::Null, Value::Null), ("swarm_dispatch", json!("prepare"), json!("cpu"))]);
        let shown = started(&result).unwrap();
        assert_eq!((shown["worker"]["id"].as_str(), shown["worker"]["state"].as_str(), shown["background"].as_bool()), (Some("worker-new"), Some("preparing"), Some(true)));
        assert!(shown["next"].as_str().unwrap().contains(&format!("yougori bounty status {}", worker_handle("worker-new"))), "{shown}");
        let named = started(&json!({"worker":{"id":"worker-new","name":"keen-heron-2","state":"preparing"}})).unwrap();
        assert!(named["next"].as_str().unwrap().contains("yougori bounty status keen-heron-2"), "{named}");
        // --worker resumes a worker that is not running: its status first, then one resume.
        for state in ["stopped", "paused", "failed"] {
            let script = parse(&words("start bounty --worker worker-old --yes --no-wait")).unwrap().unwrap();
            let mut actions = Vec::new();
            let result = start_scripted(script.request, &Value::Null, |_, params| {
                actions.push(params["request"]["action"].clone());
                let state = if params["request"]["action"] == "resume" { "preparing" } else { state };
                std::future::ready(Ok(json!({"worker":{"id":"worker-old","state":state}})))
            })
            .await
            .unwrap();
            assert_eq!(actions, [json!("status"), json!("resume")], "{state}");
            assert!(started(&result).unwrap()["next"].as_str().unwrap().contains(&format!("bounty status {}", worker_handle("worker-old"))));
        }
        // One the engine already prepares or runs is returned as it is: a resume would restart it.
        for state in ["preparing", "preparing_bounty", "ready_waiting", "running", "awaiting_review"] {
            let script = parse(&words("start bounty --worker worker-old --yes --no-wait")).unwrap().unwrap();
            let mut actions = Vec::new();
            let result = start_scripted(script.request, &Value::Null, |_, params| {
                actions.push(params["request"]["action"].clone());
                std::future::ready(Ok(json!({"worker":{"id":"worker-old","state":state}})))
            })
            .await
            .unwrap();
            assert_eq!(actions, [json!("status")], "{state} is never resumed");
            assert_eq!(result["worker"]["state"], state);
        }
        // The saved worker plain `start bounty` reconnects to is listed already: no request.
        let saved = json!({"id":"worker-old","state":"running"});
        let result = start_scripted(json!({"action":"resume","workerId":"worker-old"}), &saved, |_, _| {
            panic!("a running saved worker needs no request");
            #[allow(unreachable_code)]
            std::future::ready(Ok(Value::Null))
        })
        .await
        .unwrap();
        assert_eq!(result, json!({"worker":saved}));
        let paused = started(&json!({"worker":{"id":"worker-old","state":"paused"}})).unwrap();
        assert!(paused["next"].as_str().unwrap().contains(&format!("yougori bounty resume {}", worker_handle("worker-old"))) && paused["background"].is_null());
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
    fn resuming_after_the_work_budget_is_spent_extends_it_only_when_asked() {
        let resume = parse(&words("bounty resume worker-1 --budget-minutes 90")).unwrap().unwrap();
        assert_eq!(resume.request, json!({"action":"resume","workerId":"worker-1","budgetMinutes":90}));
        let plain = parse(&words("bounty resume worker-1")).unwrap().unwrap();
        assert_eq!(plain.request, json!({"action":"resume","workerId":"worker-1"}), "no extension unless asked");
        for minutes in [1, 1440] {
            let args = format!("bounty resume worker-1 --budget-minutes {minutes}");
            assert_eq!(parse(&words(&args)).unwrap().unwrap().request["budgetMinutes"], minutes);
        }
        for args in [
            "bounty resume worker-1 --budget-minutes 0",
            "bounty resume worker-1 --budget-minutes 1441",
            "bounty resume worker-1 --budget-minutes 1.5",
            "bounty resume worker-1 --budget-minutes -5",
            "bounty resume worker-1 --budget-minutes",
            "bounty resume worker-1 --budget-minutes 30 --budget-minutes 60",
            "bounty resume --budget-minutes 30",
            "bounty pause worker-1 --budget-minutes 30",
            "start bounty --worker worker-1 --budget-minutes 30",
        ] {
            assert!(parse(&words(args)).is_err(), "{args}");
        }
        assert!(HELP.contains("bounty resume WORKER [--budget-minutes N]"));
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

    #[test]
    fn worker_short_names_are_stable_memorable_and_mostly_distinct() {
        for list in [&HANDLE_ADJECTIVES, &HANDLE_NOUNS] {
            assert_eq!(list.iter().collect::<BTreeSet<_>>().len(), 100, "100 different words");
            assert!(list.iter().all(|word| (3..=8).contains(&word.len()) && word.bytes().all(|b| b.is_ascii_lowercase())), "{list:?}");
        }
        assert!(HANDLE_ADJECTIVES.iter().all(|word| !HANDLE_NOUNS.contains(word)));
        // Pinned: an ID keeps its short name across releases.
        assert_eq!(worker_handle("worker-bd89af264d434eb286e5dad338db9512"), "apt-whale");
        assert_eq!(worker_handle("worker-1"), "happy-turtle");
        assert_eq!(worker_handle("worker-1"), worker_handle("worker-1"));
        let handles: Vec<String> = (0..200).map(|n| worker_handle(&format!("worker-{:032x}", n * 7919))).collect();
        for handle in &handles {
            let (adjective, noun) = handle.split_once('-').unwrap();
            assert!(HANDLE_ADJECTIVES.contains(&adjective) && HANDLE_NOUNS.contains(&noun), "{handle}");
        }
        assert!(handles.iter().collect::<BTreeSet<_>>().len() >= 190, "different IDs mostly get different names");
    }

    #[test]
    fn a_new_worker_gets_a_memorable_name_no_other_worker_answers_to() {
        let (a, b) = ("worker-aaaa1111aaaa1111aaaa1111aaaa1111", "worker-bbbb2222bbbb2222bbbb2222bbbb2222");
        // Taken names compare as commands compare them: in any case, a space for the hyphen.
        let listed = json!({"workers":[{"id":a,"name":"keen-heron"},{"id":b,"name":"Keen Heron 2"}]});
        assert_eq!(new_worker_name("keen-heron", &listed), "keen-heron-3");
        assert_eq!(new_worker_name(" Calm  Otter ", &listed), "calm-otter");
        assert_eq!(new_worker_name("calm-otter", &Value::Null), "calm-otter", "nothing listed, nothing taken");
        // A worker's short name and its ID are taken too.
        let handle = worker_handle(a);
        assert_eq!(new_worker_name(&handle.to_uppercase(), &listed), format!("{handle}-2"));
        let odd = json!({"workers":[{"id":"keen-heron","name":"Laptop"}]});
        assert_eq!(new_worker_name("keen-heron", &odd), "keen-heron-2");
        // Nothing a command reads as the first digits of an ID is ever given.
        for (base, given) in [("cafe", "cafe-2"), ("worker-beef", "worker-beef-2"), ("C0FFEE", "c0ffee-2")] {
            assert!(id_digits(base) && !id_digits(given), "{base}");
            assert_eq!(new_worker_name(base, &Value::Null), given);
        }
        let mut names = BTreeSet::new();
        for adjective in HANDLE_ADJECTIVES {
            for noun in HANDLE_NOUNS {
                let name = format!("{adjective}-{noun}");
                assert!(memorable_name(&name) && !id_digits(&name) && !id_digits(&format!("{name}-2")), "{name}");
                names.insert(name);
            }
        }
        for _ in 0..20 {
            assert!(names.contains(&fresh_worker_name()));
        }
        for (name, memorable) in [("keen-heron-2", true), ("Keen Heron 12", true), ("keen-heron-1", false), ("keen-heron-02", false), ("keen-heron-x", false), ("keen", false), ("heron-keen", false), ("Bounty worker", false), ("keen-heron-2-3", false)] {
            assert_eq!(memorable_name(name), memorable, "{name}");
        }
    }

    #[test]
    fn a_new_name_always_finds_the_new_worker_and_nobody_is_renamed() {
        let mut listed = fleet();
        let before: Vec<String> = listed_workers(&listed).map(|worker| typed_name(worker["id"].as_str().unwrap(), &listed)).collect();
        // Each new worker is told apart from every worker before it, including earlier new ones.
        for (n, digits) in ["dddd4444", "eeee5555", "ffff6666"].into_iter().enumerate() {
            let name = new_worker_name("keen-heron", &listed);
            assert_eq!(name, if n == 0 { "keen-heron".to_owned() } else { format!("keen-heron-{}", n + 1) });
            let id = format!("worker-{}", digits.repeat(4));
            listed["workers"].as_array_mut().unwrap().push(json!({"id":id,"name":name,"state":"ready_waiting"}));
            assert_eq!(resolve_worker(&name, &listed).unwrap(), id, "{name}");
            assert_eq!(resolve_worker(&name.replace('-', " ").to_uppercase(), &listed).unwrap(), id);
            assert_eq!(typed_name(&id, &listed), name, "hints use the new name");
        }
        let after: Vec<String> = listed_workers(&listed).take(before.len()).map(|worker| typed_name(worker["id"].as_str().unwrap(), &listed)).collect();
        assert_eq!(before, after, "existing workers keep what to type for them");
        assert_eq!(worker_names(&listed_workers(&listed).collect::<Vec<_>>())[3..], ["keen-heron", "keen-heron-2", "keen-heron-3"]);
        let choices = worker_choices(&listed_workers(&listed).collect::<Vec<_>>());
        assert!(choices.contains("keen-heron (ready for offers)") || choices.contains("keen-heron ("), "{choices}");
        assert!(!choices.contains("keen-heron (keen-heron"), "a name that is what to type is said once: {choices}");
    }

    #[test]
    fn a_name_two_workers_answer_to_is_never_taken_as_either() {
        // A worker made later can get a short name an earlier worker already has as its own.
        let (earlier, later) = ("worker-aaaa1111aaaa1111aaaa1111aaaa1111", "worker-cccc3333cccc3333cccc3333cccc3333");
        let shared = worker_handle(later);
        let listed = json!({"workers":[{"id":earlier,"name":shared,"state":"ready_waiting"},{"id":later,"name":"Bounty worker","state":"paused"}]});
        let error = resolve_worker(&shared, &listed).unwrap_err();
        assert!(error.contains("more than one worker"), "{error}");
        // Each is then named by something only it answers to.
        assert_eq!(typed_name(earlier, &listed), worker_handle(earlier));
        assert_eq!(typed_name(later, &listed), later);
        for id in [earlier, later] {
            assert_eq!(resolve_worker(&typed_name(id, &listed), &listed).unwrap(), id);
        }
        // A result names the worker the same way.
        let mut status = json!({"worker":{"id":later,"name":"Bounty worker"}});
        with_handles(&mut status, &listed);
        assert_eq!(typed_in_result(&status["worker"]), later);
        assert_eq!(typed_in_result(&json!({"id":earlier,"name":"Keen Heron"})), "keen-heron");
        assert_eq!(typed_in_result(&json!({"id":earlier,"name":"Laptop"})), worker_handle(earlier));
    }

    fn fleet() -> Value {
        json!({"workers":[
            {"id":"worker-aaaa1111aaaa1111aaaa1111aaaa1111","name":"Bounty worker","state":"ready_waiting","createdAt":100},
            {"id":"worker-bbbb2222bbbb2222bbbb2222bbbb2222","name":"Bounty worker","state":"failed","createdAt":200},
            {"id":"worker-cccc3333cccc3333cccc3333cccc3333","name":"Laptop","state":"paused","createdAt":50},
        ]})
    }

    #[test]
    fn workers_are_found_by_id_short_name_own_name_or_id_digits() {
        let listed = fleet();
        let [a, b, c] = ["worker-aaaa1111aaaa1111aaaa1111aaaa1111", "worker-bbbb2222bbbb2222bbbb2222bbbb2222", "worker-cccc3333cccc3333cccc3333cccc3333"];
        assert_eq!(resolve_worker(a, &listed).unwrap(), a);
        assert_eq!(resolve_worker(&worker_handle(b), &listed).unwrap(), b);
        assert_eq!(resolve_worker(&format!(" {} ", worker_handle(c).to_uppercase()), &listed).unwrap(), c, "any case");
        assert_eq!(resolve_worker(&worker_handle(c).replace('-', " "), &listed).unwrap(), c, "spaces for the hyphen");
        assert_eq!(resolve_worker("laptop", &listed).unwrap(), c);
        for digits in ["cccc", "CCCC3333", "worker-cccc3"] {
            assert_eq!(resolve_worker(digits, &listed).unwrap(), c, "{digits}");
        }
        let both = resolve_worker("Bounty worker", &listed).unwrap_err();
        assert!(both.contains("more than one worker") && both.contains(&worker_handle(a)) && both.contains(&worker_handle(b)), "{both}");
        assert!(!both.contains(&worker_handle(c)), "{both}");
        for unknown in ["ccc", "worker", "nope", "keen-heron-2"] {
            let error = resolve_worker(unknown, &listed).unwrap_err();
            assert!(error.contains("No bounty worker matches") && error.contains(&worker_handle(c)) && error.contains("Laptop, paused"), "{error}");
        }
        assert!(resolve_worker("apt-whale", &json!({"workers":[]})).unwrap_err().contains("yougori start bounty"));
        assert!(!resolve_worker("x\u{1b}[2J", &listed).unwrap_err().contains('\u{1b}'));
        // Two workers that share a short name are told apart by their IDs.
        let mut seen = std::collections::BTreeMap::new();
        let (first, second) = (0..100_000)
            .map(|n| format!("worker-{n:032x}"))
            .find_map(|id| seen.insert(worker_handle(&id), id.clone()).map(|earlier| (earlier, id)))
            .unwrap();
        let twins = json!({"workers":[{"id":first,"name":"One"},{"id":second,"name":"Two"}]});
        let error = resolve_worker(&worker_handle(&first), &twins).unwrap_err();
        assert!(error.contains(&first) && error.contains(&second), "{error}");
        assert_eq!(resolve_worker(&first, &twins).unwrap(), first);
    }

    #[tokio::test]
    async fn dry_runs_keep_the_worker_as_typed() {
        let shown = run(&words("bounty status apt-whale --dry-run")).await.unwrap().unwrap();
        assert_eq!(shown["request"]["workerId"], "apt-whale");
        let shown = run(&words("start bounty --worker apt-whale --dry-run")).await.unwrap().unwrap();
        assert_eq!((shown["request"]["action"].as_str(), shown["request"]["workerId"].as_str()), (Some("resume"), Some("apt-whale")));
        assert!(HELP.contains("WORKER is the name to type for a worker") && HELP.contains("keen-heron"));
        assert!(!HELP.contains("env start bounty") && HELP.contains("yougori start --environment bounty"), "env commands take IDs");
    }

    #[test]
    fn results_and_hints_name_workers_by_their_short_names() {
        let mut result = json!({"worker":{"id":"worker-1","state":"paused"},"workers":[{"id":"worker-2"},{"name":"no id"}]});
        with_handles(&mut result, &Value::Null);
        assert_eq!(result["worker"]["handle"], "happy-turtle");
        assert_eq!(result["workers"][0]["handle"], worker_handle("worker-2"));
        assert!(result["workers"][1]["handle"].is_null());
        assert_eq!(result["worker"]["id"], "worker-1", "IDs stay for scripts");
        assert!(result["worker"]["handleShared"].is_null(), "only a shared name is marked");
        let mut list = json!(["worker-1"]);
        with_handles(&mut list, &Value::Null);
        assert_eq!(list, json!(["worker-1"]));
        let shown = started(&json!({"worker":{"id":"worker-1","state":"preparing"}})).unwrap();
        assert_eq!(shown["worker"]["handle"], "happy-turtle");
        // `start bounty` alone reconnects to the newest worker, so only another one needs its name.
        let listed = fleet();
        assert_eq!(reconnect_command("worker-bbbb2222bbbb2222bbbb2222bbbb2222", &listed, &[]), "yougori start bounty");
        let older = reconnect_command("worker-aaaa1111aaaa1111aaaa1111aaaa1111", &listed, &[]);
        assert_eq!(older, format!("yougori start bounty --worker {}", worker_handle("worker-aaaa1111aaaa1111aaaa1111aaaa1111")));
        assert!(reconnect_command("worker-1", &Value::Null, &[]).ends_with("--worker happy-turtle"));
        let saved = &listed["workers"][1];
        let line = saved_line(saved, &listed);
        assert!(line.contains(&format!("Bounty worker ({})", worker_handle("worker-bbbb2222bbbb2222bbbb2222bbbb2222"))), "{line}");
        let named = json!({"id":"worker-dddd4444dddd4444dddd4444dddd4444","name":"keen-heron","model":"hf.co/owner/model"});
        let line = saved_line(&named, &json!({"workers":[named]}));
        assert!(line.starts_with("Your worker: keen-heron · "), "a name that is what to type is said once: {line}");
        // A failed saved worker can open the newest worker that did not fail instead.
        assert_eq!(other_worker(&listed, saved, &[])["id"], "worker-aaaa1111aaaa1111aaaa1111aaaa1111");
        assert!(other_worker(&json!({"workers":[saved]}), saved, &[]).is_null());
        assert_eq!(waiting_label("delete"), "Deleting your worker");
    }

    #[test]
    fn the_model_question_and_its_checks_explain_that_only_gguf_runs() {
        assert!(MODEL_QUESTION.contains("GGUF") && MODEL_NOTE.contains("hf.co/OWNER/MODEL-GGUF") && MODEL_NOTE.contains(":Q4_K_M"));
        assert!(HELP.contains("GGUF models (the llama.cpp format)") && HELP.contains("Esc goes back"));
        let safetensors = json!({"format":"safetensors","runner":"yougori-transformers-chat","supported":true});
        let problem = gguf_problem(&safetensors).unwrap();
        assert!(problem.contains("no GGUF files") && problem.contains("only GGUF models") && problem.contains("-GGUF"), "{problem}");
        let unverified = json!({"format":"gguf","runner":"dedicatedRunnerRequired","reason":"The repository did not provide SHA-256 checksums for its GGUF files, so they cannot be verified before loading"});
        let problem = gguf_problem(&unverified).unwrap();
        assert!(problem.contains("SHA-256 checksums") && problem.ends_with("before loading. Choose another GGUF repository."), "{problem}");
        // Prompts cut each note line at the screen's edge, so a long problem is wrapped.
        let lines = wrapped(&gguf_problem(&safetensors).unwrap(), 76);
        assert!(lines.len() > 1 && lines.iter().all(|line| ui::width(line) <= 76), "{lines:?}");
        assert_eq!(lines.join(" "), gguf_problem(&safetensors).unwrap(), "nothing is lost");
        let long = wrapped(&"word ".repeat(400), 40);
        assert!(long.len() == 5 && long[4].ends_with('…'), "{long:?}");
        assert!(gguf_problem(&json!({"format":"gguf","runner":"yougori-llama-cpp"})).is_none());
        assert!(gguf_problem(&Value::Null).is_none(), "an engine without preflight leaves it to preparation");
        let engine = model_problem("hf.co/owner/model has no GGUF files; --quant chooses a GGUF quantization");
        assert!(engine.contains("only GGUF models") && !engine.contains("--quant"), "{engine}");
        assert_eq!(model_problem("Hugging Face 401\u{1b}[2J"), "Hugging Face 401 [2J");
        assert!(model("yg/user/model").unwrap_err().contains("GGUF"));
        // A model too large for this computer needs attention before any question about it.
        let host = json!({"totalCpu":16,"totalMemoryGb":31.6});
        assert!(too_big(&json!({}), &host, 32).unwrap().contains("about 32 GB"));
        assert!(too_big(&json!({}), &host, 24).is_none());
        assert!(too_big(&json!({"resources":{"memoryGb":16}}), &host, 32).is_none(), "--memory is the person's choice");
        assert!(too_big(&json!({}), &json!({}), 64).is_none(), "unknown memory is left to the engine");
    }

    #[test]
    fn worker_names_need_two_bytes_like_the_engine() {
        assert!(parse(&words("start bounty --name a")).is_err());
        assert_eq!(parse(&words("start bounty --name Laptop")).unwrap().unwrap().request["name"], "Laptop");
        assert!(worker_name(&"x".repeat(65)).is_err() && worker_name("ab").is_ok());
    }

    fn setup(given: Value) -> Setup {
        Setup { enter_model: given["model"].is_null(), given, checks: true, ..Setup::default() }
    }

    #[test]
    fn setup_questions_follow_the_choices_made_so_far() {
        let all = |setup: &Setup| STEPS.iter().copied().filter(|step| !setup.skips(*step)).collect::<Vec<_>>();
        let mut fresh = setup(json!({"action":"prepare"}));
        assert_eq!(all(&fresh)[..4], [Step::Model, Step::Drive, Step::Summary, Step::Gpu]);
        fresh.quick = Some(true);
        assert_eq!(all(&fresh), [Step::Model, Step::Drive, Step::Summary], "Prepare skips the customize questions");
        fresh.quick = Some(false);
        assert_eq!(all(&fresh).len(), 9, "Customize asks each question, ending on the confirmation");
        fresh.attention = true;
        assert_eq!(all(&fresh)[0], Step::Attention, "a failed saved worker asks first");
        // Command line choices are not asked again.
        let given = parse(&words("start bounty --model hf.co/owner/model --gpu cpu --name Laptop --storage-drive D:\\ --keep-loaded")).unwrap().unwrap();
        let mut chosen = setup(given.request);
        assert_eq!(all(&chosen), [Step::Model, Step::Summary, Step::Size, Step::Quota, Step::Confirm], "the model step still checks a given model");
        chosen.checks = false;
        assert!(all(&chosen).is_empty(), "--yes asks nothing about a given model");
        let mut scripted = setup(json!({"action":"prepare"}));
        scripted.checks = false;
        assert_eq!(all(&scripted), [Step::Model], "--yes still asks for a missing model in a terminal");
    }

    #[test]
    fn setup_answers_are_kept_apart_so_back_can_change_them() {
        let host = json!({"totalCpu":16,"totalMemoryGb":64,"storageDrives":[{"path":"C:\\","freeGb":40.0},{"path":"D:\\","freeGb":900.0}]});
        let preflight = json!({"quant":"Q4_K_M","resources":{"weightsBytes":7_381_384_864u64}});
        let mut answers = setup(parse(&words("start bounty")).unwrap().unwrap().request);
        answers.host = Some(host.clone());
        answers.cuda = Some(json!({"supported":true}));
        answers.model = Some("hf.co/owner/model".into());
        answers.preflight = preflight.clone();
        answers.drive = Some("D:\\".into());
        answers.fresh_name = "keen-heron".into();
        // Prepare: the recommended settings for the checked model.
        answers.quick = Some(true);
        let request = answers.request().unwrap();
        assert_eq!(request["name"], "keen-heron", "a new worker gets its fresh name");
        assert_eq!((request["model"].as_str(), request["quant"].as_str()), (Some("hf.co/owner/model"), Some("Q4_K_M")));
        assert_eq!((request["gpu"].as_str(), request["resources"]["memoryGb"].as_u64()), (Some("nvidia"), Some(16)));
        assert_eq!(request["resources"]["storageDrive"], "D:\\");
        // Customize, then each answer.
        answers.quick = Some(false);
        answers.gpu = Some("cpu");
        answers.sizes = vec![6, 24];
        answers.quota = Some(30.0);
        answers.name = Some("Laptop".into());
        answers.keep = Some(true);
        let request = answers.request().unwrap();
        assert_eq!((request["gpu"].as_str(), request["resources"]["cpu"].as_u64(), request["resources"]["memoryGb"].as_u64()), (Some("cpu"), Some(6), Some(24)));
        assert_eq!((request["workspaceQuotaGb"].as_f64(), request["name"].as_str(), request["keepResident"].as_bool()), (Some(30.0), Some("Laptop"), Some(true)));
        // Back to the summary and Prepare: the customized answers no longer apply.
        answers.quick = Some(true);
        assert_eq!(answers.request().unwrap()["name"], "keen-heron");
        // An entered :QUANT wins; a model given with its own variant does not pass it to another one.
        answers.model = Some("hf.co/owner/other:IQ4_XS".into());
        answers.preflight = Value::Null;
        assert_eq!(answers.selection().unwrap()["quant"], "IQ4_XS");
        let mut replaced = setup(parse(&words("start bounty --model hf.co/owner/model:Q8_0")).unwrap().unwrap().request);
        replaced.model = Some("hf.co/owner/other".into());
        assert!(replaced.selection().unwrap()["quant"].is_null());
        let mut flagged = setup(parse(&words("start bounty --quant Q5_K_M")).unwrap().unwrap().request);
        flagged.model = Some("hf.co/owner/other".into());
        assert_eq!(flagged.selection().unwrap()["quant"], "Q5_K_M", "--quant without --model applies to the entered model");
        flagged.model = Some("hf.co/owner/other:Q8_0".into());
        assert!(flagged.selection().is_err(), "a conflicting :QUANT is refused");
        // With --yes the scripted defaults follow later, so nothing else is filled in here.
        let mut scripted = setup(json!({"action":"prepare"}));
        scripted.checks = false;
        scripted.model = Some("hf.co/owner/model".into());
        let request = scripted.request().unwrap();
        assert_eq!(request["model"], "hf.co/owner/model");
        assert!(request["gpu"].is_null() && request["resources"].is_null());
    }

    #[tokio::test]
    async fn the_waiting_view_asks_for_offers_only_once_the_worker_is_registered() {
        // A worker whose setup never finished, such as a paused one plain `start bounty` opens,
        // is not registered: the engine would refuse an offers request and end the view.
        let mut asked = Vec::new();
        for state in [json!({"id":"worker-1","state":"paused","serverId":null}), json!({"id":"worker-1","state":"preparing"})] {
            let count = count_offers("worker-1", &state, |request| {
                asked.push(request);
                std::future::ready(Err::<Value, String>("Worker registration has not completed".into()))
            })
            .await;
            assert_eq!(count, Ok(0), "{state}");
        }
        assert!(asked.is_empty(), "{asked:?}");
        let registered = json!({"id":"worker-1","state":"ready_waiting","serverId":"server-1"});
        let count = count_offers("worker-1", &registered, |request| {
            asked.push(request);
            std::future::ready(Ok(json!({"offers":[{"id":"offer-1"},{"id":"offer-2"}]})))
        })
        .await;
        assert_eq!(count, Ok(2));
        assert_eq!(asked, [json!({"action":"offers","workerId":"worker-1"})]);
    }

    #[test]
    fn a_quant_given_without_a_model_becomes_the_suggested_variant() {
        let flagged = setup(parse(&words("start bounty --quant iq4_xs")).unwrap().unwrap().request);
        let prefill = flagged.model_prefill();
        assert_eq!(prefill, "hf.co/thesamgodson/Gemma-4-12B-Hephaestus-GGUF:IQ4_XS");
        assert_eq!(model_entry(&flagged.entry_base(), &prefill), Ok(prefill.clone()), "Enter accepts the suggestion");
        assert!(model_entry(&flagged.entry_base(), "hf.co/owner/model:Q8_0").is_err(), "a typed conflicting variant is still refused");
        let mut saved = setup(parse(&words("start bounty --quant Q8_0")).unwrap().unwrap().request);
        saved.saved = json!({"model":"owner/model","quant":"Q4_K_M"});
        assert_eq!(saved.model_prefill(), "hf.co/owner/model:Q8_0", "the saved worker's model too");
        assert!(model_entry(&saved.entry_base(), &saved.model_prefill()).is_ok());
        // Without --quant the suggestion keeps its variant, and a given model keeps its own.
        assert_eq!(setup(parse(&words("start bounty")).unwrap().unwrap().request).model_prefill(), DEFAULT_MODEL);
        let given = setup(parse(&words("start bounty --model hf.co/owner/model --quant Q5_K_M")).unwrap().unwrap().request);
        assert_eq!(given.model_prefill(), "hf.co/owner/model:Q5_K_M");
        // A --quant that is no GGUF label leaves the suggestion without one, so Enter still works.
        let odd = setup(json!({"action":"prepare","quant":"Q4 K"}));
        assert_eq!(odd.model_prefill(), "hf.co/thesamgodson/Gemma-4-12B-Hephaestus-GGUF");
        assert!(model_entry(&odd.entry_base(), &odd.model_prefill()).is_ok());
    }

    #[test]
    fn leaving_a_preparation_inside_the_waiting_view_goes_back_to_it() {
        let labels = |bounty: bool| preparation_choices(bounty).map(|choice| choice.label);
        assert_eq!(labels(true), ["Cancel", "Stop preparation", "Back to the waiting view"]);
        assert_eq!(labels(false), ["Cancel", "Stop preparation", "Back to terminal"]);
    }

    #[test]
    fn a_practice_in_the_terminal_prints_no_json_after_its_console() {
        let id = "worker-bd89af264d434eb286e5dad338db9512";
        let shown = practice_shown(json!({"practice":true,"workerId":id,"exampleProject":"practice-login"}), id);
        assert_eq!(shown["detached"], true, "main prints nothing after a detached result");
        assert_eq!((shown["workerId"].as_str(), shown["handle"].as_str()), (Some(id), Some("apt-whale")));
        assert_eq!((shown["practice"].as_bool(), shown["exampleProject"].as_str()), (Some(true), Some("practice-login")));
    }

    #[test]
    fn a_running_practice_can_be_stopped_from_a_script() {
        let stop = parse(&words("bounty practice worker-1 --stop")).unwrap().unwrap();
        assert_eq!(stop.request, json!({"action":"practiceStop","workerId":"worker-1"}));
        assert!(!stop.interactive_start);
        for args in ["bounty practice --stop", "bounty status worker-1 --stop", "bounty practice worker-1 --stop --stop", "start bounty --stop"] {
            assert!(parse(&words(args)).is_err(), "{args}");
        }
        assert_eq!(waiting_label("practiceStop"), "Stopping the practice");
        assert!(HELP.contains("yougori bounty practice WORKER [--stop]"));
        // The help states the limits a practice without a terminal stops at.
        let (attempts, minutes) = (crate::bounty_practice::MAX_ATTEMPTS, crate::bounty_practice::SCRIPT_MINUTES);
        assert!(HELP.contains(&format!("stops after {attempts} rejected findings or {minutes} minutes")) && HELP.contains("--stop ends it"));
    }

    #[test]
    fn hints_name_a_worker_by_its_id_when_another_shares_its_short_name() {
        let mut seen = std::collections::BTreeMap::new();
        let (first, second) = (0..100_000)
            .map(|n| format!("worker-{n:032x}"))
            .find_map(|id| seen.insert(worker_handle(&id), id.clone()).map(|earlier| (earlier, id)))
            .unwrap();
        let third = "worker-1";
        let twins = json!({"workers":[
            {"id":first,"name":"One","state":"paused","createdAt":100},
            {"id":second,"name":"Two","state":"ready_waiting","createdAt":200},
            {"id":third,"name":"Three","state":"ready_waiting","createdAt":50}]});
        assert_eq!(typed_name(&first, &twins), first);
        assert_eq!(typed_name(&second, &twins), second);
        assert_eq!(typed_name(third, &twins), worker_handle(third), "a name no other worker has");
        assert_eq!(typed_name(&first, &Value::Null), worker_handle(&first), "without a listing, the short name");
        // The same choice as the workers table.
        let listed: Vec<&Value> = twins["workers"].as_array().unwrap().iter().collect();
        assert_eq!(worker_names(&listed), [first.clone(), second.clone(), worker_handle(third)]);
        // Reconnect commands for any worker but the newest, which plain `start bounty` opens.
        assert_eq!(reconnect_command(&first, &twins, &[]), format!("yougori start bounty --worker {first}"));
        assert_eq!(reconnect_command(&second, &twins, &[]), "yougori start bounty");
        assert_eq!(reconnect_command(third, &twins, &[]), format!("yougori start bounty --worker {}", worker_handle(third)));
        // The waiting view's hint is given the typed name.
        let restored = json!({"state":"paused","restored":true});
        assert!(state_hint(&restored, &typed_name(&first, &twins)).unwrap().ends_with(&format!("yougori bounty resume {first}")));
        // Results mark a shared name, so the status card names that worker by its ID.
        let mut status = json!({"worker":{"id":first,"state":"paused"}});
        with_handles(&mut status, &twins);
        assert_eq!((status["worker"]["handle"].as_str(), status["worker"]["handleShared"].as_bool()), (Some(worker_handle(&first).as_str()), Some(true)));
        let mut listing = twins.clone();
        with_handles(&mut listing, &twins);
        let marked: Vec<bool> = listing["workers"].as_array().unwrap().iter().map(|worker| worker["handleShared"] == true).collect();
        assert_eq!(marked, [true, true, false]);
    }
}
