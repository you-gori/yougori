//! A model on this computer, outside a grid: one model sandbox made by Yougori's model runner
//! (`run_model`), with a private API on 127.0.0.1 and its own key. The Model Server and Model
//! Collection recipes use it. `ModelServiceHandler` (grids.rs) hands every model service with no
//! `compute` to this module; one served by a Neo Grid pool stays there.
//!
//! Ownership: the runner keeps this setup's stamp (`setup:SETUP/RESOURCE/GENERATION`) in the
//! model's workload (`YOUGORI_SETUP_STAMP`), and the setup records the sandbox's ID. Every step
//! acts only on a sandbox that has both. A model the person ran themselves has no stamp, so it is
//! never adopted, stopped or deleted here; a create whose answer was lost is found again by its
//! stamp, never by its model or its name.
//!
//! Secrets: this handler stores none. The runner makes the model's API key and keeps it in this
//! computer's credential store, where `yougori model access` shows it; the key is dropped here the
//! moment a call returns it, so it never reaches a receipt, an event, a review or a log. When a
//! setup's model can't be made the runner forgets what it stored for it, and removing the model
//! forgets the entries only that model used.
//!
//! The review checks this computer's GPU and the runner's preflight of the model (its files, its
//! format and its download size), so an unsupported model, a GPU-only model on a computer without
//! one, or a processor run of a model with no GGUF files is refused before anything runs.
use super::grids::GridCalls;
use super::handler::{recovery_from, HandlerError, HandlerFuture, HealthReport, Observation, Outcome, Planned, Recovery, StepContext};
use super::journal::{Action, Receipt};
use super::model::{now, Cost, Health, Observed, Resource};
use serde_json::{json, Value};
use std::{
    sync::{Arc, Mutex, Weak},
    time::{Duration, Instant},
};

/// The model runner's own words, matched exactly.
const NOT_FOUND: &str = "Model environment not found";
const NOT_A_MODEL: &str = "This is not a model environment";
const ENVIRONMENT_NOT_FOUND: &str = "Environment not found";
const STILL_CREATING: &str = "Wait for this environment to finish creating before deleting it";
const SERVER_STARTING: &str = "Model server is starting. Check Logs for installation/download progress and try again.";
const NOT_RUNNING: &str = "Start the model environment first";
/// What a product call returns when the step was cancelled while it waited.
const CANCELLED: &str = "\u{0}cancelled";
/// A download this large is called out plainly in the review.
const LARGE_DOWNLOAD_GB: f64 = 20.0;
/// How long the review waits for this computer's GPU status and the model's preflight.
const PROBE_WAIT: Duration = Duration::from_secs(15);
/// How long a review's findings are reused, so notes and a second look don't fetch again.
const PROBE_LIFETIME: Duration = Duration::from_secs(120);

/// Whether a model service runs on this computer alone: it names no pool or sandbox to run on.
pub(crate) fn is_local(spec: &Value) -> bool {
    spec["compute"].is_null()
}

#[derive(Clone)]
pub(crate) struct LocalModels {
    calls: Arc<dyn GridCalls>,
}

/// A model sandbox this setup made, as the engine reports it.
#[derive(Clone, Debug)]
struct Found {
    id: String,
    name: String,
    status: String,
    /// Whether its API listens on this computer.
    api: bool,
    /// The vault entries only this model uses, forgotten once it is deleted.
    secrets: Vec<String>,
}

/// What the review learned about this computer and the model, when it could ask.
#[derive(Clone, Debug, Default)]
struct Probe {
    /// Whether this computer has an NVIDIA GPU Yougori can use.
    cuda: Option<bool>,
    /// The runner's preflight of the model.
    preflight: Option<Value>,
}

fn refused(message: &str) -> HandlerError {
    HandlerError::new(Outcome::Unsupported, "unsupported_here", format!("{message} Nothing was changed."))
}

fn invalid(message: impl Into<String>) -> HandlerError {
    HandlerError::new(Outcome::Failed, "invalid_spec", message)
}

fn text(spec: &Value, field: &str) -> Option<String> {
    spec[field].as_str().map(str::trim).filter(|value| !value.is_empty()).map(str::to_owned)
}

/// A product's message without the CLI commands it suggests, which mean nothing in a setup.
fn plain(message: &str) -> String {
    let message = crate::lifecycle::safe_diagnostic(message);
    let kept = message.split_inclusive(". ").filter(|sentence| !sentence.contains('`') && !sentence.contains(" --")).collect::<String>();
    let kept = kept.trim();
    let kept = if kept.is_empty() { message.trim() } else { kept };
    if kept.ends_with(['.', '!', '?']) { kept.to_owned() } else { format!("{kept}.") }
}

fn receipt(runtime_id: Option<String>, observed: Observed, adopted: bool) -> Receipt {
    Receipt { runtime_id, observed, retained_data: false, cost: Cost::Free, at: now(), adopted }
}

fn gone() -> HandlerError {
    HandlerError::new(Outcome::Failed, "resource_missing", "This model isn't on this computer anymore. Refresh the setup, then repair it to make it again.")
}

/// Where the model runs: on the GPU, or on the processor.
fn on_processor(spec: &Value, cuda: Option<bool>) -> bool {
    match spec["gpu"].as_str().unwrap_or("none") {
        "required" => false,
        "optional" => cuda == Some(false),
        _ => true,
    }
}

/// Gigabytes, one decimal.
fn gigabytes(bytes: f64) -> String {
    format!("{:.1}", bytes / (1024.0 * 1024.0 * 1024.0))
}

/// Unix seconds from an RFC 3339 time or a number.
fn seconds(value: &Value) -> Option<i64> {
    match value {
        Value::Number(number) => number.as_i64().map(|at| if at > 100_000_000_000 { at / 1000 } else { at }),
        Value::String(at) => chrono::DateTime::parse_from_rfc3339(at).ok().map(|at| at.timestamp()),
        _ => None,
    }
}

/// A free port on 127.0.0.1 for the model's API, chosen by the system.
fn free_port() -> Option<u16> {
    std::net::TcpListener::bind(("127.0.0.1", 0)).ok()?.local_addr().ok().map(|address| address.port())
}

/// Recent findings of the review, by product calls and model.
struct Remembered {
    calls: Weak<dyn GridCalls>,
    key: String,
    at: Instant,
    probe: Probe,
}

static PROBES: Mutex<Vec<Remembered>> = Mutex::new(Vec::new());

impl LocalModels {
    pub(crate) fn new(calls: Arc<dyn GridCalls>) -> Self {
        Self { calls }
    }

    /// What this setup puts on the model it makes, and looks for to know it again.
    fn stamp(context: &StepContext) -> String {
        format!("setup:{}/{}/{}", context.setup, context.resource, context.generation)
    }

    /// A product call that gives way to the step's cancellation. The product may still finish
    /// what it began, so a cancelled call's outcome is settled by looking.
    async fn ask(&self, context: &StepContext, method: &str, params: Value) -> Result<Value, String> {
        tokio::select! {
            result = self.calls.call(method, params) => result,
            _ = context.cancel.cancelled() => Err(CANCELLED.into()),
        }
    }

    fn failed(context: &StepContext, error: &str) -> HandlerError {
        if error == CANCELLED || context.cancel.is_cancelled() {
            return HandlerError::new(Outcome::Unknown, "outcome_unknown", "Cancelled while waiting for the model runner. Checking what happened before anything else runs.");
        }
        HandlerError::new(Outcome::Failed, "model_refused", plain(error))
    }

    // ----- Review -----

    pub(crate) fn validate(&self, spec: &Value) -> Result<(), HandlerError> {
        let model = text(spec, "model").ok_or_else(|| invalid("A model service needs its model."))?;
        if model.len() > 200 || model.chars().any(char::is_whitespace) {
            return Err(invalid("A model is named hf.co/OWNER/MODEL or yg/PUBLISHER/MODEL."));
        }
        if !spec["team"].is_null() {
            return Err(refused("A team of models runs on a Neo Grid; give it compute: with the grid's pool."));
        }
        if !spec["network"].is_null() {
            return Err(refused("Listing a model on the Yougori Network is done from the Network page for now."));
        }
        if spec["replicas"].as_u64().is_some_and(|replicas| replicas > 1) {
            return Err(refused("A model on this computer runs once; several copies need a Neo Grid."));
        }
        if !spec["placement"].is_null() || !spec["share_percent"].is_null() {
            return Err(refused("Placement and share_percent are for a model a Neo Grid serves; leave them out for a model on this computer."));
        }
        if !spec["revision"].is_null() {
            return Err(refused("Pinning a model revision isn't available in setups yet; the runner pins the newest one and checks its files."));
        }
        if !spec["format"].is_null() || !spec["backend"].is_null() {
            return Err(refused("The runner picks the format and backend from the model's files; choose the GPU with gpu: none, optional or required."));
        }
        if spec["api"]["keys"].as_u64().unwrap_or(0) > 0 || !spec["api"]["first_key"].is_null() {
            return Err(refused("A model on this computer has one API key, made by the runner and shown by yougori model access; extra app keys are for Neo Grid."));
        }
        if spec["secrets"].as_object().is_some_and(|secrets| !secrets.is_empty()) {
            return Err(refused("A model on this computer takes no secrets from a template; gated Hugging Face models use the sign-in saved with yougori model auth login."));
        }
        if !matches!(spec["gpu"].as_str().unwrap_or("none"), "none" | "optional" | "required") {
            return Err(invalid("gpu is none, optional or required."));
        }
        if spec["memory_gb"].as_f64().is_some_and(|memory| memory < 4.0) {
            return Err(invalid("A model on this computer needs at least 4 GB of memory (memory_gb: 4 or more)."));
        }
        Ok(())
    }

    /// Refuses at review what can't work on this computer, from its GPU and the runner's
    /// preflight of the model. When either can't be asked, nothing is concluded here: the
    /// runner checks again before anything is downloaded.
    pub(crate) fn review(&self, id: &str, spec: &Value) -> Result<(), HandlerError> {
        let model = text(spec, "model").unwrap_or_default();
        let probe = self.probe(spec);
        if spec["gpu"].as_str() == Some("required") && probe.cuda == Some(false) {
            return Err(refused(&format!(
                "{id} is set to run only on an NVIDIA GPU, and this computer has none that Yougori can use. Let it use the processor when there is no GPU, or run the template on a computer with an NVIDIA GPU."
            )));
        }
        let Some(preflight) = probe.preflight else { return Ok(()) };
        if preflight["supported"] != true {
            let reason = preflight["reason"].as_str().map(plain).unwrap_or_else(|| "The runner can't serve it.".into());
            return Err(refused(&format!("{model} can't run with Yougori's model runner: {reason} Choose another model for {id}.")));
        }
        if on_processor(spec, probe.cuda) && preflight["runner"] != "yougori-llama-cpp" {
            let gpu = if spec["gpu"].as_str() == Some("none") { ", or let it use an NVIDIA GPU" } else { "" };
            return Err(refused(&format!("{id} runs on the processor here, which needs a GGUF model, and {model} has no GGUF files. Choose a GGUF model{gpu}.")));
        }
        Ok(())
    }

    /// A model on this computer is made once; changing it means a new one.
    pub(crate) fn plan(&self, current: Option<&Resource>, spec_digest: &str) -> Result<Planned, HandlerError> {
        Ok(match current {
            None => Planned::Step(Action::Create),
            Some(resource) if resource.runtime_id.is_none() => Planned::Step(Action::Create),
            Some(resource) if resource.spec_digest != spec_digest => {
                return Err(refused(&format!(
                    "{} can't be changed in place yet. To run another model, size or memory, add it to the template under a new ID and remove this one.",
                    resource.id
                )))
            }
            Some(_) => Planned::Unchanged,
        })
    }

    pub(crate) fn notes(&self, resource: &str, spec: &Value, action: Action) -> Vec<String> {
        let model = text(spec, "model").unwrap_or_default();
        match action {
            Action::Create => {
                let probe = self.probe(spec);
                let mut notes = Vec::new();
                let size = probe.preflight.as_ref().filter(|preflight| preflight["supported"] == true).and_then(|preflight| {
                    let weights = preflight["resources"]["weightsBytes"].as_f64().filter(|bytes| *bytes > 0.0)?;
                    Some((weights, preflight["resources"]["storageGbRecommended"].as_f64(), preflight["quant"].as_str().map(str::to_owned)))
                });
                notes.push(match size {
                    Some((weights, storage, quant)) => {
                        let quant = quant.map(|quant| format!(" ({quant})")).unwrap_or_default();
                        let mut note = format!("{resource} downloads {model}{quant} to this computer before it runs: about {} GB.", gigabytes(weights));
                        if weights / (1024.0 * 1024.0 * 1024.0) >= LARGE_DOWNLOAD_GB {
                            let room = storage.map(|storage| format!(" and needs about {storage:.0} GB free on the drive"));
                            note.push_str(&format!(" That is a large download: it can take a long time{}.", room.unwrap_or_default()));
                        }
                        note
                    }
                    None => format!("{resource} downloads {model} to this computer before it runs; models are often several gigabytes. The runner checks the model's files and this computer first, and stops with nothing made when they don't fit."),
                });
                if spec["gpu"].as_str() == Some("optional") && probe.cuda == Some(false) {
                    notes.push(format!("This computer has no NVIDIA GPU that Yougori can use, so {resource} runs on the processor."));
                }
                notes.push(format!("{resource}'s API listens on this computer only, with its own key; yougori model access shows both. The key is never shown in the setup."));
                notes
            }
            Action::Remove => vec![format!(
                "Removing {resource} deletes its model sandbox and the model files it downloaded; they can be downloaded again. Its API key stops working. Models you ran yourself are left alone."
            )],
            _ => Vec::new(),
        }
    }

    /// The GPU status and the model's preflight, asked once per review and remembered briefly.
    /// The review is synchronous, so the product calls run on a thread of their own and are
    /// waited for at most `PROBE_WAIT`; nothing is concluded from a call that didn't answer.
    fn probe(&self, spec: &Value) -> Probe {
        let model = text(spec, "model").unwrap_or_default();
        let quant = text(spec, "quantization");
        let key = format!("{model}\u{0}{}", quant.clone().unwrap_or_default());
        {
            let mut remembered = PROBES.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            remembered.retain(|entry| entry.at.elapsed() < PROBE_LIFETIME && entry.calls.strong_count() > 0);
            let ours = Arc::downgrade(&self.calls);
            if let Some(entry) = remembered.iter().find(|entry| entry.key == key && Weak::ptr_eq(&entry.calls, &ours)) {
                return entry.probe.clone();
            }
        }
        let calls = self.calls.clone();
        let (answer, answered) = std::sync::mpsc::channel();
        let asked = std::thread::Builder::new().name("setup-model-review".into()).spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread().enable_all().build() else { return };
            let probe = runtime.block_on(async {
                let (gpu, preflight) = tokio::join!(
                    tokio::time::timeout(PROBE_WAIT, calls.call("model_compute_status", json!({}))),
                    tokio::time::timeout(PROBE_WAIT, calls.call("model_preflight", json!({ "model": model, "quant": quant }))),
                );
                Probe {
                    cuda: gpu.ok().and_then(Result::ok).and_then(|status| status["cudaSupported"].as_bool()),
                    preflight: preflight.ok().and_then(Result::ok).filter(|preflight| preflight["supported"].is_boolean()),
                }
            });
            let _ = answer.send(probe);
        });
        let probe = asked.ok().and_then(|_| answered.recv_timeout(PROBE_WAIT + Duration::from_secs(1)).ok()).unwrap_or_default();
        if probe.cuda.is_some() || probe.preflight.is_some() {
            PROBES.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).push(Remembered { calls: Arc::downgrade(&self.calls), key, at: Instant::now(), probe: probe.clone() });
        }
        probe
    }

    // ----- Looking -----

    /// The stamp a model sandbox carries, and what the engine says about its API and vault
    /// entries. `None` when the sandbox isn't there or isn't a model. The API key in the answer is
    /// dropped here.
    async fn stamp_of(&self, id: &str) -> Result<Option<(Option<String>, bool, Vec<String>)>, String> {
        match self.calls.call("model_api_status", json!({ "environmentId": id })).await {
            Ok(access) => {
                let secrets = access["setupSecrets"].as_array().into_iter().flatten().filter_map(Value::as_str).map(str::to_owned).collect();
                Ok(Some((access["setupStamp"].as_str().map(str::to_owned), !access["apiUrl"].is_null(), secrets)))
            }
            Err(error) if error == NOT_FOUND || error == NOT_A_MODEL => Ok(None),
            Err(error) => Err(plain(&error)),
        }
    }

    /// This setup's model sandbox: the one whose ID was recorded and that carries this setup's
    /// stamp, or, before a receipt exists, the one that carries the stamp. `since` limits the
    /// search to sandboxes made after that time, when the step's start is known.
    async fn find(&self, context: &StepContext, since: Option<i64>) -> Result<Option<Found>, String> {
        let state = self.calls.call("get_platform_state", json!({})).await.map_err(|error| plain(&error))?;
        let stamp = Self::stamp(context);
        let models = state["environments"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|env| env["description"].as_str().is_some_and(|description| description.starts_with("Hugging Face · ")))
            .filter(|env| match &context.runtime_id {
                Some(id) => env["id"].as_str() == Some(id.as_str()),
                None => since.is_none_or(|since| seconds(&env["createdAt"]).is_none_or(|made| made >= since - 5)),
            })
            .cloned()
            .collect::<Vec<_>>();
        for env in models {
            let id = env["id"].as_str().unwrap_or_default().to_owned();
            let Some((found, api, secrets)) = self.stamp_of(&id).await? else { continue };
            if found.as_deref() == Some(stamp.as_str()) {
                return Ok(Some(Found {
                    name: env["name"].as_str().unwrap_or(&id).to_owned(),
                    status: env["status"].as_str().unwrap_or_default().to_owned(),
                    id,
                    api,
                    secrets,
                }));
            }
        }
        Ok(None)
    }

    fn observed(found: &Found) -> Observed {
        match found.status.as_str() {
            "running" => Observed::Running,
            "stopped" | "paused" => Observed::Stopped,
            _ => Observed::Present,
        }
    }

    pub(crate) fn observe<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Observation> {
        Box::pin(async move {
            let since = if context.runtime_id.is_none() { context.started_at } else { None };
            Ok(match self.find(context, since).await {
                Ok(Some(found)) => Observation::Present { observed: Self::observed(&found), runtime_id: found.id, label: None, retained_data: false, cost: Cost::Free },
                Ok(None) => Observation::Absent,
                Err(reason) => Observation::Unknown { reason },
            })
        })
    }

    // ----- Acting -----

    pub(crate) fn apply<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move {
            match context.action {
                Action::Create => self.create(context).await,
                Action::Start => {
                    let found = self.find(context, None).await.map_err(|reason| HandlerError::new(Outcome::NotStarted, "model_unavailable", format!("Yougori couldn't check the model: {reason} Nothing was changed.")))?;
                    let found = found.ok_or_else(gone)?;
                    match self.ask(context, "start_model", json!({ "environmentId": found.id })).await {
                        Ok(_) => Ok(receipt(Some(found.id), Observed::Running, false)),
                        Err(error) if error == NOT_FOUND => Err(gone()),
                        Err(error) => Err(Self::failed(context, &error)),
                    }
                }
                _ => Err(refused("A model on this computer can't be changed in place yet.")),
            }
        })
    }

    /// Makes the model sandbox once. Everything that could refuse it is checked first, so a
    /// refusal leaves nothing behind; a sandbox an earlier attempt made is kept, never made twice.
    async fn create(&self, context: &StepContext) -> Result<Receipt, HandlerError> {
        let spec = &context.spec;
        let model = text(spec, "model").unwrap_or_default();
        let looked = self.find(context, None).await.map_err(|reason| HandlerError::new(Outcome::NotStarted, "model_unavailable", format!("Yougori couldn't check this computer's models: {reason} Nothing was changed.")))?;
        if let Some(found) = looked {
            return Ok(receipt(Some(found.id.clone()), Self::observed(&found), true));
        }
        let cuda = match self.calls.call("model_compute_status", json!({})).await {
            Ok(status) => status["cudaSupported"].as_bool().unwrap_or(false),
            Err(_) if spec["gpu"].as_str().unwrap_or("none") == "none" => false,
            Err(error) => {
                return Err(HandlerError::new(Outcome::NotStarted, "gpu_unknown", format!("Yougori couldn't check this computer's GPU: {} Nothing was changed.", plain(&error))));
            }
        };
        if spec["gpu"].as_str() == Some("required") && !cuda {
            return Err(refused(&format!("{} is set to run only on an NVIDIA GPU, and this computer has none that Yougori can use.", context.resource)));
        }
        let processor = on_processor(spec, Some(cuda));
        let port = free_port().ok_or_else(|| HandlerError::new(Outcome::NotStarted, "no_port", "This computer has no free local port for the model's API right now. Nothing was changed."))?;
        let mut resources = json!({ "cpuOnly": processor, "setupStamp": Self::stamp(context) });
        if !processor {
            resources["backend"] = json!("cuda");
        }
        if let Some(memory) = spec["memory_gb"].as_f64() {
            resources["memoryGb"] = json!(memory);
        }
        let request = json!({ "model": model, "port": port, "quant": text(spec, "quantization"), "resources": resources });
        match self.ask(context, "run_model", request).await {
            Ok(made) => {
                // The answer carries the API key; only the sandbox's ID is kept.
                let id = made["id"].as_str().map(str::to_owned).ok_or_else(|| HandlerError::new(Outcome::Unknown, "outcome_unknown", "The model runner didn't say which sandbox it made. Checking before anything else runs."))?;
                Ok(receipt(Some(id), Observed::Running, false))
            }
            Err(error) => {
                if error == CANCELLED || context.cancel.is_cancelled() {
                    return Err(Self::failed(context, &error));
                }
                // The runner refuses before it makes anything, but a sandbox that was made and
                // then didn't start is there: it is this step's, and is settled by looking.
                match self.find(context, None).await {
                    Ok(None) => Err(HandlerError::new(Outcome::Failed, "model_refused", plain(&error))),
                    Ok(Some(_)) => Err(HandlerError::new(
                        Outcome::Unknown,
                        "outcome_unknown",
                        format!("{}'s model sandbox was made, but the runner then said: {} Checking what happened before anything else runs.", context.resource, plain(&error)),
                    )),
                    Err(reason) => Err(HandlerError::new(Outcome::Unknown, "outcome_unknown", format!("{} Yougori couldn't tell whether the model sandbox was made ({reason}). Checking before anything else runs.", plain(&error)))),
                }
            }
        }
    }

    pub(crate) fn stop<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move {
            let found = self.find(context, None).await.map_err(|reason| HandlerError::new(Outcome::NotStarted, "model_unavailable", format!("Yougori couldn't check the model: {reason} Nothing was changed.")))?;
            let found = found.ok_or_else(gone)?;
            match self.ask(context, "stop_model", json!({ "environmentId": found.id })).await {
                Ok(_) => Ok(receipt(Some(found.id), Observed::Stopped, false)),
                Err(error) if error == NOT_FOUND => Err(gone()),
                Err(error) => Err(Self::failed(context, &error)),
            }
        })
    }

    /// Deletes the model sandbox this setup recorded, with the model files it downloaded, then
    /// forgets the vault entries only it used. One that is gone, or that isn't this setup's, is
    /// left alone and the removal finishes.
    pub(crate) fn remove<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move {
            if context.runtime_id.is_none() {
                return Ok(receipt(None, Observed::Missing, false));
            }
            let found = self.find(context, None).await.map_err(|reason| {
                HandlerError::new(Outcome::NotStarted, "model_unavailable", format!("Yougori couldn't check the model: {reason} Nothing was removed; retry."))
            })?;
            let Some(found) = found else { return Ok(receipt(None, Observed::Missing, false)) };
            match self.ask(context, "delete_environment", json!({ "environmentId": found.id, "recoverRuntime": null })).await {
                Ok(_) => {}
                Err(error) if error == ENVIRONMENT_NOT_FOUND => {}
                Err(error) if error == STILL_CREATING => {
                    return Err(HandlerError::new(Outcome::NotStarted, "model_busy", "The model sandbox is still being made. Nothing was removed; retry in a moment."));
                }
                Err(error) => return Err(HandlerError { retryable: true, ..Self::failed(context, &error) }),
            }
            for name in &found.secrets {
                // Names only; a vault that won't answer leaves an unused entry, never a used one.
                let _ = self.calls.call("delete_deployment_secret", json!({ "name": name })).await;
            }
            Ok(receipt(None, Observed::Missing, false))
        })
    }

    pub(crate) fn health<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, HealthReport> {
        Box::pin(async move {
            let report = |health, detail: String| HealthReport { health, detail };
            let found = match self.find(context, None).await {
                Ok(Some(found)) => found,
                Ok(None) => return Ok(report(Health::Failed, "This model isn't on this computer anymore.".into())),
                Err(reason) => return Ok(report(Health::Unknown, format!("Yougori couldn't check the model: {reason}"))),
            };
            if found.status != "running" {
                return Ok(report(Health::Degraded, format!("{} is stopped. Start the setup, or run yougori model start {}.", found.name, found.name)));
            }
            let status = match self.calls.call("model_status", json!({ "environmentId": found.id })).await {
                Ok(status) => status,
                Err(error) if error == SERVER_STARTING => return Ok(report(Health::Starting, "The model server is starting.".into())),
                Err(error) if error == NOT_RUNNING => return Ok(report(Health::Degraded, format!("{} is stopped.", found.name))),
                Err(error) => return Ok(report(Health::Unknown, plain(&error))),
            };
            Ok(match status["status"].as_str().unwrap_or_default() {
                "ready" if found.api => report(Health::Ready, format!("{} is ready. yougori model access {} shows its address and key.", found.name, found.name)),
                "ready" => report(Health::Degraded, format!("{} is ready, but its API is off. Turn it on with yougori model api {}.", found.name, found.name)),
                "downloading" => {
                    let download = &status["download"];
                    let detail = match (download["receivedBytes"].as_f64(), download["totalBytes"].as_f64().filter(|total| *total > 0.0)) {
                        (Some(received), Some(total)) => format!("Downloading the model: {} of {} GB.", gigabytes(received), gigabytes(total)),
                        _ => "Downloading the model.".into(),
                    };
                    report(Health::Starting, detail)
                }
                "verifying" => report(Health::Starting, "Checking the downloaded model files.".into()),
                "loading" => report(Health::Starting, "Loading the model.".into()),
                "installing" => report(Health::Starting, "Installing the model runner.".into()),
                "queued" => report(Health::WaitingForComputer, status["optimizer"]["waitingFor"].as_str().map(plain).unwrap_or_else(|| "Waiting for the GPU.".into())),
                "error" => report(Health::Failed, status["error"].as_str().map(plain).unwrap_or_else(|| "The model server stopped with an error.".into())),
                _ => report(Health::Unknown, "The model server didn't say how it is.".into()),
            })
        })
    }

    /// Settles an unknown outcome by looking, and only looking: nothing is made or started here,
    /// so an engine that starts up never runs a model by itself.
    pub(crate) fn recover<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Recovery> {
        Box::pin(async move {
            let observation = self.observe(context).await?;
            Ok(match (context.action, observation) {
                (Action::Create, Observation::Present { runtime_id, observed, retained_data, cost, .. }) => {
                    Recovery::Applied(Receipt { runtime_id: Some(runtime_id), observed, retained_data, cost, at: now(), adopted: true })
                }
                (_, observation) => recovery_from(context, observation),
            })
        })
    }
}

#[cfg(test)]
pub(crate) mod fake {
    //! Yougori's model runner in memory, for tests. It answers as the runner does where it matters
    //! to a setup: its exact refusals, a stamp kept with each sandbox, an API key in every answer,
    //! and vault entries stored when a model is made.
    use super::*;
    use crate::setups::ordinary::BoxFuture;
    use std::collections::{BTreeMap, BTreeSet};

    #[derive(Clone, Debug)]
    pub(crate) struct Env {
        pub id: String,
        pub name: String,
        pub model: String,
        pub status: String,
        pub stamp: Option<String>,
        pub secrets: Vec<String>,
        pub cpu_only: bool,
        pub api: bool,
        pub created_at: String,
    }

    #[derive(Default)]
    pub(crate) struct State {
        pub envs: Vec<Env>,
        pub calls: Vec<String>,
        pub cuda: bool,
        /// Preflight answers by model; a model not listed is a supported GGUF model of 4 GB.
        pub preflight: BTreeMap<String, Value>,
        pub vault: BTreeSet<String>,
        /// The next `run_model` refuses with this, making nothing.
        pub refuse: Option<String>,
        /// The next `run_model` makes the sandbox and then loses its answer.
        pub lose_answer: bool,
        /// The next `run_model` makes the sandbox, which then fails to start with this.
        pub fail_start: Option<String>,
        /// Every call fails as an engine that doesn't answer would.
        pub unreachable: bool,
        /// The health the next `model_status` reports.
        pub health: Option<Value>,
        next: u32,
    }

    #[derive(Default)]
    pub(crate) struct FakeModels {
        pub state: Mutex<State>,
    }

    pub(crate) fn gguf(gigabytes: f64) -> Value {
        let bytes = gigabytes * 1024.0 * 1024.0 * 1024.0;
        json!({"supported": true, "runner": "yougori-llama-cpp", "format": "gguf", "quant": "Q4_K_M", "reason": "GGUF weights run with llama.cpp",
            "resources": {"weightsBytes": bytes, "storageGbRecommended": (gigabytes * 1.05 + 6.0).ceil(), "gpuMemoryGbEstimated": (gigabytes * 1.15 + 1.5).ceil()}})
    }

    impl FakeModels {
        pub(crate) fn add_own(&self, model: &str) -> String {
            let mut state = self.state.lock().unwrap();
            state.next += 1;
            let next = state.next;
            let id = format!("env-mine-{next}");
            let secret = format!("model-api-mine-{next}");
            state.vault.insert(secret.clone());
            state.envs.push(Env { id: id.clone(), name: format!("my-{next}"), model: model.into(), status: "running".into(), stamp: None, secrets: vec![secret], cpu_only: true, api: true, created_at: chrono::Utc::now().to_rfc3339() });
            id
        }
    }

    impl GridCalls for FakeModels {
        fn call<'a>(&'a self, method: &'a str, params: Value) -> BoxFuture<'a, Result<Value, String>> {
            Box::pin(async move {
                let mut state = self.state.lock().unwrap();
                state.calls.push(method.to_owned());
                if state.unreachable {
                    return Err("The engine did not answer".into());
                }
                let env_id = params["environmentId"].as_str().unwrap_or_default().to_owned();
                match method {
                    "get_platform_state" => {
                        let envs = state.envs.iter().map(|env| json!({"id": env.id, "name": env.name, "status": env.status, "description": format!("Hugging Face · {}", env.model), "createdAt": env.created_at})).collect::<Vec<_>>();
                        Ok(json!({"environments": envs, "host": {"totalMemoryGb": 32}}))
                    }
                    "model_compute_status" => Ok(json!({"cudaSupported": state.cuda, "backend": if state.cuda { "cuda" } else { "cpu" }})),
                    "model_preflight" => {
                        let model = params["model"].as_str().unwrap_or_default().trim_start_matches("hf.co/").to_owned();
                        Ok(state.preflight.get(&model).cloned().unwrap_or_else(|| gguf(4.0)))
                    }
                    "run_model" => {
                        if let Some(refusal) = state.refuse.take() {
                            return Err(refusal);
                        }
                        let model = params["model"].as_str().unwrap_or_default().trim_start_matches("hf.co/").to_owned();
                        let preflight = state.preflight.get(&model).cloned().unwrap_or_else(|| gguf(4.0));
                        let cpu_only = params["resources"]["cpuOnly"] == true;
                        if cpu_only && preflight["runner"] != "yougori-llama-cpp" {
                            return Err("CPU model workers currently require a supported GGUF repository. Choose a GGUF variant or an NVIDIA GPU.".into());
                        }
                        state.next += 1;
                        let next = state.next;
                        let id = format!("env-{next}");
                        let secrets = vec![format!("model-api-{next}"), format!("model-admin-{next}"), format!("gpu-control-{next}")];
                        state.vault.extend(secrets.iter().cloned());
                        let fail = state.fail_start.take();
                        state.envs.push(Env {
                            id: id.clone(),
                            name: format!("{}-{next}", model.rsplit('/').next().unwrap_or("model").to_ascii_lowercase()),
                            model: model.clone(),
                            status: if fail.is_some() { "stopped".into() } else { "running".into() },
                            stamp: params["resources"]["setupStamp"].as_str().map(str::to_owned),
                            secrets,
                            cpu_only,
                            api: params["port"].is_u64(),
                            created_at: chrono::Utc::now().to_rfc3339(),
                        });
                        if let Some(error) = fail {
                            return Err(format!("Environment {id} was created but could not start: {error}. Inspect or retry starting this environment before creating another."));
                        }
                        if std::mem::take(&mut state.lose_answer) {
                            return Err("The connection to the engine was lost".into());
                        }
                        Ok(json!({"id": id, "name": "model", "started": true, "model": model, "status": "loading", "apiUrl": format!("http://127.0.0.1:{}/v1", params["port"]), "apiKey": format!("KEY-VALUE-{next}")}))
                    }
                    "model_api_status" => {
                        let env = state.envs.iter().find(|env| env.id == env_id).ok_or(NOT_FOUND)?;
                        let others = state.envs.iter().filter(|other| other.id != env.id).flat_map(|other| other.secrets.iter()).collect::<Vec<_>>();
                        let sole = if env.stamp.is_some() { env.secrets.iter().filter(|name| !others.contains(name)).cloned().collect() } else { Vec::new() };
                        Ok(json!({"id": env.id, "model": env.model, "apiKey": "KEY-VALUE", "apiUrl": if env.api { json!("http://127.0.0.1:1/v1") } else { Value::Null }, "setupStamp": env.stamp, "setupSecrets": sole}))
                    }
                    "start_model" => {
                        let env = state.envs.iter_mut().find(|env| env.id == env_id).ok_or(NOT_FOUND)?;
                        env.status = "running".into();
                        Ok(json!({"id": env_id, "model": env.model}))
                    }
                    "stop_model" => {
                        let env = state.envs.iter_mut().find(|env| env.id == env_id).ok_or(NOT_FOUND)?;
                        env.status = "stopped".into();
                        Ok(json!({"id": env_id, "stopped": true}))
                    }
                    "model_status" => {
                        let env = state.envs.iter().find(|env| env.id == env_id).ok_or(NOT_FOUND)?;
                        if env.status != "running" {
                            return Err(NOT_RUNNING.into());
                        }
                        Ok(state.health.clone().unwrap_or_else(|| json!({"status": "ready"})))
                    }
                    "delete_environment" => {
                        let before = state.envs.len();
                        state.envs.retain(|env| env.id != env_id);
                        if state.envs.len() == before {
                            return Err(ENVIRONMENT_NOT_FOUND.into());
                        }
                        Ok(json!({"state": {}, "storageCleanup": {}}))
                    }
                    "delete_deployment_secret" => {
                        let name = params["name"].as_str().unwrap_or_default().to_owned();
                        state.vault.remove(&name);
                        Ok(json!({"reference": name, "deleted": true}))
                    }
                    other => Err(format!("The fake model runner doesn't know {other}")),
                }
            })
        }
    }
}

#[cfg(test)]
mod tests {
    //! The Model Server and Model Collection recipes, planned through the planner and applied
    //! through the engine and these handlers, against the runner in memory.
    use super::fake::{gguf, FakeModels};
    use super::*;
    use crate::setups::{
        handler::Handlers,
        journal::OperationState,
        model::new_id,
        service::{DeclaredResource, PlanIntent, Service},
    };
    use std::{collections::BTreeMap, path::PathBuf};
    use yougori_setup::resource::Kind;

    struct Bench {
        _root: tempfile::TempDir,
        setups: PathBuf,
        data: PathBuf,
        models: Arc<FakeModels>,
    }

    impl Bench {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let data = root.path().join("data");
            std::fs::create_dir_all(&data).unwrap();
            Self { setups: data.join("setups"), data, _root: root, models: Default::default() }
        }

        /// A fresh engine over the same folders and runner, as after a restart.
        fn service(&self) -> Arc<Service> {
            let mut handlers = Handlers::default();
            for each in crate::setups::grids::Grids::new(self.models.clone()).handlers() {
                handlers.register(each);
            }
            Arc::new(Service::open(&self.setups, &self.data, handlers))
        }

        fn state(&self) -> std::sync::MutexGuard<'_, fake::State> {
            self.models.state.lock().unwrap()
        }
    }

    struct NoHub;

    impl crate::setups::planning::Hub for NoHub {
        fn fetch<'a>(&'a self, _: &'a str, _: &'a str, _: Option<&'a str>, _: Option<&'a str>) -> crate::setups::ordinary::BoxFuture<'a, Result<crate::setups::planning::Fetched, String>> {
            Box::pin(async { Err("The Hub can't be reached in this test.".to_owned()) })
        }

        fn components<'a>(&'a self, _: &'a yougori_setup::format::Checked) -> crate::setups::ordinary::BoxFuture<'a, Result<BTreeMap<String, yougori_setup::plan::Component>, Vec<yougori_setup::dto::Diagnostic>>> {
            Box::pin(async { Err(vec![yougori_setup::dto::Diagnostic::error("component_unavailable", "The Hub can't be reached in this test.")]) })
        }
    }

    fn host() -> yougori_setup::plan::Host {
        use yougori_setup::capability::{Arch, Gpu, Host, Os, Runtime};
        yougori_setup::plan::Host {
            yougori: "1.2.0".into(),
            platform: "windows-x86_64".into(),
            gpu: Some(true),
            memory_gb: Some(32.0),
            free_disk_gb: Some(500.0),
            capabilities: Host::new(Os::Windows, Arch::X86_64, Gpu::Nvidia, vec![Runtime::Containers, Runtime::NvidiaContainers, Runtime::LocalModels], true),
        }
    }

    fn example(name: &str) -> String {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("examples").join("hub").join(name).to_string_lossy().into_owned()
    }

    /// Plans a package from its folder with these answers, and returns the setup and its digest.
    async fn planned(service: &Service, package: &str, answers: Value) -> Result<(String, String, Value), crate::setups::model::Diagnostic> {
        let answers = answers.as_object().unwrap().iter().map(|(field, value)| json!({"field": field, "value": value})).collect::<Vec<_>>();
        let call = serde_json::from_value(json!({"source": {"kind": "local_folder", "path": example(package)}, "name": package, "answers": answers})).unwrap();
        let planned = crate::setups::planning::plan(&host(), &NoHub, service, call).await?;
        Ok((planned["setupId"].as_str().unwrap().to_owned(), planned["digest"].as_str().unwrap().to_owned(), planned))
    }

    async fn applied(service: &Service, setup: &str, digest: &str) -> String {
        let reviewed = service.reviewed(setup, digest).unwrap();
        let operation = new_id("op-");
        service.submit(&reviewed, &operation, reviewed.base_revision, BTreeMap::new()).unwrap();
        service.run(&operation).await.unwrap();
        operation
    }

    fn state_of(service: &Service, operation: &str) -> OperationState {
        service.snapshot().operations[operation].state
    }

    fn server_answers() -> Value {
        json!({"model": "hf.co/Qwen/Qwen3-0.6B-GGUF", "quantization": "Q8_0", "gpu": "optional", "memory_gb": 8})
    }

    /// A step context for one recorded resource, as the engine builds it for a later step.
    fn context(service: &Service, setup: &str, resource: &str, action: Action) -> StepContext {
        let registry = service.snapshot();
        let record = &registry.instances[setup].resources[resource];
        StepContext {
            setup: setup.into(),
            operation: "op-test".into(),
            step: resource.into(),
            resource: resource.into(),
            kind: Kind::ModelService,
            action,
            label: format!("op-test/{resource}/{}", action.as_str()),
            created_label: None,
            generation: record.generation,
            spec: record.spec.clone(),
            runtime_id: record.runtime_id.clone(),
            owner: None,
            peers: Default::default(),
            planned: Default::default(),
            cancel: Default::default(),
            secrets: Default::default(),
            started_at: None,
            recorded: Some(record.spec.clone()),
            consents: Default::default(),
        }
    }

    #[tokio::test]
    async fn the_model_server_template_makes_one_stamped_model_and_its_key_never_reaches_the_setup() {
        let bench = Bench::new();
        bench.state().cuda = true;
        let service = bench.service();
        let (setup, digest, planned) = planned(&service, "model-server", server_answers()).await.unwrap();
        let notes = planned.to_string();
        assert!(notes.contains("downloads Qwen") || notes.contains("downloads hf.co/Qwen"), "the review says the model is downloaded: {notes}");
        assert!(notes.contains("about 4.0 GB"), "with the preflight's size: {notes}");
        let operation = applied(&service, &setup, &digest).await;
        assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
        {
            let state = bench.state();
            assert_eq!(state.envs.len(), 1);
            let env = &state.envs[0];
            assert_eq!(env.model, "Qwen/Qwen3-0.6B-GGUF");
            assert_eq!(env.stamp.as_deref(), Some(format!("setup:{setup}/model/1").as_str()), "the model carries this setup's stamp");
            assert!(!env.cpu_only, "a GPU is used when this computer has one");
            assert!(env.api, "its API is turned on, on a local port");
        }
        let record = &service.snapshot().instances[&setup].resources["model"];
        assert_eq!(record.runtime_id.as_deref(), Some("env-1"));
        let saved = std::fs::read_to_string(service.store().path()).unwrap();
        assert!(!saved.contains("KEY-VALUE"), "the API key is never saved with the setup");
        let progress = serde_json::to_string(&service.operation(&operation, 0).unwrap()).unwrap();
        assert!(!progress.contains("KEY-VALUE"), "nor shown in its progress");
        assert!(!notes.contains("KEY-VALUE"), "nor in the review");
    }

    #[tokio::test]
    async fn the_model_collection_template_makes_each_model_once_and_a_third_only_when_asked() {
        let bench = Bench::new();
        let service = bench.service();
        let answers = json!({"model_one": "hf.co/Qwen/Qwen3-0.6B-GGUF", "quant_one": "Q8_0", "model_two": "hf.co/Qwen/Qwen3-1.7B-GGUF", "quant_two": "Q4_K_M", "third": "no", "gpu": "optional", "memory_gb": 8});
        let (setup, digest, planned) = planned(&service, "model-collection", answers).await.unwrap();
        assert!(planned.to_string().contains("runs on the processor"), "no GPU here: the review says so");
        let operation = applied(&service, &setup, &digest).await;
        assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
        let state = bench.state();
        assert_eq!(state.envs.len(), 2);
        assert!(state.envs.iter().all(|env| env.cpu_only), "without a GPU both run on the processor");
        assert_ne!(state.envs[0].stamp, state.envs[1].stamp, "each model has its own stamp");
    }

    #[tokio::test]
    async fn stop_start_health_and_removal_touch_only_this_setups_model_and_forget_its_vault_entries() {
        let bench = Bench::new();
        let service = bench.service();
        let mine = bench.models.add_own("Qwen/Qwen3-0.6B-GGUF");
        let (setup, digest, _) = planned(&service, "model-server", server_answers()).await.unwrap();
        applied(&service, &setup, &digest).await;
        let local = LocalModels::new(bench.models.clone());

        let stop = context(&service, &setup, "model", Action::Stop);
        assert_eq!(local.stop(&stop).await.unwrap().observed, Observed::Stopped);
        assert_eq!(local.health(&stop).await.unwrap().health, Health::Degraded);
        let start = context(&service, &setup, "model", Action::Start);
        assert_eq!(local.apply(&start).await.unwrap().observed, Observed::Running);
        bench.state().health = Some(json!({"status": "downloading", "download": {"receivedBytes": 1073741824u64, "totalBytes": 4294967296u64}}));
        let health = local.health(&start).await.unwrap();
        assert_eq!((health.health, health.detail.as_str()), (Health::Starting, "Downloading the model: 1.0 of 4.0 GB."));
        bench.state().health = None;
        assert_eq!(local.health(&start).await.unwrap().health, Health::Ready);

        let remove = service.plan(PlanIntent::Remove { setup: setup.clone() }).unwrap();
        assert!(remove.notes.iter().any(|note| note.contains("deletes its model sandbox and the model files")), "{:?}", remove.notes);
        let operation = new_id("op-");
        service.apply(&remove, &operation, BTreeMap::new()).await.unwrap();
        assert_eq!(state_of(&service, &operation), OperationState::Completed);
        let state = bench.state();
        assert_eq!(state.envs.iter().map(|env| env.id.as_str()).collect::<Vec<_>>(), vec![mine.as_str()], "the model the person ran is untouched");
        assert_eq!(state.vault.iter().cloned().collect::<Vec<_>>(), vec!["model-api-mine-1".to_owned()], "the removed model's own vault entries are forgotten, and only those");
    }

    #[tokio::test]
    async fn a_model_the_person_made_is_never_adopted_stopped_or_deleted() {
        let bench = Bench::new();
        let service = bench.service();
        let (setup, digest, _) = planned(&service, "model-server", server_answers()).await.unwrap();
        applied(&service, &setup, &digest).await;
        // The recorded sandbox is replaced outside Yougori by one the person made, under the same ID.
        {
            let mut state = bench.state();
            let env = &mut state.envs[0];
            env.stamp = None;
        }
        let local = LocalModels::new(bench.models.clone());
        let stop = context(&service, &setup, "model", Action::Stop);
        assert_eq!(local.stop(&stop).await.unwrap_err().code, "resource_missing", "a sandbox without this setup's stamp isn't this setup's");
        let removed = local.remove(&context(&service, &setup, "model", Action::Remove)).await.unwrap();
        assert_eq!(removed.observed, Observed::Missing);
        let state = bench.state();
        assert_eq!(state.envs.len(), 1, "it is left where it is");
        assert!(!state.calls.iter().any(|call| call == "stop_model" || call == "delete_environment"));
    }

    #[tokio::test]
    async fn a_crash_mid_create_is_settled_by_the_stamp_without_a_second_model() {
        let bench = Bench::new();
        let service = bench.service();
        bench.state().lose_answer = true;
        let (setup, digest, _) = planned(&service, "model-server", server_answers()).await.unwrap();
        let operation = applied(&service, &setup, &digest).await;
        assert_eq!(state_of(&service, &operation), OperationState::Unknown, "a lost answer is an unknown outcome");
        // A restarted engine looks rather than acting again.
        let restarted = bench.service();
        restarted.reconcile_all().await;
        assert_eq!(state_of(&restarted, &operation), OperationState::Completed, "{:?}", restarted.snapshot().operations[&operation].events);
        let state = bench.state();
        assert_eq!(state.envs.len(), 1, "never made twice");
        assert_eq!(state.calls.iter().filter(|call| *call == "run_model").count(), 1, "recovery made and started nothing");
        drop(state);
        assert_eq!(restarted.snapshot().instances[&setup].resources["model"].runtime_id.as_deref(), Some("env-1"));
    }

    #[tokio::test]
    async fn a_sandbox_made_but_not_started_is_this_steps_and_is_settled_by_looking() {
        let bench = Bench::new();
        let service = bench.service();
        bench.state().fail_start = Some("The GPU runtime is busy".into());
        let (setup, digest, _) = planned(&service, "model-server", server_answers()).await.unwrap();
        let operation = applied(&service, &setup, &digest).await;
        assert_eq!(state_of(&service, &operation), OperationState::Unknown);
        let error = service.snapshot().operations[&operation].steps[0].error.clone().unwrap();
        assert!(error.message.contains("was made, but the runner then said"), "{}", error.message);
        service.reconcile_all().await;
        assert_eq!(state_of(&service, &operation), OperationState::Completed);
        assert_eq!(bench.state().envs.len(), 1);
    }

    #[tokio::test]
    async fn a_refusal_leaves_nothing_and_the_runners_exact_words_reach_the_person() {
        let bench = Bench::new();
        let service = bench.service();
        bench.state().refuse = Some("This model needs approximately 71 GB of persistent storage for its weights and runtime. No environment was created.".into());
        let (setup, digest, _) = planned(&service, "model-server", server_answers()).await.unwrap();
        let operation = applied(&service, &setup, &digest).await;
        assert_eq!(state_of(&service, &operation), OperationState::Failed);
        let error = service.snapshot().operations[&operation].error.clone().unwrap();
        assert!(error.message.contains("approximately 71 GB"), "{}", error.message);
        assert!(bench.state().envs.is_empty());
    }

    #[tokio::test]
    async fn the_review_refuses_a_gpu_only_model_without_a_gpu_and_a_processor_model_without_gguf() {
        let bench = Bench::new();
        let service = bench.service();
        let mut answers = server_answers();
        answers["gpu"] = json!("required");
        let refused = planned(&service, "model-server", answers).await.unwrap_err();
        assert_eq!(refused.code, "unsupported_here");
        assert!(refused.message.contains("only on an NVIDIA GPU"), "{}", refused.message);

        bench.state().preflight.insert("example/safetensors-only".into(), json!({"supported": true, "runner": "yougori-transformers-chat", "format": "safetensors", "resources": {"weightsBytes": 1e9}}));
        let answers = json!({"model": "hf.co/example/safetensors-only", "gpu": "none", "memory_gb": 8});
        let refused = planned(&service, "model-server", answers).await.unwrap_err();
        assert!(refused.message.contains("needs a GGUF model"), "{}", refused.message);

        bench.state().preflight.insert("example/unsupported".into(), json!({"supported": false, "reason": "The pinned Transformers architecture catalog does not support this model type with built-in causal generation"}));
        let answers = json!({"model": "hf.co/example/unsupported", "gpu": "optional", "memory_gb": 8});
        let refused = planned(&service, "model-server", answers).await.unwrap_err();
        assert!(refused.message.contains("can't run with Yougori's model runner"), "{}", refused.message);
        assert!(bench.state().envs.is_empty() && !bench.state().calls.iter().any(|call| call == "run_model"), "nothing was run");
    }

    #[tokio::test]
    async fn a_large_download_is_named_plainly_in_the_review() {
        let bench = Bench::new();
        bench.state().cuda = true;
        bench.state().preflight.insert("example/big-GGUF".into(), gguf(46.0));
        let service = bench.service();
        let answers = json!({"model": "hf.co/example/big-GGUF", "gpu": "optional", "memory_gb": 64});
        let (_, _, planned) = planned(&service, "model-server", answers).await.unwrap();
        let text = planned.to_string();
        assert!(text.contains("about 46.0 GB") && text.contains("That is a large download"), "{text}");
    }

    #[tokio::test]
    async fn a_model_cant_be_changed_in_place_and_says_what_to_do() {
        let bench = Bench::new();
        let service = bench.service();
        let (setup, digest, _) = planned(&service, "model-server", server_answers()).await.unwrap();
        applied(&service, &setup, &digest).await;
        let record = service.snapshot().instances[&setup].resources["model"].clone();
        let mut spec = record.spec.clone();
        spec["memory_gb"] = json!(12.0);
        let instance = service.snapshot().instances[&setup].clone();
        let change = crate::setups::model::InstanceChange {
            name: instance.name,
            source: instance.source,
            format_version: instance.format_version,
            protocol_version: instance.protocol_version,
            lock_digest: instance.lock_digest,
            lock: instance.lock,
            answers: instance.answers,
            capabilities: instance.capabilities,
            secret_bindings: instance.secret_bindings,
        };
        let draft = crate::setups::service::SetupDraft {
            change,
            resources: vec![DeclaredResource { id: "model".into(), kind: Kind::ModelService, spec, requires: Vec::new(), owner: None }],
        };
        let refused = service.plan(PlanIntent::Update { setup: setup.clone(), draft }).unwrap_err();
        assert_eq!(refused.code, "unsupported_here");
        assert!(refused.message.contains("can't be changed in place"), "{}", refused.message);
    }

    /// AI Team's shape: a team on a Neo Grid pool another setup runs. It is not a model on this
    /// computer, so it must never reach the local handler, and it is refused at review.
    #[test]
    fn a_team_on_another_setups_grid_is_refused_at_review_and_never_run_here() {
        let models: Arc<FakeModels> = Default::default();
        let handlers = crate::setups::grids::Grids::new(models.clone()).handlers();
        let handler = handlers.iter().find(|handler| handler.kind() == Kind::ModelService).unwrap();
        // As the planner leaves it once the chosen pool became a borrowed resource: the pool is
        // not among the setup's own declared resources.
        let team = json!({"model": "swarm/research", "compute": {"resource": "neo_computers"},
            "team": {"strategy": "plan", "lead": {"resource": "lead_model"}, "workers": [{"resource": "worker_model"}], "computers": 4}});
        assert!(handler.validate(&team).is_ok(), "a team is a valid model service; the grid decides where it runs");
        let refused = handler.review("team", &team, &BTreeMap::new()).unwrap_err();
        assert_eq!(refused.code, "unsupported_here");
        assert!(refused.message.contains("pool of a Neo Grid this setup makes"), "{}", refused.message);
        // A team with no pool at all is refused by the local handler, which never runs one.
        let alone = json!({"model": "swarm/research", "team": {"strategy": "plan", "lead": {"resource": "a"}}});
        let refused = handler.validate(&alone).unwrap_err();
        assert!(refused.message.contains("A team of models runs on a Neo Grid"), "{}", refused.message);
        assert!(models.state.lock().unwrap().calls.is_empty(), "nothing was asked of the model runner");
    }

    #[test]
    fn specs_a_model_on_this_computer_cant_honour_are_refused_plainly() {
        let local = LocalModels::new(Arc::new(FakeModels::default()));
        let base = json!({"model": "hf.co/a/b", "gpu": "optional", "api": {"protocol": "openai", "keys": 0}});
        for (field, value, words) in [
            ("replicas", json!(2), "runs once"),
            ("network", json!({"listing": "free"}), "Yougori Network"),
            ("api", json!({"keys": 2}), "one API key"),
            ("revision", json!("main"), "revision"),
            ("backend", json!("vllm"), "picks the format"),
            ("share_percent", json!(50), "Neo Grid"),
            ("secrets", json!({"HF_TOKEN": "apply.token"}), "no secrets"),
            ("memory_gb", json!(2), "at least 4 GB"),
        ] {
            let mut spec = base.clone();
            spec[field] = value;
            let refused = local.validate(&spec).unwrap_err();
            assert!(refused.message.contains(words), "{field}: {}", refused.message);
        }
        assert!(local.validate(&base).is_ok());
    }
}
