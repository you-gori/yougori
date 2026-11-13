use super::*;
use std::time::Duration;
use yougori_cli::workload::Options;
mod status_batch;
mod control;
mod wake;
mod events;
mod configuration;
mod capacity;

/// How often, and past what age, the scheduler sweeps served helper directories no environment
/// binds (G08).
const SERVED_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(600);

/// The local GPU's total memory as the host probe reads it, for a measurement's host
/// description (the helper trial); `None` when the probe does not answer.
pub(crate) async fn local_gpu_total_bytes() -> Option<u64> {
    capacity::local_gpu_total().await
}
mod runtime_binding;
#[cfg(test)]
mod protocol_integration;
/// The exact runner releases this engine pins, for the helper rollout journal (G08).
pub(super) use runtime_binding::{pinned_release, pinned_transformers_release};

static WAKE: std::sync::LazyLock<wake::Wake> = std::sync::LazyLock::new(wake::Wake::new);
// User configuration can start an unmanaged loader when automatic memory is
// disabled. It must not interleave between another runner's unload and grant.
static ADMISSION: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Serializes a local CUDA stop/delete with grants and captures the exact reservation.
/// Confirmation is explicit: pause, failed operations and dropped futures release nothing.
pub(crate) struct RuntimeEnd {
    _admission: tokio::sync::MutexGuard<'static, ()>,
    receipt: Option<capacity::EndReceipt>,
}

impl RuntimeEnd {
    pub(crate) async fn capture(environment: &str) -> Result<Self, String> {
        let guard = tokio::time::timeout(control::TIMEOUT, ADMISSION.lock()).await
            .map_err(|_| "GPU admission is busy. No runtime end was sent; retry after the current operation finishes.")?;
        Ok(Self { _admission: guard, receipt: capacity::capture_end(environment)? })
    }

    /// Call only after the runtime acknowledged stopping/removing the container.
    pub(crate) fn confirm(&mut self) {
        capacity::confirm_end(self.receipt.take());
        WAKE.notify();
    }
}

pub(super) fn stamp_capacity(environment: &mut Value, compatibility: &Value) -> Result<(), String> {
    capacity::stamp(environment, compatibility)
}

/// Stamps a new Transformers chat workload for host-ledger admission when the demand that
/// covers its context at original precision fits this host's one GPU
/// (`local-single-transformers-v1`, G03: `capacity::ContextDemand`), and a GGUF workload with
/// the demand its header gives (`local-single-llama-cpp-v1`); otherwise it keeps the legacy
/// scheduler. Says whether it stamped.
pub(super) async fn stamp_local_capacity(environment: &mut Value, compatibility: &Value) -> bool {
    capacity::local_stamp(environment, compatibility).await
}

/// The admission profile and demand host admission reserves for a model, read from its saved
/// workload (`model_status` → `admission`); `None` for the one-resident legacy path. The runner
/// reports a grant itself only for the profile it enforces (Transformers).
pub(super) fn admission(options: &std::collections::BTreeMap<String, String>) -> Option<Value> {
    capacity::demand(options).ok().flatten().map(capacity::Demand::describe)
}

pub(super) fn shared_host_ledger() -> Option<crate::foundation::coordination::SharedLedger<crate::foundation::ids::SystemClock>> {
    capacity::shared_host_ledger()
}

pub(super) fn ledger_view() -> Value {
    capacity::ledger_view()
}

/// The GPU memory in use as the host probe reads it now: a helper trial's measure for runners
/// that report no allocator peak (vLLM, llama.cpp).
pub(crate) async fn host_gpu_used() -> Option<u64> {
    capacity::local_used(&tokio_util::sync::CancellationToken::new()).await
}

pub(super) async fn refresh_host_capacity(shutdown: &tokio_util::sync::CancellationToken) -> Result<crate::foundation::coordination::SharedLedger<crate::foundation::ids::SystemClock>, String> {
    capacity::refresh_host_capacity(shutdown).await
}
pub(super) async fn refresh_gpu_capacity(shutdown: &tokio_util::sync::CancellationToken) -> Result<crate::foundation::coordination::SharedLedger<crate::foundation::ids::SystemClock>, String> {
    capacity::refresh_gpu_capacity(shutdown).await
}

pub(super) fn request_completed(path: &str, posted: bool, succeeded: bool) {
    WAKE.request_completed(path, posted, succeeded);
}

pub(super) fn source() -> String {
    let mut packed = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    std::io::Write::write_all(&mut packed, include_bytes!("gpu_optimizer.py")).expect("GPU helper");
    STANDARD.encode(packed.finish().expect("GPU helper compression"))
}

pub(super) fn environment(environment: &mut Value, protected: &mut Value) -> Result<(), String> {
    super::carry_server(environment);
    let reference = format!("gpu-control-{}", uuid::Uuid::new_v4().simple());
    crate::projects::secrets::store(&reference, &uuid::Uuid::new_v4().simple().to_string())?;
    environment["YOUGORI_GPU_SOURCE"] = json!(source());
    environment["YOUGORI_GPU_OPTIMIZER"] = json!("1");
    protected["YOUGORI_GPU_CONTROL_TOKEN"] = json!(reference);
    Ok(())
}

pub(super) fn refresh_options(options: &mut Options) -> Result<(), String> {
    carry_sources(options);
    // A GGUF model's reservation follows the context window this start allocates.
    capacity::reprice_llama_cpp(&mut options.environment, true);
    if options.environment.get("YOUGORI_MODEL_CPU").is_some_and(|v|v == "1") {
        options.environment.insert("YOUGORI_GPU_OPTIMIZER".into(),"0".into());
        return Ok(());
    }
    if options.environment.get("YOUGORI_MODEL_FORMAT").is_some_and(|v| v == "source") { return Ok(()); }
    options.environment.entry("YOUGORI_GPU_OPTIMIZER".into()).or_insert("1".into());
    if !options.secret_environment.contains_key("YOUGORI_GPU_CONTROL_TOKEN") {
        let reference = format!("gpu-control-{}", uuid::Uuid::new_v4().simple());
        crate::projects::secrets::store(&reference, &uuid::Uuid::new_v4().simple().to_string())?;
        options.secret_environment.insert("YOUGORI_GPU_CONTROL_TOKEN".into(), reference);
    }
    Ok(())
}

/// The sources a runner of this model's format and launch reads, put into its options: the model
/// server, the engine backends, the megakernel host, the media backends and the GPU optimizer, each
/// only where the runner reads it. None of them is a secret, so this stores nothing in the vault.
pub(super) fn carry_sources(options: &mut Options) {
    options.environment.insert("YOUGORI_MODEL_SERVER_SOURCE".into(),super::server_payload());
    // The engine backends travel with the server that checks them, for GGUF and vLLM runners only.
    if super::loads_backends(options.environment.get("YOUGORI_MODEL_FORMAT").map(String::as_str)) {
        options.environment.insert("YOUGORI_BACKENDS_SOURCE".into(), super::backends_source());
    } else {
        options.environment.remove("YOUGORI_BACKENDS_SOURCE");
    }
    // The megakernel host travels with the backends that can start it, for vLLM runners only.
    if super::carries_megakernel(options.environment.get("YOUGORI_MODEL_FORMAT").map(String::as_str), options.environment.get("YOUGORI_MODEL_LAUNCH").map(String::as_str)) {
        options.environment.insert("YOUGORI_MEGAKERNEL_SOURCE".into(), super::megakernel_source());
    } else {
        options.environment.remove("YOUGORI_MEGAKERNEL_SOURCE");
    }
    // The media backends travel with media runners only.
    if super::carries_media(options.environment.get("YOUGORI_MODEL_FORMAT").map(String::as_str)) {
        options.environment.insert("YOUGORI_MEDIA_SOURCE".into(), super::media_source());
    } else {
        options.environment.remove("YOUGORI_MEDIA_SOURCE");
    }
    options.environment.insert("YOUGORI_GPU_SOURCE".into(),source());
}

#[tauri::command]
pub async fn model_optimizer(environment_id: String, enabled: Option<bool>, pinned: Option<bool>, idle_timeout_seconds: Option<u64>, parallel: Option<u64>, context: Option<u64>, launch: Option<String>, runner: Option<String>, keep_outputs_hours: Option<u64>, app: AppHandle) -> Result<Value, String> {
    let live = enabled.is_some() || pinned.is_some() || idle_timeout_seconds.is_some();
    if let Some(refusal) = alone_refusal(live, parallel.is_some() || context.is_some(), launch.is_some() || runner.is_some(), keep_outputs_hours.is_some()) {
        return Err(refusal.into());
    }
    if let Some(hours) = keep_outputs_hours {
        // A media model's output retention: saved for its next start and applied now when it runs.
        return save_keep_hours(&app, &environment_id, hours).await;
    }
    if (enabled.is_some() || pinned.is_some() || idle_timeout_seconds.is_some() || parallel.is_some()) && model_format(&app, &environment_id)?.as_deref() == Some("media") {
        return Err("A media model stays loaded while it runs and generates one job at a time; stop it to free the GPU. Its setting is --keep-outputs HOURS, how long finished jobs' files are kept.".into());
    }
    if launch.is_some() || runner.is_some() {
        // Saved on its own and applied at the next start; nothing is sent to the runner. A
        // runner given alone means the megakernel launch with it.
        let mode = launch.unwrap_or_else(|| "megakernel".into());
        let _admission = tokio::time::timeout(control::TIMEOUT, ADMISSION.lock()).await
            .map_err(|_| "GPU settings are busy. No changes were sent; retry after the current operation finishes.")?;
        let saved = save_launch(&app, &environment_id, &mode, runner.as_deref())?;
        let mut result = json!({"launch": mode, "restartRequired": true});
        if let Some(reference) = saved { result["runner"] = json!(reference); }
        return Ok(result);
    }
    let _admission = if enabled.is_some() || pinned.is_some() || idle_timeout_seconds.is_some() || parallel.is_some() || context.is_some() {
        Some(tokio::time::timeout(control::TIMEOUT, ADMISSION.lock()).await
            .map_err(|_| "GPU settings are busy. No changes were sent; retry after the current operation finishes.")?)
    } else { None };
    // Checked before anything is saved, so a refused value leaves every setting as it was.
    if idle_timeout_seconds.is_some_and(|timeout| timeout != 0 && !(10..=3600).contains(&timeout)) {
        return Err("Idle timeout must be 0 (keep loaded until switching) or 10–3600 seconds".into());
    }
    if let Some(slots) = parallel {
        check_parallel(&app, &environment_id, slots)?;
    }
    if let Some(tokens) = context {
        check_context(&app, &environment_id, tokens).await?;
    }
    // Start settings alone are saved now; with other settings, with them once the runner acknowledged.
    if (parallel.is_some() || context.is_some()) && enabled.is_none() && pinned.is_none() && idle_timeout_seconds.is_none() {
        save_start_settings(&app, &environment_id, parallel, context)?;
        return Ok(start_answer(json!({}), parallel, context));
    }
    let health = super::model_status(environment_id.clone(), app.clone()).await?;
    if enabled.is_none() && pinned.is_none() && idle_timeout_seconds.is_none() { return Ok(health["optimizer"].clone()); }
    if health["optimizer"]["supported"] != true { return Err("Restart this model with the updated engine to enable Automatic GPU memory. Files are kept.".into()); }
    let timeout = idle_timeout_seconds.unwrap_or(health["optimizer"]["idleTimeoutSeconds"].as_u64().unwrap_or(0));
    if timeout != 0 && !(10..=3600).contains(&timeout) { return Err("Idle timeout must be 0 (keep loaded until switching) or 10–3600 seconds".into()); }
    let on = enabled.unwrap_or(health["optimizer"]["enabled"] == true);
    let pin = pinned.unwrap_or(health["optimizer"]["pinned"] == true);
    let pending = configuration::record(&health)?;
    let body = control::fence_configuration(&health, json!({"action":"configure","enabled":on,"pinned":pin,"idleTimeoutSeconds":timeout}))
        .map_err(|_| "Restart this model with the updated engine before changing GPU settings. Model files are kept.")?;
    let runtime = app.state::<RuntimeManager>();
    let state = app.state::<PlatformStore>().snapshot()?;
    let env = state.environments.iter().find(|e| e.id == environment_id).ok_or("Model not found")?;
    let id = env.runtime_id.as_deref().unwrap_or(&environment_id);
    let mut options = runtime.workload_options(id)?;
    if !on && options.environment.contains_key(capacity::POLICY) {
        return Err("This model uses shared GPU admission and cannot bypass its reservations. Keep Automatic GPU memory on; pin it to prevent automatic switching.".into());
    }
    if options.environment.get(configuration::PENDING).is_some_and(|prior| !configuration::can_replace(prior, &health)) {
        return Err("Previous GPU configuration cannot be safely reconciled. Stop and recreate this model environment before changing its settings.".into());
    }
    // Durable before send: cancellation or an engine restart cannot forget that
    // an old remote command might still acquire the runner lock and execute.
    options.environment.insert(configuration::PENDING.into(), pending.clone());
    runtime.save_workload_options(id, &options)?;
    WAKE.notify();
    let answer = tokio::time::timeout(control::TIMEOUT,
        model_request(&app, &environment_id, "/v1/yougori/optimizer", Some(body)))
        .await.map_err(|_| "GPU configuration outcome is unconfirmed. Admission is paused until it can be reconciled.")?
        .map_err(|_| "GPU configuration outcome is unconfirmed. Admission is paused until it can be reconciled.")?;
    if !control::configuration_acknowledged(&health, &answer) {
        return Err("GPU configuration outcome is unconfirmed. Admission is paused until it can be reconciled.".into());
    }
    let mut options = runtime.workload_options(id)?;
    if options.environment.get(configuration::PENDING) != Some(&pending) {
        return Err("GPU configuration changed while saving its result. Check model status before retrying.".into());
    }
    options.environment.remove(configuration::PENDING);
    options.environment.insert("YOUGORI_GPU_OPTIMIZER".into(), if on {"1"} else {"0"}.into());
    options.environment.insert("YOUGORI_GPU_PINNED".into(), if pin {"1"} else {"0"}.into());
    options.environment.insert("YOUGORI_GPU_IDLE_SECONDS".into(), timeout.to_string());
    start_settings(&mut options, parallel, context);
    // The runner read these when it started; a restart carries the new ones into its container.
    super::mark_for_start(&mut options);
    runtime.save_workload_options(id, &options)?;
    WAKE.notify();
    Ok(start_answer(answer["optimizer"].clone(), parallel, context))
}

/// Settings changed on their own, refused before anything is read or saved: a media model's
/// output retention, then the launch mode with its runner. `live` names a setting the runner
/// applies now (on, off, pin, idle), `start` one it reads at its next start (parallel requests,
/// the context window), which go together.
fn alone_refusal(live: bool, start: bool, launch: bool, keep_outputs: bool) -> Option<&'static str> {
    if keep_outputs && (live || start || launch) {
        return Some("Change the output retention on its own, then the other settings.");
    }
    if launch && (live || start) {
        return Some("Change the launch mode on its own, then the other settings.");
    }
    None
}

/// The settings a runner reads when it starts, put into its options: parallel requests and the
/// context window ([`MODEL_CONTEXT`]).
fn start_settings(options: &mut Options, parallel: Option<u64>, context: Option<u64>) {
    if let Some(slots) = parallel {
        options.environment.insert("YOUGORI_MODEL_PARALLEL".into(), slots.to_string());
    }
    if let Some(tokens) = context {
        options.environment.insert(MODEL_CONTEXT.into(), tokens.to_string());
        capacity::reprice_llama_cpp(&mut options.environment, false);
    }
}

/// An answer with the start settings saved beside it, which apply at the next start.
fn start_answer(mut result: Value, parallel: Option<u64>, context: Option<u64>) -> Value {
    if let Some(fields) = result.as_object_mut().filter(|_| parallel.is_some() || context.is_some()) {
        if let Some(slots) = parallel { fields.insert("parallel".into(), json!(slots)); }
        if let Some(tokens) = context { fields.insert("context".into(), json!(tokens)); }
        fields.insert("restartRequired".into(), json!(true));
    }
    result
}

/// The format of a model environment's runner, as its workload says (`YOUGORI_MODEL_FORMAT`).
fn model_format(app: &AppHandle, environment_id: &str) -> Result<Option<String>, String> {
    let state = app.state::<PlatformStore>().snapshot()?;
    let env = state.environments.iter().find(|e| e.id == environment_id).ok_or("Model not found")?;
    let options = app.state::<RuntimeManager>().workload_options(env.runtime_id.as_deref().unwrap_or(environment_id))?;
    Ok(options.environment.get("YOUGORI_MODEL_FORMAT").cloned())
}

/// How long a media model keeps a finished job's files (`YOUGORI_MEDIA_KEEP_HOURS`, 1-720,
/// read by media_backends.py when the runner starts): saved for the next start, and applied to
/// the running model through its owner route, which also moves the expiry of what it keeps.
async fn save_keep_hours(app: &AppHandle, environment_id: &str, hours: u64) -> Result<Value, String> {
    if !(1..=720).contains(&hours) { return Err("Outputs are kept 1–720 hours".into()); }
    let state = app.state::<PlatformStore>().snapshot()?;
    let env = state.environments.iter().find(|e| e.id == environment_id).ok_or("Model not found")?;
    let id = env.runtime_id.clone().unwrap_or_else(|| environment_id.to_owned());
    let runtime = app.state::<RuntimeManager>();
    let mut options = runtime.workload_options(&id)?;
    if options.environment.get("YOUGORI_MODEL_FORMAT").map(String::as_str) != Some("media") {
        return Err("Only a media model keeps job outputs; this model answers chat.".into());
    }
    options.environment.insert("YOUGORI_MEDIA_KEEP_HOURS".into(), hours.to_string());
    super::mark_for_start(&mut options);
    runtime.save_workload_options(&id, &options)?;
    let applied = if env.status == EnvironmentStatus::Running {
        super::model_request(app, environment_id, "/v1/yougori/media", Some(json!({"action": "configure", "keepHours": hours}))).await.is_ok()
    } else { false };
    Ok(json!({"keepOutputsHours": hours, "applied": applied, "restartRequired": !applied}))
}

/// How many requests a GGUF (llama.cpp slots sharing one KV pool) or vLLM model generates
/// together (G02, `YOUGORI_MODEL_PARALLEL`) and a GGUF model's context window
/// ([`MODEL_CONTEXT`]): the runner reads them when it starts, so a saved change takes effect at
/// the next start. Other runners generate one request at a time and size their own context.
fn save_start_settings(app: &AppHandle, environment_id: &str, parallel: Option<u64>, context: Option<u64>) -> Result<(), String> {
    let (_, id, mut options) = model_workload(app, environment_id)?;
    start_settings(&mut options, parallel, context);
    super::mark_for_start(&mut options);
    app.state::<RuntimeManager>().save_workload_options(&id, &options)
}

/// A model environment's kind, the id its workload is saved under and its options as they are.
fn model_workload(app: &AppHandle, environment_id: &str) -> Result<(EnvironmentKind, String, Options), String> {
    let state = app.state::<PlatformStore>().snapshot()?;
    let env = state.environments.iter().find(|e| e.id == environment_id).ok_or("Model not found")?;
    let id = env.runtime_id.clone().unwrap_or_else(|| environment_id.to_owned());
    let options = app.state::<RuntimeManager>().workload_options(&id)?;
    Ok((env.kind.clone(), id, options))
}

/// The context window, in tokens, a GGUF runner's llama.cpp allocates (`-c`): engine_backends.py
/// reads it when the runner starts (32,768 without it) and never goes past the model's own
/// longest context (`context_length` in its GGUF header); `model status` reports the window that
/// serves as `context`. Agents' first requests run near 30,000 tokens, past the default.
const MODEL_CONTEXT: &str = "YOUGORI_MODEL_CONTEXT";

/// Refuses a context window this model cannot take, before anything is saved: out of range, a
/// runner that sizes its own, or, under the llama.cpp admission profile, a window whose
/// reservation this GPU cannot hold.
async fn check_context(app: &AppHandle, environment_id: &str, tokens: u64) -> Result<(), String> {
    let (kind, _, options) = model_workload(app, environment_id)?;
    if let Some(refusal) = context_refusal(&kind, &options.environment, tokens) {
        return Err(refusal.into());
    }
    match (capacity::llama_cpp_demand_at(&options.environment, tokens)?, capacity::local_gpu_total().await) {
        (Some(bytes), Some(total)) => capacity::llama_cpp_fits(bytes, total),
        _ => Ok(()),
    }
}

/// Why a model takes no context window of `tokens` from this engine, if it takes none: out of
/// range, a cloud server's runner and the native host service keep their own settings, and only
/// llama.cpp allocates the window the owner chooses. vLLM fits its context to the GPU at start
/// (its audited launch caps it at 32,768, `model_memory::profiles::audit`); the Transformers
/// runner serves what its checkpoint and GPU grant cover.
fn context_refusal(kind: &EnvironmentKind, environment: &std::collections::BTreeMap<String, String>, tokens: u64) -> Option<&'static str> {
    if !(4096..=262_144).contains(&tokens) || tokens % 1024 != 0 {
        return Some("The context window must be 4,096–262,144 tokens in steps of 1,024, for example 65536 or 131072.");
    }
    if *kind == EnvironmentKind::Cloud {
        return Some("A model on a cloud server serves with that server's own settings; set its context window where it runs.");
    }
    if environment.contains_key("YOUGORI_NATIVE_BACKEND") {
        return Some("The native host model service keeps its own 32,768-token context window; the setting applies to GGUF runners in containers.");
    }
    match environment.get("YOUGORI_MODEL_FORMAT").map(String::as_str) {
        Some("gguf") => None,
        Some("media") => Some("A media model has no context window; its setting is --keep-outputs HOURS."),
        Some("vllm") => Some("A vLLM model fits its context window to the GPU when it starts, at most 32,768 tokens; the context window setting applies to GGUF models."),
        _ => Some("Only GGUF models take a context window setting; this model's runner sizes its own (model status shows it as context)."),
    }
}

/// How a vLLM model runs (`YOUGORI_MODEL_LAUNCH`, read by engine_backends.py when the runner
/// starts): "compiled" captures CUDA graphs and compiles the model with torch.compile,
/// "speculative" (the default) adds n-gram speculative decoding, and "eager" runs it as launches
/// did before 6 November 2026. A launch that fails to start steps down by itself: speculative to
/// compiled, then to eager. "megakernel" serves the same checkpoint with the owner's own runner
/// (`YOUGORI_MODEL_RUNNER`: a folder of theirs bound read-only at [`RUNNER_TARGET`], or a public
/// Hugging Face repository `hf:OWNER/REPO@COMMIT`), and falls back to vLLM when the runner
/// cannot serve (health says why).
const LAUNCHES: [&str; 4] = ["compiled", "speculative", "eager", "megakernel"];

/// Where a runner folder is bound in the model's container (engine_backends.py reads the
/// reference from `YOUGORI_MODEL_RUNNER`).
pub(crate) const RUNNER_TARGET: &str = "/yougori-runner";

/// Saves the launch mode, and the runner when one is given; returns the saved runner reference.
fn save_launch(app: &AppHandle, environment_id: &str, mode: &str, runner: Option<&str>) -> Result<Option<String>, String> {
    if !LAUNCHES.contains(&mode) {
        return Err("The launch mode must be compiled, speculative, eager or megakernel".into());
    }
    let state = app.state::<PlatformStore>().snapshot()?;
    let env = state.environments.iter().find(|e| e.id == environment_id).ok_or("Model not found")?;
    let id = env.runtime_id.clone().unwrap_or_else(|| environment_id.to_owned());
    let runtime = app.state::<RuntimeManager>();
    let mut options = runtime.workload_options(&id)?;
    if let Some(refusal) = launch_refusal(&env.kind, &options.environment, mode) {
        return Err(refusal.into());
    }
    let reference = match runner.map(str::trim).filter(|reference| !reference.is_empty()) {
        Some(reference) => Some(runner_reference(reference, env.kind == EnvironmentKind::Cloud)?),
        None => None,
    };
    if mode == "megakernel" && reference.is_none() && !options.environment.contains_key("YOUGORI_MODEL_RUNNER") {
        return Err("A megakernel launch needs its runner: --runner FOLDER (a folder with runner.json) or --runner hf:OWNER/REPO@COMMIT".into());
    }
    let saved = reference.as_ref().map(|reference| apply_runner(&mut options, reference));
    options.environment.insert("YOUGORI_MODEL_LAUNCH".into(), mode.into());
    super::mark_for_start(&mut options);
    runtime.save_workload_options(&id, &options)?;
    Ok(saved)
}

/// A runner reference as the owner gives it.
#[derive(Debug, PartialEq, Eq)]
enum RunnerReference {
    /// A folder on this computer holding runner.json, bound into the container.
    Folder(String),
    /// `hf:OWNER/REPO@COMMIT`, which the host downloads; the only kind a cloud pod takes.
    Hub(String),
}

fn runner_reference(reference: &str, cloud: bool) -> Result<RunnerReference, String> {
    if let Some(rest) = reference.strip_prefix("hf:") {
        let part = |name: &str| !name.is_empty() && name.len() <= 96 && !name.starts_with('.') && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
        let pinned = rest.split_once('@').filter(|(repo, commit)| {
            repo.split_once('/').is_some_and(|(owner, name)| part(owner) && part(name))
                && commit.len() == 40 && commit.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
        });
        return match pinned {
            Some((repo, commit)) => Ok(RunnerReference::Hub(format!("hf:{repo}@{commit}"))),
            None => Err("A Hugging Face runner reads hf:OWNER/REPO@COMMIT, the commit as its 40 hex characters".into()),
        };
    }
    if cloud {
        return Err("A model on a Neocloud pod takes its runner from Hugging Face: --runner hf:OWNER/REPO@COMMIT".into());
    }
    let folder = std::fs::canonicalize(reference).map_err(|_| format!("The runner folder {reference} does not exist"))?;
    if !folder.join("runner.json").is_file() {
        return Err(format!("The runner folder {} has no runner.json", folder.display()));
    }
    let folder = folder.to_string_lossy().trim_start_matches(r"\\?\").to_owned();
    Ok(RunnerReference::Folder(folder))
}

/// Puts the runner into the model's options: a folder as the one bind at [`RUNNER_TARGET`] (an
/// earlier runner's bind goes), a repository as the reference itself. Returns what was saved.
fn apply_runner(options: &mut Options, reference: &RunnerReference) -> String {
    options.binds.retain(|bind| bind.target != RUNNER_TARGET);
    let saved = match reference {
        RunnerReference::Folder(folder) => {
            options.binds.push(yougori_cli::workload::Volume { source: folder.clone(), target: RUNNER_TARGET.into(), read_only: true });
            options.environment.insert("YOUGORI_MODEL_RUNNER".into(), RUNNER_TARGET.into());
            folder.clone()
        }
        RunnerReference::Hub(reference) => {
            options.environment.insert("YOUGORI_MODEL_RUNNER".into(), reference.clone());
            reference.clone()
        }
    };
    saved
}

/// Why a model takes no launch mode from this engine, or not `mode`, if it does not: only vLLM
/// runners have one, in this engine's containers and on Neocloud pods (whose next start carries it).
/// A model run from a folder takes no megakernel launch: its start would carry the registry
/// verifier and the megakernel host beside the model server and backends, more than the CUDA
/// runtime's agent reads in one request (128 KiB), so the start would keep the server it had.
pub(super) fn launch_refusal(kind: &EnvironmentKind, environment: &std::collections::BTreeMap<String, String>, mode: &str) -> Option<&'static str> {
    let _ = kind;
    if !environment.get("YOUGORI_MODEL_FORMAT").is_some_and(|f| f == "vllm") {
        return Some("Only vLLM models have a launch mode; this model's runner runs one way.");
    }
    if mode == "megakernel" && environment.contains_key("YOUGORI_MODEL_PATH") {
        return Some("A model run from a folder on this computer cannot use the megakernel launch yet: its runner would need more than the CUDA runtime takes at one start. Run the same model from Hugging Face to use a megakernel.");
    }
    None
}

/// Refuses a parallel setting this model cannot take, before anything is saved; returns the
/// workload's id and its options as they are.
fn check_parallel(app: &AppHandle, environment_id: &str, slots: u64) -> Result<(String, Options), String> {
    if !(1..=16).contains(&slots) { return Err("Parallel requests must be 1–16".into()); }
    let state = app.state::<PlatformStore>().snapshot()?;
    let env = state.environments.iter().find(|e| e.id == environment_id).ok_or("Model not found")?;
    let id = env.runtime_id.clone().unwrap_or_else(|| environment_id.to_owned());
    let options = app.state::<RuntimeManager>().workload_options(&id)?;
    match parallel_refusal(&env.kind, &options.environment) {
        Some(refusal) => Err(refusal.into()),
        None => Ok((id, options)),
    }
}

/// Why a model takes no parallel setting from this engine, if it takes none: a cloud server's
/// runner keeps its own settings, and the native host service and the Transformers runner
/// generate one request at a time.
fn parallel_refusal(kind: &EnvironmentKind, environment: &std::collections::BTreeMap<String, String>) -> Option<&'static str> {
    if *kind == EnvironmentKind::Cloud {
        return Some("A model on a cloud server serves with that server's own settings; set parallel requests where it runs.");
    }
    if environment.contains_key("YOUGORI_NATIVE_BACKEND") {
        return Some("The native host model service generates one request at a time; parallel requests apply to GGUF and vLLM runners in containers.");
    }
    if !environment.get("YOUGORI_MODEL_FORMAT").is_some_and(|f| f == "gguf" || f == "vllm") {
        return Some("Only GGUF and vLLM models generate requests in parallel; this model's runner answers one at a time.");
    }
    None
}

// A conservative shared-device scheduler: one resident model while switching.
// Active/pinned models always retain residency; runners enforce this atomically.
// Real demand goes first; a model waiting only because a preparation started it follows (G05).
fn demand<'a>(rows: &'a [(String, Value)]) -> Option<&'a (String, Value)> {
    demand_by(rows, super::prepare::speculative)
}

fn demand_by<'a>(rows: &'a [(String, Value)], speculative: impl Fn(&str) -> bool) -> Option<&'a (String, Value)> {
    rows.iter().filter(|(_, h)| waiting(h))
        .min_by(|a,b| speculative(&a.0).cmp(&speculative(&b.0))
            .then_with(|| a.1["optimizer"]["waitingSince"].as_f64().unwrap_or(f64::MAX).total_cmp(&b.1["optimizer"]["waitingSince"].as_f64().unwrap_or(f64::MAX))))
}

/// What each model's measured loads cost (G05, retention by actual reload cost), from its runner's
/// load view: a parked vLLM's wake (engine wake plus weight reload), else the last completed load
/// without the stages a reload of retained files does not repeat (the GPU wait, downloads and
/// imports), with the bytes it holds.
#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Reload {
    pub reload_seconds: f64,
    pub woke: bool,
    #[serde(skip)]
    observed: f64,
}

static RELOADS: std::sync::Mutex<std::collections::BTreeMap<String, Reload>> = std::sync::Mutex::new(std::collections::BTreeMap::new());

/// The reload cost of a completed load, from its load view.
fn reload_of_load(load: &Value) -> Option<Reload> {
    if load["inProgress"] != false || load["outcome"] != "ok" { return None; }
    let stages = &load["stages"];
    let elapsed = load["elapsedMs"].as_f64()?;
    // Stages nest (a download inside its snapshot, an import inside its checkpoint), so none is
    // subtracted from another: a load that fetched or imported nothing is itself a reload (its
    // time less its GPU wait); a first load counts the engine start or weight load it repeats.
    let fetched = ["download", "snapshot", "import", "checkpoint"].iter().any(|name| stages.get(*name).is_some());
    let (seconds, woke) = match (stages["engine_wake"].as_f64(), stages["weight_reload"].as_f64()) {
        (Some(wake), Some(reload)) => ((wake + reload) / 1000.0, true),
        _ if !fetched => ((elapsed - stages["admission_wait"].as_f64().unwrap_or(0.0)) / 1000.0, false),
        _ => (stages["engine_start_to_ready"].as_f64().or_else(|| stages["weight_load"].as_f64())? / 1000.0, false),
    };
    Some(Reload { reload_seconds: seconds.max(0.1), woke, observed: elapsed })
}

/// Records the reload cost `health` reports, once per load.
fn record_reload(id: &str, health: &Value) {
    let Some(reload) = reload_of_load(&health["load"]) else { return };
    let mut reloads = RELOADS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if reloads.get(id).is_none_or(|known| known.observed != reload.observed) {
        reloads.insert(id.to_owned(), reload);
    }
}

/// The measured reload cost of `id`, for its status.
pub(super) fn reload_cost(id: &str) -> Option<Value> {
    RELOADS.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(id).and_then(|reload| serde_json::to_value(reload).ok())
}

/// Which resident models are parked first when room is needed (GPU §2.7): the library's
/// GreedyDual-Size ("Landlord") policy over measured reload costs. A model's credit is its reload
/// cost, renewed whenever it serves; whenever a resident leaves the GPU every other one pays rent
/// in proportion to its bytes. Idle models that are cheap to bring back per byte go first; a model
/// never measured counts its first load, or 30 s.
#[derive(Default)]
struct Retention {
    policy: crate::model_memory::residency::retention::GreedyDualSize,
    /// Each resident's idle clock and size at the last pass, and since when it has not answered.
    seen: std::collections::BTreeMap<String, (u64, u64, Option<std::time::Instant>)>,
    /// The models the scheduler sent to park to make room, and when: only their departures were
    /// its choice, and only those charge the others rent. Forgotten after a minute without one.
    parked: std::collections::BTreeMap<String, std::time::Instant>,
    step: u64,
}

impl Retention {
    fn bytes(health: &Value) -> u64 {
        health["optimizer"]["allocatedBytes"].as_u64().or_else(|| health["admission"]["bytes"].as_u64()).unwrap_or(1 << 30).max(1)
    }

    fn view(id: &str, bytes: u64, evictable: bool, protected: bool) -> crate::model_memory::residency::retention::ObjectView<'_> {
        let reload = RELOADS.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(id).map_or(30.0, |reload| reload.reload_seconds);
        crate::model_memory::residency::retention::ObjectView {
            key: id, kind: crate::model_memory::residency::retention::ObjectKind::BaseWeights, bytes,
            reload_seconds: reload, last_use_step: 0, use_count: 0, protected, evictable,
        }
    }

    /// One scheduler pass over the models that answered: renews the credit of each one used since
    /// the last pass (a request active, or its idle clock restarted), and forgets the ones that
    /// left the GPU. A model the scheduler parked to make room charges every other resident rent
    /// (pinned or busy ones are exempt, as they cannot leave); a stop, an idle unload or a crash
    /// was no such choice and charges none.
    fn observe(&mut self, rows: &[(String, Value)], now: std::time::Instant) {
        use crate::model_memory::residency::retention::RetentionPolicy;
        self.step += 1;
        let resident = rows.iter().filter(|(_, h)| h["optimizer"]["resident"] == true).collect::<Vec<_>>();
        let held = |h: &Value| h["optimizer"]["pinned"] == true || h["optimizer"]["active"].as_u64().unwrap_or(0) > 0;
        for (id, health) in &resident {
            record_reload(id, health);
            let idle = health["optimizer"]["idleSeconds"].as_u64().unwrap_or(0);
            let bytes = Self::bytes(health);
            let used = health["optimizer"]["active"].as_u64().unwrap_or(0) > 0
                || self.seen.get(id).is_none_or(|(before, _, _)| idle < *before);
            if used { self.policy.on_use(&Self::view(id, bytes, false, false), self.step); }
            self.seen.insert(id.clone(), (idle, bytes, None));
        }
        let mut left = Vec::new();
        for (id, (_, bytes, silent_since)) in self.seen.iter_mut() {
            if resident.iter().any(|(other, _)| other == id) { continue; }
            // One that did not answer may still hold the GPU: it has left once it answers not
            // resident, or after a minute of silence.
            let answered = rows.iter().any(|(other, _)| other == id);
            let since = *silent_since.get_or_insert(now);
            if answered || now.saturating_duration_since(since) >= Duration::from_secs(60) { left.push((id.clone(), *bytes)); }
        }
        // Parked one after another to make room, each in turn charges the least credit per byte
        // left, which adds up to the largest parked one's: one charge for all of them.
        let density = |(id, bytes): &&(String, u64)| self.policy.credit(id).unwrap_or(0.0) / *bytes as f64;
        let charged = left.iter().filter(|(id, _)| self.parked.contains_key(id))
            .max_by(|a, b| density(a).total_cmp(&density(b))).cloned();
        if let Some((id, bytes)) = charged {
            let mut views = resident.iter().map(|(other, health)| Self::view(other, Self::bytes(health), false, held(health))).collect::<Vec<_>>();
            views.push(Self::view(&id, bytes, true, false));
            let _ = self.policy.choose_victim(&views, self.step);
        }
        for (id, _) in &left {
            self.policy.on_evict(id);
            self.seen.remove(id);
            self.parked.remove(id);
        }
        self.parked.retain(|_, at| now.saturating_duration_since(*at) < Duration::from_secs(60));
    }

    /// The models the scheduler sent to park to make room (their unload requests).
    fn note_parks(&mut self, ids: Vec<String>, now: std::time::Instant) {
        for id in ids { self.parked.insert(id, now); }
    }

    /// `candidates` in the order to park them: least credit per byte first, then as given (the
    /// longest idle first).
    fn order(&self, candidates: Vec<String>, rows: &[(String, Value)]) -> Vec<String> {
        let density = |id: &str| {
            let bytes = rows.iter().find(|(other, _)| other == id).map_or(1 << 30, |(_, h)| Self::bytes(h));
            self.policy.credit(id).unwrap_or(0.0) / bytes as f64
        };
        let mut ordered = candidates.into_iter().enumerate().collect::<Vec<_>>();
        ordered.sort_by(|(a_index, a), (b_index, b)| density(a).total_cmp(&density(b)).then(a_index.cmp(b_index)));
        ordered.into_iter().map(|(_, id)| id).collect()
    }
}

/// A vLLM runner parked by sleep whose engine an unload ends now: the engine still holds part of
/// the GPU although the runner is not resident. An idle one, or one whose own requests wait when
/// its runner ends a parked engine even then (`control::ends_parked_while_waiting`); an older
/// runner refuses that unload, so its engine stays.
fn parked_engine(health: &Value) -> bool {
    let o = &health["optimizer"];
    health["parked"] == "sleep" && o["resident"] == false && o["loading"] == false && o["pinned"] == false
        && o["releaseUncertain"] == false && o["active"].as_u64().unwrap_or(0) == 0
        && (o["pending"].as_u64().unwrap_or(0) == 0 || control::ends_parked_while_waiting(health))
}

/// A vLLM runner parked by sleep and idle: its engine still holds part of the GPU although it is
/// not resident, and unloading it again ends that engine.
fn sleeper(health: &Value) -> bool {
    parked_engine(health) && health["optimizer"]["pending"].as_u64().unwrap_or(0) == 0
}

/// The vLLM runners parked by sleep whose engines end for `target`'s admission. None for a model
/// only a preparation started (it switches no other model out), and none before the target was
/// refused for want of GPU memory: a model that fits beside their leftovers leaves them parked, as
/// a wake takes seconds and a cold start much longer. Then every parked engine but the target's,
/// also of a model waiting itself: it starts its engine again when its turn comes, where its
/// leftover would keep the first in line refused and both models waiting.
fn parked_in_the_way(target: &str, rows: &[(String, Value)], speculative: bool, refused_for_room: bool) -> Vec<(String, Value)> {
    if speculative || !refused_for_room {
        return Vec::new();
    }
    rows.iter().filter(|(other, health)| other != target && parked_engine(health)).cloned().collect()
}

/// A refusal without its numbers, for the scheduler to tell a new reason from the same one: the
/// byte counts in a capacity refusal follow the host probe and move on almost every pass.
fn refusal_kind(reason: &str) -> String {
    reason.chars().filter(|c| !c.is_ascii_digit()).collect()
}

/// What the engine's host probe read around a vLLM runner's park by sleep: the GPU memory in use
/// before and after it, when, and the runner instance that parked.
#[derive(Clone, Debug, PartialEq)]
struct Park {
    before: u64,
    after: u64,
    at: std::time::Instant,
    instance: Option<String>,
}

impl Park {
    /// The park the answer `reply` to a watched unload reports, measured `before` and `after`.
    fn of(reply: &Value, before: u64, after: u64) -> Self {
        Self { before, after, at: std::time::Instant::now(), instance: reply["optimizer"]["instanceId"].as_str().map(str::to_owned) }
    }

    /// Whether this park may still describe the engine of the runner `health` answers for: the same
    /// runner instance (a new one ended the engine with the old process), still parked, loading (its
    /// wake or a cold start) or bound again holding its model (the wake is recorded then). A runner
    /// holding a model it is not bound with, or neither parked nor loading, has no such engine now.
    fn describes(&self, health: &Value, bound: bool) -> bool {
        let o = &health["optimizer"];
        self.instance.as_deref() == o["instanceId"].as_str()
            && (health["parked"] == "sleep" || o["loading"] == true || (o["resident"] == true && bound))
    }

    /// What the admission of the runner `health` answers for credits from this park, while that
    /// runner is the one that parked and is parked still ([`capacity::Parked`]).
    fn credit(&self, health: &Value) -> Option<capacity::Parked> {
        (health["parked"] == "sleep" && self.instance.as_deref() == health["optimizer"]["instanceId"].as_str())
            .then_some(capacity::Parked { before: self.before, after: self.after })
    }
}

/// A model that asked for the GPU and does not hold it.
fn waiting(health: &Value) -> bool {
    health["optimizer"]["pending"].as_u64().unwrap_or(0) > 0 && health["optimizer"]["resident"] != true && health["status"] != "error"
}

/// Why each model waiting for the GPU waits, by model id, in words its person can act on. The
/// scheduler rewrites it on every pass, so a reason is gone once its model is granted or stops
/// waiting.
static WAITING: std::sync::Mutex<std::collections::BTreeMap<String, String>> = std::sync::Mutex::new(std::collections::BTreeMap::new());

/// Why this model waits for the GPU, while it does.
pub(super) fn waiting_for(id: &str) -> Option<String> {
    WAITING.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).get(id).cloned()
}

/// Why each model waiting for the GPU waits: which models hold it, and what the person can do
/// about them, most actionable first. The first in line is the one the scheduler weighs, and the
/// others wait behind it; one the scheduler can grant now gets no reason.
fn reasons(rows: &[(String, Value)], silent: &[String], name: impl Fn(&str) -> String) -> std::collections::BTreeMap<String, String> {
    let mut reasons = std::collections::BTreeMap::new();
    let Some((first, _)) = demand(rows) else { return reasons };
    let others = |holds: fn(&Value) -> bool| rows.iter().filter(|(other, h)| other != first && holds(&h["optimizer"])).map(|(other, _)| name(other)).collect::<Vec<_>>();
    let silent: Vec<String> = silent.iter().map(|id| name(id)).collect();
    let pinned = others(|o| o["resident"] == true && o["pinned"] == true);
    let loading = others(|o| o["loading"] == true);
    let busy = others(|o| o["resident"] == true && (o["active"].as_u64().unwrap_or(0) > 0 || o["pending"].as_u64().unwrap_or(0) > 0));
    let why = match (silent.as_slice(), pinned.as_slice(), loading.as_slice(), busy.as_slice()) {
        ([one], ..) => Some(format!("{one} still holds the GPU (paused or not answering). Resume or stop {one} to let this model load.")),
        ([_, _, ..], ..) => Some(format!("Paused or unresponsive models still hold the GPU: {}. Resume or stop them to let this model load.", silent.join(", "))),
        ([], [one], ..) => Some(format!("{one} keeps the GPU because Prevent automatic model switching is on for it. Turn that off, or stop {one}, to let this model load.")),
        ([], [_, _, ..], ..) => Some(format!("{} keep the GPU because Prevent automatic model switching is on for them. Turn that off, or stop them, to let this model load.", pinned.join(", "))),
        ([], [], [one], _) => Some(format!("{one} is loading into GPU memory. This model loads after it.")),
        ([], [], [_, _, ..], _) => Some(format!("{} are loading into GPU memory. This model loads after them.", loading.join(", "))),
        ([], [], [], [one]) => Some(format!("{one} is using the GPU. This model loads once it is free.")),
        ([], [], [], [_, _, ..]) => Some(format!("{} are using the GPU. This model loads once it is free.", busy.join(", "))),
        ([], [], [], []) => None,
    };
    let ahead = name(first);
    for (id, _) in rows.iter().filter(|(id, health)| id != first && waiting(health)) {
        reasons.insert(id.clone(), format!("{ahead} is first in line for the GPU. This model loads after it."));
    }
    if let Some(why) = why {
        reasons.insert(first.clone(), why);
    }
    reasons
}

/// Whether `id`, waiting for the GPU, must wait longer: another model is using, waiting for or
/// pinning it, or a model may hold GPU memory without saying so (`silent`: paused, or not
/// answering), which cannot be asked to unload, so granting now would only fail this load.
fn must_wait(rows: &[(String, Value)], id: &str, silent: usize) -> bool {
    silent > 0 || rows.iter().filter(|(other, h)| other != id && h["optimizer"]["resident"] == true)
        .any(|(_, h)| h["optimizer"]["active"].as_u64().unwrap_or(0) > 0 || h["optimizer"]["pending"].as_u64().unwrap_or(0) > 0 || h["optimizer"]["pinned"] == true)
}

/// One look at a GPU-optimized model: what it answered, or `None` when it is paused (and cannot
/// be asked) or did not answer.
struct Seen {
    id: String,
    health: Option<Value>,
}

/// Once a running member advertises fencing, missing/invalid metadata cannot
/// silently downgrade it to legacy control or prove that its GPU memory is free.
fn validate_seen(seen: &mut [Seen], fenced: &mut std::collections::HashSet<String>, revisions: &mut std::collections::HashMap<String, (String, u64)>) -> Vec<String> {
    fenced.retain(|id| seen.iter().any(|row| &row.id == id));
    revisions.retain(|id, _| seen.iter().any(|row| &row.id == id));
    let mut unknown = Vec::new();
    for row in seen {
        let advertised = row.health.as_ref().is_some_and(|health| {
            ["controlProtocol", "instanceId", "sequence"].iter().any(|field| health["optimizer"].get(*field).is_some())
        });
        if advertised { fenced.insert(row.id.clone()); }
        let valid = row.health.as_ref().is_some_and(|health| match control::observation(health) {
            Ok(control::Observation::V1 { instance_id, sequence }) => {
                if revisions.get(&row.id).is_some_and(|(prior, previous)| prior == &instance_id && sequence < *previous) {
                    false
                } else {
                    revisions.insert(row.id.clone(), (instance_id, sequence));
                    true
                }
            },
            Ok(control::Observation::Legacy) => !fenced.contains(&row.id),
            Err(_) => false,
        });
        if !valid {
            row.health = None;
            if fenced.contains(&row.id) { unknown.push(row.id.clone()); }
        }
    }
    unknown
}

/// Updates the models last seen holding the GPU and returns the rows that answered with the
/// optimizer on, with the models that may hold GPU memory without saying so: one paused, or no
/// longer answering, while it held the GPU. One that held none when last seen (paused before it
/// loaded, or still starting) holds none now, so it never keeps another model waiting. A model
/// paused before this engine started is unknown here; if it does hold memory, the load it would
/// have blocked fails with an error instead of every model waiting for good.
fn observe(seen: &[Seen], resident: &mut std::collections::HashSet<String>) -> (Vec<(String, Value)>, Vec<String>) {
    let mut rows = Vec::new();
    let mut silent = Vec::new();
    for model in seen {
        match &model.health {
            Some(health) => {
                if health["optimizer"]["resident"] == true || health["optimizer"]["loading"] == true || health["optimizer"]["releaseUncertain"] == true { resident.insert(model.id.clone()); } else { resident.remove(&model.id); }
                if health["optimizer"]["enabled"] == true { rows.push((model.id.clone(), health.clone())); }
                else if resident.contains(&model.id) || health["optimizer"]["active"].as_u64().unwrap_or(0) > 0 {
                    // Disabled automatic management cannot prove free capacity;
                    // this runner cannot be asked to evict, so block other grants.
                    silent.push(model.id.clone());
                }
            }
            None => if resident.contains(&model.id) { silent.push(model.id.clone()) },
        }
    }
    resident.retain(|id| seen.iter().any(|model| &model.id == id));
    (rows, silent)
}

/// What this pass saw of the runner of a GPU grant (S04/G03; `capacity::RunnerGone`): gone
/// when its environment is stopped or failed, as the engine itself observed through the
/// platform store (the runner was a process of that container), or when its environment runs
/// and the runner answering is another instance holding no model. A paused environment is not
/// gone: its frozen memory stays allocated. One provisioning, or running without a valid
/// answer, is unknown and keeps its marker.
fn runner_gone(id: &str, name: &str, status: &EnvironmentStatus, marker: &str, health: Option<&Value>) -> Option<capacity::RunnerGone> {
    let how = match status {
        EnvironmentStatus::Stopped => capacity::Gone::Stopped,
        EnvironmentStatus::Error => capacity::Gone::Error,
        EnvironmentStatus::Running => capacity::replaced(marker, health?)?,
        EnvironmentStatus::Paused | EnvironmentStatus::Provisioning => return None,
    };
    Some(capacity::RunnerGone { environment: id.to_owned(), name: name.to_owned(), how })
}

/// The resident models that may be parked to make room (GPU-W05 "park eligible idle models"),
/// longest idle first: not pinned, not loading, not uncertain, no request active or pending.
fn evictable(residents: &[(String, Value)]) -> Vec<String> {
    let idle = |o: &Value| o["pinned"] == false && o["loading"] == false && o["releaseUncertain"] == false
        && o["active"].as_u64().unwrap_or(0) == 0 && o["pending"].as_u64().unwrap_or(0) == 0;
    let mut idle_models = residents.iter().filter(|(_, h)| idle(&h["optimizer"]))
        .map(|(id, h)| (id.clone(), h["optimizer"]["idleSeconds"].as_u64().unwrap_or(0))).collect::<Vec<_>>();
    idle_models.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    idle_models.into_iter().map(|(id, _)| id).collect()
}

fn idle_expired(health: &Value) -> bool {
    let o = &health["optimizer"];
    let timeout = o["idleTimeoutSeconds"].as_u64().unwrap_or(0);
    o["resident"] == true && timeout > 0 && o["idleSeconds"].as_u64().unwrap_or(0) >= timeout
}

pub(crate) fn start(app: &AppHandle) {
    start_until(app, crate::automation::shutdown_signal(app));
}

pub(crate) fn start_until(app: &AppHandle, shutdown: tokio_util::sync::CancellationToken) -> tauri::async_runtime::JoinHandle<()> {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        // VM-first startup must not require a GPU, a model or NVIDIA tooling. A
        // failed probe does not prevent existing product startup; host admission
        // remains unavailable and a consumer can explicitly retry its refresh.
        if let Err(reason) = capacity::refresh_host_capacity(&shutdown).await {
            if !shutdown.is_cancelled() { eprintln!("Host capacity initialization: {reason}"); }
        }
        // The catalog views of the environments still running lease again and stay; the
        // rest are swept (S02). Files are copied only where a view is incomplete.
        {
            let restore_app = app.clone();
            let _ = tokio::task::spawn_blocking(move || {
                let store = restore_app.state::<PlatformStore>();
                let runtime = restore_app.state::<RuntimeManager>();
                super::restore_catalog_views(&store, &runtime);
            }).await;
        }
        let subscriptions = shutdown.child_token();
        let (membership, updates) = tokio::sync::watch::channel(Vec::new());
        let event_app = app.clone();
        let watching = events::run(updates, &subscriptions, || WAKE.notify(), move |id, body| {
            let app = event_app.clone();
            async move { model_request(&app, &id, "/v1/yougori/optimizer", Some(body)).await }
        });
        // The local vLLM runtimes this scheduler bound to the engine's host evidence (G03).
        let mut binder = runtime_binding::Binder::default();
        // vLLM runners that parked by sleep when asked to unload, with the GPU memory in use the
        // host probe read before and after, when, and which runner instance: their wake is matched
        // once they are bound again (CORE-01 sleep-mode weight discarding, G01/G02). A park whose
        // engine ended, or whose runner was replaced, is dropped (`Park::describes`).
        let sleeping = std::sync::Mutex::new(std::collections::BTreeMap::<String, Park>::new());
        let scheduling = async {
        // This scope owns the subscription lifetime, even on early return/error.
        let _stop = subscriptions.clone().drop_guard();
        // Models last seen holding the GPU.
        let mut resident = std::collections::HashSet::<String>::new();
        let mut fenced = std::collections::HashSet::<String>::new();
        let mut revisions = std::collections::HashMap::new();
        // The kind of the last refusal each waiting model's admission met (`refusal_kind`), so the
        // log says it once, and a model refused for want of GPU memory has parked engines ended.
        let mut last_wait = std::collections::HashMap::<String, String>::new();
        let mut last_started = None;
        // The served helper directories a restarted runner left (its share server held them
        // when its options moved on) are swept every few minutes, as at the engine's start.
        let mut last_served_sweep = tokio::time::Instant::now();
        let mut retention = Retention::default();
        loop {
            if !WAKE.wait(&shutdown, last_started).await { break; }
            last_started = Some(tokio::time::Instant::now());
            let _admission = tokio::select! {
                biased;
                _ = shutdown.cancelled() => return,
                guard = ADMISSION.lock() => guard,
            };
            let Ok(state) = app.state::<PlatformStore>().snapshot() else { continue };
            // A completed deletion may have removed both the environment and its marker.
            // Runtime receipts survive that removal; only their own grants are settled.
            if let Err(error) = capacity::reconcile_ends(&shutdown).await {
                eprintln!("GPU completed-runtime reconciliation: {error}");
            }
            // A recorded runner whose environment the engine sees stopped, failed or gone has
            // ended: its helper pins end with it (G08; `helpers::reconcile_runners`).
            let alive = |id: &str| state.environments.iter().any(|env| env.id == id && !matches!(env.status, EnvironmentStatus::Stopped | EnvironmentStatus::Error));
            for (runner, outcome) in super::helpers::reconcile_runners(&alive) {
                if let Err(error) = outcome { eprintln!("Helper pins of the ended model runner {runner} were not recorded: {error}"); }
            }
            if last_served_sweep.elapsed() >= SERVED_SWEEP_INTERVAL {
                last_served_sweep = tokio::time::Instant::now();
                let (swept, _held) = super::sweep_unbound_served(&state, &app.state::<RuntimeManager>(), Some(SERVED_SWEEP_INTERVAL));
                if !swept.is_empty() { eprintln!("Served helper directories swept: {}", swept.len()); }
            }
            let runtime = app.state::<RuntimeManager>();
            let mut pending = std::collections::HashMap::new();
            let mut unreadable = Vec::new();
            let mut capacity_markers = std::collections::BTreeMap::new();
            let mut capacity_demand = std::collections::BTreeMap::new();
            // The stamped context and the facts behind a Transformers demand (G03 co-residency).
            let mut capacity_context = std::collections::BTreeMap::new();
            let mut capacity_facts = std::collections::BTreeMap::new();
            let mut unreadable_marker = false;
            let mut launches = std::collections::HashMap::new();
            for env in state.environments.iter().filter(|env| env.kind == EnvironmentKind::Container) {
                if let Ok(options) = runtime.workload_options(env.runtime_id.as_deref().unwrap_or(&env.id)) {
                    if let Some(marker) = options.environment.get(capacity::PENDING) {
                        capacity_markers.insert(env.id.clone(), marker.clone());
                    }
                } else if env.gpu_access { unreadable_marker = true; }
            }
            let models = state.environments.iter().filter(|e| matches!(e.status, EnvironmentStatus::Running | EnvironmentStatus::Paused) && e.kind == EnvironmentKind::Container)
                .filter(|e| match runtime.workload_options(e.runtime_id.as_deref().unwrap_or(&e.id)) {
                    Ok(options) => {
                        if let Some(marker) = options.environment.get(capacity::PENDING) { capacity_markers.insert(e.id.clone(), marker.clone()); }
                        launches.insert(e.id.clone(), runtime_binding::Launch::of(&options.environment));
                        let demand = if options.environment.contains_key(capacity::POLICY)
                            && e.provider != Some(RuntimeProviderKind::YougoriCuda) {
                            Err("Shared GPU admission requires a local CUDA workload; this runtime cannot use host capacity evidence.".into())
                        } else { capacity::demand(&options.environment) };
                        capacity_demand.insert(e.id.clone(), demand);
                        if let Some(context) = capacity::stamped_context(&options.environment) { capacity_context.insert(e.id.clone(), context); }
                        if let Some(facts) = capacity::Facts::read(&options.environment) { capacity_facts.insert(e.id.clone(), facts); }
                        if let Some(marker) = options.environment.get(configuration::PENDING) { pending.insert(e.id.clone(), marker.clone()); }
                        pending.contains_key(&e.id) || (options.environment.contains_key("YOUGORI_GPU_OPTIMIZER")
                            && options.environment.get("YOUGORI_MODEL_CPU").is_none_or(|value| value != "1")
                            && options.environment.get("YOUGORI_MODEL_FORMAT").is_none_or(|value| value != "source"))
                    },
                    Err(_) => {
                        let known = resident.contains(&e.id) || fenced.contains(&e.id)
                            || (e.gpu_access && e.description.starts_with("Hugging Face · "));
                        if known { unreadable.push(e.id.clone()); }
                        known
                    },
                }).collect::<Vec<_>>();
            let inputs = models.iter().map(|model| (model.id.clone(), model.status == EnvironmentStatus::Paused)).collect();
            let Some(mut seen) = status_batch::collect(inputs, &shutdown, Duration::from_secs(3), |id| {
                super::model_status(id, app.clone())
            }).await else { return };
            let mut unknown = validate_seen(&mut seen, &mut fenced, &mut revisions);
            unknown.extend(unreadable);
            let mut unconfirmed = Vec::new();
            for (id, marker) in pending {
                let invalidated = seen.iter().find(|row| row.id == id).and_then(|row| row.health.as_ref())
                    .is_some_and(|health| configuration::invalidated(&marker, health));
                let cleared = invalidated && models.iter().find(|model| model.id == id).is_some_and(|model| {
                    let options_id = model.runtime_id.as_deref().unwrap_or(&model.id);
                    let Ok(mut options) = runtime.workload_options(options_id) else { return false; };
                    if options.environment.get(configuration::PENDING) != Some(&marker) { return false; }
                    options.environment.remove(configuration::PENDING);
                    runtime.save_workload_options(options_id, &options).is_ok()
                });
                if !cleared { unconfirmed.push(id); }
            }
            membership.send_replace(events::members(&seen));
            let (rows, mut silent) = observe(&seen, &mut resident);
            retention.observe(&rows, std::time::Instant::now());
            // What each granted runner reports allocated goes on its grant as an observation
            // (S03: observed allocations on the one host ledger); never authority, never a
            // change to what is reserved, and the runner's word only about its own grant.
            for (id, health) in rows.iter().filter(|(id, _)| capacity_markers.contains_key(id)) {
                if let Some(bytes) = health["optimizer"]["allocatedBytes"].as_u64() {
                    if let Err(error) = capacity::local_observe_usage(id, bytes) { eprintln!("GPU usage of {id} was not recorded on its grant: {error}"); }
                }
            }
            // Bind each local vLLM runtime known to run under its GPU grant; unbind the ones
            // that stopped, were released or are gone (G03).
            let runners = models.iter().map(|model| runtime_binding::Runner {
                id: &model.id,
                running: model.status == EnvironmentStatus::Running,
                local_cuda: model.provider == Some(RuntimeProviderKind::YougoriCuda),
                image: &model.runtime,
                launch: launches.get(&model.id).copied(),
                grant: capacity_markers.get(&model.id).map(String::as_str),
                health: seen.iter().find(|row| row.id == model.id).and_then(|row| row.health.as_ref()),
            }).collect::<Vec<_>>();
            let changes = runtime_binding::pass(&mut binder, &runners);
            runtime_binding::apply(changes, binder.unbound()).await;
            // A runner that parked by sleep and is bound again after a wake (its last load woke
            // the engine and reloaded the weights, with no cold start) completed a sleep cycle.
            let parked = sleeping.lock().unwrap_or_else(std::sync::PoisonError::into_inner).keys().cloned().collect::<Vec<_>>();
            for id in parked {
                // A park outlives neither its model nor its engine: an ended engine's numbers would be
                // credited to a later park nobody measured, which would also escape the idle unload.
                let health = seen.iter().find(|row| row.id == id).and_then(|row| row.health.as_ref());
                let bound = binder.bindings().contains_key(&id);
                let kept = models.iter().any(|model| model.id == id) && sleeping.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get(&id).is_some_and(|park| health.is_none_or(|health| park.describes(health, bound)));
                if !kept {
                    sleeping.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&id);
                    continue;
                }
                let (Some(binding), Some(health)) = (binder.bindings().get(&id), health) else { continue };
                let load = &health["load"];
                let stages = &load["stages"];
                let woke = load["inProgress"] == false && load["outcome"] == "ok" && stages.get("engine_start_to_ready").is_none();
                let (Some(wake), Some(reload)) = (stages["engine_wake"].as_f64(), stages["weight_reload"].as_f64()) else {
                    sleeping.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&id);
                    continue;
                };
                if !woke {
                    sleeping.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&id);
                    continue;
                }
                let Some(awake) = capacity::local_used(&shutdown).await else { continue };
                let Some(Park { before, after, at, .. }) = sleeping.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&id) else { continue };
                let cycle = crate::host_evidence::SleepCycle {
                    used_before_bytes: before, used_parked_bytes: after, used_awake_bytes: awake,
                    engine_wake_ms: wake, weight_reload_ms: reload,
                    slept_ms: u64::try_from(at.elapsed().as_millis()).unwrap_or(u64::MAX),
                    recorded_at: crate::foundation::ids::MonotonicTime::from_nanos(0),
                };
                let (returned, retaken) = cycle.returned_and_retaken();
                match crate::host_evidence::record_sleep_cycle(binding.runtime(), cycle).await {
                    Ok(_) => eprintln!("Sleep cycle of {id}: the park returned {} MiB, the wake took {} MiB again ({wake:.0} ms wake, {reload:.0} ms weight reload)", returned >> 20, retaken >> 20),
                    Err(error) => eprintln!("Sleep cycle of {id} was not recorded: {error}"),
                }
            }
            for id in unknown { if !silent.contains(&id) { silent.push(id); } }
            for id in &unconfirmed { if !silent.contains(id) { silent.push(id.clone()); } }
            // The grants whose runner this pass saw gone (S04/G03): their markers are
            // settled through the host probe, never on a runner's word.
            let runners_gone = state.environments.iter().filter_map(|env| runner_gone(&env.id, &env.name, &env.status, capacity_markers.get(&env.id)?,
                seen.iter().find(|row| row.id == env.id).and_then(|row| row.health.as_ref()))).collect::<Vec<_>>();
            let name = |id: &str| models.iter().find(|model| model.id == id).map_or_else(|| id.to_owned(), |model| model.name.clone());
            // The models still waiting this pass keep the reason an earlier pass recorded until a new
            // one replaces it: the map is rebuilt every pass, and a reason recorded only after this
            // pass's probe (a refused switch) was otherwise missing from most status reads.
            let still_waiting = rows.iter().filter(|(_, h)| waiting(h)).map(|(id, _)| id.clone()).collect::<Vec<_>>();
            // A refusal is remembered while its model waits: the next wait starts afresh.
            last_wait.retain(|id, _| still_waiting.contains(id));
            let mut waiting = reasons(&rows, &silent, name);
            if let Some((first, _)) = demand(&rows).filter(|_| !unconfirmed.is_empty()) {
                let names = unconfirmed.iter().map(|id| name(id)).collect::<Vec<_>>().join(", ");
                waiting.insert(first.clone(), format!("GPU settings for {names} have an unconfirmed outcome. Admission resumes after reconciliation; stop or recreate the model if it cannot recover."));
            } else if let Some((first, _)) = demand(&rows) {
                let disabled = seen.iter().filter(|row| row.health.as_ref().is_some_and(|health|
                    health["optimizer"]["enabled"] == false && (resident.contains(&row.id)
                        || health["optimizer"]["active"].as_u64().unwrap_or(0) > 0)))
                    .map(|row| name(&row.id)).collect::<Vec<_>>();
                if !disabled.is_empty() {
                    waiting.insert(first.clone(), format!("{} keep GPU memory while Automatic GPU memory is off. Re-enable it or stop those models to let this model load.", disabled.join(", ")));
                }
            }
            {
                let mut shown = WAITING.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                for id in &still_waiting {
                    if !waiting.contains_key(id) {
                        if let Some(reason) = shown.get(id) { waiting.insert(id.clone(), reason.clone()); }
                    }
                }
                *shown = waiting;
            }
            // Never admit another model while a loader owns the GPU.
            if rows.iter().any(|(_,h)|h["optimizer"]["loading"] == true) { continue; }
            // A vLLM runner asked to unload may park by sleep: the host probe is read around the
            // unload, and its answer says whether it slept (`sleeping` above).
            let vllm_runners = launches.iter().filter(|(_, launch)| launch.is_vllm()).map(|(id, _)| id.clone()).collect::<std::collections::HashSet<_>>();
            let send = |id: String, body: Value| {
                let app = app.clone();
                let watched = body["action"] == "unload" && vllm_runners.contains(&id);
                let (sleeping, shutdown) = (&sleeping, &shutdown);
                async move {
                    let before = if watched { capacity::local_used(shutdown).await } else { None };
                    let answer = model_request(&app, &id, "/v1/yougori/optimizer", Some(body)).await;
                    if let (true, Ok(reply)) = (watched, &answer) {
                        if reply["unloaded"] == true {
                            // This unload's park, measured; an unload that ended the engine, or a park
                            // the probe could not read, leaves nothing of an earlier park.
                            let park = match before {
                                Some(before) if reply["parked"] == "sleep" => capacity::local_used(shutdown).await.map(|after| Park::of(reply, before, after)),
                                _ => None,
                            };
                            let mut sleeping = sleeping.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                            match park {
                                Some(park) => { sleeping.insert(id.clone(), park); }
                                None => { sleeping.remove(&id); }
                            }
                        }
                    }
                    answer
                }
            };
            let persist_capacity = |id: &str, marker: Option<&str>| {
                let env = state.environments.iter().find(|env| env.id == id).ok_or("GPU model disappeared during reservation persistence.")?;
                let runtime_id = env.runtime_id.as_deref().unwrap_or(id);
                let mut options = runtime.workload_options(runtime_id)?;
                if let Some(marker) = marker { options.environment.insert(capacity::PENDING.into(), marker.into()); }
                else { options.environment.remove(capacity::PENDING); }
                runtime.save_workload_options(runtime_id, &options)
            };
            // A model waiting only because a preparation started it loads into a GPU no other
            // model holds (or as normal demand once a request arrives for it): while residents
            // hold the GPU it is not served, and this pass does the housekeeping that lets them
            // leave as their own settings say (idle unloads, releases) instead.
            let first = demand(&rows).filter(|(id, _)| !(super::prepare::speculative(id)
                && rows.iter().any(|(other, h)| other != id && h["optimizer"]["resident"] == true)));
            if let Some((waiting, _)) = demand(&rows).filter(|_| first.is_none()) {
                WAITING.lock().unwrap_or_else(|p| p.into_inner()).insert(waiting.clone(),
                    "Being prepared in the background: it loads once no other model holds the GPU, or at once when a request arrives for it.".into());
            }
            if let Some((id,health)) = first {
                let others = rows.iter().filter(|(other,h)|other != id && h["optimizer"]["resident"] == true).cloned().collect::<Vec<_>>();
                let requested = match capacity_demand.get(id) {
                    Some(Ok(requested)) => *requested,
                    Some(Err(reason)) => {
                        WAITING.lock().unwrap_or_else(|p| p.into_inner()).insert(id.clone(), reason.clone());
                        continue;
                    },
                    None => continue,
                };
                // Co-residency (G03): a model with a ledger demand is admitted beside resident
                // models that all hold grants, at its stamped context when that fits, after
                // parking the idle ones when it does not, or at the longest context that fits
                // beside busy or pinned ones. Everything else keeps the one-resident path.
                let shared = requested.is_some() && !others.is_empty() && silent.is_empty() && !unreadable_marker
                    && others.iter().all(|(other, _)| capacity_markers.contains_key(other));
                if shared {
                    // The reason this model waits is co-admission's alone: the one-resident
                    // texts computed above (pinned, busy) do not apply beside granted residents.
                    WAITING.lock().unwrap_or_else(|p| p.into_inner()).remove(id);
                    let evictable = retention.order(evictable(&others), &rows);
                    let observations = seen.iter().filter_map(|row| row.health.clone().map(|h| (row.id.clone(), h))).collect::<Vec<_>>();
                    // The residents stamped with their facts can be held to a shorter context
                    // (their stamped one at most) to make a fair share for this model.
                    let resident_facts = others.iter().filter_map(|(other, _)| {
                        let facts = capacity_facts.get(other)?;
                        Some((other.clone(), (*facts, capacity_context.get(other).copied().unwrap_or_else(|| facts.served_context()))))
                    }).collect::<std::collections::BTreeMap<_, _>>();
                    // The residents it actually asks to unload are the parks retention charges for.
                    let parking = std::sync::Mutex::new(Vec::new());
                    let noting = |target: String, body: Value| {
                        if body["action"] == "unload" { parking.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(target.clone()); }
                        send(target, body)
                    };
                    let result = capacity::local_coadmit(id, health, &others, &evictable, &observations, &capacity_markers, &runners_gone,
                        requested.expect("a shared admission has a demand"), capacity_context.get(id).copied(), capacity_facts.get(id).copied(),
                        &resident_facts, &shutdown, &noting, &persist_capacity).await;
                    retention.note_parks(parking.into_inner().unwrap_or_else(std::sync::PoisonError::into_inner), std::time::Instant::now());
                    match result {
                        Ok(terms) => {
                            last_wait.remove(id);
                            eprintln!("GPU co-admission granted {id} {} bytes{} beside {} resident model(s)", terms.bytes,
                                terms.context.map_or(String::new(), |context| format!(" covering {context} tokens")), others.len());
                        }
                        Err(reason) => {
                            // Logged once per reason, not once per two-second pass.
                            let kind = refusal_kind(&reason);
                            if last_wait.get(id) != Some(&kind) {
                                eprintln!("GPU co-admission of {id} waits: {reason}");
                                last_wait.insert(id.clone(), kind);
                            }
                            let holders = others.iter().map(|(other, _)| name(other)).collect::<Vec<_>>().join(", ");
                            WAITING.lock().unwrap_or_else(|p| p.into_inner()).insert(id.clone(), capacity::waiting_words(&reason, &holders));
                        }
                    }
                    continue;
                }
                if must_wait(&rows, id, silent.len()) { continue; }
                if requested.is_some() || !capacity_markers.is_empty() || capacity::has_reservations() || unreadable_marker {
                    // Read all persisted grant intents, including stopped/failed
                    // members omitted from the active scheduler snapshot. Missing
                    // health is uncertainty, never permission to forget a grant.
                    if unreadable_marker {
                        WAITING.lock().unwrap_or_else(|p| p.into_inner()).insert(id.clone(), "GPU workload options could not be read; shared admission is paused.".into());
                        continue;
                    }
                    let observations = seen.iter().filter_map(|row| row.health.clone().map(|h| (row.id.clone(), h))).collect::<Vec<_>>();
                    // A runner parked by sleep asking again holds part of its own grant ([`capacity::Parked`]);
                    // the engine's probes around its park say how much.
                    let parked = sleeping.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(id).and_then(|park| park.credit(health));
                    // Other vLLM runners parked by sleep keep part of the GPU without being resident:
                    // once this model was refused for want of memory, they are unloaded with the
                    // residents (their engines end), or no other model fits.
                    let refused_for_room = last_wait.get(id).is_some_and(|kind| capacity::refused_for_room(kind));
                    let mut unload = others.clone();
                    unload.extend(parked_in_the_way(id, &rows, super::prepare::speculative(id), refused_for_room));
                    let result = capacity::local_switch(id, health, &unload, &observations, &capacity_markers, &runners_gone, requested, parked, &shutdown, &send, &persist_capacity).await;
                    if result.is_ok() { last_wait.remove(id); }
                    if let Err(reason) = &result {
                        // Logged once per reason, not once per pass.
                        let kind = refusal_kind(reason);
                        if last_wait.get(id) != Some(&kind) {
                            eprintln!("GPU admission of {id} waits: {reason}");
                            last_wait.insert(id.clone(), kind);
                        }
                    }
                    if let Err(reason) = result {
                        WAITING.lock().unwrap_or_else(|p| p.into_inner()).insert(id.clone(), reason);
                    }
                } else {
                    let _ = control::switch(id, health, &others, &shutdown, control::TIMEOUT, &send).await;
                }
            } else {
                let mut observations = seen.iter().filter_map(|row| row.health.clone().map(|h| (row.id.clone(), h))).collect::<Vec<_>>();
                for (id, h) in &rows {
                    let measured = sleeping.lock().unwrap_or_else(std::sync::PoisonError::into_inner).contains_key(id);
                    if sleeper(h) && !measured {
                        if let Ok(answer) = control::request(id, control::Action::Unload, h, &shutdown, control::TIMEOUT, &send).await {
                            if let Some((_, observed)) = observations.iter_mut().find(|(key, _)| key == id) { *observed = answer; }
                        }
                    }
                }
                for (id,h) in &rows {
                    if idle_expired(h) && !super::prepare::keeps(id) {
                        if let Ok(answer) = control::request(id, control::Action::Unload, h, &shutdown, control::TIMEOUT, &send).await {
                            if let Some((_, observed)) = observations.iter_mut().find(|(key, _)| key == id) { *observed = answer; }
                        }
                    }
                }
                if !unreadable_marker && (!capacity_markers.is_empty() || capacity::has_reservations()) {
                    // Residents keep their grants; a grant whose runner is gone, or answered
                    // holding nothing, returns through the host probe (G03 co-residency).
                    let residents = rows.iter().filter(|(_, h)| h["optimizer"]["resident"] == true).cloned().collect::<Vec<_>>();
                    if let Err(reason) = capacity::local_release(&residents, &observations, &capacity_markers, &runners_gone, &shutdown, &persist_capacity).await {
                        if reason != "GPU release is not yet confirmed." { eprintln!("GPU idle reconciliation: {reason}"); }
                    }
                }
                // Grow-back (G03): with no model waiting, a trimmed resident regains context
                // when a neighbour left (or memory was freed outside), within what the ledger
                // admits; its runner grows only on a fenced request and is shown only what it
                // answers holding.
                if !unreadable_marker && silent.is_empty() && capacity::growth_due() {
                    let residents = rows.iter().filter(|(id, h)| h["optimizer"]["resident"] == true && capacity_markers.contains_key(id)).cloned().collect::<Vec<_>>();
                    let candidates = residents.iter().filter_map(|(id, h)| {
                        let facts = capacity_facts.get(id)?;
                        let stamped = capacity_context.get(id).copied()?;
                        let current = h["optimizer"]["capacityContext"].as_u64()?;
                        (current < stamped).then(|| (id.clone(), (*facts, stamped, current)))
                    }).collect::<std::collections::BTreeMap<_, _>>();
                    if !residents.is_empty() {
                        match capacity::local_regrow(&residents, &candidates, &shutdown, &send).await {
                            Ok(grown) => for (id, terms) in grown {
                                eprintln!("GPU grant of {id} grew back to {} bytes{}", terms.bytes,
                                    terms.context.map_or(String::new(), |context| format!(" covering {context} tokens")));
                            },
                            Err(reason) => eprintln!("GPU grow-back: {reason}"),
                        }
                    }
                }
            }
        }
        };
        tokio::join!(scheduling, watching);
        // Nothing this scheduler bound is observed running any longer.
        let changes = binder.clear();
        runtime_binding::apply(changes, binder.unbound()).await;
    })
}

#[cfg(test)] mod tests {
    use super::*;
    #[tokio::test] async fn the_transformers_stamp_bridge_leaves_other_runners_on_the_legacy_scheduler() {
        // The runner check runs before the host probe, so nothing is spawned here.
        for runner in ["yougori-vllm", "yougori-clef", "local-transformers", "file-publisher"] {
            let compatibility = json!({"runner": runner, "resources": {"weightsBytes": 988_097_824u64, "gpuMemoryGbEstimated": 3,
                "attention": {"layers":24,"heads":14,"kvHeads":2,"headDim":64,"hiddenSize":896,"bytesPerValue":2,"contextTokens":32768}}});
            let before = json!({"YOUGORI_MODEL": "example/chat", "YOUGORI_MODEL_PRECISION": "auto"});
            let mut environment = before.clone();
            assert!(!stamp_local_capacity(&mut environment, &compatibility).await);
            assert_eq!(environment, before, "{runner}");
        }
    }
    fn fenced_health(resident: bool) -> Value {
        json!({"status":"idle","optimizer":{"controlProtocol":1,"instanceId":"a".repeat(32),"sequence":1,
            "enabled":true,"pinned":false,"resident":resident,"loading":false,"releaseUncertain":false,"active":0,"pending":0}})
    }
    #[test] fn malformed_versioned_health_preserves_occupancy_and_blocks_downgrade() {
        let mut fenced = std::collections::HashSet::new();
        let mut revisions = std::collections::HashMap::new();
        let mut resident = std::collections::HashSet::new();
        let mut good = vec![Seen { id:"model".into(), health:Some(fenced_health(true)) }];
        assert!(validate_seen(&mut good, &mut fenced, &mut revisions).is_empty());
        observe(&good, &mut resident);
        for answer in [None, Some(json!({"status":"idle","optimizer":{"controlProtocol":1}})),
                       Some(json!({"status":"idle","optimizer":{"enabled":true,"resident":false}}))] {
            let mut broken = vec![Seen { id:"model".into(), health:answer }];
            assert_eq!(validate_seen(&mut broken, &mut fenced, &mut revisions), vec!["model"]);
            assert!(broken[0].health.is_none());
            let (rows, silent) = observe(&broken, &mut resident);
            assert!(resident.contains("model"));
            assert!(must_wait(&rows, "other", silent.len()));
        }
        let mut recovered = vec![Seen { id:"model".into(), health:Some(fenced_health(false)) }];
        assert!(validate_seen(&mut recovered, &mut fenced, &mut revisions).is_empty());
        observe(&recovered, &mut resident);
        assert!(!resident.contains("model"));
    }
    #[test] fn invalid_fenced_members_block_even_without_a_previous_resident_snapshot() {
        let mut fenced = std::collections::HashSet::new();
        let mut revisions = std::collections::HashMap::new();
        let mut seen = vec![Seen { id:"unknown".into(), health:Some(json!({"optimizer":{"controlProtocol":2}})) }];
        assert_eq!(validate_seen(&mut seen, &mut fenced, &mut revisions), vec!["unknown"]);
        let mut downgraded = vec![Seen { id:"unknown".into(), health:Some(json!({"optimizer":{"enabled":true}})) }];
        assert_eq!(validate_seen(&mut downgraded, &mut fenced, &mut revisions), vec!["unknown"]);
        validate_seen(&mut [], &mut fenced, &mut revisions); // Membership removal ends this incarnation history.
        assert!(fenced.is_empty());
        assert!(validate_seen(&mut [Seen { id:"old".into(), health:Some(json!({"optimizer":{"enabled":true}})) }], &mut fenced, &mut revisions).is_empty());
    }
    #[test] fn same_instance_health_cannot_roll_back_a_known_revision_or_free_memory() {
        let mut fenced = std::collections::HashSet::new();
        let mut revisions = std::collections::HashMap::new();
        let mut resident = std::collections::HashSet::new();
        let mut current = fenced_health(true);
        current["optimizer"]["sequence"] = json!(9);
        let mut seen = vec![Seen { id:"model".into(), health:Some(current) }];
        assert!(validate_seen(&mut seen, &mut fenced, &mut revisions).is_empty());
        observe(&seen, &mut resident);
        let mut regressed = vec![Seen { id:"model".into(), health:Some(fenced_health(false)) }];
        assert_eq!(validate_seen(&mut regressed, &mut fenced, &mut revisions), vec!["model"]);
        observe(&regressed, &mut resident);
        assert!(resident.contains("model"));
        let mut replacement = fenced_health(false);
        replacement["optimizer"]["instanceId"] = json!("b".repeat(32));
        let mut replaced = vec![Seen { id:"model".into(), health:Some(replacement) }];
        assert!(validate_seen(&mut replaced, &mut fenced, &mut revisions).is_empty());
        observe(&replaced, &mut resident);
        assert!(!resident.contains("model"));
    }
    #[test] fn disabled_gpu_runners_keep_capacity_until_observed_empty() {
        for field in ["resident", "loading", "releaseUncertain"] {
            let mut health = fenced_health(false);
            health["optimizer"]["enabled"] = json!(false);
            health["optimizer"][field] = json!(true);
            let mut resident = std::collections::HashSet::new();
            let (rows, silent) = observe(&[Seen { id:"disabled".into(), health:Some(health.clone()) }], &mut resident);
            assert!(rows.is_empty());
            assert!(must_wait(&rows, "next", silent.len()));
            health["optimizer"][field] = json!(false);
            let (_, cleared) = observe(&[Seen { id:"disabled".into(), health:Some(health) }], &mut resident);
            assert!(cleared.is_empty());
        }
    }
    #[test] fn a_loading_or_uncertain_model_still_holds_memory_when_it_stops_answering() {
        for field in ["loading", "releaseUncertain"] {
            let mut health = json!({"optimizer":{"enabled":true,"resident":false}});
            health["optimizer"][field] = json!(true);
            let mut resident = std::collections::HashSet::new();
            observe(&[Seen { id:"model".into(), health:Some(health) }], &mut resident);
            let (_, silent) = observe(&[Seen { id:"model".into(), health:None }], &mut resident);
            assert_eq!(silent, vec!["model"]);
        }
    }
    #[test] fn resident_waits_for_other_model_demand_without_an_idle_deadline() {
        let resident = json!({"status":"ready","optimizer":{"resident":true,"idleTimeoutSeconds":0,"idleSeconds":86400,"pending":0}});
        let mut rows = vec![("current".into(),resident.clone())];
        assert!(!idle_expired(&resident));
        assert!(demand(&rows).is_none());
        rows.push(("next".into(),json!({"status":"queued","optimizer":{"pending":1,"resident":false,"waitingSince":1}})));
        assert_eq!(demand(&rows).unwrap().0,"next");
        assert!(!idle_expired(&resident));
    }
    #[test] fn only_a_model_that_held_the_gpu_keeps_it_from_being_granted() {
        let model = |id: &str, optimizer: Value| Seen { id: id.into(), health: Some(json!({"status":"ready","optimizer":optimizer})) };
        let waiting = || Seen { id: "waiting".into(), health: Some(json!({"status":"queued","optimizer":{"enabled":true,"pending":1,"resident":false,"waitingSince":1}})) };
        let holding = || model("other", json!({"enabled":true,"resident":true,"active":0,"pending":0}));
        let empty = || model("other", json!({"enabled":true,"resident":false,"active":0,"pending":0}));
        // Paused models are not asked, and an unanswering one says nothing: both are seen alike.
        let paused = || Seen { id: "other".into(), health: None };
        let unanswering = paused;
        // Each round is one pass of the scheduler; the answer is whether the waiting model is granted.
        let granted = |rounds: Vec<Vec<Seen>>| {
            let mut resident = std::collections::HashSet::new();
            rounds.into_iter().map(|round| {
                let (rows, silent) = observe(&round, &mut resident);
                !must_wait(&rows, "waiting", silent.len())
            }).last().unwrap()
        };
        // An idle resident model is asked to unload for the waiting one.
        assert!(granted(vec![vec![waiting(), holding()]]));
        // A model paused while it held no GPU memory holds none: it never blocks a grant.
        assert!(granted(vec![vec![waiting(), empty()], vec![waiting(), paused()]]));
        assert!(granted(vec![vec![waiting(), paused()]]));
        assert!(granted(vec![vec![waiting(), empty()], vec![waiting(), unanswering()]]));
        // One paused, or no longer answering, while it held the GPU may still hold it: wait.
        assert!(!granted(vec![vec![waiting(), holding()], vec![waiting(), paused()]]));
        assert!(!granted(vec![vec![waiting(), holding()], vec![waiting(), unanswering()]]));
        // Resumed and unloaded, it holds nothing again.
        assert!(granted(vec![vec![waiting(), holding()], vec![waiting(), paused()], vec![waiting(), empty()]]));
        // A resident model that is busy keeps it as well.
        assert!(!granted(vec![vec![waiting(), model("busy", json!({"enabled":true,"resident":true,"active":1}))]]));
    }
    #[test] fn a_model_waiting_for_the_gpu_says_which_model_holds_it_and_what_to_do() {
        let name = |id: &str| format!("Model {}", id.to_uppercase());
        let waiter = json!({"status":"queued","optimizer":{"pending":1,"resident":false,"waitingSince":1}});
        let behind = json!({"status":"queued","optimizer":{"pending":1,"resident":false,"waitingSince":2}});
        let idle = json!({"status":"ready","optimizer":{"resident":true,"active":0,"pending":0}});
        let busy = json!({"status":"ready","optimizer":{"resident":true,"active":1,"pending":0}});
        let pinned = json!({"status":"ready","optimizer":{"resident":true,"active":0,"pending":0,"pinned":true}});
        let loading = json!({"status":"loading","optimizer":{"resident":true,"loading":true}});
        let rows = |others: Vec<(&str, Value)>| {
            let mut rows = vec![("w".to_owned(), waiter.clone())];
            rows.extend(others.into_iter().map(|(id, health)| (id.to_owned(), health)));
            rows
        };
        // Held by a model that is paused or not answering: which one, and what to do.
        assert_eq!(reasons(&rows(vec![]), &["a".into()], name)["w"], "Model A still holds the GPU (paused or not answering). Resume or stop Model A to let this model load.");
        assert_eq!(reasons(&rows(vec![]), &["a".into(), "b".into()], name)["w"], "Paused or unresponsive models still hold the GPU: Model A, Model B. Resume or stop them to let this model load.");
        // Kept by a pinned model, loading or answering: named too.
        assert_eq!(reasons(&rows(vec![("p", pinned)]), &[], name)["w"], "Model P keeps the GPU because Prevent automatic model switching is on for it. Turn that off, or stop Model P, to let this model load.");
        assert_eq!(reasons(&rows(vec![("l", loading)]), &[], name)["w"], "Model L is loading into GPU memory. This model loads after it.");
        assert_eq!(reasons(&rows(vec![("b", busy.clone())]), &[], name)["w"], "Model B is using the GPU. This model loads once it is free.");
        // A model behind it in line waits for it.
        assert_eq!(reasons(&rows(vec![("b", busy), ("n", behind)]), &[], name)["n"], "Model W is first in line for the GPU. This model loads after it.");
        // One the scheduler grants now (an idle model is asked to unload) has nothing to explain,
        // and with nothing waiting there are no reasons left to show.
        assert!(!reasons(&rows(vec![("i", idle.clone())]), &[], name).contains_key("w"));
        assert!(reasons(&[("i".to_owned(), idle)], &[], name).is_empty());
    }
    #[test] fn timed_idle_unloading_remains_opt_in() {
        let mut health = json!({"optimizer":{"resident":true,"idleSeconds":119,"idleTimeoutSeconds":120}});
        assert!(!idle_expired(&health));
        health["optimizer"]["idleSeconds"] = json!(120);
        assert!(idle_expired(&health));
        health["optimizer"].as_object_mut().unwrap().remove("idleTimeoutSeconds");
        assert!(!idle_expired(&health));
    }
    #[test] fn a_grants_runner_is_gone_when_its_environment_ended_or_another_runner_answers_holding_nothing() {
        let marker = configuration::record(&fenced_health(false)).unwrap();
        let mut replacement = fenced_health(false);
        replacement["optimizer"]["instanceId"] = json!("b".repeat(32));
        let gone = |status: &EnvironmentStatus, health: Option<&Value>| runner_gone("model", "Model", status, &marker, health).map(|gone| gone.how);
        // The engine saw the container end, stopped or failed: nothing of its runner is asked.
        assert_eq!(gone(&EnvironmentStatus::Stopped, None), Some(capacity::Gone::Stopped));
        assert_eq!(gone(&EnvironmentStatus::Error, None), Some(capacity::Gone::Error));
        // A paused environment keeps its frozen memory; a provisioning one is not observed yet.
        assert_eq!(gone(&EnvironmentStatus::Paused, None), None);
        assert_eq!(gone(&EnvironmentStatus::Provisioning, None), None);
        // Running: only another instance holding no model is a replaced runner. The same
        // instance is today's path (a higher sequence settles it); no answer is unknown.
        assert_eq!(gone(&EnvironmentStatus::Running, None), None);
        assert_eq!(gone(&EnvironmentStatus::Running, Some(&fenced_health(false))), None);
        assert_eq!(gone(&EnvironmentStatus::Running, Some(&replacement)),
            Some(capacity::Gone::Replaced { old_instance: "a".repeat(32), new_instance: "b".repeat(32) }));
        for field in ["resident", "loading", "releaseUncertain"] {
            let mut holding = replacement.clone();
            holding["optimizer"][field] = json!(true);
            assert_eq!(gone(&EnvironmentStatus::Running, Some(&holding)), None, "{field}");
        }
        let mut busy = replacement.clone();
        busy["optimizer"]["active"] = json!(1);
        assert_eq!(gone(&EnvironmentStatus::Running, Some(&busy)), None);
        let mut disabled = replacement.clone();
        disabled["optimizer"]["enabled"] = json!(false);
        assert_eq!(gone(&EnvironmentStatus::Running, Some(&disabled)), None);
        let observed = runner_gone("model", "Model", &EnvironmentStatus::Stopped, &marker, None).unwrap();
        assert_eq!((observed.environment.as_str(), observed.name.as_str()), ("model", "Model"));
    }
    #[test] fn oldest_waiter_wins_and_loaded_or_failed_models_are_excluded() {
        let rows = vec![("loaded".into(),json!({"status":"ready","optimizer":{"pending":3,"resident":true,"waitingSince":1}})),
            ("new".into(),json!({"status":"queued","optimizer":{"pending":1,"waitingSince":20}})),
            ("old".into(),json!({"status":"queued","optimizer":{"pending":1,"waitingSince":10}})),
            ("failed".into(),json!({"status":"error","optimizer":{"pending":1,"waitingSince":0}}))];
        assert_eq!(demand(&rows).unwrap().0,"old");
    }
    #[test] fn only_vllm_runners_take_a_launch_mode() {
        let options = |pairs: &[(&str, &str)]| pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<std::collections::BTreeMap<_, _>>();
        for mode in LAUNCHES {
            assert_eq!(launch_refusal(&EnvironmentKind::Container, &options(&[("YOUGORI_MODEL_FORMAT", "vllm")]), mode), None);
        }
        for format in ["gguf", "safetensors"] {
            assert!(launch_refusal(&EnvironmentKind::Container, &options(&[("YOUGORI_MODEL_FORMAT", format)]), "speculative").unwrap().contains("Only vLLM"));
        }
        assert!(launch_refusal(&EnvironmentKind::Container, &options(&[]), "speculative").is_some());
        // A Neocloud pod's next start carries the launch (neocloud.rs forwards it to the pod).
        assert_eq!(launch_refusal(&EnvironmentKind::Cloud, &options(&[("YOUGORI_MODEL_FORMAT", "vllm")]), "megakernel"), None);
        // A vLLM model from a folder keeps every launch but the megakernel, whose start would not fit
        // the CUDA runtime's request (model_runner.rs, the injected-sources test).
        let folder = options(&[("YOUGORI_MODEL_FORMAT", "vllm"), ("YOUGORI_MODEL_PATH", "/yougori-model")]);
        for mode in ["compiled", "speculative", "eager"] {
            assert_eq!(launch_refusal(&EnvironmentKind::Container, &folder, mode), None, "{mode}");
        }
        assert!(launch_refusal(&EnvironmentKind::Container, &folder, "megakernel").unwrap().contains("from a folder"));
        // The modes engine_backends.py reads, in the same order.
        let backends = include_str!("engine_backends.py");
        assert_eq!(backends.matches("VLLM_LAUNCHES = (\"compiled\", \"speculative\", \"eager\", \"megakernel\")").count(), 1);
        assert_eq!(LAUNCHES, ["compiled", "speculative", "eager", "megakernel"]);
    }
    #[test] fn a_runner_reference_is_a_folder_with_a_manifest_or_a_pinned_hugging_face_repository() {
        let commit = "0123456789abcdef0123456789abcdef01234567";
        assert_eq!(runner_reference(&format!("hf:acme/fast-qwen@{commit}"), true), Ok(RunnerReference::Hub(format!("hf:acme/fast-qwen@{commit}"))));
        for bad in ["hf:acme/fast-qwen", "hf:acme/fast-qwen@main", "hf:acme@0123456789abcdef0123456789abcdef01234567", "hf:/x@0123456789abcdef0123456789abcdef01234567",
                    &format!("hf:acme/fast-qwen@{}", commit.to_uppercase())] {
            assert!(runner_reference(bad, false).unwrap_err().contains("hf:OWNER/REPO@COMMIT"), "{bad}");
        }
        let folder = tempfile::tempdir().unwrap();
        assert!(runner_reference(folder.path().to_str().unwrap(), false).unwrap_err().contains("no runner.json"));
        std::fs::write(folder.path().join("runner.json"), "{}").unwrap();
        let RunnerReference::Folder(saved) = runner_reference(folder.path().to_str().unwrap(), false).unwrap() else { panic!("a folder") };
        assert!(!saved.starts_with(r"\\?\") && std::path::Path::new(&saved).join("runner.json").is_file(), "{saved}");
        assert!(runner_reference(folder.path().to_str().unwrap(), true).unwrap_err().contains("Neocloud pod"), "a pod takes no folder");
        assert!(runner_reference(&folder.path().join("missing").to_string_lossy(), false).unwrap_err().contains("does not exist"));
        // Applied: a folder is the one bind at the runner target and the reference its path there;
        // a repository replaces an earlier folder's bind.
        let mut options = Options::default();
        assert_eq!(apply_runner(&mut options, &RunnerReference::Folder(saved.clone())), saved);
        assert_eq!(options.binds.len(), 1);
        assert_eq!((options.binds[0].target.as_str(), options.binds[0].read_only), (RUNNER_TARGET, true));
        assert_eq!(options.environment["YOUGORI_MODEL_RUNNER"], RUNNER_TARGET);
        apply_runner(&mut options, &RunnerReference::Hub(format!("hf:acme/fast-qwen@{commit}")));
        assert!(options.binds.is_empty());
        assert_eq!(options.environment["YOUGORI_MODEL_RUNNER"], format!("hf:acme/fast-qwen@{commit}"));
    }
    #[test] fn only_container_gguf_and_vllm_runners_take_a_parallel_setting() {
        let options = |pairs: &[(&str, &str)]| pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<std::collections::BTreeMap<_, _>>();
        for format in ["gguf", "vllm"] {
            assert_eq!(parallel_refusal(&EnvironmentKind::Container, &options(&[("YOUGORI_MODEL_FORMAT", format)])), None);
        }
        assert!(parallel_refusal(&EnvironmentKind::Container, &options(&[("YOUGORI_MODEL_FORMAT", "safetensors")])).unwrap().contains("one at a time"));
        assert!(parallel_refusal(&EnvironmentKind::Container, &options(&[])).is_some());
        assert!(parallel_refusal(&EnvironmentKind::Container, &options(&[("YOUGORI_MODEL_FORMAT", "gguf"), ("YOUGORI_NATIVE_BACKEND", "metal")])).unwrap().contains("native host"));
        assert!(parallel_refusal(&EnvironmentKind::Cloud, &options(&[("YOUGORI_MODEL_FORMAT", "gguf")])).unwrap().contains("cloud server"));
    }
    #[test] fn only_container_gguf_runners_take_a_context_window_of_4096_to_262144_tokens_in_steps_of_1024() {
        let options = |pairs: &[(&str, &str)]| pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<std::collections::BTreeMap<_, _>>();
        let gguf = options(&[("YOUGORI_MODEL_FORMAT", "gguf")]);
        for tokens in [4096, 32_768, 65_536, 131_072, 262_144, 5120] {
            assert_eq!(context_refusal(&EnvironmentKind::Container, &gguf, tokens), None, "{tokens}");
        }
        for tokens in [0, 1024, 3072, 4095, 131_000, 131_073, 263_168, u64::MAX] {
            assert!(context_refusal(&EnvironmentKind::Container, &gguf, tokens).unwrap().contains("4,096–262,144 tokens in steps of 1,024"), "{tokens}");
        }
        for (format, words) in [("media", "--keep-outputs"), ("vllm", "fits its context window to the GPU"), ("safetensors", "Only GGUF models"), ("source", "Only GGUF models")] {
            assert!(context_refusal(&EnvironmentKind::Container, &options(&[("YOUGORI_MODEL_FORMAT", format)]), 131_072).unwrap().contains(words), "{format}");
        }
        assert!(context_refusal(&EnvironmentKind::Container, &options(&[]), 131_072).is_some());
        assert!(context_refusal(&EnvironmentKind::Container, &options(&[("YOUGORI_MODEL_FORMAT", "gguf"), ("YOUGORI_NATIVE_BACKEND", "metal")]), 131_072).unwrap().contains("native host"));
        assert!(context_refusal(&EnvironmentKind::Cloud, &gguf, 131_072).unwrap().contains("cloud server"));
    }
    #[test] fn output_retention_and_launch_change_alone_and_start_settings_go_with_live_ones() {
        // (live, start, launch, keep outputs)
        for alone in [(true, false, false, false), (false, true, false, false), (true, true, false, false), (false, false, true, false), (false, false, false, true), (false, false, false, false)] {
            assert_eq!(alone_refusal(alone.0, alone.1, alone.2, alone.3), None, "{alone:?}");
        }
        for (live, start, launch) in [(true, false, false), (false, true, false), (false, false, true)] {
            assert!(alone_refusal(live, start, launch, true).unwrap().contains("output retention on its own"));
        }
        // The context window, like parallel requests, is a start setting: not beside a launch.
        for (live, start) in [(true, false), (false, true), (true, true)] {
            assert!(alone_refusal(live, start, true, false).unwrap().contains("launch mode on its own"));
        }
    }
    #[test] fn start_settings_are_saved_for_the_next_start_and_answered_with_restart_required() {
        let mut options = Options::default();
        start_settings(&mut options, None, Some(131_072));
        assert_eq!(options.environment[MODEL_CONTEXT], "131072");
        assert!(!options.environment.contains_key("YOUGORI_MODEL_PARALLEL"));
        start_settings(&mut options, Some(2), None);
        assert_eq!((options.environment["YOUGORI_MODEL_PARALLEL"].as_str(), options.environment[MODEL_CONTEXT].as_str()), ("2", "131072"));
        // engine_backends.py reads the same variable.
        assert_eq!(include_str!("engine_backends.py").matches("\"YOUGORI_MODEL_CONTEXT\"").count(), 1);
        // A GGUF model under the llama.cpp admission profile reserves for the window it saved.
        let mut stamped = Options::default();
        stamped.environment.extend([(capacity::POLICY.to_owned(), "local-single-llama-cpp-v1".to_owned()), (capacity::DEMAND.to_owned(), "1".to_owned()),
            (capacity::GGUF.to_owned(), r#"{"tensorBytes":1000,"kvBytesPerToken":10}"#.to_owned())]);
        start_settings(&mut stamped, None, Some(131_072));
        assert_eq!(stamped.environment[capacity::DEMAND], (1000 + 10 * 131_072 + 512 * 1024 * 1024u64).to_string());
        // Alone, and beside the settings the runner acknowledged.
        assert_eq!(start_answer(json!({}), None, Some(131_072)), json!({"context": 131_072, "restartRequired": true}));
        assert_eq!(start_answer(json!({}), Some(4), None), json!({"parallel": 4, "restartRequired": true}));
        assert_eq!(start_answer(json!({}), Some(4), Some(65_536)), json!({"parallel": 4, "context": 65_536, "restartRequired": true}));
        assert_eq!(start_answer(json!({"enabled": true}), None, Some(65_536)), json!({"enabled": true, "context": 65_536, "restartRequired": true}));
        assert_eq!(start_answer(json!({"enabled": true}), None, None), json!({"enabled": true}));
    }

    #[test] fn real_demand_goes_before_a_model_waiting_only_for_its_preparation() {
        let rows = vec![
            ("prepared".into(),json!({"status":"queued","optimizer":{"pending":1,"resident":false,"waitingSince":1}})),
            ("requested".into(),json!({"status":"queued","optimizer":{"pending":1,"resident":false,"waitingSince":5}}))];
        assert_eq!(demand_by(&rows, |_| false).unwrap().0, "prepared");
        assert_eq!(demand_by(&rows, |id| id == "prepared").unwrap().0, "requested");
        // A preparation alone in line is still served.
        assert_eq!(demand_by(&rows[..1], |id| id == "prepared").unwrap().0, "prepared");
    }
    #[test] fn a_reload_costs_what_a_retained_load_repeats() {
        // A first load (it downloaded): what a reload repeats is its engine start.
        let cold = json!({"inProgress":false,"outcome":"ok","elapsedMs":20_000.0,
            "stages":{"admission_wait":1_000.0,"snapshot":13_000.0,"download":12_000.0,"engine_start_to_ready":3_500.0}});
        let reload = reload_of_load(&cold).unwrap();
        assert!((reload.reload_seconds - 3.5).abs() < 1e-9 && !reload.woke);
        // A reload of retained files: its own time less its GPU wait.
        let warm = json!({"inProgress":false,"outcome":"ok","elapsedMs":4_200.0,"stages":{"admission_wait":200.0,"engine_start_to_ready":3_900.0}});
        assert!((reload_of_load(&warm).unwrap().reload_seconds - 4.0).abs() < 1e-9);
        // A parked vLLM's wake: its engine wake plus weight reload.
        let wake = json!({"inProgress":false,"outcome":"ok","elapsedMs":900.0,"stages":{"engine_wake":591.0,"weight_reload":153.0}});
        let reload = reload_of_load(&wake).unwrap();
        assert!((reload.reload_seconds - 0.744).abs() < 1e-9 && reload.woke);
        // Nothing for a load still running or failed; never below 0.1 s.
        assert!(reload_of_load(&json!({"inProgress":true,"outcome":"ok","elapsedMs":5.0,"stages":{}})).is_none());
        assert!(reload_of_load(&json!({"inProgress":false,"outcome":"error","elapsedMs":5.0,"stages":{}})).is_none());
        let tiny = json!({"inProgress":false,"outcome":"ok","elapsedMs":10.0,"stages":{"admission_wait":10.0}});
        assert_eq!(reload_of_load(&tiny).unwrap().reload_seconds, 0.1);
    }
    #[test] fn models_cheap_to_bring_back_per_byte_are_parked_first() {
        let gib = 1u64 << 30;
        let resident = |idle: u64, bytes: u64| json!({"status":"ready","optimizer":{"resident":true,"active":0,"pending":0,"idleSeconds":idle,"allocatedBytes":bytes}});
        let rows = vec![("vllm-sleeper".to_owned(), resident(5, 20 * gib)), ("gguf".to_owned(), resident(5, 2 * gib)), ("fresh".to_owned(), resident(0, 2 * gib))];
        {
            let mut reloads = RELOADS.lock().unwrap();
            reloads.insert("vllm-sleeper".into(), Reload { reload_seconds: 0.8, woke: true, observed: 1.0 });
            reloads.insert("gguf".into(), Reload { reload_seconds: 4.0, woke: false, observed: 2.0 });
            reloads.remove("fresh");
        }
        let now = std::time::Instant::now();
        let mut retention = Retention::default();
        retention.observe(&rows, now);
        // Every model is credited its reload cost when first seen in use: 0.8 s over 20 GiB is
        // cheaper per byte than 4 s over 2 GiB or the 30 s assumed for one never measured.
        let order = retention.order(vec!["gguf".into(), "fresh".into(), "vllm-sleeper".into()], &rows);
        assert_eq!(order, vec!["vllm-sleeper".to_owned(), "gguf".to_owned(), "fresh".to_owned()]);
        // The model the scheduler sent to park charges every other one rent and is forgotten.
        retention.note_parks(vec!["vllm-sleeper".into()], now);
        let mut parked = rows.clone();
        parked[0].1["optimizer"]["resident"] = json!(false);
        retention.observe(&parked, now);
        assert!(retention.policy.credit("vllm-sleeper").is_none());
        let rent = retention.policy.credit("gguf").unwrap();
        assert!(rent < 4.0, "{rent}");
        // A departure the scheduler did not choose (a stop, an idle unload) only forgets the
        // model; one that stops answering keeps its place for a minute of silence.
        let mut stopped = parked.clone();
        stopped[2].1["optimizer"]["resident"] = json!(false);
        retention.observe(&stopped, now);
        assert!(retention.policy.credit("fresh").is_none());
        assert_eq!(retention.policy.credit("gguf"), Some(rent));
        retention.observe(&stopped[..1], now + Duration::from_secs(59));
        assert_eq!(retention.policy.credit("gguf"), Some(rent));
        retention.observe(&stopped[..1], now + Duration::from_secs(120));
        assert!(retention.policy.credit("gguf").is_none() && retention.seen.is_empty());
        for id in ["vllm-sleeper", "gguf", "fresh"] { RELOADS.lock().unwrap().remove(id); }
    }
    #[test] fn models_parked_together_charge_the_rest_once() {
        let gib = 1u64 << 30;
        let resident = |bytes: u64| json!({"status":"ready","optimizer":{"resident":true,"active":0,"pending":0,"idleSeconds":5,"allocatedBytes":bytes}});
        let rows = vec![("park-a".to_owned(), resident(2 * gib)), ("park-b".to_owned(), resident(2 * gib)), ("keep-c".to_owned(), resident(gib))];
        {
            let mut reloads = RELOADS.lock().unwrap();
            reloads.insert("park-a".into(), Reload { reload_seconds: 4.0, woke: false, observed: 1.0 });
            reloads.insert("park-b".into(), Reload { reload_seconds: 8.0, woke: false, observed: 1.0 });
            reloads.insert("keep-c".into(), Reload { reload_seconds: 100.0, woke: false, observed: 1.0 });
        }
        let now = std::time::Instant::now();
        let mut retention = Retention::default();
        retention.observe(&rows, now);
        retention.note_parks(vec!["park-a".into(), "park-b".into()], now);
        let mut left = rows.clone();
        for row in &mut left[..2] { row.1["optimizer"]["resident"] = json!(false); }
        retention.observe(&left, now);
        // 2 s/GiB then 4 s/GiB parked in turn: C pays 4 s/GiB over its 1 GiB once, not 2 + 4.
        assert_eq!(retention.policy.credit("keep-c"), Some(96.0));
        assert!(retention.parked.is_empty());
        for id in ["park-a", "park-b", "keep-c"] { RELOADS.lock().unwrap().remove(id); }
    }

    /// A vLLM runner parked by sleep (instance `instance`), with `pending` requests of its own
    /// waiting; `ends` says whether its runner ends a parked engine while they wait.
    fn parked_runner(instance: char, pending: u64, ends: bool) -> Value {
        let mut health = fenced_health(false);
        health["parked"] = json!("sleep");
        health["status"] = json!(if pending > 0 { "queued" } else { "idle" });
        health["optimizer"]["instanceId"] = json!(instance.to_string().repeat(32));
        health["optimizer"]["pending"] = json!(pending);
        if ends { health["optimizer"]["endsParkedWhileWaiting"] = json!(true); }
        health
    }

    #[test] fn a_waiting_parked_engine_ends_for_the_first_in_line_once_it_was_refused_for_room() {
        // A is first in line; B, parked by sleep, waits behind it, its leftover in A's way.
        let rows = vec![("a".to_owned(), parked_runner('a', 1, true)), ("b".to_owned(), parked_runner('b', 2, true)),
            ("idle".to_owned(), parked_runner('c', 0, false)), ("old".to_owned(), parked_runner('d', 1, false))];
        let ended = |speculative, refused| parked_in_the_way("a", &rows, speculative, refused).into_iter().map(|(id, _)| id).collect::<Vec<_>>();
        // Once A was refused for want of memory: the waiting B and the idle one end, never A's own
        // engine, nor that of a runner that refuses such an unload while its requests wait.
        assert_eq!(ended(false, true), ["b", "idle"]);
        // A model that may fit beside their leftovers, or one a preparation started, ends none.
        assert!(ended(false, false).is_empty());
        assert!(ended(true, true).is_empty());
        // The idle unload still takes only idle sleepers.
        assert!(sleeper(&rows[2].1) && !sleeper(&rows[1].1));
        // Busy, loading or awake runners are no parked engines.
        for (field, value) in [("active", json!(1)), ("loading", json!(true)), ("resident", json!(true)), ("pinned", json!(true)), ("releaseUncertain", json!(true))] {
            let mut busy = rows[1].1.clone();
            busy["optimizer"][field] = value;
            assert!(!parked_engine(&busy), "{field}");
        }
        assert!(control::ends_parked_while_waiting(&rows[1].1) && !control::ends_parked_while_waiting(&rows[3].1));
        assert!(capacity::refused_for_room(&refusal_kind("GPU capacity is not available: VRAM on GPU x: 22583493552 bytes requested, 1203 bytes free")));
        assert!(!capacity::refused_for_room("GPU eviction or target fencing was not confirmed. Capacity remains reserved."));
    }

    #[test] fn the_same_refusal_with_other_byte_counts_is_logged_once() {
        let first = "GPU capacity is not available: VRAM on GPU x: 22583493552 bytes requested, 1203961856 bytes free under this host's capacity; it fits after 1514010624 bytes is released";
        let next = "GPU capacity is not available: VRAM on GPU x: 22583493552 bytes requested, 1198718976 bytes free under this host's capacity; it fits after 1519253504 bytes is released";
        assert_eq!(refusal_kind(first), refusal_kind(next));
        assert_ne!(refusal_kind(first), refusal_kind("GPU grant outcome is unconfirmed. Its reservation remains held until reconciliation."));
    }

    #[test] fn a_park_is_credited_and_kept_only_while_its_engine_is_parked() {
        let reply = json!({"unloaded": true, "parked": "sleep", "optimizer": {"instanceId": "a".repeat(32)}});
        let park = Park::of(&reply, 10 << 30, 3 << 30);
        let parked = parked_runner('a', 1, true);
        assert_eq!(park.credit(&parked), Some(capacity::Parked { before: 10 << 30, after: 3 << 30 }));
        assert!(park.describes(&parked, false));
        // Its wake loads, then holds the model bound again: kept until the cycle is recorded.
        let mut waking = fenced_health(false);
        waking["optimizer"]["instanceId"] = json!("a".repeat(32));
        waking["optimizer"]["loading"] = json!(true);
        assert!(park.describes(&waking, false) && park.credit(&waking).is_none());
        let mut awake = fenced_health(true);
        awake["optimizer"]["instanceId"] = json!("a".repeat(32));
        assert!(park.describes(&awake, true));
        // Holding a model it is not bound with, its engine ended (an unload that did not park), or
        // another runner instance: the numbers describe no engine it has, and are never credited.
        assert!(!park.describes(&awake, false));
        let mut ended = fenced_health(false);
        ended["optimizer"]["instanceId"] = json!("a".repeat(32));
        assert!(!park.describes(&ended, false) && park.credit(&ended).is_none());
        let replaced = parked_runner('b', 1, true);
        assert!(!park.describes(&replaced, false) && park.credit(&replaced).is_none());
    }
}
