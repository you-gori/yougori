use crate::{models::*, runtime::RuntimeManager, store::PlatformStore};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use tauri::Manager;
use crate::AppHandle;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
mod neocloud;
pub(crate) mod optimizer;
pub(crate) mod measurement;
mod local;
mod catalog_binding;
mod import_phase;
pub(crate) mod helpers;
pub(crate) mod migration;
pub(crate) mod prepare;
pub(crate) mod lora;
pub(crate) mod macos;
mod compute;
pub(crate) mod huggingface;
pub(crate) mod preflight;
mod vllm;
mod streaming;
#[cfg(test)]
mod packaging;
pub(crate) use neocloud::{agent_preflight, run_neocloud_agent_model, start_model, stop_model};
/// Owner settings (recording, publisher downloads, usage reset) require a second credential that
/// stays in the container and this engine. The API key is shared with apps and the network.
pub(crate) const ADMIN_TOKEN: &str = "YOUGORI_MODEL_ADMIN_TOKEN";
/// A container keeps the environment it was configured with, and a model's start reconfigures
/// it only when the start changes the saved options. An owner setting the runner reads when it
/// starts (GPU memory settings, adapters) marks the options when it is saved between starts; the
/// next start removes the mark, and that change carries every saved setting into the container.
const START_MARK: &str = "YOUGORI_RECONFIGURE_AT_START";
pub(crate) fn mark_for_start(options: &mut yougori_cli::workload::Options) {
    options.environment.insert(START_MARK.into(), "1".into());
}
pub(crate) fn marked_for_start(options: &yougori_cli::workload::Options) -> bool {
    options.environment.contains_key(START_MARK)
}
const ADMIN_PATHS: [&str; 5] = ["/v1/listen/config", "/v1/usage/reset", "/v1/yougori/publishing", "/v1/yougori/adapters", "/v1/yougori/kv"];
fn timing_diagnostics(path: &str) -> bool {
    matches!(path.split('?').next(), Some("/v1/diagnostics/timings" | "/v1/diagnostics/load"))
}

/// The local production host ledger, shared by GPU and host-memory consumers.
/// Startup initializes it without a GPU; None if host evidence is unavailable.
/// Its observations can expire: refresh before new host-level admission.
#[allow(dead_code)] // VM/transfer production enrollment remains a separate task.
pub(crate) fn host_capacity_ledger() -> Option<crate::foundation::coordination::SharedLedger<crate::foundation::ids::SystemClock>> {
    optimizer::shared_host_ledger()
}

/// The `model_ledger` method: the shared host ledger's reservations as they stand (read-only).
pub(crate) fn ledger_view() -> Value {
    optimizer::ledger_view()
}

/// Observe host RAM and CPU-initialization slots before a VM/transfer admission,
/// returning the same ledger used by local GPU models. No tenant budget is granted
/// here, and initialization slots do not account for a VM's vCPU allocation.
#[allow(dead_code)] // The composed VM service consumes this handoff next.
pub(crate) async fn refresh_host_capacity(shutdown: &tokio_util::sync::CancellationToken) -> Result<crate::foundation::coordination::SharedLedger<crate::foundation::ids::SystemClock>, String> {
    optimizer::refresh_host_capacity(shutdown).await
}
pub(crate) async fn refresh_gpu_capacity(shutdown: &tokio_util::sync::CancellationToken) -> Result<crate::foundation::coordination::SharedLedger<crate::foundation::ids::SystemClock>, String> {
    optimizer::refresh_gpu_capacity(shutdown).await
}
fn admin_reference() -> Result<String, String> {
    let reference = format!("model-admin-{}", uuid::Uuid::new_v4().simple());
    crate::projects::secrets::store(&reference, &format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple()))?;
    Ok(reference)
}
pub(crate) fn ensure_admin_token(options: &mut yougori_cli::workload::Options) -> Result<(), String> {
    if !options.secret_environment.contains_key(ADMIN_TOKEN) {
        options.secret_environment.insert(ADMIN_TOKEN.into(), admin_reference()?);
    }
    Ok(())
}
pub fn normalize_model(model: &str) -> Result<String, String> {
    if crate::model_registry::is_registry(model.trim()) { return Ok(model.trim().into()); }
    let model = model
        .trim()
        .strip_prefix("https://huggingface.co/")
        .or_else(|| model.trim().strip_prefix("hf.co/"))
        .unwrap_or(model.trim());
    let parts = model.split('/').collect::<Vec<_>>();
    if parts.len() != 2
        || parts.iter().any(|s| {
            s.is_empty()
                || s.len() > 96
                || s.starts_with(['.', '-'])
                || s.ends_with(['.', '-'])
                || s.contains("..")
                || !s
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        })
    {
        return Err(
            "Use a Hugging Face model ID such as hf.co/TinyLlama/TinyLlama-1.1B-Chat-v1.0".into(),
        );
    }
    Ok(model.into())
}
#[tauri::command]
pub async fn run_model(model: String, port: Option<u16>, quant: Option<String>, folder: Option<String>, backend: Option<String>, memory_gb: Option<f64>, app: AppHandle, window: crate::WebviewWindow) -> Result<Value, String> {
    // A local model folder is a raw host path: dashboard or same-user CLI only.
    if folder.is_some() { crate::host_terminal::require_dashboard(window.label())?; }
    run_model_with_resources(model, port, Some(ModelResources { model_folder:folder, backend, memory_gb, ..Default::default() }), quant, app).await
}
/// The dashboard's `--neocloud`: serve a model on an existing, powered-on RunPod GPU pod.
#[tauri::command]
pub async fn run_neocloud_model(model: String, environment_id: String, port: Option<u16>, app: AppHandle) -> Result<Value, String> {
    neocloud::run_neocloud_model(model, environment_id, port, app).await
}
#[tauri::command]
pub async fn model_compute_status(app: AppHandle) -> Result<Value, String> {
    let runtime = app.state::<RuntimeManager>();
    if cfg!(target_os="macos") { return Ok(runtime.native_model_capabilities().await); }
    let cuda = runtime.cuda_status().await;
    Ok(json!({"os":std::env::consts::OS,"architecture":std::env::consts::ARCH,"native":false,
        "available":true,"metalSupported":false,"cudaSupported":cuda.supported,
        "backend":if cuda.supported {"cuda"} else {"cpu"},"unifiedMemory":false}))
}
/// Safetensors models run on the PyTorch CUDA image. GGUF models need a newer C library for the
/// pinned llama.cpp CUDA build, which the model server downloads and verifies itself.
const TRANSFORMERS_IMAGE: &str = "docker.io/pytorch/pytorch:2.8.0-cuda12.8-cudnn9-runtime";
const LLAMA_CPP_IMAGE: &str = "docker.io/library/python:3.12-slim-trixie";

#[derive(Default, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModelResources {
    pub cpu: Option<f64>,
    pub memory_gb: Option<f64>,
    pub storage_gb: Option<f64>,
    pub storage_drive: Option<String>,
    pub model_folder: Option<String>,
    #[serde(default)]
    pub cpu_only: bool,
    pub backend: Option<String>,
    #[serde(default)]
    pub agent_api: bool,
    /// The ownership stamp of the setup that makes this model, kept in its workload as
    /// `YOUGORI_SETUP_STAMP`. Only the setup engine sets it; a model without one is the person's.
    #[serde(default)]
    pub setup_stamp: Option<String>,
    /// `vllm` serves a checkpoint Transformers would run on the pinned vLLM image instead
    /// (`preflight::prefer_vllm`); `auto` or none keeps the preflight's runner.
    #[serde(default)]
    pub runner: Option<String>,
}

/// Where a model made by a setup carries that setup's stamp (`ModelResources::setup_stamp`).
pub(crate) const SETUP_STAMP: &str = "YOUGORI_SETUP_STAMP";

impl ModelResources {
    /// The setup stamp, checked: one line of plain characters, never a value from elsewhere.
    fn stamp(&self) -> Result<Option<&str>, String> {
        match self.setup_stamp.as_deref() {
            None => Ok(None),
            Some(stamp) if !stamp.is_empty() && stamp.len() <= 200 && stamp.bytes().all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b)) => Ok(Some(stamp)),
            Some(_) => Err("A setup stamp uses up to 200 letters, digits, dots, colons, slashes, dashes or underscores".into()),
        }
    }
    /// Whether `--runner vllm` was asked for; any other value than `vllm` or `auto` is refused.
    fn wants_vllm(&self) -> Result<bool, String> {
        match self.runner.as_deref() {
            None | Some("auto") => Ok(false),
            Some("vllm") => Ok(true),
            Some(_) => Err("--runner takes vllm or auto".into()),
        }
    }
    /// Puts the setup's stamp, if any, in a new model's workload environment.
    fn stamp_into(&self, environment: &mut Value) -> Result<(), String> {
        if let Some(stamp) = self.stamp()? {
            environment[SETUP_STAMP] = json!(stamp);
        }
        Ok(())
    }
}

/// The vault entries a new model's workload holds only for itself: its API key, admin token and
/// GPU control token. The shared Hugging Face token is never one of them.
fn own_references(protected: &Value) -> Vec<String> {
    protected.as_object().into_iter().flat_map(|names| names.values()).filter_map(Value::as_str).filter(|reference| own_reference(reference)).map(str::to_owned).collect()
}

fn own_reference(reference: &str) -> bool {
    ["model-api-", "model-admin-", "gpu-control-"].iter().any(|prefix| reference.starts_with(prefix))
}

/// The model environment that carries `stamp`, if any. `Err` when a model's workload can't be
/// read, so a caller deciding to forget something treats it as possibly there.
fn stamped(app: &AppHandle, stamp: &str) -> Result<Option<String>, String> {
    let runtime = app.state::<RuntimeManager>();
    for env in app.state::<PlatformStore>().snapshot()?.environments.iter().filter(|env| env.description.starts_with("Hugging Face · ")) {
        let options = runtime.workload_options(env.runtime_id.as_deref().unwrap_or(&env.id))?;
        if options.environment.get(SETUP_STAMP).map(String::as_str) == Some(stamp) {
            return Ok(Some(env.id.clone()));
        }
    }
    Ok(None)
}

/// After a setup's model could not be made, forgets the vault entries this attempt stored for it.
/// A sandbox with the setup's stamp that exists after all still needs them, so they stay then.
fn forget_unmade(app: &AppHandle, resources: &ModelResources, protected: &Value) {
    let Ok(Some(stamp)) = resources.stamp() else { return };
    if !matches!(stamped(app, stamp), Ok(None)) {
        return;
    }
    for reference in own_references(protected) {
        let _ = crate::projects::secrets::forget(&reference);
    }
}

/// The vault entries only this model's workload refers to, for the setup that made it to forget
/// once it is deleted. Empty for a model no setup made, and for one whose entries another
/// workload also uses (a duplicate, say).
fn sole_references(app: &AppHandle, environment_id: &str, options: &yougori_cli::workload::Options) -> Vec<String> {
    if !options.environment.contains_key(SETUP_STAMP) {
        return Vec::new();
    }
    let mut references = options.secret_environment.values().filter(|reference| own_reference(reference)).cloned().collect::<Vec<_>>();
    let runtime = app.state::<RuntimeManager>();
    let Ok(state) = app.state::<PlatformStore>().snapshot() else { return Vec::new() };
    for env in state.environments.iter().filter(|env| env.id != environment_id) {
        match runtime.workload_options(env.runtime_id.as_deref().unwrap_or(&env.id)) {
            Ok(other) => references.retain(|reference| !other.secret_environment.values().any(|used| used == reference)),
            // Unreadable: it might use them, so nothing is offered for forgetting.
            Err(_) => return Vec::new(),
        }
    }
    references
}

impl ModelResources {
    fn allocation(&self, total_cpu: usize, total_memory: f64, available_storage: f64) -> Result<(f64, f64, f64), String> {
        // The GPU does the work, so a model needs little CPU or memory of its own.
        let cpu = self.cpu.unwrap_or(2.0);
        let memory = self.memory_gb.unwrap_or(4.0);
        let storage = self.storage_gb.unwrap_or(available_storage.min(20.0));
        if !cpu.is_finite() || cpu < 2.0 || cpu > total_cpu as f64 || !memory.is_finite() || memory < 4.0 || memory > total_memory {
            return Err("Models require at least 2 CPU cores and 4 GB RAM, within this computer's capacity".into());
        }
        if !storage.is_finite() || storage > available_storage {
            return Err("Model storage exceeds available capacity".into());
        }
        if storage < 12.0 {
            return Err("Model workloads need at least 12 GB of available storage for the model runtime and weights".into());
        }
        Ok((cpu, memory, storage))
    }
}

/// Where a model environment keeps its own model files: the runner's Hugging Face cache.
const MODEL_CACHE: &str = "/root/.cache/huggingface";

/// A new model environment's own cache volume, named so model deletion recognizes it as the
/// environment's own (`model_cache_names` in runtime/workload.rs).
fn model_cache_volume() -> String {
    format!("model-{}-models", &uuid::Uuid::new_v4().simple().to_string()[..8])
}

/// The `workload` of a new model environment (G04, GPU-W01). A Hugging Face model downloads
/// into its own cache volume. A local folder or registry version is bound read-only at
/// `/yougori-model` as the import source; with a cache volume the runner imports it there
/// once (`YOUGORI_MODEL_IMPORT`) and reads only the copy, without one it reads the bind.
fn model_workload(mut environment: Value, protected: &Value, folder: Option<&Value>, cache: Option<&str>) -> Value {
    if folder.is_some() && cache.is_some() {
        environment["YOUGORI_MODEL_IMPORT"] = json!("1");
    }
    let mut workload = json!({"environment":environment,"secretEnvironment":protected});
    if let Some(cache) = cache {
        workload["volumes"] = json!([{"source":cache,"target":MODEL_CACHE,"readOnly":false}]);
    }
    if let Some(folder) = folder {
        workload["binds"] = json!([{"source":folder,"target":"/yougori-model","readOnly":true}]);
    }
    workload
}

/// Whole GB of persistent storage for an environment that imports `bytes` of model files into
/// its own cache volume: the files plus 15% and 12 GB for the runtime, at least 20 GB, as the
/// registry preflight recommends (model_registry.rs).
pub(crate) fn import_storage_gb(bytes: u64) -> u64 {
    (bytes.saturating_mul(23).div_ceil(20 << 30) + 12).max(20)
}

/// Sizes a new environment whose runner imports the model's files: the preflight's
/// recommendation unless the person chose more. Less is refused before anything is made, as a
/// Hugging Face model's is.
fn import_storage(resources: &mut ModelResources, check: &Value) -> Result<(), String> {
    let required = check["resources"]["storageGbRecommended"].as_f64().unwrap_or(20.0).max(20.0);
    match resources.storage_gb {
        None => resources.storage_gb = Some(required),
        Some(chosen) if chosen < required => {
            return Err(format!("This model needs approximately {required:.0} GB of persistent storage to import its files and run. No environment was created."));
        }
        Some(_) => {}
    }
    Ok(())
}

pub async fn run_model_with_resources(model: String, port: Option<u16>, resources: Option<ModelResources>, quant: Option<String>, app: AppHandle) -> Result<Value, String> {
    run_model_at_revision(model,port,resources,quant,None,None,app).await
}
async fn run_model_at_revision(model: String, port: Option<u16>, resources: Option<ModelResources>, quant: Option<String>, pinned: Option<String>, precision: Option<String>, app: AppHandle) -> Result<Value, String> {
    let model = normalize_model(&model)?;
    if let Some(resources) = &resources {
        // A setup's model is downloaded and verified like any other, never served from a folder.
        if resources.stamp()?.is_some() && resources.model_folder.is_some() {
            return Err("A setup runs a model from Hugging Face or Yougori, not from a folder on this computer".into());
        }
    }
    let wants_vllm = resources.as_ref().map(ModelResources::wants_vllm).transpose()?.unwrap_or(false);
    if resources.as_ref().is_some_and(|r|r.model_folder.is_some()) {return local::run(model,port,resources.unwrap(),quant,app).await;}
    if crate::model_registry::is_registry(&model) {
        if wants_vllm { return Err("--runner vllm takes a Hugging Face model or a folder; a Yougori registry version runs as published. No environment was created.".into()); }
        return run_registry_model(model,port,resources,quant,app).await;
    }
    let mut compatibility=preflight::preflight_pinned(&model, quant.as_deref(),pinned.as_deref()).await?;
    if compatibility["supported"]!=true {
        let help=if compatibility["supportAvailable"]==true {format!(" Implement support with `yougori model support hf.co/{model} --agent codex --launch` or choose a coding agent in the App.")}else{String::new()};
        return Err(format!("{}: {}. No environment was created.{help}",model,compatibility["reason"].as_str().unwrap_or("Model compatibility could not be established")));
    }
    if wants_vllm { preflight::prefer_vllm(&mut compatibility)?; }
    let cpu_only = resources.as_ref().is_some_and(|r| r.cpu_only);
    let mut backend = compute::Backend::select(std::env::consts::OS, std::env::consts::ARCH,
        resources.as_ref().and_then(|r| r.backend.as_deref()), cpu_only)?;
    if backend == compute::Backend::Metal && resources.as_ref().and_then(|r|r.backend.as_deref()).is_none_or(|b|b=="auto")
        && app.state::<RuntimeManager>().native_model_capabilities().await["metalSupported"] != true {
        backend = compute::Backend::MacCpu;
    }
    if backend.native() {
        if resources.as_ref().is_some_and(|r| r.setup_stamp.is_some()) {
            return Err("Setups run models in a model sandbox; this Mac's native runner isn't available to setups yet. No environment was created.".into());
        }
        if compatibility["runner"] != "yougori-llama-cpp" {
            return Err("Native Mac inference currently requires GGUF weights. Select a supported GGUF repository.".into());
        }
        let mut resources = resources.unwrap_or_default();
        resources.backend = Some(backend.name().into());
        if resources.memory_gb.is_none() { resources.memory_gb = Some(compatibility["resources"]["gpuMemoryGbEstimated"].as_f64().unwrap_or(4.).max(4.)); }
        let host = app.state::<PlatformStore>().snapshot()?.host;
        let free = app.state::<RuntimeManager>().new_storage_on_drive(resources.storage_drive.as_deref())?.maximum_gb;
        resources.allocation(host.total_cpu,host.total_memory_gb,free)?;
        let required = compatibility["resources"]["storageGbRecommended"].as_f64().unwrap_or(20.);
        if free < required { return Err(format!("Native model storage needs approximately {required:.0} GB free")); }
        let folder = macos::download(&model, &compatibility, &resources, &app).await?;
        resources.model_folder = Some(folder.to_string_lossy().into_owned());
        return local::run_verified(model, port, resources, compatibility, app).await;
    }
    let cpu_only = backend == compute::Backend::Cpu;
    if cpu_only && compatibility["runner"] != "yougori-llama-cpp" {
        return Err("CPU model workers currently require a supported GGUF repository. Choose a GGUF variant or an NVIDIA GPU.".into());
    }
    let shared_capacity = if !cpu_only { vllm::check_local_hardware(&compatibility).await? } else { false };
    if port == Some(0) {
        return Err("Invalid API port".into());
    }
    let mut resources=resources.unwrap_or_default();
    // A vLLM model without a memory choice gets the preflight's RAM recommendation, not the 4 GB
    // default its API server and engine core outgrow (preflight::VLLM_MEMORY_GB).
    if compatibility["runner"] == "yougori-vllm" && resources.memory_gb.is_none() { resources.memory_gb = compatibility["resources"]["memoryGbRecommended"].as_f64(); }
    let available = app
        .state::<RuntimeManager>()
        .new_storage_on_drive(resources.storage_drive.as_deref())?
        .maximum_gb;
    let state = app.state::<PlatformStore>().snapshot()?;
    let host = state.host;
    let required_storage=compatibility["resources"]["storageGbRecommended"].as_f64().unwrap_or(20.0).max(12.0);
    if resources.storage_gb.is_none(){resources.storage_gb=Some(required_storage.max(20.0));}
    if resources.storage_gb.is_some_and(|s|s<required_storage){return Err(format!("This model needs approximately {required_storage:.0} GB of persistent storage for its weights and runtime. No environment was created."))}
    let (cpu, memory, storage) = resources.allocation(host.total_cpu, host.total_memory_gb, available)?;
    let token = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    let token_reference=format!("model-api-{}",uuid::Uuid::new_v4().simple());
    crate::projects::secrets::store(&token_reference,&token)?;
    let name = yougori_cli::public::model_environment_name(&model, state.environments.iter().map(|e| e.name.as_str()));
    let volume = model_cache_volume();
    let range = |n: f64| json!({"min":n,"preferred":n,"max":n});
    let command = server_command();
    let gguf = compatibility["runner"] == "yougori-llama-cpp";
    let vllm = compatibility["runner"] == "yougori-vllm";
    let mut protected = json!({"YOUGORI_MODEL_TOKEN": token_reference});
    protected[ADMIN_TOKEN] = json!(admin_reference()?);
    if let Some(token) = huggingface::token() {
        crate::projects::secrets::store(huggingface::TOKEN_REFERENCE, &token)?;
        protected["HF_TOKEN"] = json!(huggingface::TOKEN_REFERENCE);
    }
    let mut environment = json!({"YOUGORI_MODEL":model,"YOUGORI_MODEL_REVISION":compatibility["revision"],"HF_HOME":"/root/.cache/huggingface","HF_HUB_DISABLE_TELEMETRY":"1"});
    if resources.agent_api { environment["YOUGORI_MODEL_AGENT_API"] = json!("1"); }
    environment["YOUGORI_PUBLISHER_SOURCE"] = json!(publisher_source());
    environment["YOUGORI_MODEL_PRECISION"] = json!(precision.as_deref().unwrap_or(if pinned.is_some(){"original"}else{"auto"}));
    if model == "Cloudflare/clef" { environment["YOUGORI_CLEF_SOURCE"] = json!(clef_source()); }
    if gguf {
        environment["YOUGORI_MODEL_FORMAT"] = json!("gguf");
        environment["YOUGORI_MODEL_QUANT"] = compatibility["quant"].clone();
        environment["YOUGORI_MODEL_FILES"] = json!(compatibility["files"].to_string());
    }
    if vllm { environment["YOUGORI_MODEL_FORMAT"] = json!("vllm"); }
    resources.stamp_into(&mut environment)?;
    optimizer::environment(&mut environment, &mut protected)?;
    if shared_capacity { optimizer::stamp_capacity(&mut environment, &compatibility)?; }
    // A Transformers chat model on this host's one GPU joins host-ledger admission when the
    // demand covering its context fits (G03), and a GGUF model with the demand its header gives;
    // a quantized registry version, Clef and several GPUs keep the legacy scheduler.
    else if !cpu_only { optimizer::stamp_local_capacity(&mut environment, &compatibility).await; }
    if cpu_only {
        environment["YOUGORI_MODEL_CPU"] = json!("1");
        environment["YOUGORI_MODEL_CPU_THREADS"] = json!(cpu.floor().max(1.).min(64.).to_string());
        environment["YOUGORI_GPU_OPTIMIZER"] = json!("0");
    }
    // The helpers the rollout serves to this runner (G08): bundles into the workload, the
    // model server's own bundle as the command; source injection for the rest.
    let mut command = command;
    let mut workload = model_workload(environment.clone(), &protected, None, Some(&volume));
    let selected = serve_helpers_into(&mut workload, &mut command)?;
    let request = json!({"name":name,"kind":"container","provider":if cpu_only {"yougoriOci"} else {"yougoriCuda"},"autoSetupCuda":!cpu_only,"runtime":if gguf {LLAMA_CPP_IMAGE} else if vllm {vllm::IMAGE} else {TRANSFORMERS_IMAGE},"containerCommand":command,"gpuAccess":!cpu_only,"networkAccess":true,"storageGb":storage,"storageDrive":resources.storage_drive,"description":format!("Hugging Face · {model}"),"resourcePolicy":{"cpu":range(cpu),"memoryGb":range(memory),"priority":"normal","dynamic":false},"workload":workload,"ports":port.map(|p|vec![format!("{p}:8000")]).unwrap_or_default()});
    let mut result = crate::projects::run_workload(request, true, app.clone()).await.inspect_err(|_| forget_unmade(&app, &resources, &protected))?;
    result["helpers"] = record_runner_start(&app, result["id"].as_str().unwrap_or_default(), selected).await;
    result["model"] = model.into();
    result["status"] = json!("loading");
    result["preflight"]=compatibility;
    if let Some(port) = port {
        result["apiUrl"] = json!(format!("http://127.0.0.1:{port}/v1"));
        result["apiKey"] = token.into();
    }
    Ok(result)
}
async fn run_registry_model(model:String,port:Option<u16>,resources:Option<ModelResources>,quant:Option<String>,app:AppHandle)->Result<Value,String>{
    let resolved=crate::model_registry::resolve_quant(&model,quant.as_deref()).await?;
    let version=&resolved["version"];
    let version_id=version["id"].as_str().ok_or("Missing registry version")?;
    if version["source"]=="endpoint" && (version["delivery"]!="publisher" || resolved["model"]["canDownload"]!=true) { return Err(format!("This model runs on the publisher's endpoint. Use model={model} with your Yougori API key.")); }
    if quant.as_deref().is_some_and(|q|!version["quant"].as_str().is_some_and(|saved|q.eq_ignore_ascii_case(saved))) {return Err("The requested precision does not match this published version; use its exact quantized variant".into())}
    if version["source"]=="huggingface" {
        let repo=version["upstreamModel"].as_str().ok_or("Missing Hugging Face checkpoint")?;
        let gguf=version["files"].as_array().is_some_and(|files|files.iter().any(|f|f.as_str().is_some_and(|name|name.ends_with(".gguf"))));
        let precision=match version["quant"].as_str(){Some("NF4")=>Some("4bit".into()),Some("INT8")=>Some("8bit".into()),_=>None};
        let mut result=Box::pin(run_model_at_revision(repo.into(),port,resources,if gguf{version["quant"].as_str().map(str::to_owned)}else{None},version["revision"].as_str().map(str::to_owned),precision,app.clone())).await?;
        let id=result["id"].as_str().ok_or("Missing environment ID")?;
        let runtime=app.state::<RuntimeManager>();let state=app.state::<PlatformStore>().snapshot()?;
        let env=state.environments.iter().find(|e|e.id==id).ok_or("Model environment not found")?;
        let runtime_id=env.runtime_id.as_deref().unwrap_or(id);
        let mut options=runtime.workload_options(runtime_id)?;
        options.environment.insert("YOUGORI_REGISTRY_MODEL".into(),model.clone());
        options.environment.insert("YOUGORI_REGISTRY_VERSION".into(),version_id.into());runtime.save_workload_options(runtime_id,&options)?;
        app.state::<PlatformStore>().mutate(|s|{if let Some(e)=s.environments.iter_mut().find(|e|e.id==id){e.description=format!("Hugging Face · {model}");}Ok(())})?;
        result["model"]=json!(model);return Ok(result)
    }
    let mut check=crate::model_registry::preflight(&model,quant.as_deref()).await?;
    if check["supported"]!=true {return Err(check["reason"].as_str().unwrap_or("Unsupported uploaded architecture").into())}
    if port==Some(0){return Err("Invalid API port".into())}
    let mut resources=resources.unwrap_or_default();
    let backend = compute::Backend::select(std::env::consts::OS,std::env::consts::ARCH,resources.backend.as_deref(),resources.cpu_only)?;
    // A CUDA runner imports the version's files into its own volume once (G04): size it for them.
    if backend == compute::Backend::Cuda { import_storage(&mut resources,&check)?; }
    let state=app.state::<PlatformStore>().snapshot()?;
    let available=app.state::<RuntimeManager>().new_storage_on_drive(resources.storage_drive.as_deref())?.maximum_gb;
    let required=version["weightsBytes"].as_f64().unwrap_or(0.0)/1073741824.0*1.15+resources.storage_gb.unwrap_or(20.0);
    if available<required{return Err(format!("This drive needs approximately {required:.0} GB free for verified model artifacts and its GPU runtime"))}
    let (cpu,memory,storage)=resources.allocation(state.host.total_cpu,state.host.total_memory_gb,available)?;
    let cached=crate::model_registry::cached(&model,resources.storage_drive.as_deref(),version_id,&app).await?;
    let folder=cached["folder"].as_str().ok_or("Missing model artifact folder")?;
    // Once the version's files are cached, its preflight learns what the Transformers admission
    // profile needs (G03): the safetensors bytes and the configuration's attention shape.
    preflight::registry_admission_facts(&mut check,std::path::Path::new(folder),cached["files"].as_array().map(Vec::as_slice).unwrap_or(&[]));
    if backend != compute::Backend::Cuda {
        if version["format"] != "gguf" { return Err("This backend requires a GGUF publication".into()); }
        let mut resources = resources;
        resources.model_folder = Some(folder.into());
        let files:Vec<Value> = cached["files"].as_array().into_iter().flatten().filter(|f|f["name"].as_str().is_some_and(|n|n.ends_with(".gguf"))).cloned().collect();
        let bytes:f64 = files.iter().filter_map(|f|f["size"].as_u64()).map(|n|n as f64).sum();
        let native_check = json!({"supported":true,"format":"gguf","runner":"yougori-llama-cpp","revision":version["revision"],"quant":version["quant"],"files":files,
            "resources":{"gpuMemoryGbEstimated":(bytes/1073741824.*1.15+1.5).ceil()}});
        let result = local::run_verified(model.clone(),port,resources,native_check,app.clone()).await?;
        let id=result["id"].as_str().ok_or("Missing environment ID")?;
        let runtime=app.state::<RuntimeManager>();
        let env=app.state::<PlatformStore>().environment(id)?;
        let runtime_id=env.runtime_id.as_deref().unwrap_or(id);
        let mut options=runtime.workload_options(runtime_id)?;
        options.environment.insert("YOUGORI_REGISTRY_MODEL".into(),model);
        options.environment.insert("YOUGORI_REGISTRY_VERSION".into(),version_id.into());
        runtime.save_workload_options(runtime_id,&options)?;
        return Ok(result);
    }
    // The catalog path (G04/S02) for the registry's verified folder: with the engine catalog
    // open its files and its verified-files record are published once and the workload binds
    // a read-only view of the copies (see `catalog_binding`); without a catalog the cached
    // folder is bound, as before.
    let binding={
        let (folder,check,files)=(folder.to_owned(),check.clone(),cached["files"].as_array().cloned().unwrap_or_default());
        import_phase::blocking("catalog", move |cancel| catalog_binding::bind_registry_engine(std::path::Path::new(&folder),&check,&files,cancel).map_err(|e|e.to_string()), import_phase::release_binding).await?
    };
    let mut adopted = false;
    let outcome = async {
    import_phase::check()?;
    let token=format!("{}{}",uuid::Uuid::new_v4().simple(),uuid::Uuid::new_v4().simple());
    let reference=format!("model-api-{}",uuid::Uuid::new_v4().simple());crate::projects::secrets::store(&reference,&token)?;
    let gguf=version["format"]=="gguf";
    let mut environment=registry_environment(&model,version,version_id,&cached,&binding)?;
    let mut protected=json!({"YOUGORI_MODEL_TOKEN":reference});
    protected[ADMIN_TOKEN]=json!(admin_reference()?);
    resources.stamp_into(&mut environment)?;
    optimizer::environment(&mut environment,&mut protected)?;
    // A Transformers chat version at original precision on this host's one GPU joins host-ledger
    // admission when the demand covering its context fits (G03); a quantized version (its
    // precision is 4bit or 8bit) and GGUF keep the legacy scheduler.
    optimizer::stamp_local_capacity(&mut environment,&check).await;
    let range=|n:f64|json!({"min":n,"preferred":n,"max":n});
    let name=yougori_cli::public::model_environment_name(&model,state.environments.iter().map(|e|e.name.as_str()));
    let mut command=server_command();
    let mut workload=model_workload(environment.clone(),&protected,Some(&json!(binding.bind_source(folder))),Some(&model_cache_volume()));
    let selected=serve_helpers_into(&mut workload,&mut command)?;
    import_phase::check().inspect_err(|_|forget_unmade(&app,&resources,&protected))?;
    let mut result=crate::projects::run_workload(json!({"name":name,"kind":"container","provider":"yougoriCuda","autoSetupCuda":true,"runtime":if gguf{LLAMA_CPP_IMAGE}else{TRANSFORMERS_IMAGE},"containerCommand":command,"gpuAccess":true,"networkAccess":true,"storageGb":storage,"storageDrive":resources.storage_drive,"description":format!("Hugging Face · {model}"),"resourcePolicy":{"cpu":range(cpu),"memoryGb":range(memory),"priority":"normal","dynamic":false},"workload":workload,"ports":port.map(|p|vec![format!("{p}:8000")]).unwrap_or_default()}),true,app.clone()).await.inspect_err(|_|forget_unmade(&app,&resources,&protected))?;
    adopted = true;
    result["helpers"]=record_runner_start(&app,result["id"].as_str().unwrap_or_default(),selected).await;
    result["model"]=json!(model);result["status"]=json!("loading");result["preflight"]=check;result["catalog"]=binding.result();
    if let Some(port)=port{result["apiUrl"]=json!(format!("http://127.0.0.1:{port}/v1"));result["apiKey"]=json!(token);}
    Ok(result)
    }.await;
    if !adopted { catalog_binding::release_unadopted(&binding).await; }
    outcome
}

/// The workload variables of `environment` (a JSON object of strings), for the helper rollout.
fn environment_map(environment: &Value) -> std::collections::BTreeMap<String, String> {
    environment
        .as_object()
        .map(|object| {
            object
                .iter()
                .filter_map(|(name, value)| value.as_str().map(|value| (name.clone(), value.to_owned())))
                .collect()
        })
        .unwrap_or_default()
}

/// Serves the helpers the rollout selects for a new runner (G08; `helpers::serve`) into its
/// workload: the variables naming the served bundles go into `environment`, the served
/// directory's read-only bind into `workload`, and a model server served from a bundle
/// replaces `command`. A selection the rollout refuses, or a bundle that cannot be served, is
/// this start's error; a journal that is unavailable leaves source injection, as before.
pub(super) fn serve_helpers_into(
    workload: &mut Value,
    command: &mut String,
) -> Result<Vec<crate::model_memory::helpers::RunnerHelpers>, String> {
    let served = match helpers::serve(&environment_map(&workload["environment"])) {
        Ok(served) => served,
        Err(refusal) if helpers::blocks_start(&refusal) => return Err(refusal.to_string()),
        Err(refusal) => {
            eprintln!("Model helpers were not selected for a new runner: {refusal}");
            return Ok(Vec::new());
        }
    };
    // Into the workload's own variables: `model_workload` added the import flag there, and a
    // copy of the caller's environment put over them lost it (the second GPU run of 30
    // October: a new folder environment read its mount on every load).
    for (name, value) in &served.variables {
        workload["environment"][*name] = json!(value);
    }
    if let Some(bind) = served.bind() {
        match workload.get_mut("binds").and_then(Value::as_array_mut) {
            Some(binds) => binds.push(bind),
            None => workload["binds"] = json!([bind]),
        }
    }
    if let Some(served_command) = served.command {
        *command = served_command;
    }
    Ok(served.selected)
}

/// Records what the new model runner `environment_id` starts with in the helper rollout journal
/// (G08; `helpers::record_start` with exactly what `serve_helpers_into` served) and describes
/// it for the run result. A journal that is not open or refuses to record is reported in the
/// result, never a reason to undo the start the workload already made.
pub(super) async fn record_runner_start(
    app: &AppHandle,
    environment_id: &str,
    selected: Vec<crate::model_memory::helpers::RunnerHelpers>,
) -> Value {
    let recorded = (|| -> Result<helpers::Start, String> {
        let state = app.state::<PlatformStore>().snapshot()?;
        let env = state.environments.iter().find(|e| e.id == environment_id).ok_or("Model environment not found")?;
        let options = app.state::<RuntimeManager>().workload_options(env.runtime_id.as_deref().unwrap_or(&env.id))?;
        helpers::record_start(environment_id, &options.environment, selected).map_err(|refusal| refusal.to_string())
    })();
    match recorded {
        Ok(start) => start.view(),
        Err(detail) => json!({"state": "not_recorded", "detail": detail}),
    }
}

/// The `model_helpers` method with the runtime at hand: `opt-in` sets or clears
/// `YOUGORI_HELPERS_OPT_IN` on a model environment's workload (its next start takes the opt-in
/// candidates of its helpers' tracks); every other action is `helpers::dispatch`.
pub(crate) async fn helpers_dispatch(app: AppHandle, action: Option<String>, params: Value) -> Result<Value, String> {
    if action.as_deref() == Some("opt-in") {
        let environment_id = params["environment"].as_str().filter(|id| !id.is_empty()).ok_or("model_helpers opt-in: environment is required")?.to_owned();
        let enabled = params["enabled"].as_bool().unwrap_or(true);
        let state = app.state::<PlatformStore>().snapshot()?;
        let env = state.environments.iter().find(|e| e.id == environment_id).ok_or("Model environment not found")?;
        let runtime = app.state::<RuntimeManager>();
        let options_id = env.runtime_id.as_deref().unwrap_or(&env.id);
        let mut options = runtime.workload_options(options_id)?;
        if enabled {
            options.environment.insert(helpers::OPT_IN_OPTION.into(), "1".into());
        } else {
            options.environment.remove(helpers::OPT_IN_OPTION);
        }
        runtime.save_workload_options(options_id, &options)?;
        return Ok(json!({
            "environment": environment_id,
            "optedIn": enabled,
            "detail": if enabled { "The next start of this model takes the opt-in candidates of its helpers' tracks; a running model keeps what it started with until it restarts." } else { "The next start of this model takes its helpers' defaults." },
            "status": helpers::status(),
        }));
    }
    if action.as_deref() == Some("trial") {
        return helpers::trial::run(app, params).await;
    }
    tokio::task::spawn_blocking(move || helpers::dispatch(action, &params)).await.map_err(|e| e.to_string())?
}

/// The workload environment of a registry model on the CUDA path, before its secrets, stamp
/// and GPU optimizer. It never carries YOUGORI_LOCAL_MANIFEST: the runner then verifies the
/// mount against the registry's own record, `.yougori-verified-files.json`
/// (`registry_snapshot.py`, lines 22–30), which a catalog view holds too. On the catalog path
/// it carries the catalog's execution, model and content options (`catalog_binding`).
fn registry_environment(model:&str,version:&Value,version_id:&str,cached:&Value,binding:&catalog_binding::Binding)->Result<Value,String>{
    let gguf=version["format"]=="gguf";
    let upstream=version["upstreamModel"].as_str().unwrap_or(model);
    let mut environment=json!({"YOUGORI_MODEL":upstream,"YOUGORI_REGISTRY_MODEL":model,"YOUGORI_REGISTRY_VERSION":version_id,"YOUGORI_MODEL_REVISION":version["revision"],"YOUGORI_MODEL_PATH":"/yougori-model","YOUGORI_REGISTRY_SOURCE":registry_source(),"YOUGORI_MODEL_PRECISION":"original","HF_HOME":"/root/.cache/huggingface","HF_HUB_DISABLE_TELEMETRY":"1"});
    environment["YOUGORI_PUBLISHER_SOURCE"]=json!(publisher_source());
    if version["prequantized"]!=true {if let Some(precision)=match version["quant"].as_str(){Some("NF4")=>Some("4bit"),Some("INT8")=>Some("8bit"),_=>None}{environment["YOUGORI_MODEL_PRECISION"]=json!(precision);}}
    if gguf {environment["YOUGORI_MODEL_FORMAT"]=json!("gguf");environment["YOUGORI_MODEL_QUANT"]=version["quant"].clone();let files=cached["files"].as_array().into_iter().flatten().filter(|file|file["name"].as_str().is_some_and(|name|name.ends_with(".gguf"))).cloned().collect::<Vec<_>>();environment["YOUGORI_MODEL_FILES"]=json!(serde_json::to_string(&files).map_err(|e|e.to_string())?);}
    for (name,value) in catalog_binding::workload_variables(None,binding) {environment[name]=json!(value);}
    Ok(environment)
}

/// The model catalog binding an environment holds, read while its workload options still
/// exist: the runtime removes them with the container and its storage, so a release that reads
/// them afterwards finds nothing (the first hardware run of the catalog path found exactly
/// that, a view and its leases left held after a delete). `None` when the environment serves
/// no catalog binding.
pub(crate) fn model_catalog_binding(runtime_id: &str, runtime: &RuntimeManager) -> Option<yougori_cli::workload::Options> {
    runtime
        .workload_options(runtime_id)
        .ok()
        .filter(|options| options.environment.contains_key(catalog_binding::EXECUTION_OPTION))
}

/// Sweeps the served helper directories no environment's options bind (G08); `older_than` as
/// [`helpers::sweep_served`] takes it.
pub(crate) fn sweep_unbound_served(
    state: &crate::models::PlatformState,
    runtime: &RuntimeManager,
    older_than: Option<std::time::Duration>,
) -> (Vec<std::path::PathBuf>, Vec<String>) {
    let bound: std::collections::BTreeSet<std::path::PathBuf> = state
        .environments
        .iter()
        .filter_map(|env| runtime.workload_options(env.runtime_id.as_deref().unwrap_or(&env.id)).ok())
        .flat_map(|options| options.binds.into_iter())
        .filter(|bind| bind.target == helpers::HELPERS_TARGET)
        .map(|bind| std::path::PathBuf::from(bind.source))
        .collect();
    helpers::sweep_served(&bound, older_than)
}

/// At the engine's start, before the scheduler's first pass: every running or paused model
/// environment on the catalog path leases its model again and keeps its view, so a container
/// that kept running across the restart never loses the bind under it; every other view is
/// swept (S02 "restart-safe views and leases"; `catalog_binding::restore_engine`). Reported,
/// never fatal.
pub(crate) fn restore_catalog_views(store: &PlatformStore, runtime: &RuntimeManager) {
    let Ok(state) = store.snapshot() else { return };
    let running: Vec<crate::catalog_service::RunningModel> = state
        .environments
        .iter()
        .filter(|env| env.kind == EnvironmentKind::Container && matches!(env.status, EnvironmentStatus::Running | EnvironmentStatus::Paused))
        .filter_map(|env| {
            let options = runtime.workload_options(env.runtime_id.as_deref().unwrap_or(&env.id)).ok()?;
            match catalog_binding::running_model(&env.id, &options) {
                Ok(model) => model,
                Err(error) => {
                    eprintln!("Model catalog view of {} was not restored: {error}", env.id);
                    None
                }
            }
        })
        .collect();
    // Served helper directories no environment binds are swept with the stale views (G08).
    let (swept, failures) = sweep_unbound_served(&state, runtime, None);
    if !swept.is_empty() || !failures.is_empty() {
        eprintln!(
            "Served helper directories at start: {} swept, {} not removed{}",
            swept.len(),
            failures.len(),
            if failures.is_empty() { String::new() } else { format!(" ({})", failures.join("; ")) }
        );
    }
    match catalog_binding::restore_engine(&running) {
        Ok(Some(restored)) => {
            if !restored.restored.is_empty() || !restored.failures.is_empty() || !restored.swept.removed.is_empty() {
                eprintln!(
                    "Model catalog views at start: {} restored, {} failed, {} swept{}",
                    restored.restored.len(),
                    restored.failures.len(),
                    restored.swept.removed.len(),
                    if restored.failures.is_empty() { String::new() } else { format!(" ({})", restored.failures.join("; ")) }
                );
            }
        }
        Ok(None) => {}
        Err(error) => eprintln!("Model catalog views were not restored at start: {error}"),
    }
}

/// Gives a deleted environment's catalog leases and view back ([`model_catalog_binding`] read
/// them before the deletion). The published copies stay for the next import.
pub(crate) async fn release_model_catalog(options: yougori_cli::workload::Options) -> Result<bool, String> {
    tokio::task::spawn_blocking(move || catalog_binding::release_engine(&options).map_err(|error| error.to_string()))
        .await
        .map_err(|error| error.to_string())?
}
/// The container command that runs this version's model server.
fn server_payload() -> String {
    let mut compressed = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    std::io::Write::write_all(&mut compressed, include_bytes!("model_server.py"))
        .expect("writing the embedded model server to memory");
    STANDARD.encode(compressed.finish().expect("compressing the embedded model server"))
}
/// How this version's model server command starts. Older environments were made with
/// `exec python -u -c `; `refresh_server` recognizes both and replaces the old one.
const SERVER_COMMAND_PREFIX: &str = "exec python3 -u -c ";
const SERVER_COMMAND_PREFIXES: [&str; 2] = [SERVER_COMMAND_PREFIX, "exec python -u -c "];
fn server_command() -> String {
    // Keep startup below the guest command limit regardless of runner growth.
    // The public compressed source travels in the workload environment instead.
    // `python3` is in every runner image; the pinned vLLM image has no `python`.
    format!("{SERVER_COMMAND_PREFIX}{}", shell_quote(
        "import os,base64,zlib;exec(compile(zlib.decompress(base64.b64decode(os.environ['YOUGORI_MODEL_SERVER_SOURCE'])),'yougori-model','exec'))"))
}

fn clef_source() -> String {
    let mut adapter = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    std::io::Write::write_all(&mut adapter, include_bytes!("model_runner/adapters/clef/joint_schema_model.py")).expect("compressing the bundled Clef adapter");
    STANDARD.encode(adapter.finish().expect("finishing the bundled Clef adapter"))
}
fn publisher_source() -> String {
    let mut source=flate2::write::ZlibEncoder::new(Vec::new(),flate2::Compression::best());
    std::io::Write::write_all(&mut source,include_str!("model_runner/publisher_artifacts.py").replace("\r\n","\n").as_bytes()).expect("compressing publisher routes");
    STANDARD.encode(source.finish().expect("finishing publisher routes"))
}
fn registry_source() -> String {
    let mut adapter=flate2::write::ZlibEncoder::new(Vec::new(),flate2::Compression::best());
    std::io::Write::write_all(&mut adapter,include_str!("model_runner/registry_snapshot.py").replace("\r\n","\n").as_bytes()).expect("compressing the bundled registry verifier");
    STANDARD.encode(adapter.finish().expect("finishing the bundled registry verifier"))
}
/// The llama.cpp and vLLM loaders (`model_runner/engine_backends.py`, the engine-backends helper):
/// the model server executes them before a GGUF or vLLM load, after checking them against the
/// digest it ships (`BACKENDS_SHA256`), so its own source stays under the guest's 64 KiB variable.
fn backends_source() -> String {
    let mut source=flate2::write::ZlibEncoder::new(Vec::new(),flate2::Compression::best());
    std::io::Write::write_all(&mut source,include_str!("model_runner/engine_backends.py").replace("\r\n","\n").as_bytes()).expect("compressing the engine backends");
    STANDARD.encode(source.finish().expect("finishing the engine backends"))
}
/// Whether a runner of this format loads the engine backends: GGUF (llama.cpp) and vLLM.
fn loads_backends(format: Option<&str>) -> bool {
    matches!(format, Some("gguf" | "vllm"))
}
/// The model server a new runner carries, with the engine backends when its format loads them.
fn carry_server(environment: &mut Value) {
    environment["YOUGORI_MODEL_SERVER_SOURCE"] = json!(server_payload());
    if loads_backends(environment["YOUGORI_MODEL_FORMAT"].as_str()) {
        environment["YOUGORI_BACKENDS_SOURCE"] = json!(backends_source());
    }
}
pub(crate) fn server_source() -> String {
    format!("__YOUGORI_GPU_SOURCE__ = '{}'\n__YOUGORI_CLEF_SOURCE__ = '{}'\n__YOUGORI_PUBLISHER_SOURCE__ = '{}'\n__YOUGORI_BACKENDS_SOURCE__ = '{}'\n{}", optimizer::source(), clef_source(), publisher_source(), backends_source(), include_str!("model_server.py"))
}
/// Brings a stopped model environment's server up to this version before it starts, so reused
/// environments get the same fixes as new ones. Only commands this runner wrote are replaced.
pub(crate) async fn refresh_server(
    environment_id: &str,
    store: &PlatformStore,
    runtime: &RuntimeManager,
) -> Result<(), String> {
    let state = store.snapshot()?;
    let Some(env) = state.environments.iter().find(|e| e.id == environment_id) else {
        return Ok(());
    };
    // Environments from before models were named after themselves take the model's name.
    if let Some(model) = env.description.strip_prefix("Hugging Face · ") {
        if yougori_cli::public::generated_model_name(&env.name) {
            let others = state.environments.iter().filter(|e| e.id != env.id);
            let name = yougori_cli::public::model_environment_name(model, others.map(|e| e.name.as_str()));
            store.mutate(|state| {
                if let Some(env) = state.environments.iter_mut().find(|e| e.id == environment_id) {
                    env.name = name;
                }
                Ok(())
            })?;
        }
    }
    let current = env.container_command.as_deref().unwrap_or_default();
    let command = server_command();
    if env.status != EnvironmentStatus::Stopped || !is_server_command(current) {
        return Ok(());
    }
    // Older model environments could reserve only 1 CPU/2 GiB. Upgrade their
    // floor before admission and scheduling, while preserving larger settings.
    if env.resource_policy.cpu.min < 2.0 || env.resource_policy.memory_gb.min < 4.0 {
        store.mutate(|state| {
            let env = state.environments.iter_mut().find(|env| env.id == environment_id).ok_or("Model environment not found")?;
            for (range, minimum) in [(&mut env.resource_policy.cpu, 2.0), (&mut env.resource_policy.memory_gb, 4.0)] {
                range.min = range.min.max(minimum);
                range.preferred = range.preferred.max(minimum);
                range.max = range.max.max(minimum);
            }
            Ok(())
        })?;
    }
    // Options are keyed by runtime ID; a factory reset gives the environment a new one.
    let options_id=env.runtime_id.as_deref().unwrap_or(&env.id);
    let mut options=runtime.workload_options(options_id)?;
    let old=options.clone();
    // Settings saved since the container was configured reach it through this start's change.
    options.environment.remove(START_MARK);
    // A catalog environment (G04/S02): its execution's leases are renewed, or taken again
    // after a restart, and its read-only view completed before the start; the model bind
    // follows the view. A refusal is this start's error: the view is not served from the
    // owner's folder instead.
    options=tokio::task::spawn_blocking(move||catalog_binding::refresh_engine(&mut options).map(|_view|options).map_err(|error|error.to_string())).await.map_err(|e|e.to_string())??;
    optimizer::refresh_options(&mut options)?;
    ensure_admin_token(&mut options)?;
    options.environment.insert("YOUGORI_PUBLISHER_SOURCE".into(),publisher_source());
    if options.environment.contains_key("YOUGORI_MODEL_PATH") { options.environment.insert("YOUGORI_REGISTRY_SOURCE".into(),registry_source()); }
    // Keep already working, unquantized environments at their original precision.
    // New models choose automatically; the dedicated decision runners may need it.
    if !options.environment.contains_key("YOUGORI_MODEL_PRECISION") {
        let decision=options.environment.get("YOUGORI_MODEL").is_some_and(|model| matches!(model.as_str(), "Cloudflare/clef" | "superagent-ai/security-one-27b"));
        options.environment.insert("YOUGORI_MODEL_PRECISION".into(), if decision {"auto"} else {"original"}.into());
    }
    if options.environment.get("YOUGORI_MODEL").is_some_and(|model| model == "Cloudflare/clef") {
        options.environment.insert("YOUGORI_CLEF_SOURCE".into(), clef_source());
    }
    if let Some(token) = huggingface::token() {
        crate::projects::secrets::store(huggingface::TOKEN_REFERENCE, &token)?;
        options.secret_environment.insert("HF_TOKEN".into(), huggingface::TOKEN_REFERENCE.into());
    } else if options.secret_environment.get("HF_TOKEN").is_some_and(|reference| reference == huggingface::TOKEN_REFERENCE) {
        options.secret_environment.remove("HF_TOKEN");
    }
    if !options.secret_environment.contains_key("YOUGORI_MODEL_TOKEN") {
        if let Some(token)=options.environment.get("YOUGORI_MODEL_TOKEN").cloned().filter(|value|value.len()==64&&value.bytes().all(|b|b.is_ascii_hexdigit())) {
            let reference=format!("model-api-{}",uuid::Uuid::new_v4().simple());
            crate::projects::secrets::store(&reference,&token)?;
            options.environment.remove("YOUGORI_MODEL_TOKEN");options.secret_environment.insert("YOUGORI_MODEL_TOKEN".into(),reference);
        }
    }
    if !options.environment.contains_key("YOUGORI_MODEL_REVISION") {
        if let Some(model)=options.environment.get("YOUGORI_MODEL").cloned(){
            let compatibility=preflight::preflight(&normalize_model(&model)?).await?;
            if compatibility["supported"]!=true{return Err(format!("{}: {}. The existing environment and data were preserved.",model,compatibility["reason"].as_str().unwrap_or("A dedicated runner is required")))}
            options.environment.insert("YOUGORI_MODEL_REVISION".into(),compatibility["revision"].as_str().ok_or("Compatibility preflight did not return a pinned revision")?.into());
        }
    }
    // The helpers the rollout serves to the runner about to start (G08): bundles written for it
    // and named in its options, the served directory bound read-only, a model server from a
    // bundle as the command; the start recorded with exactly that. A selection the rollout
    // refuses, or a bundle that cannot be served, is this start's error; a journal that is
    // unavailable leaves source injection. Served before the options are saved and the
    // runtime validates every bind (the second rollout run of 30 October started an
    // environment whose served directory was gone and failed on its stale bind).
    let mut command = command;
    let served = match helpers::serve(&options.environment) {
        Ok(served) => Some(served),
        Err(refusal) if helpers::blocks_start(&refusal) => return Err(refusal.to_string()),
        Err(refusal) => { eprintln!("Helper pins of the model runner {environment_id} were not recorded: {refusal}"); None }
    };
    let previous = apply_served(&mut options, served.as_ref(), &mut command);
    if options!=old {
        runtime.save_workload_options(options_id,&options)?;
        if let Err(error)=runtime.update_workload_configuration(env).await{runtime.save_workload_options(options_id,&old)?;return Err(error)}
    }
    if let Some(previous) = previous {
        // Its workload's share server holds it open until the start serves the new binds.
        helpers::remove_served_later(std::path::PathBuf::from(previous));
    }
    if let Some(served) = served {
        if let Err(refusal)=helpers::record_start(environment_id,&options.environment,served.selected) {
            eprintln!("Helper pins of the model runner {environment_id} were not recorded: {refusal}");
        }
    }
    if current==command{return Ok(())}
    crate::commands::startup::update(environment_id, &command, store, runtime)
        .await
        .map(|_| ())
}
/// Puts what the rollout `served` into `options` (and the bundled model server into `command`):
/// the served directory bound read-only at the helpers target in place of any earlier one, the
/// helper variables replaced. Without a serving (the journal unavailable), a stale helpers bind
/// whose directory is gone is dropped with its variables, so the runner falls back to source
/// injection instead of failing on a bind the runtime cannot find. Returns the directory of an
/// earlier serving that is no longer bound, for its removal.
fn apply_served(options: &mut yougori_cli::workload::Options, served: Option<&helpers::Served>, command: &mut String) -> Option<String> {
    let previous = options.binds.iter().find(|bind| bind.target == helpers::HELPERS_TARGET).map(|bind| bind.source.clone());
    match served {
        Some(served) => {
            options.binds.retain(|bind| bind.target != helpers::HELPERS_TARGET);
            for name in [helpers::HELPERS_OPTION, helpers::SHADOW_OPTION] { options.environment.remove(name); }
            for (name, value) in &served.variables { options.environment.insert((*name).to_owned(), value.clone()); }
            let directory = served.directory.as_ref().map(|directory| directory.display().to_string());
            if let Some(directory) = &directory {
                options.binds.push(yougori_cli::workload::Volume { source: directory.clone(), target: helpers::HELPERS_TARGET.to_owned(), read_only: true });
            }
            if let Some(served_command) = &served.command { *command = served_command.clone(); }
            previous.filter(|previous| Some(previous) != directory.as_ref())
        }
        None => {
            let stale = previous.as_ref().is_some_and(|previous| !std::path::Path::new(previous).is_dir());
            if stale {
                options.binds.retain(|bind| bind.target != helpers::HELPERS_TARGET);
                for name in [helpers::HELPERS_OPTION, helpers::SHADOW_OPTION] { options.environment.remove(name); }
            }
            None
        }
    }
}
fn is_server_command(command: &str) -> bool {
    SERVER_COMMAND_PREFIXES.iter().any(|prefix| command.starts_with(prefix)) && ["yougori-model", "yougori-model-local-fix"].iter()
        .any(|name| command.contains(&format!(",'\"'\"'{name}'\"'\"',")))
}
fn shell_quote(v: &str) -> String {
    format!("'{}'", v.replace('\'', "'\"'\"'"))
}
/// An open connection to a running model server's port and its API key, for callers that
/// speak HTTP over it themselves (Closed Neo Grid members stream replies this way).
pub(crate) async fn model_socket(app: &AppHandle, id: &str) -> Result<(crate::workspace::BoxStream, String), String> {
    let (stream, _, token) = open_model(app, id).await?;
    Ok((stream, token))
}
async fn model_connection(
    app: &AppHandle,
    id: &str,
    path: &str,
    body: Option<&Value>,
    serving: Option<&streaming::Profile>,
) -> Result<crate::workspace::BoxStream, String> {
    let encoded = body.map(Value::to_string).unwrap_or_default();
    if encoded.len() > 65536 {
        return Err("Conversation exceeds 64 KiB; start a new chat".into());
    }
    let (mut stream, options, token) = open_model(app, id).await?;
    // A request reaching a prepared model uses what was prepared (model_prepare); the runner's
    // own activity covers every other path.
    if path == "/v1/chat/completions" {
        prepare::request_arrived(id);
    }
    let mut control = if path == "/v1/yougori/optimizer" { format!("X-Yougori-GPU-Control: {}\r\n", crate::projects::secrets::variable(&options,"YOUGORI_GPU_CONTROL_TOKEN")?) } else {String::new()};
    // Servers started before the owner credential existed accept these settings with the API key.
    if timing_diagnostics(path) {
        // Measurement history stays private even when an older server predates owner settings.
        let admin = crate::projects::secrets::variable(&options, ADMIN_TOKEN)
            .map_err(|_| "Restart this model with an owner credential before collecting measurements")?;
        control.push_str(&format!("X-Yougori-Admin: {admin}\r\n"));
    } else if ADMIN_PATHS.contains(&path) {
        if let Ok(admin) = crate::projects::secrets::variable(&options, ADMIN_TOKEN) { control.push_str(&format!("X-Yougori-Admin: {admin}\r\n")); }
    }
    if let Some(profile) = serving { control.push_str(&profile.headers()); }
    let request=format!("{} {path} HTTP/1.1\r\nHost: localhost\r\n{control}Authorization: Bearer {token}\r\nX-Yougori-Client: yougori\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{encoded}",if body.is_some(){"POST"}else{"GET"},encoded.len());
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    Ok(stream)
}
async fn open_model(app: &AppHandle, id: &str) -> Result<(crate::workspace::BoxStream, yougori_cli::workload::Options, String), String> {
    let runtime = app.state::<RuntimeManager>();
    let env = app
        .state::<PlatformStore>()
        .snapshot()?
        .environments
        .into_iter()
        .find(|e| e.id == id)
        .ok_or("Model environment not found")?;
    if env.status != EnvironmentStatus::Running {
        return Err("Start the model environment first".into());
    }
    let options = runtime.workload_options(env.runtime_id.as_deref().unwrap_or(id))?;
    let token = crate::projects::secrets::variable(&options,"YOUGORI_MODEL_TOKEN")?;
    if token.len()!=64 || !token.bytes().all(|c|c.is_ascii_hexdigit()) { return Err("This environment is not a Yougori model workload".into()); }
    let stream: crate::workspace::BoxStream = if env.kind == EnvironmentKind::Cloud {
        Box::new(runtime.cloud.service_stream(&env.id, 8000).await?)
    } else {
        let (endpoint, credential) = runtime.workspace_endpoint(&env).await?;
        Box::new(crate::workspace::agent_stream(
        &endpoint,
        &credential,
        env.runtime_id.as_deref().unwrap_or(id),
        8000,
    )
    .await
    .map_err(|_| {
        "Model server is starting. Check Logs for installation/download progress and try again."
    })?)
    };
    Ok((stream, options, token))
}
/// The error of a buffered reply: the model server's typed refusals in the engine's words
/// (`streaming::typed_refusal`), else the body's message, else a fixed line.
fn model_error(status_line: &str, body: &[u8]) -> Option<String> {
    if status_line.split_whitespace().nth(1) == Some("200") {
        return None;
    }
    let value = serde_json::from_slice::<Value>(body).ok();
    Some(
        value
            .as_ref()
            .and_then(streaming::typed_refusal)
            .or_else(|| value.as_ref().and_then(|v| v["error"]["message"].as_str().map(str::to_owned)))
            .unwrap_or_else(|| "Model request failed".into()),
    )
}
pub(crate) async fn model_request(
    app: &AppHandle,
    id: &str,
    path: &str,
    body: Option<Value>,
) -> Result<Value, String> {
    let profile = if path == "/v1/chat/completions" {
        let request = body.as_ref().ok_or("Chat requires a request body")?;
        if request["stream"] == true { return Err("Use streamed chat for stream=true".into()); }
        Some(streaming::profile(request)?)
    } else { None };
    let stream = model_connection(app, id, path, body.as_ref(), profile.as_ref()).await?;
    let answer = if let Some(profile) = &profile {
        streaming::read_buffered(stream, profile).await
    } else { model_response(stream, body.is_some()).await };
    optimizer::request_completed(path, body.is_some(), answer.is_ok());
    answer
}
async fn model_response(stream: crate::workspace::BoxStream, posted: bool) -> Result<Value, String> {
    tokio::time::timeout(std::time::Duration::from_secs(if posted {1800} else {15}), async {
        let mut bytes = Vec::new();
        stream
            .take(2 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .await
            .map_err(|e| e.to_string())?;
        if bytes.len() > 2 * 1024 * 1024 {
            return Err("Model response exceeded 2 MiB".into());
        }
        let split = bytes
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or("Invalid model HTTP response")?;
        let header = std::str::from_utf8(&bytes[..split]).map_err(|e| e.to_string())?;
        if let Some(error) = model_error(header.lines().next().unwrap_or(""), &bytes[split + 4..]) {
            return Err(error);
        }
        serde_json::from_slice(&bytes[split + 4..]).map_err(|e| e.to_string())
    })
    .await
    .map_err(|_| "Model response timed out; try a shorter conversation")?
}
/// Owner setting: requires the engine-held admin credential, not only the API key.
pub(crate) async fn configure_publishing(app: &AppHandle, id: &str, open: bool) -> Result<Value,String> {
    // A stopped or still-starting model says so; only a server that answers but refuses the
    // setting predates publisher-hosted pages and needs a fresh run.
    let stream = model_connection(app, id, "/v1/yougori/publishing", Some(&json!({"downloads":open})), None).await?;
    model_response(stream, true).await.map_err(|_|"Stop this model and run it again to enable publisher-hosted pages; its container and files are kept".to_owned())
}
/// Only the local engine may lease optional free-provider recording: the server requires the
/// engine-held admin credential in addition to the API key.
pub(crate) async fn configure_listen(app: &AppHandle, id: &str, mode: &str, enabled: bool) -> Result<Value, String> {
    if enabled && mode != "free" { return Err("--listen requires --nowfree".into()); }
    model_request(app, id, "/v1/listen/config", Some(json!({"enabled":enabled,"mode":mode}))).await
}
#[tauri::command]
pub async fn model_status(environment_id: String, app: AppHandle) -> Result<Value, String> {
    let state = app.state::<PlatformStore>().snapshot()?;
    if state.environments.iter().any(|e| e.id == environment_id && e.kind == EnvironmentKind::Cloud) {
        let runtime = app.state::<RuntimeManager>();
        let session = runtime.cloud.session(&environment_id).await?;
        let options = runtime.workload_options(&environment_id)?;
        let token = crate::projects::secrets::variable(&options,"YOUGORI_MODEL_TOKEN")?;
        return session.request("model/status", json!({"token":token})).await;
    }
    let mut health = model_request(&app, &environment_id, "/health", None).await?;
    // The profile and demand host admission reserves for it (vLLM, llama.cpp and Transformers alike).
    if let Some(env) = state.environments.iter().find(|e| e.id == environment_id) {
        let options = app.state::<RuntimeManager>().workload_options(env.runtime_id.as_deref().unwrap_or(&env.id));
        if let Some(admission) = options.ok().and_then(|options| optimizer::admission(&options.environment)) {
            health["admission"] = admission;
        }
    }
    // What the load spent its time on, while it runs and after (first-use stage timings); a
    // server from before this answer, or without the owner credential, shows none.
    if let Ok(load) = model_request(&app, &environment_id, "/v1/diagnostics/load", None).await {
        health["load"] = load;
    }
    // What bringing it back costs as measured (G05): retention parks cheap-to-reload models first.
    if let Some(reload) = optimizer::reload_cost(&environment_id) {
        health["reload"] = reload;
    }
    Ok(with_waiting(health, optimizer::waiting_for(&environment_id)))
}

/// A model waiting for the GPU says why, and only while it waits: queued, or phased to
/// `freeing_memory` by a switch whose admission was then refused (seen live on 30 October:
/// the grant refused for want of capacity left the runner phased, not queued).
fn with_waiting(mut health: Value, reason: Option<String>) -> Value {
    if let Some(reason) = reason.filter(|_| matches!(health["status"].as_str(), Some("queued" | "freeing_memory")) && health["optimizer"].is_object()) {
        health["optimizer"]["waitingFor"] = json!(reason);
    }
    health
}
#[tauri::command]
pub async fn model_api(environment_id: String, port: u16, app: AppHandle) -> Result<Value, String> {
    if port == 0 {
        return Err("Choose a port between 1 and 65535".into());
    }
    let runtime = app.state::<RuntimeManager>();
    let env = app
        .state::<PlatformStore>()
        .snapshot()?
        .environments
        .into_iter()
        .find(|e| e.id == environment_id)
        .ok_or("Model environment not found")?;
    let options = runtime.workload_options(env.runtime_id.as_deref().unwrap_or(&env.id))?;
    let model = options
        .environment
        .get("YOUGORI_MODEL")
        .ok_or("This is not a model environment")?;
    let token = crate::projects::secrets::variable(&options,"YOUGORI_MODEL_TOKEN")?;
    let current = crate::automation::dispatch::dispatch(
        &app,
        "list_environment_services",
        &json!({"environmentId":environment_id}),
    )
    .await?;
    if let Some(existing) = current["publications"].as_array().into_iter().flatten()
        .find(|p| p["kind"] == "loopback" && p["port"] == 8000 && p["hostPort"] != port) {
        return Err(format!("This model already has local API access on port {}. Turn it off in /api before choosing another port.", existing["hostPort"]));
    }
    if !current["publications"].as_array().is_some_and(|items| {
        items
            .iter()
            .any(|p| p["kind"] == "loopback" && p["port"] == 8000 && p["hostPort"] == port)
    }) {
        crate::automation::dispatch::dispatch(
            &app,
            "publish_environment_service",
            &json!({"environmentId":environment_id,"port":8000,"hostPort":port,"kind":"loopback"}),
        )
        .await?;
    }
    Ok(
        json!({"id":environment_id,"model":model,"apiUrl":format!("http://127.0.0.1:{port}/v1"),"apiKey":token}),
    )
}
/// Current API access for a model: its key plus any localhost and public (Cloudflare) addresses.
fn public_api_url(publication: &Value) -> Option<String> {
    // Publication readiness is the tunnel's active connection, separate from
    // model health and the website's independent provider admission checks.
    if !matches!(publication["status"].as_str(), Some("active" | "ready")) { return None; }
    publication["urls"][0].as_str().map(|url| format!("{}/v1", url.trim_end_matches('/')))
}

pub(crate) async fn api_status(app: &AppHandle, environment_id: &str) -> Result<Value, String> {
    let runtime = app.state::<RuntimeManager>();
    let env = app
        .state::<PlatformStore>()
        .snapshot()?
        .environments
        .into_iter()
        .find(|e| e.id == environment_id)
        .ok_or("Model environment not found")?;
    let options = runtime.workload_options(env.runtime_id.as_deref().unwrap_or(&env.id))?;
    let model = options
        .environment
        .get("YOUGORI_MODEL")
        .ok_or("This is not a model environment")?;
    let token = crate::projects::secrets::variable(&options,"YOUGORI_MODEL_TOKEN")?;
    let services = crate::automation::dispatch::dispatch(
        app,
        "list_environment_services",
        &json!({"environmentId":environment_id}),
    )
    .await?;
    let publications = services["publications"].as_array().cloned().unwrap_or_default();
    let local = publications
        .iter()
        .find(|p| p["kind"] == "loopback" && p["port"] == 8000);
    let public = publications
        .iter()
        .find(|p| p["kind"] == "cloudflare" && p["port"] == 8000);
    Ok(json!({
        "id": environment_id,
        "model": model,
        "apiKey": token,
        "apiUrl": local.map(|p| format!("http://127.0.0.1:{}/v1", p["hostPort"])),
        "publicUrl": public.and_then(public_api_url),
        "publicStatus": public.map(|p|p["status"].clone()),
        "publicId": public.map(|p| p["id"].clone()),
        "publicAccount": public.is_some_and(|p| p["cloudflareAccount"] == true),
        // The setup that made this model, if one did, and the vault entries (names, never values)
        // only it uses, which that setup forgets after deleting it.
        "setupStamp": options.environment.get(SETUP_STAMP),
        "setupSecrets": sole_references(app, environment_id, &options),
    }))
}
/// Where a model environment's chat history lives; shared by the app and the CLI.
pub(crate) fn chat_history_file(store: &PlatformStore, environment_id: &str) -> std::path::PathBuf {
    let safe = environment_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect::<String>();
    // Different models on one cloud pod keep separate conversations.
    let model = store.snapshot().ok().and_then(|s| s.neocloud_deployments.get(environment_id)
        .and_then(|d| d.extra["yougoriModel"].as_str()).map(str::to_owned));
    let suffix = model.map(|model| {
        use sha2::{Digest, Sha256};
        format!("-{}", hex::encode(Sha256::digest(model.as_bytes())))
    }).unwrap_or_default();
    store.data_folder("model-chats").join(format!("{safe}{suffix}.json"))
}
const CHAT_HISTORY_LIMIT: usize = 16 * 1024 * 1024;
fn model_environment_exists(store: &PlatformStore, environment_id: &str) -> Result<(), String> {
    store
        .snapshot()?
        .environments
        .iter()
        .any(|e| e.id == environment_id)
        .then_some(())
        .ok_or_else(|| "Model environment not found".into())
}
/// Conversations and chat settings for a model, or null when none are saved yet.
#[tauri::command]
pub fn model_chat_history(
    environment_id: String,
    store: tauri::State<'_, PlatformStore>,
) -> Result<Value, String> {
    model_environment_exists(&store, &environment_id)?;
    match std::fs::read(chat_history_file(&store, &environment_id)) {
        Ok(bytes) if bytes.len() <= CHAT_HISTORY_LIMIT => {
            serde_json::from_slice(&bytes).map_err(|_| "Saved chat history is unreadable".into())
        }
        Ok(_) => Err("Saved chat history is too large".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Value::Null),
        Err(error) => Err(error.to_string()),
    }
}
/// Replaces a model's chat history and tells open windows, so the app and the CLI continue the same conversations.
#[tauri::command]
pub fn save_model_chat_history(
    environment_id: String,
    history: Value,
    app: AppHandle,
    store: tauri::State<'_, PlatformStore>,
) -> Result<(), String> {
    model_environment_exists(&store, &environment_id)?;
    if !history["conversations"].is_array() || !history["settings"].is_object() {
        return Err("Chat history needs conversations and settings".into());
    }
    let bytes = serde_json::to_vec(&history).map_err(|e| e.to_string())?;
    if bytes.len() > CHAT_HISTORY_LIMIT {
        return Err("Chat history exceeds 16 MB; delete old conversations".into());
    }
    let path = chat_history_file(&store, &environment_id);
    let folder = path.parent().ok_or("Invalid chat history folder")?;
    std::fs::create_dir_all(folder).map_err(|e| e.to_string())?;
    let mut file = tempfile::NamedTempFile::new_in(folder).map_err(|e| e.to_string())?;
    std::io::Write::write_all(&mut file, &bytes).map_err(|e| e.to_string())?;
    file.persist(&path).map_err(|e| e.to_string())?;
    let _ = tauri::Emitter::emit(&app, "yougori-model-chat-history", &environment_id);
    Ok(())
}
/// Usage recorded by the model server (counts and token totals only, never prompts). `reset` clears it first.
#[tauri::command]
pub async fn model_usage(environment_id: String, reset: bool, app: AppHandle) -> Result<Value, String> {
    if reset {
        model_request(&app, &environment_id, "/v1/usage/reset", Some(json!({}))).await?;
    }
    model_request(&app, &environment_id, "/v1/usage", None)
        .await
        .map_err(|e| {
            if e == "Endpoint not found" {
                "Run this model again from Hugging Face to track usage".into()
            } else {
                e
            }
        })
}
#[tauri::command]
pub async fn model_api_status(environment_id: String, app: AppHandle) -> Result<Value, String> {
    api_status(&app, &environment_id).await
}
pub(crate) fn chat_body(
    messages: Value,
    max_tokens: Option<u32>,
    temperature: Option<f64>,
    stream: bool,
) -> Result<Value, String> {
    if !messages.is_array() {
        return Err("Messages must be an array".into());
    }
    let mut body = json!({"messages":messages,"max_tokens":max_tokens.unwrap_or(256),"stream":stream});
    if let Some(temperature) = temperature {
        body["temperature"] = json!(temperature);
    }
    if stream {
        // Yougori extension: the server drops the oldest turns instead of failing when the context is full.
        body["truncate"] = json!(true);
    }
    Ok(body)
}
#[tauri::command]
pub async fn model_chat(
    environment_id: String,
    messages: Value,
    max_tokens: Option<u32>,
    temperature: Option<f64>,
    app: AppHandle,
) -> Result<Value, String> {
    let body = chat_body(messages, max_tokens, temperature, false)?;
    model_request(&app, &environment_id, "/v1/chat/completions", Some(body)).await
}
type CancelMap = std::collections::HashMap<String, std::sync::Arc<tokio::sync::Notify>>;
static CHAT_CANCELS: std::sync::LazyLock<std::sync::Mutex<CancelMap>> =
    std::sync::LazyLock::new(Default::default);
struct CancelGuard(String);
impl Drop for CancelGuard {
    fn drop(&mut self) {
        if let Ok(mut cancels) = CHAT_CANCELS.lock() {
            cancels.remove(&self.0);
        }
    }
}
/// Streams a reply as `{"delta": text}` messages on `on_event` and resolves with the finish reason and usage.
#[tauri::command]
pub async fn model_chat_stream(
    environment_id: String,
    request_id: String,
    messages: Value,
    max_tokens: Option<u32>,
    temperature: Option<f64>,
    on_event: tauri::ipc::Channel<Value>,
    app: AppHandle,
) -> Result<Value, String> {
    // A cancel that arrives first leaves a stored permit, so this request stops immediately.
    let cancel = CHAT_CANCELS
        .lock()
        .map_err(|e| e.to_string())?
        .entry(request_id.clone())
        .or_default()
        .clone();
    let _guard = CancelGuard(request_id);
    let body = chat_body(messages, max_tokens, temperature, true)?;
    stream_reply(&app, &environment_id, &cancel, &body, |text| {
        on_event
            .send(json!({"delta":text}))
            .map_err(|e| e.to_string())
    })
    .await
}
/// Streams a reply, handing each piece of text to `delta`; resolves with the finish reason and usage.
async fn stream_reply(
    app: &AppHandle,
    environment_id: &str,
    cancel: &tokio::sync::Notify,
    body: &Value,
    mut delta: impl FnMut(&str) -> Result<(), String>,
) -> Result<Value, String> {
    stream_deltas(app, environment_id, cancel, body, |piece| match piece["content"].as_str() {
        Some(text) if !text.is_empty() => delta(text),
        _ => Ok(()),
    })
    .await
}
/// Streams display text immediately and releases complete tool calls only after
/// protocol and request-schema validation; resolves with finish reason and usage.
pub(crate) async fn stream_deltas(
    app: &AppHandle,
    environment_id: &str,
    cancel: &tokio::sync::Notify,
    body: &Value,
    delta: impl FnMut(&Value) -> Result<(), String>,
) -> Result<Value, String> {
    let profile = streaming::profile(body)?;
    let stream = tokio::select! {
        biased;
        _ = cancel.notified() => return Ok(json!({"finishReason":"cancelled"})),
        stream = model_connection(app, environment_id, "/v1/chat/completions", Some(body), Some(&profile)) => stream?,
    };
    streaming::read(stream, cancel, &profile, delta).await
}
/// A reply streamed for clients that poll for it, such as the CLI.
struct PolledReply {
    text: String,
    outcome: Option<Result<Value, String>>,
    /// When the reply began or a reader last asked for it.
    touched: std::time::Instant,
}
static POLLED_REPLIES: std::sync::LazyLock<std::sync::Mutex<std::collections::HashMap<String, PolledReply>>> =
    std::sync::LazyLock::new(Default::default);
/// Starts a streamed reply that `model_chat_read` returns piece by piece.
pub async fn model_chat_begin(
    environment_id: String,
    messages: Value,
    max_tokens: Option<u32>,
    temperature: Option<f64>,
    app: AppHandle,
) -> Result<Value, String> {
    let body = chat_body(messages, max_tokens, temperature, true)?;
    let request_id = format!("poll-{}", uuid::Uuid::new_v4().simple());
    {
        let mut replies = POLLED_REPLIES.lock().map_err(|e| e.to_string())?;
        // Readers that went away leave replies behind. A reply that is still being read is
        // kept however long it runs; an abandoned one that is still generating is stopped.
        let mut abandoned = Vec::new();
        replies.retain(|id, reply| {
            let keep = reply.touched.elapsed() < std::time::Duration::from_secs(900);
            if !keep && reply.outcome.is_none() { abandoned.push(id.clone()); }
            keep
        });
        for id in abandoned { let _ = model_chat_cancel(id); }
        if replies.len() >= 16 {
            return Err("Too many replies are streaming; wait for one to finish".into());
        }
        replies.insert(
            request_id.clone(),
            PolledReply {
                text: String::new(),
                outcome: None,
                touched: std::time::Instant::now(),
            },
        );
    }
    let cancel = CHAT_CANCELS
        .lock()
        .map_err(|e| e.to_string())?
        .entry(request_id.clone())
        .or_default()
        .clone();
    let id = request_id.clone();
    tauri::async_runtime::spawn(async move {
        let _guard = CancelGuard(id.clone());
        let outcome = stream_reply(&app, &environment_id, &cancel, &body, |text| {
            if let Some(reply) = POLLED_REPLIES.lock().map_err(|e| e.to_string())?.get_mut(&id) {
                reply.text.push_str(text);
            }
            Ok(())
        })
        .await;
        if let Ok(mut replies) = POLLED_REPLIES.lock() {
            if let Some(reply) = replies.get_mut(&id) {
                reply.outcome = Some(outcome);
            }
        }
    });
    Ok(json!({"requestId":request_id}))
}
/// Text streamed since `offset`, and once the reply ends `done` with its result or error.
/// `stop` asks the model to stop generating; the text so far is kept.
pub fn model_chat_read(request_id: String, offset: Option<usize>, stop: Option<bool>) -> Result<Value, String> {
    if stop == Some(true) {
        model_chat_cancel(request_id.clone())?;
    }
    let mut replies = POLLED_REPLIES.lock().map_err(|e| e.to_string())?;
    let reply = replies
        .get_mut(&request_id)
        .ok_or("This reply is no longer available")?;
    reply.touched = std::time::Instant::now();
    let offset = offset.unwrap_or(0).min(reply.text.len());
    if !reply.text.is_char_boundary(offset) {
        return Err("Invalid reply offset".into());
    }
    let mut value = json!({"text":&reply.text[offset..],"offset":reply.text.len(),"done":reply.outcome.is_some()});
    match &reply.outcome {
        Some(Ok(result)) => value["result"] = result.clone(),
        Some(Err(error)) => value["error"] = json!(error),
        None => return Ok(value),
    }
    replies.remove(&request_id);
    Ok(value)
}
#[tauri::command]
pub fn model_chat_cancel(request_id: String) -> Result<(), String> {
    if request_id.len() > 64 {
        return Err("Invalid request ID".into());
    }
    CHAT_CANCELS
        .lock()
        .map_err(|e| e.to_string())?
        .entry(request_id)
        .or_default()
        .notify_one();
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn timing_replay_always_uses_owner_auth_without_matching_other_routes() {
        assert!(timing_diagnostics("/v1/diagnostics/timings"));
        assert!(timing_diagnostics("/v1/diagnostics/timings?after=32&limit=16"));
        assert!(!timing_diagnostics("/v1/diagnostics/timings-extra"));
        assert!(!timing_diagnostics("/health?path=/v1/diagnostics/timings"));
        assert!(!timing_diagnostics("/v1/diagnostics/timings/replay"));
    }
    #[test]
    fn a_buffered_reply_renders_the_servers_typed_refusals_before_its_message() {
        let context = br#"{"error":{"code":"yougori_context_window","message":"the runner's text","context":9728,"promptTokens":10294,"maxTokens":256,"grantContext":9728}}"#;
        let rendered = model_error("HTTP/1.1 400 Bad Request", context).unwrap();
        assert!(rendered.starts_with("This conversation needs 10294 prompt tokens"), "{rendered}");
        assert!(rendered.contains("the GPU grant covers"));
        let memory = model_error("HTTP/1.1 507 Insufficient Storage", br#"{"error":{"code":"yougori_gpu_memory","message":"x"}}"#).unwrap();
        assert!(memory.starts_with("The GPU ran out of memory"), "{memory}");
        // Other bodies keep the server's message; a body without one gets the fixed line; 200 is no error.
        assert_eq!(model_error("HTTP/1.1 429 Busy", br#"{"error":{"message":"The GPU is busy"}}"#).as_deref(), Some("The GPU is busy"));
        assert_eq!(model_error("HTTP/1.1 500 Error", b"not json").as_deref(), Some("Model request failed"));
        assert!(model_error("HTTP/1.1 200 OK", b"{}").is_none());
    }
    #[test]
    fn a_model_waiting_for_the_gpu_says_why_only_while_it_waits() {
        let said = with_waiting(json!({"status":"queued","optimizer":{"pending":1}}), Some("Model A is using the GPU. This model loads once it is free.".into()));
        assert_eq!(said["optimizer"]["waitingFor"], "Model A is using the GPU. This model loads once it is free.");
        let phased = with_waiting(json!({"status":"freeing_memory","optimizer":{"pending":1}}), Some("GPU capacity is not available: in use elsewhere".into()));
        assert_eq!(phased["optimizer"]["waitingFor"], "GPU capacity is not available: in use elsewhere", "a switch refused after its phase leaves the runner phased, still waiting");
        let ready = with_waiting(json!({"status":"ready","optimizer":{}}), Some("a reason from the last pass".into()));
        assert!(ready["optimizer"].get("waitingFor").is_none(), "a model that stopped waiting shows nothing stale");
        for status in ["loading", "idle", "error", "unloading"] {
            assert!(with_waiting(json!({"status":status,"optimizer":{}}), Some("stale".into()))["optimizer"].get("waitingFor").is_none(), "{status}");
        }
        assert!(with_waiting(json!({"status":"queued","optimizer":{}}), None)["optimizer"].get("waitingFor").is_none());
    }
    fn new_model_environment() -> (Value, Value) {
        (json!({"YOUGORI_MODEL":"owner/model","YOUGORI_MODEL_REVISION":"a".repeat(40),"HF_HOME":"/root/.cache/huggingface"}),
         json!({"YOUGORI_MODEL_TOKEN":"model-api-1","YOUGORI_MODEL_ADMIN_TOKEN":"model-admin-1"}))
    }
    #[test]
    fn a_hugging_face_workload_is_unchanged_by_imports() {
        let (environment, protected) = new_model_environment();
        let volume = model_cache_volume();
        // Byte for byte what run_model_at_revision built before folder imports existed.
        assert_eq!(model_workload(environment.clone(), &protected, None, Some(&volume)),
            json!({"environment":environment,"secretEnvironment":protected,"volumes":[{"source":volume,"target":"/root/.cache/huggingface","readOnly":false}]}));
    }
    #[test]
    fn a_new_registry_workload_imports_its_read_only_bind_into_its_own_cache_volume() {
        let (environment, protected) = new_model_environment();
        let folder = json!("D:\\pool\\model-registry\\0123abcd");
        let volume = model_cache_volume();
        let workload = model_workload(environment.clone(), &protected, Some(&folder), Some(&volume));
        assert_eq!(workload["binds"], json!([{"source":folder,"target":"/yougori-model","readOnly":true}]));
        assert_eq!(workload["volumes"], json!([{"source":volume,"target":"/root/.cache/huggingface","readOnly":false}]));
        assert_eq!(workload["environment"]["YOUGORI_MODEL_IMPORT"], "1");
        // A stale helpers bind whose directory is gone is dropped when nothing is served; a
        // serving replaces an earlier bind and names the earlier directory for removal.
        let dir = tempfile::tempdir().unwrap();
        let gone = dir.path().join("gone").display().to_string();
        let mut options = yougori_cli::workload::Options::default();
        options.binds.push(yougori_cli::workload::Volume { source: gone.clone(), target: helpers::HELPERS_TARGET.to_owned(), read_only: true });
        options.environment.insert(helpers::HELPERS_OPTION.to_owned(), "{}".to_owned());
        let mut command = String::from("python3 -u -");
        assert_eq!(apply_served(&mut options, None, &mut command), None);
        assert!(options.binds.is_empty() && !options.environment.contains_key(helpers::HELPERS_OPTION));
        let kept = dir.path().join("kept");
        std::fs::create_dir_all(&kept).unwrap();
        options.binds.push(yougori_cli::workload::Volume { source: kept.display().to_string(), target: helpers::HELPERS_TARGET.to_owned(), read_only: true });
        assert_eq!(apply_served(&mut options, None, &mut command), None);
        assert_eq!(options.binds.len(), 1, "a bind whose directory exists stays without a serving");
        let served = helpers::Served { directory: Some(dir.path().join("new")), variables: vec![(helpers::HELPERS_OPTION, "{\"x\":1}".to_owned())], command: Some("exec python3 -u /yougori-helpers/model-server/model_server.py".to_owned()), ..helpers::Served::default() };
        assert_eq!(apply_served(&mut options, Some(&served), &mut command), Some(kept.display().to_string()));
        assert_eq!(options.binds.len(), 1);
        assert_eq!(options.binds[0].source, dir.path().join("new").display().to_string());
        assert_eq!(options.environment[helpers::HELPERS_OPTION], "{\"x\":1}");
        assert!(command.starts_with("exec python3"));
        // Serving the helpers into the workload keeps what model_workload put there.
        let mut served = workload.clone();
        let mut command = String::from("python3 -u -");
        serve_helpers_into(&mut served, &mut command).unwrap();
        assert_eq!(served["environment"]["YOUGORI_MODEL_IMPORT"], "1");
        assert_eq!(served["binds"].as_array().map(Vec::len).unwrap_or(0), workload["binds"].as_array().map(Vec::len).unwrap_or(0) + usize::from(served["environment"].get("YOUGORI_HELPERS").is_some()));
        assert_eq!(workload["secretEnvironment"], protected);
        // Named as model deletion recognizes an environment's own cache (runtime/workload.rs); the
        // person's folder stays a bind, which deletion never removes.
        let options: yougori_cli::workload::Options = serde_json::from_value(workload).unwrap();
        assert_eq!(options.volumes.len(), 1);
        assert!(volume.strip_prefix("model-").and_then(|s| s.strip_suffix("-models")).is_some_and(|id| id.len() == 8 && id.bytes().all(|b| b.is_ascii_hexdigit())));
        assert_ne!(model_cache_volume(), volume, "every new environment gets its own volume");
        // Without a volume (environments made before imports, CPU runners) the runner reads the bind.
        let bind_only = model_workload(environment, &protected, Some(&folder), None);
        assert!(bind_only.get("volumes").is_none());
        assert!(bind_only["environment"].get("YOUGORI_MODEL_IMPORT").is_none());
    }
    #[test]
    fn imported_models_get_storage_for_their_files_or_are_refused_before_anything_is_made() {
        assert_eq!(import_storage_gb(0), 20);
        assert_eq!(import_storage_gb(7 << 30), 21, "7 GiB * 1.15 = 8.05, rounded up, plus 12");
        assert_eq!(import_storage_gb(54_713_606_072), 71, "the Hugging Face preflight's own example");
        assert_eq!(import_storage_gb(u64::MAX), u64::MAX.div_ceil(20 << 30) + 12);
        let check = json!({"resources":{"storageGbRecommended":40.0}});
        let mut resources = ModelResources::default();
        import_storage(&mut resources, &check).unwrap();
        assert_eq!(resources.storage_gb, Some(40.0));
        for (runner, wants) in [(None, Some(false)), (Some("auto"), Some(false)), (Some("vllm"), Some(true)), (Some("transformers"), None)] {
            let resources = ModelResources { runner: runner.map(str::to_owned), ..Default::default() };
            assert_eq!(resources.wants_vllm().ok(), wants, "{runner:?}");
        }
        let mut larger = ModelResources { storage_gb: Some(64.0), ..Default::default() };
        import_storage(&mut larger, &check).unwrap();
        assert_eq!(larger.storage_gb, Some(64.0));
        let mut smaller = ModelResources { storage_gb: Some(30.0), ..Default::default() };
        assert!(import_storage(&mut smaller, &check).unwrap_err().contains("40 GB"));
        let mut unknown = ModelResources::default();
        import_storage(&mut unknown, &json!({})).unwrap();
        assert_eq!(unknown.storage_gb, Some(20.0));
    }
    #[test] fn registry_verifier_digest_is_portable_and_matches_the_embedded_runner() {
        use sha2::{Digest,Sha256};
        let source=include_str!("model_runner/registry_snapshot.py").replace("\r\n","\n");
        let digest=format!("{:x}",Sha256::digest(source.as_bytes()));
        assert!(include_str!("model_server.py").contains(&digest));
    }
    #[test] fn engine_backends_digest_is_portable_and_matches_the_embedded_runner() {
        use sha2::{Digest,Sha256};
        let source=include_str!("model_runner/engine_backends.py").replace("\r\n","\n");
        let digest=format!("{:x}",Sha256::digest(source.as_bytes()));
        assert!(include_str!("model_server.py").contains(&format!("BACKENDS_SHA256 = \"{digest}\"")));
    }
    #[test] fn only_gguf_and_vllm_runners_carry_the_engine_backends() {
        for (format, carried) in [(Some("gguf"), true), (Some("vllm"), true), (None, false), (Some("safetensors"), false), (Some("source"), false)] {
            let mut environment = json!({});
            if let Some(format) = format { environment["YOUGORI_MODEL_FORMAT"] = json!(format); }
            carry_server(&mut environment);
            assert_eq!(environment["YOUGORI_MODEL_SERVER_SOURCE"], json!(server_payload()));
            assert_eq!(environment.get("YOUGORI_BACKENDS_SOURCE").is_some(), carried, "{format:?}");
        }
        let compressed = STANDARD.decode(backends_source()).unwrap();
        let mut decoded = Vec::new();
        std::io::Read::read_to_end(&mut flate2::read::ZlibDecoder::new(&compressed[..]), &mut decoded).unwrap();
        assert_eq!(decoded, include_str!("model_runner/engine_backends.py").replace("\r\n", "\n").into_bytes());
    }
    #[test]
    fn active_tunnels_are_offered_for_admission_but_failed_saved_links_are_not() {
        for status in ["active", "ready"] {
            let publication = json!({"status":status,"urls":["https://provider.example.test/"]});
            assert_eq!(public_api_url(&publication).as_deref(), Some("https://provider.example.test/v1"));
        }
        for status in ["error", "stopped", "reconnecting", "starting"] {
            assert!(public_api_url(&json!({"status":status,"urls":["https://stale.example.test"]})).is_none());
        }
        assert!(public_api_url(&json!({"status":"active","urls":[]})).is_none());
    }

    #[test]
    fn the_model_server_starts_with_python3_which_every_runner_image_has() {
        // vLLM's pinned image has only /usr/bin/python3; `exec python` failed at container start.
        let command = server_command();
        assert!(command.starts_with("exec python3 -u -c '"), "{command}");
        assert!(!command.starts_with("exec python -u -c "));
        assert_eq!(command.matches("python").count(), 1, "no other interpreter name in the command");
    }
    #[test]
    fn only_model_server_commands_are_refreshed() {
        let command = server_command();
        assert!(is_server_command(&command));
        assert!(is_server_command(&command.replace("yougori-model", "yougori-model-local-fix")));
        assert!(command.len() < 32 * 1024, "startup commands are limited to 32 KB");
        // Environments made with the earlier `python` command are still recognized and upgraded.
        let older = command.replacen("exec python3 -u -c ", "exec python -u -c ", 1);
        assert_ne!(older, command);
        assert!(is_server_command(&older));
        assert!(is_server_command(&older.replace("yougori-model", "yougori-model-local-fix")));
        for unrelated in ["exec python -u -c 'print(1)'", "exec python3 -u -c 'print(1)'", "sleep infinity",
            "exec python3 -m http.server 8080", "exec python2 -u -c 'yougori-model'"] {
            assert!(!is_server_command(unrelated), "{unrelated}");
        }
        assert!(!is_server_command(&command.replacen("exec python3 -u -c ", "exec python4 -u -c ", 1)));
        assert!(!is_server_command(&command.replace("yougori-model", "another-model")));
        // The size reduction must preserve the exact script, including Unicode
        // and the fixes applied to reused model environments.
        assert!(command.contains("YOUGORI_MODEL_SERVER_SOURCE"));
        let compressed = STANDARD.decode(server_payload()).unwrap();
        let mut decoded = Vec::new();
        std::io::Read::read_to_end(&mut flate2::read::ZlibDecoder::new(&compressed[..]), &mut decoded).unwrap();
        assert_eq!(decoded, include_bytes!("model_server.py"));
    }
    #[test]
    fn model_resource_allocation_preserves_fixed_values_and_rejects_impossible_limits() {
        let custom: ModelResources = serde_json::from_value(json!({"cpu":3,"memoryGb":6,"storageGb":25,"storageDrive":"D:\\"})).unwrap();
        assert_eq!(custom.storage_drive.as_deref(),Some("D:\\"));
        assert_eq!(custom.allocation(8,16.0,100.0).unwrap(),(3.0,6.0,25.0));
        assert_eq!(ModelResources::default().allocation(8,16.0,100.0).unwrap(),(2.0,4.0,20.0));
        assert!(ModelResources::default().allocation(1,16.0,100.0).is_err());
        assert!(ModelResources::default().allocation(8,3.0,100.0).is_err());
        assert!(ModelResources { cpu:Some(1.0), ..Default::default() }.allocation(8,16.0,100.0).is_err());
        assert!(ModelResources { memory_gb:Some(2.0), ..Default::default() }.allocation(8,16.0,100.0).is_err());
        assert!(custom.allocation(2,16.0,100.0).is_err());
        assert!(custom.allocation(8,4.0,100.0).is_err());
        assert!(custom.allocation(8,16.0,20.0).is_err());
        for value in [f64::NAN, f64::INFINITY, -1.0, 0.0, 11.0] {
            assert!(ModelResources { storage_gb:Some(value), ..Default::default() }.allocation(8,16.0,100.0).is_err());
        }
    }
    #[test]
    fn model_ids_are_not_commands_urls_or_local_paths() {
        assert_eq!(
            normalize_model("hf.co/TinyLlama/TinyLlama-1.1B-Chat-v1.0").unwrap(),
            "TinyLlama/TinyLlama-1.1B-Chat-v1.0"
        );
        for bad in [
            "/etc/passwd",
            "https://evil.test/a/b",
            "org/model;rm",
            "org/../model",
            "org/model?token=x",
        ] {
            assert!(normalize_model(bad).is_err())
        }
    }
    #[test]
    fn a_registry_model_never_carries_the_runner_manifest_and_carries_the_catalog_options_on_the_catalog_path() {
        // registry_snapshot.py:22 prefers YOUGORI_LOCAL_MANIFEST to the mount's record, and the
        // registry path verifies against its own record: the variable must stay unset.
        let version = json!({"format":"safetensors","revision":"c".repeat(64),"quant":null});
        let cached = json!({"files":[{"name":"model.safetensors","size":4,"sha256":"d".repeat(64)}]});
        let folder = catalog_binding::Binding::Folder { catalog: json!({"state":"not_configured"}) };
        let environment = registry_environment("yg/owner/model", &version, "version-1", &cached, &folder).unwrap();
        assert!(environment.get(catalog_binding::RUNNER_MANIFEST).is_none());
        for name in [catalog_binding::EXECUTION_OPTION, catalog_binding::MODEL_OPTION, catalog_binding::CONTENT_OPTION] {
            assert!(environment.get(name).is_none(), "{name}");
        }
        assert_eq!(environment["YOUGORI_MODEL_PATH"], catalog_binding::MODEL_TARGET);
        let bound = catalog_binding::CatalogBind {
            execution: crate::foundation::ids::ExecutionId::generate(),
            model: crate::foundation::catalog::ObjectId::new(
                &crate::catalog_service::owner_scope().unwrap(),
                crate::foundation::catalog::ArtifactClass::ModelSidecar,
                crate::foundation::ids::ContentKey::of(b"sidecar"),
            ),
            view: std::path::PathBuf::from("views/exe-1"),
            files: 2,
            bytes: 8,
            content: r#"{"model.safetensors":"00"}"#.into(),
            copied: true,
            reused: false,
            evicted: 0,
            evicted_bytes: 0,
        };
        let catalog = catalog_binding::Binding::Catalog(bound.clone());
        let environment = registry_environment("yg/owner/model", &version, "version-1", &cached, &catalog).unwrap();
        assert!(environment.get(catalog_binding::RUNNER_MANIFEST).is_none());
        assert_eq!(environment[catalog_binding::EXECUTION_OPTION], bound.execution.as_str());
        assert_eq!(environment[catalog_binding::MODEL_OPTION], bound.model.to_string());
        assert_eq!(environment[catalog_binding::CONTENT_OPTION], bound.content);
        assert_eq!(environment["YOUGORI_MODEL_REVISION"], version["revision"]);
    }
    #[test]
    fn only_streaming_requests_ask_the_server_to_trim_context() {
        let messages = json!([{"role":"user","content":"hi"}]);
        assert_eq!(
            chat_body(messages.clone(), None, None, false).unwrap(),
            json!({"messages":messages,"max_tokens":256,"stream":false})
        );
        assert_eq!(
            chat_body(messages.clone(), Some(1024), Some(0.2), true).unwrap(),
            json!({"messages":messages,"max_tokens":1024,"temperature":0.2,"stream":true,"truncate":true})
        );
        assert!(chat_body(json!({}), None, None, true).is_err());
    }
}
