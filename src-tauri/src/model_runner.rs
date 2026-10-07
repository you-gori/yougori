use crate::{models::*, runtime::RuntimeManager, store::PlatformStore};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use tauri::Manager;
use crate::AppHandle;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
mod neocloud;
pub(crate) mod optimizer;
mod local;
pub(crate) mod huggingface;
pub(crate) mod preflight;
mod vllm;
pub use preflight::model_preflight;
pub(crate) use neocloud::{start_model, stop_model};
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
pub async fn run_model(model: String, port: Option<u16>, quant: Option<String>, folder: Option<String>, app: AppHandle) -> Result<Value, String> {
    run_model_with_resources(model, port, Some(ModelResources { model_folder:folder, ..Default::default() }), quant, app).await
}
/// The dashboard's `--neocloud`: serve a model on an existing, powered-on RunPod GPU pod.
#[tauri::command]
pub async fn run_neocloud_model(model: String, environment_id: String, port: Option<u16>, app: AppHandle) -> Result<Value, String> {
    neocloud::run_neocloud_model(model, environment_id, port, app).await
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
            return Err("Model workloads need at least 12 GB of available storage for the CUDA image and model weights".into());
        }
        Ok((cpu, memory, storage))
    }
}

pub async fn run_model_with_resources(model: String, port: Option<u16>, resources: Option<ModelResources>, quant: Option<String>, app: AppHandle) -> Result<Value, String> {
    run_model_at_revision(model,port,resources,quant,None,None,app).await
}
async fn run_model_at_revision(model: String, port: Option<u16>, resources: Option<ModelResources>, quant: Option<String>, pinned: Option<String>, precision: Option<String>, app: AppHandle) -> Result<Value, String> {
    let model = normalize_model(&model)?;
    if resources.as_ref().is_some_and(|r|r.model_folder.is_some()) {return local::run(model,port,resources.unwrap(),quant,app).await;}
    if crate::model_registry::is_registry(&model) { return run_registry_model(model,port,resources,quant,app).await; }
    let compatibility=preflight::preflight_pinned(&model, quant.as_deref(),pinned.as_deref()).await?;
    if compatibility["supported"]!=true {
        let help=if compatibility["supportAvailable"]==true {format!(" Implement support with `yougori model support hf.co/{model} --agent codex --launch` or choose a coding agent in the App.")}else{String::new()};
        return Err(format!("{}: {}. No environment was created.{help}",model,compatibility["reason"].as_str().unwrap_or("Model compatibility could not be established")));
    }
    vllm::check_local_hardware(&compatibility).await?;
    if port == Some(0) {
        return Err("Invalid API port".into());
    }
    let mut resources=resources.unwrap_or_default();
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
    let volume = format!("model-{}-models", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    let range = |n: f64| json!({"min":n,"preferred":n,"max":n});
    let command = server_command();
    let gguf = compatibility["runner"] == "yougori-llama-cpp";
    let vllm = compatibility["runner"] == "yougori-vllm";
    let mut protected = json!({"YOUGORI_MODEL_TOKEN": token_reference});
    if let Some(token) = huggingface::token() {
        crate::projects::secrets::store(huggingface::TOKEN_REFERENCE, &token)?;
        protected["HF_TOKEN"] = json!(huggingface::TOKEN_REFERENCE);
    }
    let mut environment = json!({"YOUGORI_MODEL":model,"YOUGORI_MODEL_REVISION":compatibility["revision"],"HF_HOME":"/root/.cache/huggingface","HF_HUB_DISABLE_TELEMETRY":"1"});
    environment["YOUGORI_PUBLISHER_SOURCE"] = json!(publisher_source());
    environment["YOUGORI_MODEL_PRECISION"] = json!(precision.as_deref().unwrap_or(if pinned.is_some(){"original"}else{"auto"}));
    if model == "Cloudflare/clef" { environment["YOUGORI_CLEF_SOURCE"] = json!(clef_source()); }
    if gguf {
        environment["YOUGORI_MODEL_FORMAT"] = json!("gguf");
        environment["YOUGORI_MODEL_QUANT"] = compatibility["quant"].clone();
        environment["YOUGORI_MODEL_FILES"] = json!(compatibility["files"].to_string());
    }
    if vllm { environment["YOUGORI_MODEL_FORMAT"] = json!("vllm"); }
    optimizer::environment(&mut environment, &mut protected)?;
    let request = json!({"name":name,"kind":"container","provider":"yougoriCuda","autoSetupCuda":true,"runtime":if gguf {LLAMA_CPP_IMAGE} else if vllm {vllm::IMAGE} else {TRANSFORMERS_IMAGE},"containerCommand":command,"gpuAccess":true,"networkAccess":true,"storageGb":storage,"storageDrive":resources.storage_drive,"description":format!("Hugging Face · {model}"),"resourcePolicy":{"cpu":range(cpu),"memoryGb":range(memory),"priority":"normal","dynamic":false},"workload":{"environment":environment,"secretEnvironment":protected,"volumes":[{"source":volume,"target":"/root/.cache/huggingface","readOnly":false}]},"ports":port.map(|p|vec![format!("{p}:8000")]).unwrap_or_default()});
    let mut result = crate::projects::run_workload(request, true, app).await?;
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
    let check=crate::model_registry::preflight(&model,quant.as_deref()).await?;
    if check["supported"]!=true {return Err(check["reason"].as_str().unwrap_or("Unsupported uploaded architecture").into())}
    if port==Some(0){return Err("Invalid API port".into())}
    let resources=resources.unwrap_or_default();
    let state=app.state::<PlatformStore>().snapshot()?;
    let available=app.state::<RuntimeManager>().new_storage_on_drive(resources.storage_drive.as_deref())?.maximum_gb;
    let required=version["weightsBytes"].as_f64().unwrap_or(0.0)/1073741824.0*1.15+resources.storage_gb.unwrap_or(20.0);
    if available<required{return Err(format!("This drive needs approximately {required:.0} GB free for verified model artifacts and its GPU runtime"))}
    let (cpu,memory,storage)=resources.allocation(state.host.total_cpu,state.host.total_memory_gb,available)?;
    let cached=crate::model_registry::cached(&model,resources.storage_drive.as_deref(),version_id,&app).await?;
    let folder=cached["folder"].as_str().ok_or("Missing model artifact folder")?;
    let token=format!("{}{}",uuid::Uuid::new_v4().simple(),uuid::Uuid::new_v4().simple());
    let reference=format!("model-api-{}",uuid::Uuid::new_v4().simple());crate::projects::secrets::store(&reference,&token)?;
    let gguf=version["format"]=="gguf";
    let upstream=version["upstreamModel"].as_str().unwrap_or(&model);
    let mut environment=json!({"YOUGORI_MODEL":upstream,"YOUGORI_REGISTRY_MODEL":model,"YOUGORI_REGISTRY_VERSION":version_id,"YOUGORI_MODEL_REVISION":version["revision"],"YOUGORI_MODEL_PATH":"/yougori-model","YOUGORI_REGISTRY_SOURCE":registry_source(),"YOUGORI_MODEL_PRECISION":"original","HF_HOME":"/root/.cache/huggingface","HF_HUB_DISABLE_TELEMETRY":"1"});
    environment["YOUGORI_PUBLISHER_SOURCE"]=json!(publisher_source());
    if version["prequantized"]!=true {if let Some(precision)=match version["quant"].as_str(){Some("NF4")=>Some("4bit"),Some("INT8")=>Some("8bit"),_=>None}{environment["YOUGORI_MODEL_PRECISION"]=json!(precision);}}
    if gguf {environment["YOUGORI_MODEL_FORMAT"]=json!("gguf");environment["YOUGORI_MODEL_QUANT"]=version["quant"].clone();let files=cached["files"].as_array().into_iter().flatten().filter(|file|file["name"].as_str().is_some_and(|name|name.ends_with(".gguf"))).cloned().collect::<Vec<_>>();environment["YOUGORI_MODEL_FILES"]=json!(serde_json::to_string(&files).map_err(|e|e.to_string())?);}
    let mut protected=json!({"YOUGORI_MODEL_TOKEN":reference});
    optimizer::environment(&mut environment,&mut protected)?;
    let range=|n:f64|json!({"min":n,"preferred":n,"max":n});
    let name=yougori_cli::public::model_environment_name(&model,state.environments.iter().map(|e|e.name.as_str()));
    let mut result=crate::projects::run_workload(json!({"name":name,"kind":"container","provider":"yougoriCuda","autoSetupCuda":true,"runtime":if gguf{LLAMA_CPP_IMAGE}else{TRANSFORMERS_IMAGE},"containerCommand":server_command(),"gpuAccess":true,"networkAccess":true,"storageGb":storage,"storageDrive":resources.storage_drive,"description":format!("Hugging Face · {model}"),"resourcePolicy":{"cpu":range(cpu),"memoryGb":range(memory),"priority":"normal","dynamic":false},"workload":{"environment":environment,"secretEnvironment":protected,"binds":[{"source":folder,"target":"/yougori-model","readOnly":true}]},"ports":port.map(|p|vec![format!("{p}:8000")]).unwrap_or_default()}),true,app).await?;
    result["model"]=json!(model);result["status"]=json!("loading");result["preflight"]=check;
    if let Some(port)=port{result["apiUrl"]=json!(format!("http://127.0.0.1:{port}/v1"));result["apiKey"]=json!(token);}
    Ok(result)
}
/// The container command that runs this version's model server.
fn server_payload() -> String {
    let mut compressed = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    std::io::Write::write_all(&mut compressed, include_bytes!("model_server.py"))
        .expect("writing the embedded model server to memory");
    STANDARD.encode(compressed.finish().expect("compressing the embedded model server"))
}
fn server_command() -> String {
    // Keep startup below the guest command limit regardless of runner growth.
    // The public compressed source travels in the workload environment instead.
    format!("exec python -u -c {}", shell_quote(
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
pub(crate) fn server_source() -> String {
    format!("__YOUGORI_GPU_SOURCE__ = '{}'\n__YOUGORI_CLEF_SOURCE__ = '{}'\n__YOUGORI_PUBLISHER_SOURCE__ = '{}'\n{}", optimizer::source(), clef_source(), publisher_source(), include_str!("model_server.py"))
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
    let mut options=runtime.workload_options(env.runtime_id.as_deref().unwrap_or(&env.id))?;
    let old=options.clone();
    optimizer::refresh_options(&mut options)?;
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
    if options!=old {
        runtime.save_workload_options(&env.id,&options)?;
        if let Err(error)=runtime.update_workload_configuration(env).await{runtime.save_workload_options(&env.id,&old)?;return Err(error)}
    }
    if current==command{return Ok(())}
    crate::commands::startup::update(environment_id, &command, store, runtime)
        .await
        .map(|_| ())
}
fn is_server_command(command: &str) -> bool {
    command.starts_with("exec python -u -c ") && ["yougori-model", "yougori-model-local-fix"].iter()
        .any(|name| command.contains(&format!(",'\"'\"'{name}'\"'\"',")))
}
fn shell_quote(v: &str) -> String {
    format!("'{}'", v.replace('\'', "'\"'\"'"))
}
async fn model_connection(
    app: &AppHandle,
    id: &str,
    path: &str,
    body: Option<&Value>,
) -> Result<crate::workspace::BoxStream, String> {
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
    let encoded = body.map(Value::to_string).unwrap_or_default();
    if encoded.len() > 65536 {
        return Err("Conversation exceeds 64 KiB; start a new chat".into());
    }
    let mut stream: crate::workspace::BoxStream = if env.kind == EnvironmentKind::Cloud {
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
    let control = if path == "/v1/yougori/optimizer" { format!("X-Yougori-GPU-Control: {}\r\n", crate::projects::secrets::variable(&options,"YOUGORI_GPU_CONTROL_TOKEN")?) } else {String::new()};
    let request=format!("{} {path} HTTP/1.1\r\nHost: localhost\r\n{control}Authorization: Bearer {token}\r\nX-Yougori-Client: yougori\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{encoded}",if body.is_some(){"POST"}else{"GET"},encoded.len());
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    Ok(stream)
}
fn model_error(status_line: &str, body: &[u8]) -> Option<String> {
    if status_line.split_whitespace().nth(1) == Some("200") {
        return None;
    }
    Some(
        serde_json::from_slice::<Value>(body)
            .ok()
            .and_then(|v| v["error"]["message"].as_str().map(str::to_owned))
            .unwrap_or_else(|| "Model request failed".into()),
    )
}
async fn model_request(
    app: &AppHandle,
    id: &str,
    path: &str,
    body: Option<Value>,
) -> Result<Value, String> {
    let stream = model_connection(app, id, path, body.as_ref()).await?;
    tokio::time::timeout(std::time::Duration::from_secs(if body.is_some() {1800} else {15}), async {
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
/// Only the local engine may lease optional free-provider recording.
pub(crate) async fn configure_publishing(app: &AppHandle, id: &str, open: bool) -> Result<Value,String> {
    model_request(app,id,"/v1/yougori/publishing",Some(json!({"downloads":open}))).await.map_err(|_|"Stop this model and run it again to enable publisher-hosted pages; its container and files are kept".to_owned())
}
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
    model_request(&app, &environment_id, "/health", None).await
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
fn chat_body(
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
/// Takes complete server-sent events from `buffer`, leaving a partial event in place.
fn take_events(buffer: &mut Vec<u8>) -> Vec<String> {
    let mut events = Vec::new();
    while let Some(end) = buffer.windows(2).position(|w| w == b"\n\n") {
        let event = buffer.drain(..end + 2).collect::<Vec<_>>();
        let data = String::from_utf8_lossy(&event)
            .lines()
            .filter_map(|line| line.strip_prefix("data:").map(str::trim_start))
            .collect::<Vec<_>>()
            .join("\n");
        if !data.is_empty() {
            events.push(data);
        }
    }
    events
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
    let mut result = json!({"finishReason":"stop"});
    let mut stream = tokio::select! {
        stream = model_connection(app, environment_id, "/v1/chat/completions", Some(body)) => stream?,
        _ = cancel.notified() => {
            result["finishReason"] = json!("cancelled");
            return Ok(result);
        }
    };
    let idle = std::time::Duration::from_secs(1800);
    let mut buffer = Vec::new();
    let mut chunk = vec![0u8; 16 * 1024];
    let mut streaming = false;
    let mut total = 0usize;
    loop {
        let read = tokio::select! {
            read = tokio::time::timeout(idle, stream.read(&mut chunk)) => read
                .map_err(|_| "The model stopped responding; try again or shorten the conversation")?
                .map_err(|e| e.to_string())?,
            _ = cancel.notified() => {
                // Dropping the connection makes the server stop generating at the next token.
                result["finishReason"] = json!("cancelled");
                return Ok(result);
            }
        };
        total += read;
        if total > 8 * 1024 * 1024 {
            return Err("Model response exceeded 8 MiB".into());
        }
        buffer.extend_from_slice(&chunk[..read]);
        if !streaming {
            let Some(split) = buffer.windows(4).position(|w| w == b"\r\n\r\n") else {
                if buffer.len() > 16 * 1024 || read == 0 {
                    return Err("Invalid model HTTP response".into());
                }
                continue;
            };
            let header = String::from_utf8_lossy(&buffer[..split]).to_ascii_lowercase();
            buffer.drain(..split + 4);
            let status = header.lines().next().unwrap_or("").to_owned();
            if status.split_whitespace().nth(1) != Some("200") {
                // Error replies are small JSON documents followed by the server closing the connection.
                if read > 0 {
                    tokio::time::timeout(idle, (&mut stream).take(64 * 1024).read_to_end(&mut buffer))
                        .await
                        .map_err(|_| "Model request failed")?
                        .map_err(|e| e.to_string())?;
                }
                return Err(model_error(&status, &buffer).unwrap_or_default());
            }
            if !header.contains("content-type: text/event-stream") {
                return Err("Run this model again to enable streaming replies".into());
            }
            streaming = true;
        }
        for data in take_events(&mut buffer) {
            if data == "[DONE]" {
                return Ok(result);
            }
            let event: Value = serde_json::from_str(&data).map_err(|e| e.to_string())?;
            if let Some(message) = event["error"]["message"].as_str() {
                return Err(message.to_owned());
            }
            if let Some(text) = event["choices"][0]["delta"]["content"].as_str() {
                if !text.is_empty() {
                    delta(text)?;
                }
            }
            if let Some(reason) = event["choices"][0]["finish_reason"].as_str() {
                result["finishReason"] = json!(reason);
            }
            if event["usage"].is_object() {
                result["usage"] = event["usage"].clone();
            }
        }
        if read == 0 {
            return Err("The model closed the connection before finishing".into());
        }
    }
}
/// A reply streamed for clients that poll for it, such as the CLI.
struct PolledReply {
    text: String,
    outcome: Option<Result<Value, String>>,
    started: std::time::Instant,
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
        // Readers that went away leave replies behind; keep only recent ones.
        replies.retain(|_, reply| reply.started.elapsed() < std::time::Duration::from_secs(900));
        if replies.len() >= 16 {
            return Err("Too many replies are streaming; wait for one to finish".into());
        }
        replies.insert(
            request_id.clone(),
            PolledReply {
                text: String::new(),
                outcome: None,
                started: std::time::Instant::now(),
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
        .get(&request_id)
        .ok_or("This reply is no longer available")?;
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
    #[test] fn registry_verifier_digest_is_portable_and_matches_the_embedded_runner() {
        use sha2::{Digest,Sha256};
        let source=include_str!("model_runner/registry_snapshot.py").replace("\r\n","\n");
        let digest=format!("{:x}",Sha256::digest(source.as_bytes()));
        assert!(include_str!("model_server.py").contains(&digest));
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
    fn only_model_server_commands_are_refreshed() {
        let command = server_command();
        assert!(is_server_command(&command));
        assert!(is_server_command(&command.replace("yougori-model", "yougori-model-local-fix")));
        assert!(command.len() < 32 * 1024, "startup commands are limited to 32 KB");
        assert!(!is_server_command("exec python -u -c 'print(1)'"));
        assert!(!is_server_command("sleep infinity"));
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
    fn server_sent_events_are_taken_only_when_complete() {
        let mut buffer = b"data: {\"a\":1}\n\ndata: [DO".to_vec();
        assert_eq!(take_events(&mut buffer), vec![r#"{"a":1}"#]);
        buffer.extend_from_slice(b"NE]\n\n");
        assert_eq!(take_events(&mut buffer), vec!["[DONE]"]);
        assert!(buffer.is_empty());
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
