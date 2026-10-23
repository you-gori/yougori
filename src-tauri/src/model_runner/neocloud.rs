use super::*;

pub(crate) async fn run_neocloud_model(model: String, environment_id: String, port: Option<u16>, app: AppHandle) -> Result<Value, String> {
    let model = normalize_model(&model)?;
    if crate::model_registry::is_registry(&model){return Err("Published registry models run on this computer's GPU. To use your cloud GPU, connect its publisher-hosted API in Model library.".into())}
    let compatibility=super::preflight::preflight(&model).await?;
    if compatibility["supported"]!=true{return Err(compatibility["reason"].as_str().unwrap_or("Unsupported model runner").into())}
    // The pinned llama.cpp build needs a newer C library than RunPod's PyTorch images provide.
    if compatibility["runner"]=="yougori-llama-cpp"{return Err("GGUF models run on this computer's GPU for now. Choose a safetensors repository for a Neocloud pod.".into())}
    launch(model, compatibility, environment_id, port, app).await
}

/// The model families that have agent tool calling on a rented GPU: those with a tool-call parser
/// in the pinned vLLM 0.29.0 (vllm/tool_parsers) and a chat template that uses it. Others are not
/// offered for a Swarm worker on a rented GPU.
pub(crate) fn tool_parser(model: &str, architectures: &Value) -> Option<&'static str> {
    let has = |name: &str| architectures.as_array().is_some_and(|all| all.iter().any(|value| value == name));
    let name = model.to_ascii_lowercase();
    if has("Qwen3MoeForCausalLM") && name.contains("coder") { return Some("qwen3_coder"); }
    if has("Qwen2ForCausalLM") || has("Qwen3ForCausalLM") || has("Qwen3MoeForCausalLM") { return Some("hermes"); }
    // Llama-architecture checkpoints that are not Llama 3 have no Llama 3 tool format.
    if has("LlamaForCausalLM") && (name.contains("llama-3") || name.contains("llama3")) { return Some("llama3_json"); }
    if has("GptOssForCausalLM") { return Some("openai"); }
    if has("Gemma4ForCausalLM") { return Some("gemma4"); }
    None
}

const NO_AGENT_TOOLS: &str = "This model has no agent tool calling on a rented GPU. Choose a Qwen 2.5, Qwen 3, Llama 3, gpt-oss or Gemma 4 safetensors model.";

/// What a Swarm worker runs on a rented GPU: the model on vLLM, with its family's tool-call parser,
/// even where the Transformers runner would otherwise serve it, because only vLLM calls tools here.
pub(crate) async fn agent_preflight(model: &str) -> Result<Value, String> {
    let model = normalize_model(model)?;
    if crate::model_registry::is_registry(&model) { return Err(NO_AGENT_TOOLS.into()); }
    let mut compatibility = super::preflight::preflight(&model).await?;
    if compatibility["runner"] == "yougori-llama-cpp" {
        return Err("GGUF models run on this computer, not on a rented GPU. Choose a safetensors model.".into());
    }
    if compatibility["supported"] != true {
        return Err(compatibility["reason"].as_str().unwrap_or("Unsupported model runner").into());
    }
    agent_runner(&model, &mut compatibility)?;
    Ok(compatibility)
}

/// Switches a supported preflight to vLLM with a tool-call parser, or says why it cannot.
fn agent_runner(model: &str, compatibility: &mut Value) -> Result<(), String> {
    let parser = tool_parser(model, &compatibility["architectures"]).ok_or(NO_AGENT_TOOLS)?;
    let config = json!({"model_type": compatibility["modelType"], "architectures": compatibility["architectures"]});
    let vllm = super::vllm::inspect(&config).ok_or(NO_AGENT_TOOLS)?;
    if compatibility["runner"] != "yougori-vllm" {
        for field in ["runner", "format", "reason", "dependencies", "runtimeImage"] { compatibility[field] = vllm[field].clone(); }
        // The same room vLLM's own preflight sets aside: every weight in GPU memory, plus runtime.
        if let Some(bytes) = compatibility["resources"]["weightsBytes"].as_u64() {
            compatibility["resources"]["storageGbRecommended"] = json!(((bytes as f64 / 1073741824.0) * 1.15 + 24.0).ceil());
            compatibility["resources"]["gpuMemoryGbEstimated"] = json!(((bytes as f64 / 1073741824.0 + 2.0) / 0.90).ceil());
        }
    }
    compatibility["toolParser"] = json!(parser);
    Ok(())
}

/// A Swarm worker's model on its rented GPU: vLLM with agent tool calling. Like
/// `run_neocloud_model`, it only connects to a pod that is already running.
pub(crate) async fn run_neocloud_agent_model(model: String, environment_id: String, app: AppHandle) -> Result<Value, String> {
    let compatibility = agent_preflight(&model).await?;
    launch(normalize_model(&model)?, compatibility, environment_id, None, app).await
}

/// The model key a pod's server runs with. A pod that has one keeps it, and one that cannot be read
/// right now is an error: a fresh key written over the saved one would lock this computer out of
/// its own model server, which refuses another key as "managed by another installation" until the
/// pod is restarted. Only a pod with no key yet gets a new one.
fn pod_model_key(options: &yougori_cli::workload::Options, read: impl FnOnce() -> Result<String, String>) -> Result<String, String> {
    let bound = options.secret_environment.contains_key("YOUGORI_MODEL_TOKEN") || options.environment.contains_key("YOUGORI_MODEL_TOKEN");
    if !bound {
        return Ok(format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple()));
    }
    read().map_err(|error| format!("Yougori could not read this pod's model key ({error}). Nothing was changed; try again in a moment."))
}

async fn launch(model: String, compatibility: Value, environment_id: String, port: Option<u16>, app: AppHandle) -> Result<Value, String> {
    if port == Some(0) { return Err("Invalid API port".into()); }
    let store = app.state::<PlatformStore>();
    let runtime = app.state::<RuntimeManager>();
    let state = store.snapshot()?;
    let env = state.environments.iter().find(|e| e.id == environment_id && e.kind == EnvironmentKind::Cloud)
        .ok_or("Choose an existing RunPod environment")?;
    let deployment = state.neocloud_deployments.get(&environment_id).ok_or("This environment is not a Neocloud pod")?;
    if deployment.provider != "runpod" || !matches!(deployment.product.as_str(), "pod" | "gpu") || deployment.extra["compute"] == "cpu" {
        return Err("Choose a RunPod GPU pod; serverless endpoints cannot run this model server".into());
    }
    // Connect to the already powered-on pod. This never creates or powers on paid resources.
    if env.status != EnvironmentStatus::Running || !runtime.cloud.connected(&environment_id).await {
        crate::commands::set_environment_status(environment_id.clone(), EnvironmentStatus::Running, app.state(), app.state()).await
            .map_err(|e| format!("Cannot connect to the pod: {e}. Start it in Neocloud and wait for SSH to be ready."))?;
    }
    let id = env.runtime_id.as_deref().unwrap_or(&env.id);
    let mut options = runtime.workload_options(id)?;
    let token = pod_model_key(&options, || crate::projects::secrets::variable(&options, "YOUGORI_MODEL_TOKEN"))?;
    // Persist credentials before launching: a lost response must not orphan the API key.
    let reference=options.secret_environment.get("YOUGORI_MODEL_TOKEN").cloned().unwrap_or_else(||format!("model-api-{}",uuid::Uuid::new_v4().simple()));
    crate::projects::secrets::store(&reference,&token)?;
    options.environment.remove("YOUGORI_MODEL_TOKEN");
    options.secret_environment.insert("YOUGORI_MODEL_TOKEN".into(),reference);
    options.environment.insert("YOUGORI_MODEL_REVISION".into(),compatibility["revision"].as_str().unwrap_or("").into());
    let format=if compatibility["runner"]=="yougori-vllm" {"vllm"} else {"safetensors"};
    options.environment.insert("YOUGORI_MODEL_FORMAT".into(),format.into());
    super::ensure_admin_token(&mut options)?;
    let admin = crate::projects::secrets::variable(&options, super::ADMIN_TOKEN)?;
    // The rented pod keeps its configuration on the provider's disk. Public repositories download
    // without the account token; only gated or private ones receive it.
    let hf_token = super::huggingface::token().filter(|_| compatibility["hubTokenRequired"] != false);
    if let Some(value) = &hf_token {
        crate::projects::secrets::store(super::huggingface::TOKEN_REFERENCE, value)?;
        options.secret_environment.insert("HF_TOKEN".into(), super::huggingface::TOKEN_REFERENCE.into());
    } else if options.secret_environment.get("HF_TOKEN").is_some_and(|reference| reference == super::huggingface::TOKEN_REFERENCE) {
        options.secret_environment.remove("HF_TOKEN");
    }
    runtime.save_workload_options(id, &options)?;
    let mut run = json!({"model":model,"token":token,"adminToken":admin,"hfToken":hf_token,"revision":compatibility["revision"],"format":format,"source":super::server_source()});
    if let Some(parser) = compatibility["toolParser"].as_str() { run["toolParser"] = json!(parser); }
    let result = runtime.cloud.session(&environment_id).await?.request("model/run", run).await?;
    options.environment.insert("YOUGORI_MODEL".into(), model.clone());
    runtime.save_workload_options(id, &options)?;
    store.mutate(|state| {
        if let Some(deployment) = state.neocloud_deployments.get_mut(&environment_id) {
            if !deployment.extra.is_object() { deployment.extra = json!({}); }
            deployment.extra["yougoriModel"] = json!(model);
        }
        Ok(())
    })?;
    let mut result = json!({"id":environment_id,"name":env.name,"model":model,"status":"loading","neocloud":true,"reused":result["reused"]});
    if let Some(port) = port {
        let api = super::model_api(environment_id, port, app.clone()).await?;
        result["apiUrl"] = api["apiUrl"].clone();
        result["apiKey"] = api["apiKey"].clone();
    }
    Ok(result)
}

pub(crate) async fn start_model(environment_id: String, app: AppHandle) -> Result<Value, String> {
    let state = app.state::<PlatformStore>().snapshot()?;
    let env = state.environments.iter().find(|e| e.id == environment_id).ok_or("Model environment not found")?;
    let options = app.state::<RuntimeManager>().workload_options(env.runtime_id.as_deref().unwrap_or(&env.id))?;
    let model = options.environment.get("YOUGORI_MODEL").ok_or("This is not a model environment")?;
    if env.kind == EnvironmentKind::Cloud {
        return run_neocloud_model(model.clone(), environment_id, None, app).await;
    }
    if env.status != EnvironmentStatus::Running {
        crate::commands::set_environment_status(environment_id.clone(), EnvironmentStatus::Running, app.state(), app.state()).await?;
    }
    Ok(json!({"id":environment_id,"model":model}))
}

pub(crate) async fn stop_model(environment_id: String, app: AppHandle) -> Result<Value, String> {
    let state = app.state::<PlatformStore>().snapshot()?;
    let env = state.environments.iter().find(|e| e.id == environment_id).ok_or("Model environment not found")?;
    let runtime = app.state::<RuntimeManager>();
    let options = runtime.workload_options(env.runtime_id.as_deref().unwrap_or(&env.id))?;
    if !options.environment.contains_key("YOUGORI_MODEL") { return Err("This is not a model environment".into()); }
    if env.kind == EnvironmentKind::Cloud {
        if !runtime.cloud.connected(&environment_id).await {
            crate::commands::set_environment_status(environment_id.clone(), EnvironmentStatus::Running, app.state(), app.state()).await?;
        }
        runtime.cloud.session(&environment_id).await?.request("model/stop", json!({"token":crate::projects::secrets::variable(&options,"YOUGORI_MODEL_TOKEN")?})).await?;
        return Ok(json!({"id":environment_id,"stopped":true,"podStillRunning":true}));
    }
    crate::commands::set_environment_status(environment_id.clone(), EnvironmentStatus::Stopped, app.state(), app.state()).await?;
    Ok(json!({"id":environment_id,"stopped":true}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pod_keeps_its_model_key_when_the_vault_cannot_be_read() {
        let mut options = yougori_cli::workload::Options::default();
        assert_eq!(pod_model_key(&options, || unreachable!("nothing to read")).unwrap().len(), 64, "a pod with no key yet gets one");
        options.secret_environment.insert("YOUGORI_MODEL_TOKEN".into(), "model-api-1".into());
        assert_eq!(pod_model_key(&options, || Ok("saved-key".into())), Ok("saved-key".into()));
        // Unreadable for a moment is an error, never a fresh key written over the saved one.
        let refused = pod_model_key(&options, || Err("the vault is locked".into())).unwrap_err();
        assert!(refused.contains("could not read this pod's model key (the vault is locked)"), "{refused}");
    }

    #[test]
    fn only_families_with_a_vllm_tool_parser_run_a_worker_on_a_rented_gpu() {
        let arch = |name: &str| json!([name]);
        assert_eq!(tool_parser("huihui-ai/Qwen3-8B-abliterated", &arch("Qwen3ForCausalLM")), Some("hermes"));
        assert_eq!(tool_parser("huihui-ai/Qwen2.5-Coder-7B-Instruct-abliterated", &arch("Qwen2ForCausalLM")), Some("hermes"));
        assert_eq!(tool_parser("huihui-ai/Qwen3-30B-A3B-abliterated", &arch("Qwen3MoeForCausalLM")), Some("hermes"));
        assert_eq!(tool_parser("Qwen/Qwen3-Coder-30B-A3B-Instruct", &arch("Qwen3MoeForCausalLM")), Some("qwen3_coder"));
        assert_eq!(tool_parser("huihui-ai/Llama-3.2-3B-Instruct-abliterated", &arch("LlamaForCausalLM")), Some("llama3_json"));
        assert_eq!(tool_parser("huihui-ai/Huihui-gpt-oss-20b-BF16-abliterated", &arch("GptOssForCausalLM")), Some("openai"));
        // A Llama-architecture model that is not Llama 3 has no Llama 3 tool format.
        assert_eq!(tool_parser("TinyLlama/TinyLlama-1.1B-Chat-v1.0", &arch("LlamaForCausalLM")), None);
        assert_eq!(tool_parser("google/gemma-3-12b-it", &arch("Gemma3ForCausalLM")), None);
        assert_eq!(tool_parser("acme/model", &json!(null)), None);
    }

    #[test]
    fn a_transformers_model_with_a_parser_moves_to_vllm_and_others_are_refused() {
        let mut qwen = json!({"runner":"yougori-transformers-chat","format":"safetensors","modelType":"qwen3","architectures":["Qwen3ForCausalLM"],"resources":{"weightsBytes":16_000_000_000u64}});
        agent_runner("huihui-ai/Qwen3-8B-abliterated", &mut qwen).unwrap();
        assert_eq!(qwen["runner"], "yougori-vllm");
        assert_eq!(qwen["format"], "vllm");
        assert_eq!(qwen["toolParser"], "hermes");
        assert_eq!(qwen["remoteCodeAllowed"], json!(null), "the vLLM fields replace only the runner's own");
        assert!(qwen["resources"]["gpuMemoryGbEstimated"].as_f64().unwrap() > 16.0);
        let mut gemma = json!({"runner":"yougori-transformers-chat","modelType":"gemma3","architectures":["Gemma3ForCausalLM"]});
        assert_eq!(agent_runner("google/gemma-3-12b-it", &mut gemma).unwrap_err(), NO_AGENT_TOOLS);
        assert_eq!(gemma["runner"], "yougori-transformers-chat", "a refused model is left as it was");
    }
}
