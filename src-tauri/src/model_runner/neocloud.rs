use super::*;

pub(crate) async fn run_neocloud_model(model: String, environment_id: String, port: Option<u16>, app: AppHandle) -> Result<Value, String> {
    let model = normalize_model(&model)?;
    let compatibility=super::preflight::preflight(&model).await?;
    if compatibility["supported"]!=true{return Err(compatibility["reason"].as_str().unwrap_or("Unsupported model runner").into())}
    // The pinned llama.cpp build needs a newer C library than RunPod's PyTorch images provide.
    if compatibility["runner"]=="yougori-llama-cpp"{return Err("GGUF models run on this computer's GPU for now. Choose a safetensors repository for a Neocloud pod.".into())}
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
    let token = crate::projects::secrets::variable(&options,"YOUGORI_MODEL_TOKEN").ok()
        .unwrap_or_else(|| format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple()));
    // Persist credentials before launching: a lost response must not orphan the API key.
    let reference=options.secret_environment.get("YOUGORI_MODEL_TOKEN").cloned().unwrap_or_else(||format!("model-api-{}",uuid::Uuid::new_v4().simple()));
    crate::projects::secrets::store(&reference,&token)?;
    options.environment.remove("YOUGORI_MODEL_TOKEN");
    options.secret_environment.insert("YOUGORI_MODEL_TOKEN".into(),reference);
    options.environment.insert("YOUGORI_MODEL_REVISION".into(),compatibility["revision"].as_str().unwrap_or("").into());
    let format=if compatibility["runner"]=="yougori-vllm" {"vllm"} else {"safetensors"};
    options.environment.insert("YOUGORI_MODEL_FORMAT".into(),format.into());
    let hf_token = super::huggingface::token();
    if let Some(value) = &hf_token {
        crate::projects::secrets::store(super::huggingface::TOKEN_REFERENCE, value)?;
        options.secret_environment.insert("HF_TOKEN".into(), super::huggingface::TOKEN_REFERENCE.into());
    }
    runtime.save_workload_options(id, &options)?;
    let result = runtime.cloud.session(&environment_id).await?.request("model/run",
        json!({"model":model,"token":token,"hfToken":hf_token,"revision":compatibility["revision"],"format":format,"source":super::server_source()})).await?;
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
