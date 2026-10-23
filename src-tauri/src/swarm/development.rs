//! Explicit API-model experiments for paused private workers in a development build.
use super::*;
use crate::models::{EnvironmentKind, RuntimeProviderKind};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PreviousModel {
    model: String,
    environment_id: Option<String>,
    quant: Option<String>,
    gpu: String,
    owned: bool,
}

pub(super) fn allowed(development_build: bool, worker: &Worker) -> Result<(), String> {
    if !development_build {
        return Err("API model experiments require the development build".into());
    }
    if worker.closed.is_none() || !matches!(worker.state.as_str(), "paused" | "stopped") {
        return Err("Pause a private test worker before changing its development model".into());
    }
    if worker.rented_gpu.is_some() {
        return Err("API model tests require a worker whose original model runs on this computer".into());
    }
    Ok(())
}

fn select(worker: &mut Worker, model: String, environment: String) {
    if worker.development_previous_model.is_none() {
        worker.development_previous_model = Some(PreviousModel {
            model: worker.model.clone(), environment_id: worker.model_environment_id.clone(),
            quant: worker.quant.clone(), gpu: worker.gpu.clone(), owned: worker.owned_model,
        });
    }
    worker.model = model;
    worker.model_environment_id = Some(environment);
    worker.quant = None;
    worker.gpu = "cpu".into();
    worker.owned_model = true;
}

fn restore(worker: &mut Worker) -> Result<(), String> {
    let previous = worker.development_previous_model.take().ok_or("No development model is selected")?;
    worker.model = previous.model;
    worker.model_environment_id = previous.environment_id;
    worker.quant = previous.quant;
    worker.gpu = previous.gpu;
    worker.owned_model = previous.owned;
    Ok(())
}

pub(super) async fn configure(app: &AppHandle, mut worker: Worker, request: &Value) -> Result<Value, String> {
    allowed(cfg!(debug_assertions), &worker)?;
    if request["confirmed"] != true {
        return Err("Confirm that this private test may send model context to the configured API provider".into());
    }
    if let Some(cancel) = app.state::<Swarm>().operations.lock().await.get(&worker.id) {
        cancel.cancel();
    }
    let _execution = execution_gate(app, &worker.id).await.lock_owned().await;
    if let Some(id) = request["modelEnvironmentId"].as_str() {
        let environment = app.state::<PlatformStore>().environment(id)?;
        let options = app.state::<crate::runtime::RuntimeManager>()
            .workload_options(environment.runtime_id.as_deref().unwrap_or(id))?;
        if environment.kind != EnvironmentKind::Container
            || environment.provider != Some(RuntimeProviderKind::YougoriOci)
            || options.environment.get("YOUGORI_SWARM_DEVELOPMENT_API").map(String::as_str) != Some("1")
            || options.environment.get("YOUGORI_SWARM_MODEL_OWNER") != Some(&worker.id)
            || !options.secret_environment.contains_key("YOUGORI_API_KEY")
            || !options.secret_environment.contains_key("YOUGORI_MODEL_TOKEN")
        {
            return Err("Choose this worker's dedicated development API relay with protected credentials".into());
        }
        let model = options.environment.get("YOUGORI_MODEL").ok_or("The relay has no selected model")?.clone();
        select(&mut worker, model, id.into());
    } else {
        restore(&mut worker)?;
    }
    // Updating the harness on Start installs its private connection to the new model.
    worker.harness_version.clear();
    worker.error = None;
    worker.summary.clear();
    worker.state = "paused".into();
    worker.stage = "Test model configured. Press Start to run the private worker.".into();
    let selected = worker.clone();
    worker = update(app, &worker.id, |current| {
        current.generation += 1;
        current.model = selected.model;
        current.model_environment_id = selected.model_environment_id;
        current.quant = selected.quant;
        current.gpu = selected.gpu;
        current.owned_model = selected.owned_model;
        current.development_previous_model = selected.development_previous_model;
        current.harness_version = selected.harness_version;
        current.error = None;
        current.summary = selected.summary;
        current.state = selected.state;
        current.stage = selected.stage;
    }).await?;
    Ok(json!({"worker":worker.view()}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn worker() -> Worker {
        serde_json::from_value(json!({"id":"worker-test","name":"Test","model":"owner/local-GGUF",
            "state":"paused","stage":"Paused","site":"https://example.test","gpu":"nvidia",
            "resources":{},"quotaGb":20,"keepResident":false,"quant":"Q6_K","ownedModel":true,
            "modelEnvironmentId":"env-local","closed":{"address":"test","certificate":"test","memberId":"test","credential":"test","title":"Fixture"}})).unwrap()
    }

    #[test]
    fn only_paused_private_development_workers_can_change_models() {
        let mut worker = worker();
        assert!(allowed(true, &worker).is_ok());
        assert!(allowed(false, &worker).is_err());
        worker.rented_gpu = Some("env-rented".into());
        assert!(allowed(true, &worker).is_err());
        worker.rented_gpu = None;
        worker.state = "running".into();
        assert!(allowed(true, &worker).is_err());
        worker.state = "paused".into();
        worker.closed = None;
        assert!(allowed(true, &worker).is_err());
    }

    #[test]
    fn api_selection_preserves_the_original_local_model_for_restore() {
        let mut worker = worker();
        select(&mut worker, "fixture-api-model".into(), "env-relay".into());
        select(&mut worker, "second-api-model".into(), "env-relay-2".into());
        assert_eq!(worker.model, "second-api-model");
        assert_eq!(worker.view()["developmentApiModel"], true);
        let saved = serde_json::to_value(&worker).unwrap();
        let mut restored: Worker = serde_json::from_value(saved).unwrap();
        restore(&mut restored).unwrap();
        assert_eq!(restored.model, "owner/local-GGUF");
        assert_eq!(restored.model_environment_id.as_deref(), Some("env-local"));
        assert_eq!(restored.quant.as_deref(), Some("Q6_K"));
        assert_eq!(restored.gpu, "nvidia");
        assert!(restored.owned_model);
        assert!(restored.development_previous_model.is_none());
    }
}
