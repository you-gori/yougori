//! Named container volumes. Each container runtime keeps its own: the default one, one per extra
//! storage drive, and the GPU runtime. Volumes outlive the environments that created them.
use super::RuntimeManager;
use crate::models::RuntimeProviderKind;
use serde_json::{json, Value};
use std::sync::Arc;

/// One place named volumes can live.
pub struct VolumeStore {
    pub location: String,
    pub provider: RuntimeProviderKind,
    engine: Option<Arc<RuntimeManager>>,
}

impl RuntimeManager {
    /// True when this runtime's container appliance already runs. Never boots it.
    async fn appliance_running(&self) -> bool {
        let mut guard = self.appliance.lock().await;
        matches!(guard.as_mut().map(|process| process.child.try_wait()), Some(Ok(None)))
    }

    fn store_engine<'a>(&'a self, store: &'a VolumeStore) -> &'a RuntimeManager {
        store.engine.as_deref().unwrap_or(self)
    }

    /// Every volume store. `include_stopped` also returns runtimes that would have to boot;
    /// the GPU runtime is only returned while it runs, because starting it needs a GPU workload.
    pub async fn volume_stores(&self, include_stopped: bool) -> (Vec<VolumeStore>, Vec<String>) {
        let mut stores = Vec::new();
        let mut unavailable = Vec::new();
        if include_stopped || self.appliance_running().await {
            stores.push(VolumeStore { location: self.data_root.display().to_string(), provider: RuntimeProviderKind::YougoriOci, engine: None });
        }
        let engines: Vec<Result<Arc<Self>, String>> = if include_stopped {
            self.registered_storage_runtimes()
        } else {
            self.loaded_storage_runtimes().into_iter().map(Ok).collect()
        };
        let mut seen = std::collections::HashSet::new();
        for engine in engines {
            match engine {
                Ok(engine) => {
                    if !seen.insert(engine.data_root.clone()) { continue; }
                    if include_stopped || engine.appliance_running().await {
                        stores.push(VolumeStore { location: engine.data_root.display().to_string(), provider: RuntimeProviderKind::YougoriOci, engine: Some(engine.clone()) });
                    }
                    if engine.cuda.current_endpoint().await.is_ok() {
                        stores.push(VolumeStore { location: format!("GPU runtime ({})", engine.data_root.display()), provider: RuntimeProviderKind::YougoriCuda, engine: Some(engine) });
                    }
                }
                Err(error) => unavailable.push(error),
            }
        }
        if self.cuda.current_endpoint().await.is_ok() {
            stores.push(VolumeStore { location: "GPU runtime".into(), provider: RuntimeProviderKind::YougoriCuda, engine: None });
        }
        (stores, unavailable)
    }

    pub async fn volume_request(&self, store: &VolumeStore, body: &Value) -> Result<Value, String> {
        let engine = self.store_engine(store);
        let _lease = engine.appliance_operations.read().await;
        engine.volume_request_unlocked(&store.provider, body).await
    }

    pub(super) async fn volume_request_unlocked(&self, provider: &RuntimeProviderKind, body: &Value) -> Result<Value, String> {
        let endpoint = self.provider_endpoint(provider).await?;
        let response = self.client.post(format!("{}/v1/volumes/action", endpoint.base_url))
            .bearer_auth(&endpoint.token).json(body).send().await
            .map_err(|error| format!("Cannot reach the container runtime: {error}"))?;
        let response = super::appliance::successful_response(response).await?;
        response.json().await.map_err(|error| format!("Decode the volume response: {error}"))
    }

    /// Volumes in the given stores: `[{store, volumes: [...]} | {store, error}]`.
    pub async fn list_named_volumes(&self, stores: &[VolumeStore], size: bool) -> Vec<Value> {
        let mut results = Vec::new();
        for store in stores {
            let kind = if store.provider == RuntimeProviderKind::YougoriCuda { "gpu" } else { "containers" };
            results.push(match self.volume_request(store, &json!({"action": "list", "size": size})).await {
                Ok(volumes) => json!({"location": store.location, "runtime": kind, "volumes": volumes}),
                Err(error) => json!({"location": store.location, "runtime": kind, "error": error}),
            });
        }
        results
    }
}
