//! The engine's one evidence service and its automation method `host_evidence`.
//!
//! `status` shows what the service holds without running anything; `plan` lists the
//! queries a refresh would run, without running them; `refresh` runs them once (one
//! collection at a time) and installs the result. The local model runner binds the
//! runtimes it starts here and unbinds them when they stop (G03), and records the running
//! ones it could not bind with why, which `status` lists as `unboundRuntimes`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use serde_json::{json, Value};
use tauri::Manager;

use super::adapters::{RuntimeBinding, SleepCycle};
use super::collect::{collect, plan};
use super::inventory::{CudaRuntimeFacts, HostInventory};
use super::service::{EvidenceService, InstallReport};
use crate::foundation::evidence::{ClockReading, RuntimeSubject};
use crate::foundation::ids::SystemClock;
use crate::runtime::RuntimeManager;
use crate::AppHandle;

type Service = tokio::sync::Mutex<EvidenceService<SystemClock>>;

static SERVICE: OnceLock<Result<Service, String>> = OnceLock::new();
static COLLECTION: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
/// The running local runtimes the model runner could not bind, by environment, with why.
static UNBOUND: Mutex<BTreeMap<String, String>> = Mutex::new(BTreeMap::new());

fn service() -> Result<&'static Service, String> {
    SERVICE
        .get_or_init(|| {
            EvidenceService::new(Arc::new(SystemClock::new()))
                .map(tokio::sync::Mutex::new)
                .map_err(|error| format!("Host evidence is unavailable: {error}"))
        })
        .as_ref()
        .map_err(Clone::clone)
}

/// The engine's own report of its CUDA runtime, where it has one.
async fn cuda_runtime(app: &AppHandle) -> Option<CudaRuntimeFacts> {
    if !cfg!(windows) {
        return None;
    }
    let status = app.state::<RuntimeManager>().cuda_status().await;
    Some(CudaRuntimeFacts {
        supported: status.supported,
        installed: status.installed,
        running: status.running,
        update_available: status.update_available,
    })
}

/// The latest inventory, if one was collected, and a reading of the evidence registry's
/// clock: the sandbox doctor (M08, `runtime/doctor.rs`) names this host from the same
/// inventory and judges on the same clock as this registry. Runs nothing.
pub(crate) async fn inventory_and_now() -> Result<(Option<HostInventory>, ClockReading), String> {
    let service = service()?.lock().await;
    Ok((service.status().inventory, service.registry().now()))
}

/// Binds a runtime the local model runner started in this computer's CUDA runtime, and
/// observes it (G03).
pub(crate) async fn bind_runtime(binding: RuntimeBinding) -> Result<InstallReport, String> {
    Ok(service()?.lock().await.bind_runtime(binding))
}

/// Unbinds a runtime the local model runner bound, once it stopped, was released or is
/// gone; its evidence is dropped (G03).
pub(crate) async fn unbind_runtime(runtime: &RuntimeSubject) -> Result<InstallReport, String> {
    Ok(service()?.lock().await.unbind_runtime(runtime))
}

/// Records a sleep cycle the local model runner saw on a runtime it bound: the host probe
/// around a park by sleep and after the wake (G01/G02; CORE-01 sleep-mode weight discarding).
pub(crate) async fn record_sleep_cycle(
    runtime: &RuntimeSubject,
    cycle: SleepCycle,
) -> Result<InstallReport, String> {
    service()?.lock().await.record_sleep_cycle(runtime, cycle)
}

/// Records the running local runtimes the model runner could not bind, by environment,
/// with why; replaces the previous record.
pub(crate) fn record_unbound(unbound: BTreeMap<String, String>) {
    *UNBOUND.lock().unwrap_or_else(PoisonError::into_inner) = unbound;
}

fn encoded(value: impl serde::Serialize) -> Result<Value, String> {
    serde_json::to_value(value).map_err(|error| error.to_string())
}

/// The service's status, with the running local runtimes left unbound and why.
fn status(service: &EvidenceService<SystemClock>) -> Result<Value, String> {
    let mut status = encoded(service.status())?;
    let unbound: Vec<Value> = UNBOUND
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .map(|(environment, reason)| json!({ "environmentId": environment, "reason": reason }))
        .collect();
    let cycles: Vec<Value> = service
        .sleep_cycles()
        .into_iter()
        .map(|(runtime, cycle)| json!({ "runtime": runtime, "cycle": cycle }))
        .collect();
    if let Some(fields) = status.as_object_mut() {
        fields.insert("unboundRuntimes".into(), Value::Array(unbound));
        fields.insert("sleepCycles".into(), Value::Array(cycles));
    }
    Ok(status)
}

/// The `host_evidence` automation method: `status` (the default), `refresh` or `plan`.
pub(crate) async fn dispatch(app: AppHandle, action: Option<String>) -> Result<Value, String> {
    match action.as_deref().unwrap_or("status") {
        "status" => status(&*service()?.lock().await),
        "plan" => Ok(json!({ "queries": plan() })),
        "refresh" => {
            let _one_at_a_time = COLLECTION
                .get_or_init(|| tokio::sync::Mutex::new(()))
                .lock()
                .await;
            let started_at = service()?.lock().await.now();
            let cuda = cuda_runtime(&app).await;
            let inventory = collect(started_at, cuda).await;
            let mut service = service()?.lock().await;
            let report = service.install(inventory);
            Ok(json!({ "refresh": encoded(report)?, "status": status(&service)? }))
        }
        other => Err(format!(
            "Unknown host evidence action '{other}'. Use status, refresh or plan."
        )),
    }
}
