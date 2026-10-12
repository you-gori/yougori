use super::{vm, RuntimeManager, VmProcess};
use serde_json::{json, Value};
use std::time::Duration;

fn outcome(provider: &str, root: &str, id: Option<&str>, status: &str, error: Option<String>) -> Value {
    let stopped = error.is_none() && matches!(status, "stopped" | "forcedStopped" | "disconnected");
    json!({"provider":provider,"storageRoot":root,"environmentId":id,"status":status,
        "scope":"ownedRuntimes","postconditionVerified":stopped,"ownershipReleased":stopped,
        "error":error.as_deref().map(crate::lifecycle::safe_diagnostic),
        "recoveryAction":if error.is_some(){Some("Inspect this provider on its original storage root; close its live owner normally or reconcile verified abandoned ownership before restarting.")}else{None}})
}

fn report(outcomes: Vec<Value>) -> Value {
    let complete = outcomes.iter().all(|outcome| outcome["error"].is_null() && outcome["postconditionVerified"] == true);
    json!({"complete":complete,"scope":"ownedRuntimes","outcomes":outcomes})
}

impl RuntimeManager {
    /// Stop only runtimes held by this manager and return verified outcomes.
    /// Errors are never converted to success merely because cleanup returned.
    /// The caller supplies its independent overall shutdown deadline.
    pub async fn shutdown_all_report(&self) -> Value {
        let engines = self.loaded_storage_runtimes();
        let children = futures_util::future::join_all(engines.iter().map(|engine| Box::pin(engine.shutdown_all_report())));
        let (local, cloud, native, children) = tokio::join!(self.shutdown_local_report(), self.cloud.shutdown_report(), self.shutdown_all_native_sandboxes_report(), children);
        let mut outcomes = local;
        for child in children { if let Some(values) = child["outcomes"].as_array() { outcomes.extend(values.iter().cloned()); } }
        for mut entry in cloud.into_iter().chain(native) { entry["storageRoot"] = json!(self.data_root.display().to_string()); outcomes.push(entry); }
        report(outcomes)
    }

    async fn shutdown_local_report(&self) -> Vec<Value> {
        let root = self.data_root.display().to_string();
        let native_models = self.shutdown_native_models().await;
        let cuda = async {
            let owned = self.cuda.owns_runtime().await;
            let result = self.cuda.shutdown().await;
            // shutdown retains exclusive CUDA ownership until WSL termination
            // and its stopped postcondition are verified by the host provider.
            let cuda_disk = self.cuda.storage_path();
            let cuda_root = cuda_disk.parent().and_then(std::path::Path::parent).and_then(std::path::Path::parent).unwrap_or(&self.data_root).display().to_string();
            let mut entry = outcome("yougoriCuda", &cuda_root, None, if result.is_ok() {"stopped"} else {"failed"}, result.err());
            entry["ownedRuntime"] = json!(owned);
            if !owned && entry["error"].is_null() { entry["status"] = json!("noOwnedRuntime"); }
            entry
        };
        let oci = async {
            let _exclusive = self.appliance_operations.write().await;
            let Some(mut appliance) = self.appliance.lock().await.take() else { return None };
            let request = self.client.post(format!("{}/v1/system/shutdown", appliance.endpoint.base_url)).bearer_auth(&appliance.endpoint.token)
                .timeout(Duration::from_secs(3)).send().await;
            let graceful = tokio::time::timeout(Duration::from_secs(10), appliance.child.wait()).await.is_ok_and(|result| result.is_ok());
            let mut warnings = Vec::new();
            if !graceful {
                let kill = appliance.child.kill().await;
                let stopped = tokio::time::timeout(Duration::from_secs(3), appliance.child.wait()).await;
                if !stopped.is_ok_and(|result| result.is_ok()) {
                    let error = kill.err().map(|error| error.to_string()).unwrap_or_else(|| "Owned OCI process did not stop before its deadline".into());
                    // Retain its handle so another normal cleanup can reconcile
                    // it; never silently lose ownership after a failed stop.
                    *self.appliance.lock().await = Some(appliance);
                    return Some(outcome("yougoriOci", &root, None, "failed", Some(error)));
                }
                warnings.push("Guest did not shut down gracefully; stopped only its owned OCI process. The next launch must reconcile the preserved disk.".to_string());
            } else if let Err(error) = self.record_appliance_overlay_state() {
                warnings.push(crate::lifecycle::safe_diagnostic(&error));
            }
            if !request.is_ok_and(|response| response.status().is_success()) { warnings.push("Guest did not acknowledge its shutdown request; process exit was checked independently.".into()); }
            let mut entry = outcome("yougoriOci", &root, None, if graceful {"stopped"} else {"forcedStopped"}, None);
            entry["cleanShutdown"] = json!(graceful);
            entry["warnings"] = json!(warnings);
            Some(entry)
        };
        let vms = async {
            let processes: Vec<_> = self.vms.lock().await.drain().collect();
            futures_util::future::join_all(processes.into_iter().map(|(id, process)| self.shutdown_vm_report(id, process))).await
        };
        let (cuda, oci, vms) = tokio::join!(cuda, oci, vms);
        let mut results = vec![cuda, outcome("nativeModel", &root, None, if native_models.is_ok() {"stopped"} else {"failed"}, native_models.err())];
        results.extend(oci);
        results.extend(vms);
        results
    }

    async fn shutdown_vm_report(&self, id: String, mut process: VmProcess) -> Value {
        let root = self.data_root.display().to_string();
        let _ = vm::qmp_execute_bounded(process.qmp_port, "cont", None, Duration::from_secs(2)).await;
        let graceful_requested = if process.is_micro_vm {
            match &process.micro_endpoint { Some(endpoint) => self.request_micro_vm_shutdown(endpoint).await.is_ok(), None => false }
        } else {
            vm::qmp_execute_bounded(process.qmp_port, "system_powerdown", None, Duration::from_secs(3)).await.is_ok()
        };
        let graceful_timeout = if process.is_micro_vm {Duration::from_secs(8)} else {Duration::from_secs(12)};
        let graceful = graceful_requested && tokio::time::timeout(graceful_timeout, process.child.wait()).await.is_ok_and(|result| result.is_ok());
        if !graceful {
            vm::quiesce_and_flush_vm(process.qmp_port, process.is_micro_vm).await;
            let _ = vm::qmp_execute_bounded(process.qmp_port, "quit", None, Duration::from_secs(2)).await;
            let exited = tokio::time::timeout(Duration::from_secs(3), process.child.wait()).await.is_ok_and(|result| result.is_ok());
            if !exited {
                let kill = process.child.kill().await;
                let stopped = tokio::time::timeout(Duration::from_secs(3), process.child.wait()).await.is_ok_and(|result| result.is_ok());
                if !stopped {
                    let error = kill.err().map(|error| error.to_string()).unwrap_or_else(|| "Owned VM process did not stop before its deadline".into());
                    self.vms.lock().await.insert(id.clone(), process);
                    return outcome("qemu", &root, Some(&id), "failed", Some(error));
                }
            }
        }
        let mut entry = outcome("qemu", &root, Some(&id), if graceful {"stopped"} else {"forcedStopped"}, None);
        entry["cleanShutdown"] = json!(graceful);
        if !graceful { entry["warnings"] = json!(["Guest did not exit gracefully; stopped only its owned VM process. Check the preserved guest disk before reusing it."]); }
        entry
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_failed_cuda_shutdown_is_incomplete_with_its_provider_root_and_recovery_action() {
        let failed = outcome("yougoriCuda", "D:/private/runtime", None, "failed", Some("WSL refused stop: https://secret@private/token".into()));
        let result = report(vec![outcome("yougoriOci", "C:/private/runtime", None, "stopped", None), failed]);
        assert_eq!(result["complete"], false);
        assert_eq!(result["outcomes"][1]["provider"], "yougoriCuda");
        assert_eq!(result["outcomes"][1]["storageRoot"], "D:/private/runtime");
        assert_eq!(result["outcomes"][1]["postconditionVerified"], false);
        assert_eq!(result["outcomes"][1]["ownershipReleased"], false);
        assert!(result["outcomes"][1]["recoveryAction"].as_str().unwrap().contains("original storage"));
        assert!(!result.to_string().contains("secret@private"));
    }
}
