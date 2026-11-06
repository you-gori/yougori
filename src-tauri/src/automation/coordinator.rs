//! Coordinate conflicting resources, never the entire platform or a transfer's lifetime.
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, Weak},
};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};
use tokio_util::sync::CancellationToken;

#[derive(Default)]
pub(super) struct Coordinator {
    locks: Mutex<BTreeMap<String, Weak<AsyncMutex<()>>>>,
    owners: Mutex<BTreeMap<String, String>>,
}
pub(super) struct Lease<'a> {
    coordinator: &'a Coordinator,
    keys: Vec<String>,
    _guards: Vec<OwnedMutexGuard<()>>,
}
impl Drop for Lease<'_> {
    fn drop(&mut self) {
        let mut owners = self
            .coordinator
            .owners
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        for key in &self.keys {
            owners.remove(key);
        }
    }
}
impl Coordinator {
    pub(super) async fn acquire(
        &self,
        keys: &[String],
        id: &str,
        cancellation: &CancellationToken,
        waiting: impl Fn(&str, Option<String>),
    ) -> Result<Lease<'_>, String> {
        let mut lease = Lease {
            coordinator: self,
            keys: Vec::new(),
            _guards: Vec::new(),
        };
        for key in keys {
            let lock = {
                let mut locks = self.locks.lock().unwrap_or_else(|e| e.into_inner());
                locks.retain(|_, lock| lock.strong_count() > 0);
                if let Some(lock) = locks.get(key).and_then(Weak::upgrade) {
                    lock
                } else {
                    let lock = Arc::new(AsyncMutex::new(()));
                    locks.insert(key.clone(), Arc::downgrade(&lock));
                    lock
                }
            };
            let owner = self
                .owners
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(key)
                .cloned();
            if lock.try_lock().is_err() {
                waiting(key, owner);
            }
            let guard = tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Err("YOUGORI_OPERATION_CANCELLED: cancelled before execution".into()),
                guard = lock.lock_owned() => guard,
            };
            self.owners
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(key.clone(), id.to_owned());
            lease.keys.push(key.clone());
            lease._guards.push(guard);
        }
        Ok(lease)
    }
}

pub(super) fn resources(method: &str, params: &Value, mutating: bool) -> Vec<String> {
    if !mutating {
        return Vec::new();
    }
    // The restricted VM sandboxes hold their own authority: the service's lifecycle
    // supervisor, its leases and the host ledger arbitrate every launch, command, stop and
    // revocation, and a stop or a cancel must reach a sandbox while a command runs. Under
    // the method-wide feature lease every call waited for the running command's job (a
    // status poll took 120 s in the acceptance run of 30 October 2026).
    if method == "sandbox_vm" {
        return Vec::new();
    }
    let mut ids = BTreeSet::new();
    fn collect(value: &Value, ids: &mut BTreeSet<String>) {
        if let Some(object) = value.as_object() {
            for (key, value) in object {
                if matches!(key.as_str(), "environmentId" | "sourceId" | "targetId") {
                    if let Some(id) = value.as_str() {
                        ids.insert(id.to_owned());
                    }
                } else if matches!(key.as_str(), "request" | "invitation") {
                    collect(value, ids);
                }
            }
        }
    }
    collect(params, &mut ids);
    let prefix = match method {
        "copy_files_to_environment"
        | "copy_files_from_environment"
        | "copy_files_between_environments" => "transfer",
        "execute_guest_job" => "execution",
        _ => "environment",
    };
    let mut keys: BTreeSet<String> = ids.into_iter().map(|id| format!("{prefix}:{id}")).collect();
    if matches!(method, "update_settings" | "patch_settings") {
        keys.insert("configuration:settings".into());
    }
    if matches!(method, "project_action" | "import_compose") {
        if let Some(path) = params["path"].as_str() {
            keys.insert(format!("project:{path}"));
        }
    }
    if method == "create_environment" {
        if let Some(name) = params["request"]["name"].as_str() {
            keys.insert(format!("create:{name}"));
        }
    }
    // Independent global features may share their own lock. Their native store
    // commits remain short, and provider coordination remains in the provider.
    if keys.is_empty() {
        keys.insert(format!("feature:{method}"));
    }
    keys.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn transfer_and_unrelated_environment_do_not_block_control() {
        let coordinator = Coordinator::default();
        let token = CancellationToken::new();
        let transfer = coordinator
            .acquire(&["transfer:env-a".into()], "import", &token, |_, _| {})
            .await
            .unwrap();
        for key in [
            "environment:env-a",
            "environment:env-b",
            "configuration:settings",
        ] {
            let keys = vec![key.into()];
            let lease = tokio::time::timeout(
                std::time::Duration::from_millis(100),
                coordinator.acquire(&keys, "control", &token, |_, _| {}),
            )
            .await
            .unwrap()
            .unwrap();
            drop(lease);
        }
        drop(transfer);
    }
    #[tokio::test]
    async fn conflicting_wait_reports_owner_and_can_be_cancelled() {
        let coordinator = Coordinator::default();
        let keys = vec!["environment:env-a".into()];
        let owner_token = CancellationToken::new();
        let owner = coordinator
            .acquire(&keys, "owner-job", &owner_token, |_, _| {})
            .await
            .unwrap();
        let token = CancellationToken::new();
        let waiter = coordinator
            .acquire(&keys, "waiter-job", &token, |resource, owner| {
                assert_eq!(resource, "environment:env-a");
                assert_eq!(owner.as_deref(), Some("owner-job"));
                token.cancel();
            })
            .await;
        assert!(waiter.is_err());
        drop(owner);
        assert!(coordinator
            .acquire(&keys, "after", &owner_token, |_, _| {})
            .await
            .is_ok());
    }
    #[tokio::test]
    async fn cancelled_multi_resource_wait_releases_only_its_acquired_resources() {
        let coordinator = Coordinator::default();
        let token = CancellationToken::new();
        let owner = coordinator
            .acquire(&["environment:env-z".into()], "owner", &token, |_, _| {})
            .await
            .unwrap();
        let cancellation = CancellationToken::new();
        let waiting = coordinator
            .acquire(
                &["environment:env-a".into(), "environment:env-z".into()],
                "cancelled-waiter",
                &cancellation,
                |resource, owner| {
                    assert_eq!(resource, "environment:env-z");
                    assert_eq!(owner.as_deref(), Some("owner"));
                    cancellation.cancel();
                },
            )
            .await;
        assert!(waiting.err().unwrap().starts_with("YOUGORI_OPERATION_CANCELLED"));
        let available = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            coordinator.acquire(&["environment:env-a".into()], "next", &token, |_, _| {}),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            coordinator.owners.lock().unwrap().get("environment:env-z").map(String::as_str),
            Some("owner")
        );
        drop(available);
        drop(owner);
    }
}
