//! Short per-engine admission, independent of long provider lifecycle locks.
//! Pending boots reserve their planned allocation before any guest is started.
use super::*;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub(crate) struct Demand {
    pub id: String,
    pub cpu: f64,
    pub memory_gb: f64,
}

#[derive(Default)]
pub(crate) struct HostResourceAdmission {
    claims: Mutex<HashMap<Uuid, Vec<Demand>>>,
}

pub(crate) struct ResourceReservation {
    owner: Arc<HostResourceAdmission>,
    token: Uuid,
    pub demands: Vec<Demand>,
}

impl Drop for ResourceReservation {
    fn drop(&mut self) {
        self.owner.claims.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).remove(&self.token);
    }
}

impl HostResourceAdmission {
    /// Snapshot and reserve under one short mutex. Taking the snapshot outside
    /// this section could miss a different pool's just-committed start.
    fn reserve<F>(self: &Arc<Self>, store: &PlatformStore, plan: F) -> Result<ResourceReservation, String>
    where F: FnOnce(&mut PlatformState, &[Demand]) -> Result<Vec<Demand>, String> {
        let mut claims = self.claims.lock().map_err(|_| "Host resource admission is unavailable")?;
        let pending: Vec<_> = claims.values().flatten().cloned().collect();
        let mut state = store.snapshot()?;
        let proposed = plan(&mut state, &pending)?;
        if proposed.iter().any(|next| pending.iter().any(|current| current.id == next.id)) {
            return Err("[YOUGORI_RESOURCE_BUSY] This allocation is reserved by another operation; retry after it completes".into());
        }
        let mut required: HashMap<String, Demand> = state.environments.iter()
            .filter(|environment| environment.kind != EnvironmentKind::Cloud && !crate::peer_sharing::is_shared(environment)
                && matches!(environment.status, EnvironmentStatus::Running | EnvironmentStatus::Paused))
            .map(|environment| {
                let applied = APPLIED_RESOURCE_LIMITS.get_or_init(Default::default).lock().unwrap_or_else(|poisoned| poisoned.into_inner()).get(runtime_id(environment)).copied();
                let policy = &environment.resource_policy;
                let (cpu, memory) = applied.unwrap_or((
                    if policy.cpu.current > 0.0 { policy.cpu.current } else { policy.cpu.preferred },
                    if policy.memory_gb.current > 0.0 { policy.memory_gb.current } else { policy.memory_gb.preferred },
                ));
                (environment.id.clone(), Demand { id: environment.id.clone(), cpu: if environment.status == EnvironmentStatus::Paused { 0.0 } else { cpu }, memory_gb: memory })
            }).collect();
        let previous = required.clone();
        for demand in pending.iter().chain(&proposed) {
            if !demand.cpu.is_finite() || !demand.memory_gb.is_finite() || demand.cpu < 0.0 || demand.memory_gb < 0.0 { return Err("Invalid requested host resource allocation".into()); }
            required.insert(demand.id.clone(), demand.clone());
        }
        let (cpu, memory) = required.values().fold((0.0, 0.0), |sum, demand| (sum.0 + demand.cpu, sum.1 + demand.memory_gb));
        let (cpu_capacity, memory_capacity) = scheduler::container_capacity(&state.host);
        if cpu > cpu_capacity + 1e-9 || memory > memory_capacity + 1e-9 {
            return Err(format!("[YOUGORI_HOST_CAPACITY] Running workloads and pending starts need {cpu:.2} CPUs / {memory:.3} GB; this host's budget is {cpu_capacity:.0} CPUs / {memory_capacity:.3} GB. Stop another workload or lower the allocation, then retry."));
        }
        let token = Uuid::new_v4();
        // Keep both the old physical allocation and the new promise visible
        // until the provider has applied decreases and committed its result.
        // Other pools cannot spend a reduction that has not happened yet.
        claims.insert(token, proposed.iter().map(|next| {
            let old = previous.get(&next.id);
            Demand { id: next.id.clone(), cpu: old.map_or(next.cpu, |old| old.cpu.max(next.cpu)), memory_gb: old.map_or(next.memory_gb, |old| old.memory_gb.max(next.memory_gb)) }
        }).collect());
        Ok(ResourceReservation { owner: self.clone(), token, demands: proposed })
    }
}

/// The planned pool is the only pool whose allocations this operation changes.
/// Other pools and pending boots remain real consumers of the shared host budget.
pub(super) async fn reserve_start(store: &PlatformStore, target: &Environment, runtime: &RuntimeManager) -> Result<ResourceReservation, String> {
    let host = collect_host_metrics(&store.snapshot()?.host, runtime.storage_root());
    let target_provider = provider(target);
    let root = runtime.environment_storage_root(runtime_id(target))?;
    let planned_memory = if target.kind == EnvironmentKind::MicroVm && target_provider == RuntimeProviderKind::Qemu {
        runtime.micro_vm_startup_memory_gb(runtime_id(target), &micro_vm_manifest(target)?, &target.resource_policy).await?
    } else { target.resource_policy.memory_gb.preferred };
    store.resource_admission.reserve(store, |state, pending| {
        state.host = host;
        let mut candidate = state.clone();
        for demand in pending {
            if let Some(environment) = candidate.environments.iter_mut().find(|environment| environment.id == demand.id) {
                environment.status = EnvironmentStatus::Running;
                environment.resource_policy.cpu.current = demand.cpu;
                environment.resource_policy.memory_gb.current = demand.memory_gb;
            }
        }
        let environment = candidate.environments.iter_mut().find(|environment| environment.id == target.id).ok_or("Environment not found")?;
        environment.resource_policy = target.resource_policy.clone();
        environment.status = EnvironmentStatus::Running;
        environment.resource_policy.cpu.current = target.resource_policy.cpu.preferred;
        environment.resource_policy.memory_gb.current = planned_memory;
        if target_provider.is_container() {
            scheduler::schedule(&mut candidate);
            Ok(candidate.environments.iter().filter(|environment|
                environment.status == EnvironmentStatus::Running && provider(environment) == target_provider
                && runtime.environment_storage_root(runtime_id(environment)).is_ok_and(|other| other == root))
                .map(|environment| Demand { id: environment.id.clone(), cpu: environment.resource_policy.cpu.current, memory_gb: environment.resource_policy.memory_gb.current }).collect())
        } else {
            Ok(vec![Demand { id: target.id.clone(), cpu: target.resource_policy.cpu.preferred.round().max(1.0), memory_gb: planned_memory }])
        }
    })
}

/// Scheduler updates also participate: they cannot consume RAM/CPU promised to
/// a boot in a different pool while that boot is waiting for its provider.
pub(super) fn reserve_update(store: &PlatformStore, environment: &Environment) -> Result<ResourceReservation, String> {
    store.resource_admission.reserve(store, |state, _| {
        let current = state.environments.iter().find(|current| current.id == environment.id && current.status == EnvironmentStatus::Running && current.last_opened_at == environment.last_opened_at).ok_or("Environment changed before its scheduled resource update")?;
        Ok(vec![Demand { id: current.id.clone(), cpu: environment.resource_policy.cpu.current, memory_gb: environment.resource_policy.memory_gb.current }])
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "windows")]
    #[tokio::test]
    async fn microvm_admission_matches_verified_builtin_boot_and_preserves_custom_media() {
        let temporary = tempfile::tempdir().unwrap();
        let runtime = RuntimeManager::new(&std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")), temporary.path()).unwrap();
        let provisioned = runtime.provision_micro_vm("memory-admission", "builtin:alpine").await.unwrap();
        let store = PlatformStore::load(temporary.path().join("state.json")).unwrap();
        let mut environment: Environment = serde_json::from_value(serde_json::json!({
            "id":"memory-admission","name":"Memory admission","kind":"microVm","provider":"qemu","status":"stopped",
            "runtime":"builtin:alpine","runtimePath":provisioned.disk_path,"description":"","createdAt":"test",
            "cpuUsage":0,"memoryUsageGb":0,"storageDeltaGb":0,"networkRxMbps":0,
            "resourcePolicy":{"cpu":{"min":1,"preferred":1,"max":1,"current":0},"memoryGb":{"min":0.125,"preferred":0.25,"max":0.5,"current":0},"priority":"normal","dynamic":true}
        })).unwrap();
        store.mutate(|state| {state.environments.push(environment.clone());Ok(())}).unwrap();
        let reservation = reserve_start(&store, &environment, &runtime).await.unwrap();
        assert_eq!(reservation.demands[0].memory_gb, 0.5);
        drop(reservation);
        let saved = store.environment(&environment.id).unwrap().resource_policy.memory_gb;
        assert_eq!((saved.min,saved.preferred,saved.max,saved.current),(0.125,0.25,0.5,0.0));
        environment.resource_policy.memory_gb.max = 0.25;
        assert!(reserve_start(&store, &environment, &runtime).await.err().unwrap().contains("512 MiB"));
        assert!(store.resource_admission.claims.lock().unwrap().is_empty());
        assert!(!runtime.vm_is_running(&environment.id).await.unwrap());
        let kernel = temporary.path().join("custom-kernel");
        std::fs::write(&kernel,b"custom kernel fixture").unwrap();
        let mut manifest: serde_json::Value = serde_json::from_slice(&std::fs::read(&provisioned.source_path).unwrap()).unwrap();
        manifest["builtin"] = serde_json::json!(false);
        manifest["kernel"] = serde_json::json!(kernel);
        manifest["initrd"] = serde_json::Value::Null;
        std::fs::write(&provisioned.source_path,serde_json::to_vec(&manifest).unwrap()).unwrap();
        let custom = reserve_start(&store, &environment, &runtime).await.unwrap();
        assert_eq!(custom.demands[0].memory_gb,0.25);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn parallel_provider_pools_cannot_double_allocate_and_cancelled_boot_releases_its_claim() {
        let temporary = tempfile::tempdir().unwrap();
        let store = Arc::new(PlatformStore::load(temporary.path().join("state.json")).unwrap());
        store.mutate(|state| { state.host.total_cpu = 4; state.host.total_memory_gb = 8.0; Ok(()) }).unwrap();
        let held = store.resource_admission.reserve(&store, |_, _| Ok(vec![Demand { id:"cuda-on-D".into(), cpu:3.0, memory_gb:4.0 }])).unwrap();
        // Holding a boot reservation does not hold the admission mutex or any
        // configuration/control lock; another pool is checked immediately.
        let independent = store.resource_admission.reserve(&store, |_, _| Ok(vec![Demand { id:"oci-on-C".into(), cpu:0.5, memory_gb:1.0 }])).unwrap();
        let error = store.resource_admission.reserve(&store, |_, _| Ok(vec![Demand { id:"vm-on-E".into(), cpu:2.0, memory_gb:3.0 }])).err().unwrap();
        assert!(error.contains("YOUGORI_HOST_CAPACITY"));
        drop(held); // same RAII path as cancelled/failed asynchronous startup.
        let retry = store.resource_admission.reserve(&store, |_, _| Ok(vec![Demand { id:"vm-on-E".into(), cpu:2.0, memory_gb:3.0 }])).unwrap();
        assert_eq!(retry.demands[0].id, "vm-on-E");
        drop(independent);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_pool_admission_accepts_only_one_boot_and_keeps_configuration_available() {
        let temporary = tempfile::tempdir().unwrap();
        let store = Arc::new(PlatformStore::load(temporary.path().join("state.json")).unwrap());
        store.mutate(|state| { state.host.total_cpu = 4; state.host.total_memory_gb = 8.0; Ok(()) }).unwrap();
        let arrived = Arc::new(tokio::sync::Barrier::new(3));
        let release = Arc::new(tokio::sync::Barrier::new(3));
        let mut boots = Vec::new();
        for id in ["cuda-on-D", "oci-on-C"] {
            let store = store.clone();
            let arrived = arrived.clone();
            let release = release.clone();
            boots.push(tokio::spawn(async move {
                let claim = store.resource_admission.reserve(&store, |_, _| Ok(vec![Demand { id:id.into(), cpu:3.0, memory_gb:4.0 }])).ok();
                let accepted = claim.is_some();
                arrived.wait().await;
                release.wait().await;
                drop(claim);
                accepted
            }));
        }
        arrived.wait().await;
        assert_eq!(store.resource_admission.claims.lock().unwrap().len(), 1);
        store.mutate(|state| { state.settings.keep_awake = true; Ok(()) }).unwrap();
        assert!(store.snapshot().unwrap().settings.keep_awake);
        release.wait().await;
        let accepted = futures_util::future::join_all(boots).await.into_iter().filter(|result| matches!(result, Ok(true))).count();
        assert_eq!(accepted, 1);
        assert!(store.resource_admission.claims.lock().unwrap().is_empty());
    }

    #[test]
    fn committed_workload_remains_reserved_after_the_pending_guard_is_dropped() {
        let temporary = tempfile::tempdir().unwrap();
        let store = PlatformStore::load(temporary.path().join("state.json")).unwrap();
        store.mutate(|state| { state.host.total_cpu = 4; state.host.total_memory_gb = 8.0; Ok(()) }).unwrap();
        let reservation = store.resource_admission.reserve(&store, |_, _| Ok(vec![Demand { id:"committed".into(), cpu:3.0, memory_gb:4.0 }])).unwrap();
        store.mutate(|state| {
            state.environments.push(serde_json::from_value(serde_json::json!({"id":"committed","name":"Committed","kind":"container","provider":"yougoriOci","status":"running","runtime":"alpine","description":"","createdAt":"test","cpuUsage":0,"memoryUsageGb":0,"storageDeltaGb":0,"networkRxMbps":0,"resourcePolicy":{"cpu":{"min":3,"preferred":3,"max":3,"current":3},"memoryGb":{"min":4,"preferred":4,"max":4,"current":4},"priority":"normal","dynamic":false}})).unwrap());
            Ok(())
        }).unwrap();
        drop(reservation);
        assert!(store.resource_admission.reserve(&store, |_, _| Ok(vec![Demand { id:"second".into(), cpu:2.0, memory_gb:3.0 }])).is_err());
    }
}
