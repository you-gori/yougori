pub mod connection_skills;
pub mod cloud;
use std::{
    collections::{HashMap, HashSet},
    io::SeekFrom,
    path::PathBuf,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

#[cfg(target_os = "windows")]
use std::{
    mem::{size_of, MaybeUninit},
    ptr::null_mut,
    slice,
};

use chrono::Utc;
use sysinfo::{Disks, System};
use tauri::{Emitter, State, WebviewUrl, WebviewWindowBuilder};
use crate::{AppHandle, WebviewWindow};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use uuid::Uuid;

#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Performance::{
    PdhAddEnglishCounterW, PdhCloseQuery, PdhCollectQueryData, PdhGetFormattedCounterArrayW,
    PdhOpenQueryW, PDH_CSTATUS_NEW_DATA, PDH_CSTATUS_VALID_DATA, PDH_FMT_COUNTERVALUE_ITEM_W,
    PDH_FMT_DOUBLE, PDH_HCOUNTER, PDH_HQUERY, PDH_MORE_DATA,
};

use crate::{
    backup::BackupManager, models::*, runtime::RuntimeManager, scheduler, store::PlatformStore,
};

pub(crate) mod vm_creation;
pub(crate) mod storage;
pub(crate) mod factory_reset;
pub mod startup;
pub mod workloads;
pub(crate) mod resource_admission;
#[cfg(test)]
mod resource_policy_tests;
type EnvironmentOperationLocks = HashMap<String, std::sync::Weak<tokio::sync::Mutex<()>>>;
static NETWORK_POLICY_OPERATIONS: OnceLock<tokio::sync::Mutex<EnvironmentOperationLocks>> = OnceLock::new();

pub(crate) async fn environment_network_lock(id: &str) -> std::sync::Arc<tokio::sync::Mutex<()>> {
    let mut locks = NETWORK_POLICY_OPERATIONS.get_or_init(Default::default).lock().await;
    locks.retain(|_, lock| lock.strong_count() > 0);
    if let Some(lock) = locks.get(id).and_then(std::sync::Weak::upgrade) { return lock; }
    let lock = std::sync::Arc::new(tokio::sync::Mutex::new(()));
    locks.insert(id.to_owned(), std::sync::Arc::downgrade(&lock));
    lock
}

#[cfg(target_os = "windows")]
struct GpuSampler {
    query: usize,
    counter: usize,
}

#[cfg(target_os = "windows")]
impl GpuSampler {
    fn new() -> Option<Self> {
        let mut query: PDH_HQUERY = null_mut();
        if unsafe { PdhOpenQueryW(null_mut(), 0, &mut query) } != 0 {
            return None;
        }
        let path = "\\GPU Engine(*)\\Utilization Percentage"
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let mut counter: PDH_HCOUNTER = null_mut();
        if unsafe { PdhAddEnglishCounterW(query, path.as_ptr(), 0, &mut counter) } != 0
            || unsafe { PdhCollectQueryData(query) } != 0
        {
            unsafe { PdhCloseQuery(query) };
            return None;
        }
        Some(Self {
            query: query as usize,
            counter: counter as usize,
        })
    }

    fn sample(&mut self) -> Option<f64> {
        let query = self.query as PDH_HQUERY;
        let counter = self.counter as PDH_HCOUNTER;
        if unsafe { PdhCollectQueryData(query) } != 0 {
            return None;
        }

        let mut buffer_size = 0;
        let mut item_count = 0;
        let status = unsafe {
            PdhGetFormattedCounterArrayW(
                counter,
                PDH_FMT_DOUBLE,
                &mut buffer_size,
                &mut item_count,
                null_mut(),
            )
        };
        if status != PDH_MORE_DATA || buffer_size == 0 || item_count == 0 {
            return None;
        }

        let item_size = size_of::<PDH_FMT_COUNTERVALUE_ITEM_W>();
        let slots = (buffer_size as usize).div_ceil(item_size);
        let mut buffer = vec![MaybeUninit::<PDH_FMT_COUNTERVALUE_ITEM_W>::uninit(); slots];
        let status = unsafe {
            PdhGetFormattedCounterArrayW(
                counter,
                PDH_FMT_DOUBLE,
                &mut buffer_size,
                &mut item_count,
                buffer.as_mut_ptr().cast(),
            )
        };
        if status != 0 || item_count as usize > buffer.len() {
            return None;
        }

        let items = unsafe {
            slice::from_raw_parts(
                buffer.as_ptr().cast::<PDH_FMT_COUNTERVALUE_ITEM_W>(),
                item_count as usize,
            )
        };
        let mut samples = Vec::with_capacity(items.len());
        for item in items {
            if !matches!(
                item.FmtValue.CStatus,
                PDH_CSTATUS_VALID_DATA | PDH_CSTATUS_NEW_DATA
            ) {
                continue;
            }
            let Some(name) = wide_string(item.szName) else {
                continue;
            };
            let value = unsafe { item.FmtValue.Anonymous.doubleValue };
            samples.push((name, value));
        }
        gpu_usage_from_samples(&samples)
    }
}

#[cfg(target_os = "windows")]
impl Drop for GpuSampler {
    fn drop(&mut self) {
        unsafe { PdhCloseQuery(self.query as PDH_HQUERY) };
    }
}

#[cfg(target_os = "windows")]
fn wide_string(pointer: *const u16) -> Option<String> {
    if pointer.is_null() {
        return None;
    }
    let mut length = 0;
    while length < 1_024 && unsafe { *pointer.add(length) } != 0 {
        length += 1;
    }
    if length == 1_024 {
        return None;
    }
    String::from_utf16(unsafe { slice::from_raw_parts(pointer, length) }).ok()
}

#[cfg(target_os = "windows")]
fn gpu_usage_from_samples(samples: &[(String, f64)]) -> Option<f64> {
    let mut engines = HashMap::<String, f64>::new();
    for (name, value) in samples {
        if !value.is_finite() || *value < 0.0 {
            continue;
        }
        let lower_name = name.to_ascii_lowercase();
        let key_offset = lower_name.find("_phys_").map_or(0, |index| index + 1);
        let key = lower_name[key_offset..].to_owned();
        *engines.entry(key).or_default() += value;
    }
    engines
        .values()
        .copied()
        .reduce(f64::max)
        .map(|value| value.clamp(0.0, 100.0))
}

struct HostSampler {
    system: System,
    disks: Disks,
    last_disk_refresh: Instant,
    hostname: String,
    os: String,
    cpu_model: String,
    #[cfg(target_os = "windows")]
    gpu: Option<GpuSampler>,
}

impl HostSampler {
    fn new() -> Self {
        let mut system = System::new();
        system.refresh_cpu_all();
        system.refresh_memory();
        let disks = Disks::new_with_refreshed_list();
        let hostname = System::host_name().unwrap_or_default();
        let os = format!(
            "{} {}",
            System::name().unwrap_or_default(),
            System::os_version().unwrap_or_default()
        )
        .trim()
        .to_owned();
        let cpu_model = system
            .cpus()
            .first()
            .map(|cpu| cpu.brand().to_owned())
            .unwrap_or_default();
        Self {
            system,
            disks,
            last_disk_refresh: Instant::now(),
            hostname,
            os,
            cpu_model,
            #[cfg(target_os = "windows")]
            gpu: GpuSampler::new(),
        }
    }

    fn refresh(&mut self) -> Option<f64> {
        self.system.refresh_cpu_usage();
        self.system.refresh_memory();
        if self.last_disk_refresh.elapsed() >= Duration::from_secs(60) {
            self.disks.refresh(true);
            self.last_disk_refresh = Instant::now();
        }
        #[cfg(target_os = "windows")]
        {
            self.gpu.as_mut().and_then(GpuSampler::sample)
        }
        #[cfg(not(target_os = "windows"))]
        {
            None
        }
    }
}

static HOST_SAMPLER: OnceLock<Mutex<HostSampler>> = OnceLock::new();
static APPLIED_RESOURCE_LIMITS: OnceLock<Mutex<HashMap<String, (f64, f64)>>> = OnceLock::new();
static LAST_STORAGE_REFRESH: OnceLock<Mutex<Option<Instant>>> = OnceLock::new();
const BUILTIN_MICRO_VM_SOURCE: &str = "builtin:alpine";
const MAX_BACKUP_HISTORY: usize = 500;

fn resource_update_needed(id: &str, cpu: f64, memory_gb: f64) -> bool {
    let limits = APPLIED_RESOURCE_LIMITS.get_or_init(|| Mutex::new(HashMap::new()));
    let limits = limits
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    limits.get(id).is_none_or(|(applied_cpu, applied_memory)| {
        (applied_cpu - cpu).abs() >= 0.01 || (applied_memory - memory_gb).abs() >= 0.01
    })
}

fn record_applied_resource_limits(id: &str, cpu: f64, memory_gb: f64) {
    let limits = APPLIED_RESOURCE_LIMITS.get_or_init(|| Mutex::new(HashMap::new()));
    limits
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(id.to_owned(), (cpu, memory_gb));
}

fn forget_applied_resource_limits(id: &str) {
    let limits = APPLIED_RESOURCE_LIMITS.get_or_init(|| Mutex::new(HashMap::new()));
    limits
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(id);
}

async fn update_non_container_resource_limits(
    runtime: &RuntimeManager,
    environment: &Environment,
    cpu: f64,
    memory_gb: f64,
) -> Result<(), String> {
    match provider(environment) {
        RuntimeProviderKind::Qemu => {
            runtime.update_vm_resources(runtime_id(environment), cpu, memory_gb).await
        }
        RuntimeProviderKind::NativeSandbox => {
            runtime.update_native_sandbox_resources(runtime_id(environment), cpu, memory_gb).await
        }
        // Cloud resources are external; containers use their provider pool allocation.
        RuntimeProviderKind::CloudSsh | RuntimeProviderKind::YougoriOci | RuntimeProviderKind::YougoriCuda => Ok(()),
    }
}

async fn apply_scheduled_resource_limits(
    runtime: &RuntimeManager,
    environment: &Environment,
) -> Result<(), String> {
    let id = runtime_id(environment);
    let cpu = environment.resource_policy.cpu.current;
    let memory_gb = environment.resource_policy.memory_gb.current;
    if provider(environment).is_container() {
        runtime.update_container_resources(id, cpu, memory_gb).await?;
    } else {
        update_non_container_resource_limits(runtime, environment, cpu, memory_gb).await?;
    }
    record_applied_resource_limits(id, cpu, memory_gb);
    Ok(())
}

fn storage_refresh_due() -> bool {
    let refresh = LAST_STORAGE_REFRESH.get_or_init(|| Mutex::new(None));
    let mut refresh = refresh
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if refresh.is_some_and(|last| last.elapsed() < Duration::from_secs(60)) {
        return false;
    }
    *refresh = Some(Instant::now());
    true
}

fn now() -> String {
    Utc::now().to_rfc3339()
}

fn validate_range(label: &str, range: &CreateResourceRange) -> Result<(), String> {
    if !range.min.is_finite()
        || !range.preferred.is_finite()
        || !range.max.is_finite()
        || range.min <= 0.0
    {
        return Err(format!(
            "{label} values must be finite and greater than zero"
        ));
    }
    if range.preferred < range.min || range.max < range.preferred {
        return Err(format!(
            "{label} values must satisfy minimum ≤ preferred ≤ maximum"
        ));
    }
    Ok(())
}

pub(crate) fn validate_policy(policy: &ResourcePolicy) -> Result<(), String> {
    validate_range(
        "CPU",
        &CreateResourceRange {
            min: policy.cpu.min,
            preferred: policy.cpu.preferred,
            max: policy.cpu.max,
        },
    )?;
    validate_range(
        "Memory",
        &CreateResourceRange {
            min: policy.memory_gb.min,
            preferred: policy.memory_gb.preferred,
            max: policy.memory_gb.max,
        },
    )
}

fn validate_container_policy_capacity(policy: &ResourcePolicy, host: &HostMetrics) -> Result<(), String> {
    validate_policy(policy)?;
    if policy.cpu.max > host.total_cpu as f64 || policy.cpu.max > 255.0 {
        return Err("Container CPU maximum exceeds this computer's supported CPU count".into());
    }
    if policy.memory_gb.max > host.total_memory_gb || policy.memory_gb.max > 1024.0 {
        return Err("Container memory maximum exceeds this computer's RAM".into());
    }
    Ok(())
}

static CONTAINER_POLICY_OPERATIONS: OnceLock<tokio::sync::Mutex<EnvironmentOperationLocks>> = OnceLock::new();

pub(crate) async fn container_policy_lock(root: &std::path::Path, provider: &RuntimeProviderKind) -> std::sync::Arc<tokio::sync::Mutex<()>> {
    let key = format!("{}:{provider:?}", root.display());
    let mut locks = CONTAINER_POLICY_OPERATIONS.get_or_init(Default::default).lock().await;
    locks.retain(|_, lock| lock.strong_count() > 0);
    if let Some(lock) = locks.get(&key).and_then(std::sync::Weak::upgrade) { return lock; }
    let lock = std::sync::Arc::new(tokio::sync::Mutex::new(()));
    locks.insert(key, std::sync::Arc::downgrade(&lock));
    lock
}

pub(crate) async fn environment_container_policy_guard(runtime: &RuntimeManager, environment: &Environment) -> Result<Option<tokio::sync::OwnedMutexGuard<()>>, String> {
    let provider = provider(environment);
    if !provider.is_container() { return Ok(None); }
    let root = runtime.environment_storage_root(runtime_id(environment))?;
    let lock=container_policy_lock(&root,&provider).await;
    if let Ok(guard)=lock.clone().try_lock_owned(){return Ok(Some(guard))}
    crate::automation::context::progress(serde_json::json!({"phase":"waiting","waitingFor":{"resource":"providerPool","provider":provider,"storageRoot":root.display().to_string()}}));
    let cancellation=crate::automation::context::current().map(|operation|operation.cancellation).unwrap_or_default();
    let guard=tokio::select!{biased;
        _=cancellation.cancelled()=>return Err("YOUGORI_OPERATION_CANCELLED: cancelled while waiting for provider coordination before changing this environment".into()),
        guard=lock.lock_owned()=>guard,
    };
    crate::automation::context::progress(serde_json::json!({"phase":"starting","waitingFor":null}));
    Ok(Some(guard))
}

#[derive(Debug, Clone)]
struct ContainerAllocation {
    id: String,
    cpu: f64,
    memory_gb: f64,
}

struct PreparedContainerStart {
    rollback: Vec<ContainerAllocation>,
    target: ContainerAllocation,
}

async fn rollback_container_allocations(
    runtime: &RuntimeManager,
    allocations: &[ContainerAllocation],
) -> Result<(), String> {
    let mut errors = Vec::new();
    for allocation in allocations.iter().rev() {
        match runtime
            .update_container_resources(&allocation.id, allocation.cpu, allocation.memory_gb)
            .await
        {
            Ok(()) => {
                record_applied_resource_limits(&allocation.id, allocation.cpu, allocation.memory_gb)
            }
            Err(error) => errors.push(error),
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "could not restore previous container limits: {}",
            errors.join("; ")
        ))
    }
}

async fn prepare_container_start(
    state: &PlatformState,
    target: &Environment,
    runtime: &RuntimeManager,
    reservation: Option<&resource_admission::ResourceReservation>,
) -> Result<PreparedContainerStart, String> {
    // A creation interrupted before provisioning leaves a saved definition but
    // no runtime object. Let the later start path recreate that same ID from
    // its saved image/options before applying per-container limits.
    let mut missing_target = false;
    if let Some(limit) = target.storage_limit_gb {
        match runtime.container_storage_allocation(runtime_id(target)).await {
            Ok(current) if current.limit_enforced != Some(true) || limit > current.capacity_gb => {
                if let Err(error) = runtime.set_container_storage(runtime_id(target), limit.max(current.capacity_gb)).await {
                    if container_object_missing(&error) { missing_target = true; } else { return Err(error); }
                }
            }
            Ok(_) => {},
            Err(error) if container_object_missing(&error) => missing_target = true,
            Err(error) => return Err(error),
        }
    }
    let mut candidate = state.clone();
    candidate.host = collect_host_metrics(&state.host, runtime.storage_root());
    let target_environment = candidate
        .environments
        .iter_mut()
        .find(|environment| environment.id == target.id)
        .ok_or("Environment not found")?;
    validate_container_policy_capacity(&target_environment.resource_policy, &candidate.host)?;
    target_environment.status = EnvironmentStatus::Running;
    target_environment.resource_policy.cpu.current =
        target_environment.resource_policy.cpu.preferred;
    target_environment.resource_policy.memory_gb.current =
        target_environment.resource_policy.memory_gb.preferred;

    let running_containers = candidate.environments.iter().filter(|environment| {
        environment.status == EnvironmentStatus::Running
            && provider(environment).is_container()
    });
    let (required_cpu, mut required_memory) = running_containers
        .clone()
        .map(|environment| {
            let policy = &environment.resource_policy;
            if policy.dynamic {
                (policy.cpu.min, policy.memory_gb.min)
            } else {
                (policy.cpu.preferred, policy.memory_gb.preferred)
            }
        })
        .fold((0.0, 0.0), |(cpu, memory), current| {
            (cpu + current.0, memory + current.1)
        });
    let paused_memory: f64 = candidate.environments.iter()
        .filter(|e| provider(e).is_container() && e.status == EnvironmentStatus::Paused)
        .map(|e| e.resource_policy.memory_gb.current.max(e.resource_policy.memory_gb.preferred)).sum();
    required_memory += paused_memory;
    let (cpu_capacity, mut memory_capacity) = scheduler::container_capacity(&candidate.host);
    let other_memory: f64 = candidate.environments.iter()
        .filter(|e| !provider(e).is_container() && matches!(e.status, EnvironmentStatus::Running | EnvironmentStatus::Paused))
        .map(|e| e.resource_policy.memory_gb.current.max(e.resource_policy.memory_gb.preferred)).sum();
    memory_capacity = (memory_capacity - other_memory).max(0.0);
    if required_cpu > cpu_capacity + f64::EPSILON
        || required_memory > memory_capacity + f64::EPSILON
    {
        return Err(format!(
            "Not enough shared container capacity (available budget: {:.0} CPUs and {:.3} GB, after host and VM reserves). Stop another workload or lower its allocation",
            cpu_capacity,
            memory_capacity
        ));
    }

    scheduler::schedule(&mut candidate);
    if provider(target) == RuntimeProviderKind::YougoriCuda {
        let selected = runtime.storage_runtime(runtime_id(target))?;
        let (cpus, memory) = selected.as_deref().unwrap_or(runtime).ensure_cuda_capacity().await?;
        scheduler::limit_cuda_pool(&mut candidate, cpus, memory)?;
    } else if let Ok((cpus, memory)) = runtime.cuda_capacity().await {
        scheduler::limit_cuda_pool(&mut candidate, cpus, memory)?;
    }
    if let Some(reservation) = reservation {
        for demand in &reservation.demands {
            if let Some(environment) = candidate.environments.iter_mut().find(|environment| environment.id == demand.id) {
                environment.resource_policy.cpu.current = environment.resource_policy.cpu.current.min(demand.cpu);
                environment.resource_policy.memory_gb.current = environment.resource_policy.memory_gb.current.min(demand.memory_gb);
            }
        }
    }
    let pool_provider = provider(target);
    let pool_root = runtime.environment_storage_root(runtime_id(target))?;
    let planned_target = candidate.environments.iter().find(|environment| environment.id == target.id).ok_or("Environment not found while preparing resources")?;
    let target_allocation = ContainerAllocation { id: runtime_id(target).to_owned(), cpu: planned_target.resource_policy.cpu.current, memory_gb: planned_target.resource_policy.memory_gb.current };
    let allocations = candidate
        .environments
        .iter()
        .filter(|environment| {
            environment.status == EnvironmentStatus::Running
                && provider(environment) == pool_provider
                && runtime.environment_storage_root(runtime_id(environment)).is_ok_and(|root| root == pool_root)
        })
        .map(|environment| {
            let previous = state
                .environments
                .iter()
                .find(|previous| previous.id == environment.id)
                .ok_or("Environment not found while preparing container limits")?;
            let previous_cpu = if previous.resource_policy.cpu.current > 0.0 {
                previous.resource_policy.cpu.current
            } else {
                previous.resource_policy.cpu.preferred
            };
            let previous_memory = if previous.resource_policy.memory_gb.current > 0.0 {
                previous.resource_policy.memory_gb.current
            } else {
                previous.resource_policy.memory_gb.preferred
            };
            Ok((
                ContainerAllocation {
                    id: runtime_id(previous).to_owned(),
                    cpu: previous_cpu,
                    memory_gb: previous_memory,
                },
                ContainerAllocation {
                    id: runtime_id(environment).to_owned(),
                    cpu: environment.resource_policy.cpu.current,
                    memory_gb: environment.resource_policy.memory_gb.current,
                },
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let scheduled_cpu: f64 = allocations.iter().map(|(_, next)| next.cpu).sum();
    let scheduled_memory: f64 = allocations.iter().map(|(_, next)| next.memory_gb).sum();
    if scheduled_cpu > cpu_capacity + f64::EPSILON
        || scheduled_memory + paused_memory > memory_capacity + f64::EPSILON
    {
        return Err("Container allocations exceed the lightweight shared runtime capacity".into());
    }

    // Reserve the running policies' envelopes once, so normal scheduler changes
    // fit without restarting the appliance on each telemetry tick.
    // Stopped definitions do not reserve RAM. The runtime can grow when one of
    // them is started, without interrupting workloads already running.
    let active: Vec<_> = candidate.environments.iter().filter(|e|
        pool_provider == RuntimeProviderKind::YougoriOci && provider(e) == pool_provider
        && runtime.environment_storage_root(runtime_id(e)).is_ok_and(|root| root == pool_root)
        && matches!(e.status, EnvironmentStatus::Running | EnvironmentStatus::Paused)).collect();
    let ids: Vec<_> = active.iter().map(|e| runtime_id(e).to_owned()).collect();
    for (engine, ids) in runtime.storage_groups(&ids)? {
        let group: Vec<_> = active.iter().filter(|e| ids.iter().any(|id| id == runtime_id(e))).collect();
        let envelope_cpu: f64 = group.iter().map(|e| e.resource_policy.cpu.max).sum();
        let envelope_memory: f64 = group.iter().map(|e| e.resource_policy.memory_gb.max).sum();
        let scheduled = allocations.iter().filter(|(_, next)| ids.contains(&next.id));
        let qemu_cpu: f64 = scheduled.clone().map(|(_, next)| next.cpu).sum();
        let qemu_memory: f64 = scheduled.map(|(_, next)| next.memory_gb).sum();
        if envelope_cpu > 0.0 || envelope_memory > 0.0 {
            engine.as_deref().unwrap_or(runtime).ensure_container_capacity(envelope_cpu.min(cpu_capacity).max(qemu_cpu),
                envelope_memory.min(memory_capacity).max(qemu_memory)).await?;
        }
    }

    let mut rollback = Vec::new();
    // Apply decreases first. A redistributed allocation must never transiently
    // exceed the admitted budget before the new workload starts.
    for (previous, next) in &allocations {
        if next.id == runtime_id(target) && target.status != EnvironmentStatus::Running { continue; }
        let reduced_cpu = previous.cpu.min(next.cpu);
        let reduced_memory = previous.memory_gb.min(next.memory_gb);
        if reduced_cpu == previous.cpu && reduced_memory == previous.memory_gb { continue; }
        if let Err(error) = runtime.update_container_resources(&next.id, reduced_cpu, reduced_memory).await {
            let restore = rollback_container_allocations(runtime, &rollback).await.err();
            return Err(restore.map_or(error.clone(), |restore| format!("{error}; {restore}")));
        }
        record_applied_resource_limits(&next.id, reduced_cpu, reduced_memory);
        rollback.push(previous.clone());
    }
    for (previous, next) in allocations {
        if missing_target && next.id == runtime_id(target) {
            continue;
        }
        // Saved preferences are not evidence of applied OCI/cgroup limits.
        // Always reconcile the target on Start/Save, including stopped edits
        // and repairs where the cached allocation already equals the request.
        if next.id != runtime_id(target)
            && (previous.cpu - next.cpu).abs() <= f64::EPSILON
            && (previous.memory_gb - next.memory_gb).abs() <= f64::EPSILON
            && !resource_update_needed(&next.id, next.cpu, next.memory_gb)
        {
            continue;
        }
        if let Err(error) = runtime
            .update_container_resources(&next.id, next.cpu, next.memory_gb)
            .await
        {
            if next.id == runtime_id(target) && container_object_missing(&error) {
                continue;
            }
            let rollback_error = rollback_container_allocations(runtime, &rollback)
                .await
                .err();
            return Err(match rollback_error {
                Some(rollback_error) => format!("{error}; {rollback_error}"),
                None => error,
            });
        }
        record_applied_resource_limits(&next.id, next.cpu, next.memory_gb);
        if !rollback.iter().any(|applied| applied.id == previous.id) { rollback.push(previous); }
    }
    Ok(PreparedContainerStart { rollback, target: target_allocation })
}

fn container_object_missing(error: &str) -> bool {
    error.contains("no such object") || error.contains("no such container")
}

pub(crate) fn provider(environment: &Environment) -> RuntimeProviderKind {
    if environment.kind == EnvironmentKind::Cloud { return RuntimeProviderKind::CloudSsh; }
    if environment.kind == EnvironmentKind::ComputerBranch {
        return RuntimeProviderKind::NativeSandbox;
    }
    environment
        .provider
        .clone()
        .unwrap_or(match environment.kind {
            EnvironmentKind::Container => RuntimeProviderKind::YougoriOci,
            EnvironmentKind::ComputerBranch => RuntimeProviderKind::NativeSandbox,
            _ => RuntimeProviderKind::Qemu,
        })
}

/// A container can be missing from the runtime while Yougori still has its
/// definition: an appliance rebuilt for a new bundled image starts with an empty
/// container store. Rebuild it from that definition instead of failing to start.
/// Files written inside the previous container are not part of the definition.
async fn container_action_rebuilding_if_missing(
    runtime: &RuntimeManager,
    environment: &Environment,
    action: &str,
    allocation: Option<&ContainerAllocation>,
) -> Result<(), String> {
    let id = runtime_id(environment);
    let result = runtime
        .container_action(id, action, environment.network_access)
        .await;
    let Err(error) = result else { return Ok(()) };
    if !container_object_missing(&error) {
        return Err(error);
    }
    // Stopping or pausing something the runtime no longer has is already done.
    // Recording it as stopped also lets the next Start rebuild it.
    if !matches!(action, "start" | "resume") {
        return Ok(());
    }
    runtime.register_container_provider(id, &provider(environment))?;
    runtime
        .provision_container_with_storage(
            id,
            &environment.runtime,
            environment.container_command.as_deref().unwrap_or_default(),
            &environment.resource_policy,
            environment.network_access,
            environment.gpu_access,
            environment.storage_limit_gb.unwrap_or(20.0),
        )
        .await
        .map_err(|rebuild| format!("{error}. Rebuilding this container also failed: {rebuild}"))?;
    if let Some(allocation) = allocation {
        // An interrupted creation may have no object to update in prepare.
        // Apply its admitted, provider-limited plan before the rebuilt process
        // starts; saved preferred values are not an allocation reservation.
        runtime.update_container_resources(id, allocation.cpu, allocation.memory_gb).await?;
        record_applied_resource_limits(id, allocation.cpu, allocation.memory_gb);
    }
    runtime
        .container_action(id, "start", environment.network_access)
        .await
}

fn runtime_id(environment: &Environment) -> &str {
    environment.runtime_id.as_deref().unwrap_or(&environment.id)
}

fn container_connection(state: &PlatformState, source: &str, target: &str) -> bool {
    let source = state.environments.iter().find(|e| e.id == source && e.kind == EnvironmentKind::Container);
    let target = state.environments.iter().find(|e| e.id == target && e.kind == EnvironmentKind::Container);
    matches!((source, target), (Some(a), Some(b)) if provider(a) == provider(b))
}

fn connection_operations() -> &'static tokio::sync::Mutex<()> {
    static OPERATIONS: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    OPERATIONS.get_or_init(|| tokio::sync::Mutex::new(()))
}

fn connection_runtime_id<'a>(state: &'a PlatformState, id: &'a str) -> &'a str {
    state.environments.iter().find(|e| e.id == id).map(runtime_id).unwrap_or(id)
}

fn vm_disk(environment: &Environment) -> Result<PathBuf, String> {
    environment
        .runtime_path
        .as_deref()
        .map(PathBuf::from)
        .ok_or_else(|| "virtual machine disk metadata is missing".into())
}

fn micro_vm_manifest(environment: &Environment) -> Result<PathBuf, String> {
    if environment.runtime == BUILTIN_MICRO_VM_SOURCE {
        return vm_disk(environment)?
            .parent()
            .map(|directory| directory.join("microvm.json"))
            .ok_or_else(|| "microVM storage metadata is invalid".into());
    }
    Ok(PathBuf::from(&environment.runtime))
}

fn referenced_vm_sources(state: &PlatformState) -> Vec<PathBuf> {
    let mut sources = state
        .environments
        .iter()
        .filter(|environment| provider(environment) == RuntimeProviderKind::Qemu)
        .filter(|environment| environment.runtime != BUILTIN_MICRO_VM_SOURCE)
        .map(|environment| PathBuf::from(&environment.runtime))
        .collect::<Vec<_>>();
    sources.extend(
        state
            .snapshots
            .iter()
            .filter_map(|snapshot| snapshot.environment_state.as_ref())
            .filter(|snapshot| snapshot.provider == Some(RuntimeProviderKind::Qemu))
            .filter(|snapshot| snapshot.runtime != BUILTIN_MICRO_VM_SOURCE)
            .map(|snapshot| PathBuf::from(&snapshot.runtime)),
    );
    sources.extend(state.pending_factory_resets.iter().map(|pending| PathBuf::from(&pending.environment.runtime)));
    sources
}

async fn cleanup_snapshot_resources(
    snapshot: &Snapshot,
    state: &PlatformState,
    runtime: &RuntimeManager,
    backup: &BackupManager,
) -> Result<(), String> {
    let environment = state
        .environments
        .iter()
        .find(|environment| environment.id == snapshot.environment_id);
    let snapshot_provider = environment.map(provider).or_else(|| {
        snapshot
            .environment_state
            .as_ref()
            .and_then(|environment| environment.provider.clone())
    });
    let runtime_environment_id = environment
        .map(runtime_id)
        .unwrap_or(&snapshot.environment_id);
    let mut errors = Vec::new();
    match snapshot_provider {
        Some(RuntimeProviderKind::CloudSsh) => return Err("Cloud nodes do not have local snapshots".into()),
        Some(RuntimeProviderKind::YougoriOci | RuntimeProviderKind::YougoriCuda) => {
            if let Err(error) = runtime
                .delete_container_snapshot(runtime_environment_id, &snapshot.id)
                .await
            {
                errors.push(error);
            }
        }
        Some(RuntimeProviderKind::Qemu) => {
            if snapshot.provider_snapshot_id.is_some() {
                if let Some(environment) = environment {
                    match vm_disk(environment) {
                        Ok(disk) => {
                            if let Err(error) = runtime
                                .delete_vm_snapshot(runtime_id(environment), &disk, &snapshot.id)
                                .await
                            {
                                errors.push(error);
                            }
                        }
                        Err(error) => errors.push(error),
                    }
                }
            }
        }
        Some(RuntimeProviderKind::NativeSandbox) | None => {}
    }
    if let Some(path) = snapshot.artifact_path.as_deref().map(PathBuf::from) {
        if let Err(runtime_error) = runtime.remove_snapshot_artifact(&path).await {
            if let Err(backup_error) = backup.delete_restore_artifact(&path).await {
                errors.push(format!("{runtime_error}; {backup_error}"));
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        errors.sort();
        errors.dedup();
        Err(errors.join("; "))
    }
}

pub(crate) async fn enforce_snapshot_retention(
    store: &PlatformStore,
    runtime: &RuntimeManager,
    backup: &BackupManager,
) -> Result<PlatformState, String> {
    loop {
        let state = store.snapshot()?;
        let retention = state.settings.snapshot_retention.max(1);
        let Some(snapshot) = state.snapshots.get(retention).cloned() else {
            return Ok(state);
        };
        cleanup_snapshot_resources(&snapshot, &state, runtime, backup).await?;
        store.mutate(|state| {
            state.snapshots.retain(|item| item.id != snapshot.id);
            Ok(())
        })?;
    }
}

fn sandbox_workspace(environment: &Environment) -> Result<PathBuf, String> {
    environment
        .runtime_path
        .as_deref()
        .map(PathBuf::from)
        .ok_or_else(|| "native branch workspace metadata is missing; recreate this branch".into())
}

fn sandbox_policy(environment: &Environment) -> Result<&SandboxPolicy, String> {
    environment.sandbox_policy.as_ref().ok_or_else(|| {
        "this legacy branch used a VM; create a new Computer Branch and select an application"
            .into()
    })
}

async fn restart_vm_after_maintenance(
    runtime: &RuntimeManager,
    environment: &Environment,
    previous_status: &EnvironmentStatus,
) -> Result<(), String> {
    if !matches!(
        previous_status,
        EnvironmentStatus::Running | EnvironmentStatus::Paused
    ) {
        return Ok(());
    }
    if environment.kind == EnvironmentKind::MicroVm {
        runtime
            .start_micro_vm_with_network(
                runtime_id(environment),
                &vm_disk(environment)?,
                &micro_vm_manifest(environment)?,
                &environment.resource_policy,
                environment.network_access,
            )
            .await?;
    } else {
        runtime
            .start_vm_with_network(
                runtime_id(environment),
                &vm_disk(environment)?,
                &PathBuf::from(&environment.runtime),
                &environment.resource_policy,
                environment.gpu_access,
                environment.network_access,
            )
            .await?;
    }
    if previous_status == &EnvironmentStatus::Paused {
        runtime.vm_action(runtime_id(environment), "pause").await?;
    }
    Ok(())
}

async fn rollback_runtime_transition(
    runtime: &RuntimeManager,
    environment: &Environment,
    attempted_status: &EnvironmentStatus,
) -> Result<(), String> {
    if &environment.status == attempted_status {
        return Ok(());
    }
    match provider(environment) {
        RuntimeProviderKind::CloudSsh => { runtime.cloud.disconnect(&environment.id).await; Ok(()) },
        RuntimeProviderKind::YougoriOci | RuntimeProviderKind::YougoriCuda => {
            let action = match (attempted_status, &environment.status) {
                (EnvironmentStatus::Running, EnvironmentStatus::Paused) => "pause",
                (EnvironmentStatus::Running, _) => "stop",
                (EnvironmentStatus::Paused, EnvironmentStatus::Running) => "resume",
                (EnvironmentStatus::Stopped, EnvironmentStatus::Running) => "start",
                (EnvironmentStatus::Stopped, EnvironmentStatus::Paused) => "start",
                _ => return Ok(()),
            };
            container_action_rebuilding_if_missing(runtime, environment, action, None).await?;
            if attempted_status == &EnvironmentStatus::Stopped
                && environment.status == EnvironmentStatus::Paused
            {
                runtime
                    .container_action(runtime_id(environment), "pause", environment.network_access)
                    .await?;
            }
            Ok(())
        }
        RuntimeProviderKind::Qemu => {
            match (attempted_status, &environment.status) {
                (EnvironmentStatus::Running, EnvironmentStatus::Paused) => {
                    runtime.vm_action(runtime_id(environment), "pause").await?;
                }
                (EnvironmentStatus::Running, _) => {
                    runtime.vm_action(runtime_id(environment), "stop").await?;
                }
                (EnvironmentStatus::Paused, EnvironmentStatus::Running) => {
                    runtime.vm_action(runtime_id(environment), "resume").await?;
                }
                (EnvironmentStatus::Stopped, previous) => {
                    if environment.kind == EnvironmentKind::MicroVm {
                        runtime
                            .start_micro_vm_with_network(
                                runtime_id(environment),
                                &vm_disk(environment)?,
                                &micro_vm_manifest(environment)?,
                                &environment.resource_policy,
                                environment.network_access,
                            )
                            .await?;
                    } else {
                        runtime
                            .start_vm_with_network(
                                runtime_id(environment),
                                &vm_disk(environment)?,
                                &PathBuf::from(&environment.runtime),
                                &environment.resource_policy,
                                environment.gpu_access,
                                environment.network_access,
                            )
                            .await?;
                    }
                    if previous == &EnvironmentStatus::Paused {
                        runtime.vm_action(runtime_id(environment), "pause").await?;
                    }
                }
                _ => {}
            }
            Ok(())
        }
        RuntimeProviderKind::NativeSandbox => match (attempted_status, &environment.status) {
            (EnvironmentStatus::Running, _) => {
                runtime.stop_native_sandbox(runtime_id(environment)).await
            }
            (EnvironmentStatus::Stopped, EnvironmentStatus::Running) => {
                runtime
                    .start_native_sandbox(
                        runtime_id(environment),
                        &sandbox_workspace(environment)?,
                        sandbox_policy(environment)?,
                        &environment.resource_policy,
                    )
                    .await
            }
            _ => Ok(()),
        },
    }
}

fn begin_vm_restore_intent(store: &PlatformStore, environment_id: &str) -> Result<(), String> {
    store
        .mutate(|state| {
            if !state
                .pending_vm_restores
                .iter()
                .any(|id| id == environment_id)
            {
                state.pending_vm_restores.push(environment_id.to_owned());
            }
            Ok(())
        })
        .map(|_| ())
}

fn clear_vm_restore_intent(store: &PlatformStore, environment_id: &str) -> Result<(), String> {
    store
        .mutate(|state| {
            state.pending_vm_restores.retain(|id| id != environment_id);
            Ok(())
        })
        .map(|_| ())
}

#[tauri::command]
pub async fn get_platform_state(store: State<'_, PlatformStore>, runtime: State<'_, RuntimeManager>) -> Result<PlatformState, String> {
    let mut state = store.snapshot()?;
    for connection in &mut state.connections {
        if !connection.active || connection.enforcement_status != Some(EnforcementStatus::Enforced) { continue }
        let shared = state.environments.iter().any(|environment| {
            (environment.id == connection.source_id || environment.id == connection.target_id)
                && environment.runtime.starts_with("shared://tunnel/")
        });
        if shared && !connection.permissions.is_empty() && !runtime.remote_connection_live(&connection.id).await {
            connection.enforcement_status = Some(EnforcementStatus::Error);
            connection.last_error = Some("The private sharing tunnel disconnected. Reconnect the shared environment or switch this connection off and on to retry.".into());
        }
    }
    Ok(state)
}

fn environment_window_parts(environment_id: &str) -> Result<(String, PathBuf), String> {
    if !environment_id.starts_with("env-")
        || environment_id.len() > 80
        || !environment_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("Invalid environment window identifier".into());
    }
    Ok((
        format!("environment-{environment_id}"),
        format!("index.html?environment={environment_id}").into(),
    ))
}

#[tauri::command]
pub async fn open_environment_window(
    environment_id: String,
    app: AppHandle,
    store: State<'_, PlatformStore>,
) -> Result<bool, String> {
    let (label, location) = environment_window_parts(&environment_id)?;
    let environment = store.environment(&environment_id)?;
    if environment.kind == EnvironmentKind::ComputerBranch
        || provider(&environment) == RuntimeProviderKind::NativeSandbox
    {
        return Err("This environment does not have a Yougori guest window".into());
    }
    if environment.status != EnvironmentStatus::Running && !environment.runtime.starts_with("shared://tunnel/") {
        return Err("Start the environment before opening its guest window".into());
    }
    let title = environment.name.replace(['\r', '\n'], " ");
    let label = format!("{label}-{}", uuid::Uuid::new_v4().simple());
    crate::require_windows("The guest window")?;
    // WebView2 creation must not run inside a synchronous IPC handler: on
    // Windows it waits for the same event loop the handler would be blocking.
    WebviewWindowBuilder::new(&app, label, WebviewUrl::App(location))
        .title(format!("{title} — Yougori"))
        .inner_size(1180.0, 760.0)
        .min_inner_size(720.0, 480.0)
        .resizable(true)
        .focused(true)
        .center()
        .build()
        .map_err(|error| error.to_string())?;
    Ok(true)
}

#[tauri::command]
pub fn close_environment_window(window: WebviewWindow) -> Result<(), String> {
    if !window.label().starts_with("environment-env-") {
        return Err("Only an environment window can close itself with this command".into());
    }
    window.close().map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn reset_platform_state(
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
    backup: State<'_, BackupManager>,
) -> Result<PlatformState, String> {
    let state = store.snapshot()?;
    if state.environments.iter().any(|environment| environment.status == EnvironmentStatus::Provisioning) {
        return Err("Wait for environment creation to finish before resetting local data".into());
    }
    if state.neocloud_deployments.values().any(|deployment| deployment.state != "Deleted") {
        return Err("Delete or reconcile every Neocloud provider resource before resetting Yougori. Resetting now would lose its billing controls.".into());
    }
    if !state.pending_factory_resets.is_empty() {
        return Err("Finish the pending Factory reset before resetting all local data".into());
    }
    for destination in &state.destinations {
        backup.delete_credentials(&destination.id)?;
    }
    let mut cleanup_errors = Vec::new();
    for environment in &state.environments {
        match provider(environment) {
            RuntimeProviderKind::CloudSsh => { runtime.cloud.disconnect(&environment.id).await; },
            RuntimeProviderKind::YougoriOci | RuntimeProviderKind::YougoriCuda => {
                for snapshot in state
                    .snapshots
                    .iter()
                    .filter(|snapshot| snapshot.environment_id == environment.id)
                {
                    if let Err(error) = runtime
                        .delete_container_snapshot(runtime_id(environment), &snapshot.id)
                        .await
                    {
                        cleanup_errors.push(error);
                    }
                }
                if let Err(error) = runtime.delete_container(runtime_id(environment)).await {
                    cleanup_errors.push(error);
                }
            }
            RuntimeProviderKind::Qemu => {
                if let Err(error) = runtime.delete_vm(runtime_id(environment)).await {
                    cleanup_errors.push(error);
                }
            }
            RuntimeProviderKind::NativeSandbox => {
                if let Err(error) = runtime
                    .delete_native_sandbox(
                        runtime_id(environment),
                        environment.sandbox_policy.as_ref(),
                    )
                    .await
                {
                    cleanup_errors.push(error);
                }
            }
        }
    }
    for snapshot in &state.snapshots {
        if let Some(path) = snapshot.artifact_path.as_deref() {
            let path = PathBuf::from(path);
            if let Err(runtime_error) = runtime.remove_snapshot_artifact(&path).await {
                if let Err(backup_error) = backup.delete_restore_artifact(&path).await {
                    cleanup_errors.push(format!("{runtime_error}; {backup_error}"));
                }
            }
        }
    }
    if let Err(error) = runtime.garbage_collect_vm_bases(&[]).await {
        cleanup_errors.push(error);
    }
    if !cleanup_errors.is_empty() {
        cleanup_errors.sort();
        cleanup_errors.dedup();
        return Err(format!(
            "Yougori could not finish cleaning local runtime data: {}",
            cleanup_errors.join("; ")
        ));
    }
    let mut empty = PlatformState::empty().map_err(|error| error.to_string())?;
    empty.settings = state.settings;
    empty.host = collect_host_metrics(&state.host, runtime.storage_root());
    empty.providers = runtime.provider_statuses();
    store.replace(empty)
}

#[tauri::command]
pub async fn create_environment(
    mut request: CreateEnvironmentRequest,
    app: AppHandle,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
) -> Result<PlatformState, String> {
    // Selecting the dedicated GPU category is explicit hardware authorization.
    if request.kind == EnvironmentKind::Cloud || request.provider == RuntimeProviderKind::CloudSsh { return Err("Use Cloud environment to add an existing server. Yougori does not create cloud machines.".into()); }
    // Never infer a provider migration from the permission on an existing node.
    if request.kind == EnvironmentKind::Container && request.provider == RuntimeProviderKind::YougoriCuda {
        request.gpu_access = true;
    }
    let name = request.name.trim();
    if name.len() < 2 || name.len() > 80 {
        return Err("Environment name must be between 2 and 80 characters".into());
    }
    let runtime_source = request.runtime.trim();
    if runtime_source.is_empty() {
        return Err("An OCI image, application, or bootable media path is required".into());
    }
    if request.kind == EnvironmentKind::ComputerBranch {
        return Err("Computer Branch is temporarily unavailable".into());
    }
    validate_range("CPU", &request.resource_policy.cpu)?;
    if let Some(gb) = request.storage_gb { crate::runtime::storage::storage_bytes(gb)?; }
    validate_range("Memory", &request.resource_policy.memory_gb)?;
    if request.resource_policy.cpu.max > 255.0 {
        return Err("CPU maximum cannot exceed 255 virtual CPUs".into());
    }
    if request.resource_policy.memory_gb.max > 1024.0 {
        return Err("Memory maximum cannot exceed 1024 GiB".into());
    }
    match (&request.kind, &request.provider) {
        (EnvironmentKind::Container, RuntimeProviderKind::YougoriOci | RuntimeProviderKind::YougoriCuda) => {}
        (EnvironmentKind::Container, _) => {
            return Err("Choose the Yougori OCI or NVIDIA CUDA container runtime".into());
        }
        (EnvironmentKind::ComputerBranch, RuntimeProviderKind::NativeSandbox) => {}
        (EnvironmentKind::ComputerBranch, _) => {
            return Err(
                "Computer Branches use native Windows application isolation, not a VM".into(),
            );
        }
        (EnvironmentKind::MicroVm | EnvironmentKind::FullVm, RuntimeProviderKind::Qemu) => {}
        (_, RuntimeProviderKind::NativeSandbox) => {
            return Err("Native application isolation is only valid for Computer Branches".into());
        }
        _ => return Err("Virtual environments must use bundled Yougori virtualization".into()),
    }
    match (&request.kind, &request.branch_type) {
        (EnvironmentKind::ComputerBranch, _) => {}
        (_, Some(_)) => return Err("Branch type is only valid for computer branches".into()),
        (_, None) => {}
    }
    if request.kind == EnvironmentKind::ComputerBranch {
        let policy = request
            .sandbox_policy
            .as_ref()
            .ok_or("Choose an application and file access for this Computer Branch")?;
        if policy.executable.trim() != runtime_source {
            return Err(
                "Computer Branch application metadata does not match the selected application"
                    .into(),
            );
        }
    } else if request.sandbox_policy.is_some() {
        return Err("File access policy is only valid for Computer Branches".into());
    }
    if let Some(options) = &request.workload {
        if request.kind != EnvironmentKind::Container { return Err("OCI workload options require a container".into()); }
        options.validate()?;
    }
    let current = store.snapshot()?;
    let host = collect_host_metrics(&current.host, runtime.storage_root());
    if request.resource_policy.cpu.max > host.total_cpu as f64 {
        return Err(format!(
            "CPU maximum cannot exceed this host's {} logical processors",
            host.total_cpu
        ));
    }
    if request.resource_policy.memory_gb.max > host.total_memory_gb {
        return Err(format!(
            "Memory maximum cannot exceed this host's {:.1} GiB",
            host.total_memory_gb
        ));
    }
    if current
        .environments
        .iter()
        .any(|environment| environment.name.eq_ignore_ascii_case(name))
    {
        return Err("An environment with this name already exists".into());
    }

    let id = format!("env-{}", Uuid::new_v4());
    runtime.select_storage_drive(&id, request.storage_drive.as_deref())?;
    if let Some(options) = &request.workload { runtime.save_workload_options(&id, options)?; }
    let policy = ResourcePolicy {
        cpu: ResourceRange {
            min: request.resource_policy.cpu.min,
            preferred: request.resource_policy.cpu.preferred,
            max: request.resource_policy.cpu.max,
            current: 0.0,
        },
        memory_gb: ResourceRange {
            min: request.resource_policy.memory_gb.min,
            preferred: request.resource_policy.memory_gb.preferred,
            max: request.resource_policy.memory_gb.max,
            current: 0.0,
        },
        priority: request.resource_policy.priority.clone(),
        dynamic: request.resource_policy.dynamic,
    };
    if request.provider.is_container() {
        validate_container_policy_capacity(&policy, &host)?;
    }
    let container_command = request
        .container_command
        .as_deref()
        .map(str::trim)
        // Explicitly empty means use the image's ENTRYPOINT/CMD; only legacy
        // requests that omit this field retain the old keep-alive default.
        .unwrap_or("sleep 2147483647")
        .to_owned();
    if request.provider == RuntimeProviderKind::YougoriCuda && !request.auto_setup_cuda {
        let selected = runtime.storage_runtime(&id)?;
        let status = selected.as_deref().unwrap_or(&runtime).cuda_status().await;
        if !status.supported { return Err(format!("NVIDIA CUDA is unavailable on this computer: {}", status.detail)); }
        if !status.installed || status.update_available { return Err("Set up or update NVIDIA CUDA in New environment → GPU, or run yougori-cli gpu setup --yes, before creating a GPU container.".into()); }
    }
    // Every supported environment gets its final node ID before slow runtime work.
    // Closing the form leaves this command and its persisted progress intact.
    Box::pin(vm_creation::create_on_graph(&request, policy.clone(), &id, &store, Box::pin(async {
        if request.kind == EnvironmentKind::FullVm {
            let prepared = runtime.provision_vm_with_storage(&id, runtime_source, request.storage_gb).await?;
            return Ok((Some(prepared.disk_path.to_string_lossy().into_owned()), prepared.source_path.to_string_lossy().into_owned()));
        }
        let (runtime_path, managed_runtime_source, _managed_sandbox_policy) = match request.provider {
            RuntimeProviderKind::CloudSsh => return Err("Use Add cloud environment to connect an existing server".into()),
            RuntimeProviderKind::YougoriOci | RuntimeProviderKind::YougoriCuda => {
                runtime.register_container_provider(&id, &request.provider)?;
                if request.auto_setup_cuda {
                    let selected = runtime.storage_runtime(&id)?;
                    let cuda_runtime = selected.as_deref().unwrap_or(&runtime);
                    let status = cuda_runtime.cuda_status().await;
                    if !status.supported { return Err(format!("NVIDIA CUDA is unavailable on this computer: {}", status.detail)); }
                    if !status.installed || status.update_available { cuda_runtime.install_cuda().await?; }
                }
                Box::pin(runtime
                    .provision_container_with_storage(
                        &id,
                        runtime_source,
                        &container_command,
                        &policy,
                        request.network_access,
                        request.gpu_access,
                        request.storage_gb.unwrap_or(20.0),
                    ))
                    .await?;
                (None, runtime_source.to_owned(), None)
            }
            RuntimeProviderKind::Qemu => {
                let provisioned = if request.kind == EnvironmentKind::MicroVm {
                    runtime.provision_micro_vm(&id, runtime_source).await?
                } else if request.kind == EnvironmentKind::ComputerBranch
                    && request.branch_type != Some(BranchType::CleanOs)
                {
                    runtime
                        .provision_computer_branch(
                            &id,
                            request
                                .branch_type
                                .as_ref()
                                .ok_or("Select a current-computer branch type")?,
                        )
                        .await?
                } else {
                    runtime.provision_vm(&id, runtime_source).await?
                };
                if let Some(gb) = request.storage_gb {
                    let grow = async {
                        let storage = runtime.vm_storage_allocation(&id, &provisioned.disk_path).await?;
                        if gb > storage.capacity_gb { runtime.grow_vm_storage(&id, &provisioned.disk_path, gb).await?; }
                        Ok::<(), String>(())
                    }.await;
                    if let Err(error) = grow {
                        let _ = runtime.delete_vm(&id).await;
                        return Err(error);
                    }
                }
                let persisted_source = if request.kind == EnvironmentKind::MicroVm
                    && runtime_source == BUILTIN_MICRO_VM_SOURCE
                {
                    BUILTIN_MICRO_VM_SOURCE.to_owned()
                } else {
                    provisioned.source_path.to_string_lossy().into_owned()
                };
                (
                    Some(provisioned.disk_path.to_string_lossy().into_owned()),
                    persisted_source,
                    None,
                )
            }
            RuntimeProviderKind::NativeSandbox => {
                let provisioned = runtime
                    .provision_native_sandbox(
                        &id,
                        request
                            .sandbox_policy
                            .as_ref()
                            .ok_or("Choose a native branch application")?,
                    )
                    .await?;
                (
                    Some(provisioned.workspace_path.to_string_lossy().into_owned()),
                    provisioned.policy.executable.clone(),
                    Some(provisioned.policy),
                )
            }
        };
        Ok((runtime_path, managed_runtime_source))
    }), |state| { let _ = app.emit("yougori-platform-state", state); })).await
}

#[tauri::command]
pub async fn set_environment_status(
    environment_id: String,
    status: EnvironmentStatus,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
) -> Result<PlatformState, String> {
    if matches!(status, EnvironmentStatus::Stopped | EnvironmentStatus::Paused) { crate::file_import::cancel_transfers(&environment_id, None); crate::guest_execution::cancel_environment_jobs(&environment_id); }
    let snapshot_interruption = if matches!(status, EnvironmentStatus::Stopped | EnvironmentStatus::Paused) {
        let state = store.snapshot()?;
        let environment = state.environments.iter().find(|environment| environment.id == environment_id).ok_or("Environment not found")?;
        Some(runtime.interrupt_snapshot_exports(runtime_id(environment)))
    } else { None };
    if status == EnvironmentStatus::Running {
        // A model environment that is reused gets this version's model server; if that fails
        // it starts with the one it has.
        if let Err(error) = crate::model_runner::refresh_server(&environment_id, &store, &runtime).await {
            eprintln!("Model server was not updated for {environment_id}: {error}");
        }
    }
    let network_lock = environment_network_lock(&environment_id).await;
    let _network_serial = if snapshot_interruption.as_ref().is_some_and(|interruption| interruption.cancelled_exports > 0) {
        tokio::time::timeout(std::time::Duration::from_secs(8), network_lock.lock()).await
            .map_err(|_| "Snapshot export cleanup is still pending; inspect the interrupted snapshot before retrying this lifecycle action".to_string())?
    } else {
        network_lock.try_lock().map_err(|_| "Another lifecycle or network operation is changing this environment; retry after that operation finishes.".to_string())?
    };
    if matches!(
        status,
        EnvironmentStatus::Provisioning | EnvironmentStatus::Error
    ) {
        return Err("Provisioning and error states are controlled by the runtime".into());
    }
    let guarded = store.environment(&environment_id)?;
    let _container_serial = environment_container_policy_guard(&runtime, &guarded).await?;
    let current_state = store.snapshot()?;
    if status == EnvironmentStatus::Running && current_state.pending_factory_resets.iter().any(|p| p.environment.id == environment_id) {
        return Err("Finish the pending Factory reset before starting this environment".into());
    }
    let environment = current_state
        .environments
        .iter()
        .find(|item| item.id == environment_id)
        .cloned()
        .ok_or("Environment not found")?;
    if environment.kind == EnvironmentKind::ComputerBranch && status == EnvironmentStatus::Running {
        return Err("Computer Branch is temporarily unavailable".into());
    }
    if crate::peer_sharing::is_shared(&environment) {
        let remote=crate::peer_sharing::remote(&environment,"power",serde_json::json!({"status":status})).await?;
        return store.mutate(|state|{let e=state.environments.iter_mut().find(|e|e.id==environment_id).ok_or("Environment removed")?;e.status=serde_json::from_value(remote["environment"]["status"].clone()).map_err(|_|"Invalid shared status")?;e.last_error=None;Ok(())});
    }
    if environment.status == EnvironmentStatus::Provisioning {
        return Err("Wait for this environment to finish creating before changing its power state".into());
    }
    if status == EnvironmentStatus::Running {
        if let Err(error) = runtime.ensure_saved_oci_storage(&environment) {
            // Preserve the stable missing-storage marker so a subsequent
            // retry cannot reinterpret this finalized node as fresh creation.
            let _ = store.mutate(|state| {
                if let Some(environment) = state.environments.iter_mut().find(|item|item.id == environment_id) {environment.last_error = Some(error.clone());}
                Ok(())
            });
            return Err(error);
        }
    }
    if status == EnvironmentStatus::Running && environment.status != EnvironmentStatus::Running {
        // The runtime starts with the preferred values. Force one scheduler
        // reconciliation after every fresh start in case pressure changed.
        if !provider(&environment).is_container() {
            forget_applied_resource_limits(runtime_id(&environment));
        }
    }
    let mut container_rollback = Vec::new();
    let mut planned_container_start = None;
    let resource_reservation = if status == EnvironmentStatus::Running && environment.status != EnvironmentStatus::Running && provider(&environment) != RuntimeProviderKind::CloudSsh {
        Some(resource_admission::reserve_start(&store, &environment, &runtime)?)
    } else { None };
    let mut started_console: Option<(Option<String>, Option<String>)> = None;
    let operation = match provider(&environment) {
        RuntimeProviderKind::CloudSsh => match status {
            EnvironmentStatus::Running => runtime.connect_cloud(&environment.id).await.and_then(|info|{
                started_console=Some(crate::runtime::cloud::endpoints(&info)?);
                Ok(())
            }),
            EnvironmentStatus::Stopped => { runtime.cloud.disconnect(&environment.id).await; Ok(()) },
            _ => Err("Cloud nodes support Connect and Disconnect only. The server's power is not managed by Yougori.".into()),
        },
        RuntimeProviderKind::YougoriOci | RuntimeProviderKind::YougoriCuda => {
            if status == EnvironmentStatus::Running
                && environment.status != EnvironmentStatus::Running
            {
                let prepared = prepare_container_start(&current_state, &environment, &runtime, resource_reservation.as_ref()).await?;
                container_rollback = prepared.rollback;
                planned_container_start = Some(prepared.target);
            }
            let action = match (&environment.status, &status) {
                (EnvironmentStatus::Running, EnvironmentStatus::Running)
                | (EnvironmentStatus::Stopped, EnvironmentStatus::Stopped)
                | (EnvironmentStatus::Paused, EnvironmentStatus::Paused) => None,
                (EnvironmentStatus::Paused, EnvironmentStatus::Running) => Some("resume"),
                (_, EnvironmentStatus::Running) => Some("start"),
                (_, EnvironmentStatus::Stopped) => Some("stop"),
                (EnvironmentStatus::Running, EnvironmentStatus::Paused) => Some("pause"),
                _ => return Err("invalid container lifecycle transition".into()),
            };
            if let Some(action) = action {
                container_action_rebuilding_if_missing(&runtime, &environment, action, planned_container_start.as_ref()).await
            } else {
                Ok(())
            }
        }
        RuntimeProviderKind::Qemu => match (&environment.status, &status) {
            (EnvironmentStatus::Running, EnvironmentStatus::Running)
            | (EnvironmentStatus::Paused, EnvironmentStatus::Paused) => Ok(()),
            (EnvironmentStatus::Paused, EnvironmentStatus::Running) => {
                runtime.vm_action(runtime_id(&environment), "resume").await
            }
            (_, EnvironmentStatus::Running) => {
                let result = async {
                    if environment.kind == EnvironmentKind::MicroVm {
                        runtime
                            .start_micro_vm_with_network(
                                runtime_id(&environment),
                                &vm_disk(&environment)?,
                                &micro_vm_manifest(&environment)?,
                                &environment.resource_policy,
                                environment.network_access,
                            )
                            .await
                    } else {
                        runtime
                            .start_vm_with_network(
                                runtime_id(&environment),
                                &vm_disk(&environment)?,
                                &PathBuf::from(&environment.runtime),
                                &environment.resource_policy,
                                environment.gpu_access,
                                environment.network_access,
                            )
                            .await
                    }
                }
                .await;
                match result {
                    Ok(console) => {
                        started_console = Some((
                            (!console.headless).then_some(console.websocket_url),
                            console
                                .serial_log_path
                                .map(|path| path.to_string_lossy().into_owned()),
                        ));
                        Ok(())
                    }
                    Err(error) => Err(error),
                }
            }
            (_, EnvironmentStatus::Stopped) => {
                runtime.vm_action(runtime_id(&environment), "stop").await
            }
            (EnvironmentStatus::Running, EnvironmentStatus::Paused) => {
                runtime.vm_action(runtime_id(&environment), "pause").await
            }
            _ => Err("invalid virtual machine lifecycle transition".into()),
        },
        RuntimeProviderKind::NativeSandbox => match (&environment.status, &status) {
            (EnvironmentStatus::Running, EnvironmentStatus::Running)
            | (EnvironmentStatus::Stopped, EnvironmentStatus::Stopped) => Ok(()),
            (_, EnvironmentStatus::Running) => {
                runtime
                    .start_native_sandbox(
                        runtime_id(&environment),
                        &sandbox_workspace(&environment)?,
                        sandbox_policy(&environment)?,
                        &environment.resource_policy,
                    )
                    .await
            }
            (_, EnvironmentStatus::Stopped) => {
                runtime.stop_native_sandbox(runtime_id(&environment)).await
            }
            (_, EnvironmentStatus::Paused) => {
                Err("Native application branches cannot be paused; stop the branch instead".into())
            }
            _ => Err("invalid native application branch lifecycle transition".into()),
        },
    };
    if let Err(error) = operation {
        let rollback_error = rollback_container_allocations(&runtime, &container_rollback)
            .await
            .err();
        let stored_error = error.clone();
        let _ = store.mutate(|state| {
            if let Some(item) = state
                .environments
                .iter_mut()
                .find(|item| item.id == environment_id)
            {
                item.status = EnvironmentStatus::Error;
                item.last_error = Some(stored_error);
            }
            Ok(())
        });
        return Err(match rollback_error {
            Some(rollback_error) => format!("{error}; {rollback_error}"),
            None => error,
        });
    }
    let preserve_vm_allocation = scheduler::fixed_vm_resources(&environment)
        && matches!(environment.status, EnvironmentStatus::Running | EnvironmentStatus::Paused);
    let persisted = store.mutate(|state| {
        let environment = state
            .environments
            .iter_mut()
            .find(|item| item.id == environment_id)
            .ok_or("Environment not found")?;
        environment.status = status.clone();
        environment.last_error = None;
        if let Some((console_endpoint, control_endpoint)) = started_console.clone() {
            environment.console_endpoint = console_endpoint;
            environment.control_endpoint = control_endpoint;
        }
        if status == EnvironmentStatus::Running {
            environment.last_opened_at = Some(now());
            if !preserve_vm_allocation {
                environment.resource_policy.cpu.current = environment.resource_policy.cpu.preferred.round().max(1.0);
                if !scheduler::fixed_vm_resources(environment) {
                    environment.resource_policy.cpu.current = environment.resource_policy.cpu.preferred;
                }
                environment.resource_policy.memory_gb.current = environment.resource_policy.memory_gb.preferred;
            }
        } else if status == EnvironmentStatus::Stopped {
            environment.cpu_usage = 0.0;
            environment.memory_usage_gb = 0.0;
            environment.network_rx_mbps = 0.0;
            environment.resource_policy.cpu.current = 0.0;
            environment.resource_policy.memory_gb.current = 0.0;
            environment.console_endpoint = None;
            if environment.kind == EnvironmentKind::Cloud { environment.control_endpoint = None; }
        }
        for connection in &mut state.connections {
            if connection.source_id == environment_id || connection.target_id == environment_id {
                connection.enforcement_status = Some(EnforcementStatus::Pending);
                connection.provider_rule_ids.clear();
            }
        }
        scheduler::schedule(state);
        Ok(())
    });
    let next = match persisted {
        Ok(next) => next,
        Err(error) => {
            let mut errors = vec![error];
            if let Err(error) = rollback_runtime_transition(&runtime, &environment, &status).await {
                errors.push(format!(
                    "restoring the previous runtime state failed: {error}"
                ));
            }
            if let Err(error) = rollback_container_allocations(&runtime, &container_rollback).await
            {
                errors.push(error);
            }
            if environment.status == EnvironmentStatus::Running {
                if let Err(error) = reconcile_connections(&store, &runtime).await {
                    errors.push(format!("restoring environment connections failed: {error}"));
                }
            }
            return Err(errors.join("; "));
        }
    };
    if status == EnvironmentStatus::Stopped {
        forget_applied_resource_limits(runtime_id(&environment));
        let cuda_busy = provider(&environment) == RuntimeProviderKind::YougoriCuda && next.environments.iter().any(|peer|
            provider(peer) == RuntimeProviderKind::YougoriCuda && matches!(peer.status, EnvironmentStatus::Running | EnvironmentStatus::Paused | EnvironmentStatus::Provisioning));
        if !cuda_busy {
            if let Err(error) = runtime.reclaim_pending_container_storage(runtime_id(&environment), &provider(&environment)).await {
                eprintln!("Storage cleanup remains pending: {error}");
            }
        }
    }
    if status == EnvironmentStatus::Running {
        reconcile_connections(&store, &runtime).await?;
        return store.snapshot();
    }
    Ok(next)
}

#[tauri::command]
pub async fn recover_vm_runtime(
    environment_id: String,
    confirmed: bool,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
) -> Result<PlatformState, String> {
    if !confirmed { return Err("Confirm stopping the abandoned VM first".into()); }
    let state = store.snapshot()?;
    let environment = state.environments.iter().find(|item| item.id == environment_id).ok_or("Environment not found")?;
    if provider(environment) != RuntimeProviderKind::Qemu {
        return Err("VM recovery is only available for QEMU environments".into());
    }
    if environment.status == EnvironmentStatus::Provisioning {
        return Err("Wait for VM creation to finish".into());
    }
    let report = crate::lifecycle::recover_environment_runtime_report(environment_id, confirmed, store.clone(), runtime).await?;
    if !report.ownership_released { return Err(report.error.unwrap_or_else(|| "Recovery postcondition was not verified".into())); }
    store.snapshot()
}

#[tauri::command]
pub async fn recover_container_runtime(
    environment_id: String,
    confirmed: bool,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
) -> Result<PlatformState, String> {
    if !confirmed {
        return Err("Confirm stopping the abandoned runtime first".into());
    }
    let state = store.snapshot()?;
    let environment = state.environments.iter().find(|item| item.id == environment_id)
        .ok_or("Environment not found")?;
    if !provider(environment).is_container() {
        return Err("Runtime recovery is only available for managed containers".into());
    }
    let report = crate::lifecycle::recover_environment_runtime_report(environment_id, confirmed, store.clone(), runtime).await?;
    if !report.ownership_released { return Err(report.error.unwrap_or_else(|| "Recovery postcondition was not verified".into())); }
    store.snapshot()
}

#[tauri::command]
pub async fn delete_environment(
    environment_id: String,
    recover_runtime: Option<bool>,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
    backup: State<'_, BackupManager>,
) -> Result<EnvironmentDeletionResult, String> {
    crate::file_import::cancel_transfers(&environment_id, None); crate::guest_execution::cancel_environment_jobs(&environment_id);
    let snapshot_interruption = {
        let state = store.snapshot()?;
        let environment = state.environments.iter().find(|environment| environment.id == environment_id).ok_or("Environment not found")?;
        runtime.interrupt_snapshot_exports(runtime_id(environment))
    };
    let network_lock = environment_network_lock(&environment_id).await;
    let _network_serial = if snapshot_interruption.cancelled_exports > 0 {
        tokio::time::timeout(std::time::Duration::from_secs(8), network_lock.lock()).await
            .map_err(|_| "Snapshot export cleanup is still pending; inspect the interrupted snapshot before retrying this lifecycle action".to_string())?
    } else {
        network_lock.try_lock().map_err(|_| "Another lifecycle or network operation is changing this environment; retry after that operation finishes.".to_string())?
    };
    factory_reset::cleanup_pending(&environment_id, &store, &runtime, &backup).await?;
    let state = store.snapshot()?;
    let environment = state
        .environments
        .iter()
        .find(|item| item.id == environment_id)
        .cloned()
        .ok_or("Environment not found")?;
    if environment.status == EnvironmentStatus::Provisioning {
        return Err("Wait for this environment to finish creating before deleting it".into());
    }
    if crate::peer_sharing::is_shared(&environment) {
        for connection in state.connections.iter().filter(|connection| connection.source_id == environment_id || connection.target_id == environment_id) {
            runtime.remove_environment_connection(&connection.id, connection_runtime_id(&state, &connection.source_id), connection_runtime_id(&state, &connection.target_id), false).await?;
        }
        if environment.runtime.starts_with("shared://tunnel/") { let _ = tokio::time::timeout(std::time::Duration::from_secs(3),crate::remote_access::request_saved(&environment,"logout",serde_json::json!({}))).await; }
        crate::peer_sharing::forget(&environment_id)?;
        let state=store.mutate(|s|{s.environments.retain(|e|e.id!=environment_id);s.saved_environment_services.retain(|service|service.environment_id!=environment_id);s.connections.retain(|c|c.source_id!=environment_id&&c.target_id!=environment_id);s.settings.auto_start_environment_ids.retain(|id|id!=&environment_id);Ok(())})?;
        let mut storage_cleanup = StorageCleanupResult::default();
        if let Err(error) = yougori_cli::launcher_state::forget_environment(&environment_id) {
            storage_cleanup.warnings.push(error);
        }
        return Ok(EnvironmentDeletionResult{state,storage_cleanup});
    }
    if recover_runtime.unwrap_or(false) {
        if state.cloud_deployments.contains_key(&environment_id) {
            return Err("Manage this VM from Cloud deployment controls".into());
        }
        if !provider(&environment).is_container() {
            return Err("Runtime recovery is only available for managed containers".into());
        }
        let selected = runtime.storage_runtime(runtime_id(&environment))?;
        selected.as_deref().unwrap_or(&runtime).recover_container_provider(&provider(&environment)).await?;
    }
    if state.cloud_deployments.get(&environment_id).is_some_and(|d|d.state != "Deleted") {
        return Err("Delete the managed cloud VM from Cloud deployment controls before removing its entry".into());
    }
    if state.neocloud_deployments.get(&environment_id).is_some_and(|d| d.state != "Deleted") {
        return Err("Delete the Neocloud resource from its provider controls before removing this node".into());
    }
    forget_applied_resource_limits(runtime_id(&environment));
    for connection in state
        .connections
        .iter()
        .filter(|item| item.source_id == environment_id || item.target_id == environment_id)
    {
        let _ = runtime
            .remove_environment_connection(
                &connection.id,
                connection_runtime_id(&state, &connection.source_id),
                connection_runtime_id(&state, &connection.target_id),
                container_connection(&state, &connection.source_id, &connection.target_id),
            )
            .await;
    }
    match provider(&environment) {
        RuntimeProviderKind::CloudSsh => { runtime.cloud.disconnect(&environment.id).await; },
        RuntimeProviderKind::YougoriOci | RuntimeProviderKind::YougoriCuda => {
            for snapshot in state
                .snapshots
                .iter()
                .filter(|item| item.environment_id == environment_id)
            {
                runtime
                    .delete_container_snapshot(runtime_id(&environment), &snapshot.id)
                    .await.map_err(|error| format!("Snapshot cleanup did not finish; the environment was kept so deletion can be retried. {error}"))?;
            }
            runtime.delete_container_and_model_cache(runtime_id(&environment)).await?;
        }
        RuntimeProviderKind::Qemu => {
            for snapshot in state
                .snapshots
                .iter()
                .filter(|snapshot| snapshot.environment_id == environment_id)
            {
                if let Some(path) = snapshot.artifact_path.as_deref().map(PathBuf::from) {
                    if let Err(runtime_error) = runtime.remove_snapshot_artifact(&path).await {
                        backup
                            .delete_restore_artifact(&path)
                            .await
                            .map_err(|backup_error| format!("{runtime_error}; {backup_error}"))?;
                    }
                }
            }
            runtime.delete_vm(runtime_id(&environment)).await?
        }
        RuntimeProviderKind::NativeSandbox => {
            runtime
                .delete_native_sandbox(
                    runtime_id(&environment),
                    environment.sandbox_policy.as_ref(),
                )
                .await?
        }
    }
    let next = store.mutate(|state| {
        state.environments.retain(|item| item.id != environment_id);
        state.saved_environment_services.retain(|service| service.environment_id != environment_id);
        state.cloud_deployments.remove(&environment_id);
        state.neocloud_deployments.remove(&environment_id);
        if state.cli_environment_id.as_deref()==Some(&environment_id){state.cli_environment_id=None;}
        state.settings.auto_start_environment_ids.retain(|id| id != &environment_id);
        state.manual_service_ports.remove(&environment_id);
        state
            .connections
            .retain(|item| item.source_id != environment_id && item.target_id != environment_id);
        state
            .snapshots
            .retain(|item| item.environment_id != environment_id);
        Ok(())
    })?;
    let _ = std::fs::remove_file(crate::model_runner::chat_history_file(&store, &environment_id));
    let launcher_cleanup_error = yougori_cli::launcher_state::forget_environment(&environment_id).err();
    // Content-addressed installers and base disks are shared. Reclaim them only
    // after the final environment/snapshot reference disappears.
    let mut storage_cleanup = match runtime.garbage_collect_vm_bases(&referenced_vm_sources(&next)).await {
        Ok(bytes) => StorageCleanupResult { reclaimed_cache_bytes: bytes, ..Default::default() },
        Err(error) => StorageCleanupResult {
            warnings: vec![format!("The environment was deleted, but unused image cleanup was incomplete: {error}. Retry Storage → Reclaim space.")],
            ..Default::default()
        },
    };
    if let Some(error) = launcher_cleanup_error {
        storage_cleanup.warnings.push(format!("The environment was deleted, but launcher settings cleanup is incomplete: {error}"));
    }
    if provider(&environment).is_container() {
        match runtime.reclaim_container_storage(&provider(&environment)).await {
            Ok(cleanup) => {
                storage_cleanup.reclaimed_disk_bytes = cleanup.reclaimed_disk_bytes;
                storage_cleanup.notes.extend(cleanup.notes);
                storage_cleanup.warnings.extend(cleanup.warnings);
            }
            Err(error) => storage_cleanup.warnings.push(format!("The environment was deleted, but shared-disk cleanup is incomplete: {error}")),
        }
    }
    // Deletion is already committed. Never report it as failed just because the
    // separate shared-cache cleanup could not complete. Refresh free space now,
    // instead of returning the old numbers until the next 60-second poll.
    if environment.kind == EnvironmentKind::Cloud {
        if let Err(error)=runtime.cloud.forget(&environment.id) {storage_cleanup.warnings.push(format!("Cloud node removed, but saved connection metadata could not be removed: {error}"));}
    }
    if let Some(sampler) = HOST_SAMPLER.get() {
        let mut sampler = sampler.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        sampler.disks.refresh(true);
        sampler.last_disk_refresh = Instant::now();
    }
    let state = store.mutate_ephemeral(|state| {
        state.host = collect_host_metrics(&state.host, runtime.storage_root());
        Ok(())
    })?;
    Ok(EnvironmentDeletionResult { state, storage_cleanup })
}

#[tauri::command]
pub async fn rename_environment(
    environment_id: String,
    name: String,
    store: State<'_, PlatformStore>,
) -> Result<PlatformState, String> {
    let name = name.trim();
    if !(2..=80).contains(&name.chars().count()) || name.chars().any(char::is_control) {
        return Err("Name must contain 2–80 characters and no control characters".into());
    }
    store.mutate(|state| {
        let environment = state.environments.iter_mut()
            .find(|item| item.id == environment_id).ok_or("Environment not found")?;
        // Display metadata only: disk paths, runtime IDs and connections stay unchanged.
        environment.name = name.to_owned();
        Ok(())
    })
}

#[tauri::command]
pub async fn update_resource_policy(
    environment_id: String,
    mut resource_policy: ResourcePolicy,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
) -> Result<PlatformState, String> {
    resource_policy.dynamic = true;
    let guarded = store.environment(&environment_id)?;
    let _container_serial = environment_container_policy_guard(&runtime, &guarded).await?;
    validate_policy(&resource_policy)?;
    if guarded.description.starts_with("Hugging Face · ")
        && (resource_policy.cpu.min < 2.0 || resource_policy.memory_gb.min < 4.0) {
        return Err("Models require a minimum of 2 CPU cores and 4 GB RAM".into());
    }
    let environment = store.environment(&environment_id)?;
    // `current` is runtime-owned telemetry/allocation state, not a client-settable
    if environment.kind == EnvironmentKind::Cloud { return Err("Cloud resources are managed outside Yougori".into()); }
    // policy field. Preserve it until the scheduler computes the next allocation.
    resource_policy.cpu.current = environment.resource_policy.cpu.current;
    resource_policy.memory_gb.current = environment.resource_policy.memory_gb.current;
    let state = store.snapshot()?;
    let host = collect_host_metrics(&state.host, runtime.storage_root());
    if resource_policy.cpu.max > host.total_cpu as f64 {
        return Err(format!(
            "CPU maximum cannot exceed this host's {} logical processors",
            host.total_cpu
        ));
    }
    if resource_policy.memory_gb.max > host.total_memory_gb {
        return Err(format!(
            "Memory maximum cannot exceed this host's {:.1} GiB",
            host.total_memory_gb
        ));
    }
    let mut container_rollback = Vec::new();
    let resource_reservation = if environment.status == EnvironmentStatus::Running && !scheduler::fixed_vm_resources(&environment) {
        let mut proposed = environment.clone();
        proposed.resource_policy = resource_policy.clone();
        Some(resource_admission::reserve_start(&store, &proposed, &runtime)?)
    } else { None };
    if provider(&environment).is_container() {
        validate_container_policy_capacity(&resource_policy, &host)?;
        if environment.status == EnvironmentStatus::Running {
            let mut candidate = state.clone();
            candidate
                .environments
                .iter_mut()
                .find(|item| item.id == environment_id)
                .ok_or("Environment not found")?
                .resource_policy = resource_policy.clone();
            container_rollback =
                prepare_container_start(&candidate, &environment, &runtime, resource_reservation.as_ref()).await?.rollback;
        }
    }
    if environment.status == EnvironmentStatus::Running
        && provider(&environment) == RuntimeProviderKind::Qemu
        && !scheduler::fixed_vm_resources(&environment)
        && (resource_policy.cpu.max > environment.resource_policy.cpu.max
            || resource_policy.memory_gb.max > environment.resource_policy.memory_gb.max)
    {
        return Err("Stop the virtual machine before expanding its CPU or memory maximum".into());
    }
    let mut live_resources_changed = false;
    if environment.status == EnvironmentStatus::Running && !scheduler::fixed_vm_resources(&environment) {
        let update = match provider(&environment) {
            RuntimeProviderKind::CloudSsh => return Err("Cloud resources are managed outside Yougori".into()),
            // `prepare_container_start` already applied the newly scheduled provider-local
            // allocation to every running container without transiently exceeding the guest.
            RuntimeProviderKind::YougoriOci | RuntimeProviderKind::YougoriCuda => Ok(()),
            _ => update_non_container_resource_limits(
                &runtime, &environment, resource_policy.cpu.preferred, resource_policy.memory_gb.preferred,
            ).await,
        };
        if let Err(error) = update {
            let rollback = update_non_container_resource_limits(
                &runtime, &environment, environment.resource_policy.cpu.preferred, environment.resource_policy.memory_gb.preferred,
            ).await;
            return Err(match rollback {
                Ok(()) => error,
                Err(rollback) => format!(
                    "{error}; restoring the previous resource limits also failed: {rollback}"
                ),
            });
        }
        // Fixed policies are skipped by the scheduler, so record the limits
        // actually applied above (including prepare_container_start). Dynamic
        // policies will be recalculated when the state is persisted below.
        resource_policy.cpu.current = resource_policy.cpu.preferred;
        // update_vm_resources changes microVM CPU only; RAM remains at boot
        // size until restart, including when a lower policy is saved.
        if environment.kind != EnvironmentKind::MicroVm {
            resource_policy.memory_gb.current = resource_policy.memory_gb.preferred;
        }
        if !provider(&environment).is_container() {
            live_resources_changed = true;
            forget_applied_resource_limits(runtime_id(&environment));
        }
    }
    let persisted = store.mutate(|state| {
        state
            .environments
            .iter_mut()
            .find(|item| item.id == environment_id)
            .ok_or("Environment not found")?
            .resource_policy = resource_policy;
        scheduler::schedule(state);
        Ok(())
    });
    match persisted {
        Ok(state) => Ok(state),
        Err(error) => {
            let mut errors = vec![error];
            if let Err(error) = rollback_container_allocations(&runtime, &container_rollback).await
            {
                errors.push(error);
            }
            if live_resources_changed {
                let rollback = update_non_container_resource_limits(
                    &runtime, &environment, environment.resource_policy.cpu.preferred, environment.resource_policy.memory_gb.preferred,
                ).await;
                if let Err(error) = rollback {
                    errors.push(format!(
                        "restoring the previous resource limits failed: {error}"
                    ));
                }
            }
            Err(errors.join("; "))
        }
    }
}

#[tauri::command]
pub async fn update_container_network(
    environment_id: String,
    enabled: bool,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
) -> Result<PlatformState, String> {
    let network_lock = environment_network_lock(&environment_id).await;
    let _network_serial = network_lock.lock().await;
    let guarded = store.environment(&environment_id)?;
    let _container_serial = environment_container_policy_guard(&runtime, &guarded).await?;
    let environment = store.environment(&environment_id)?;
    let container = provider(&environment).is_container() && environment.kind == EnvironmentKind::Container;
    let vm = provider(&environment) == RuntimeProviderKind::Qemu && matches!(environment.kind, EnvironmentKind::FullVm | EnvironmentKind::MicroVm);
    if !container && !vm {
        return Err("Internet access is available for containers, MicroVMs and VMs".into());
    }
    if !matches!(environment.status, EnvironmentStatus::Stopped | EnvironmentStatus::Running | EnvironmentStatus::Paused) {
        return Err("Wait until the environment is ready before changing internet access".into());
    }
    if environment.network_access == enabled {
        return store.snapshot();
    }
    let live = environment.status != EnvironmentStatus::Stopped;
    if live {
        let applied = if container { runtime.update_container_internet(runtime_id(&environment), enabled).await }
            else { runtime.update_vm_internet(runtime_id(&environment), enabled).await };
        if let Err(error) = applied {
            // A timed-out control request can have taken effect. Reconcile the
            // old policy before reporting failure instead of leaving a stale wire.
            let rollback = if container { runtime.update_container_internet(runtime_id(&environment), environment.network_access).await }
                else { runtime.update_vm_internet(runtime_id(&environment), environment.network_access).await };
            return Err(match rollback {
                Ok(()) => error,
                Err(rollback) => format!("{error}; could not confirm the previous network connection: {rollback}"),
            });
        }
    }
    let persisted = store.mutate(|state| {
        let current = state
            .environments
            .iter_mut()
            .find(|item| item.id == environment_id)
            .ok_or("Environment not found")?;
        if current.status != environment.status || current.network_access != environment.network_access {
            return Err("The environment changed while reconnecting; please retry".into());
        }
        current.network_access = enabled;
        Ok(())
    });
    match persisted {
        Ok(state) => Ok(state),
        Err(error) => {
            let rollback = if !live { Ok(()) }
                else if container { runtime.update_container_internet(runtime_id(&environment), environment.network_access).await }
                else { runtime.update_vm_internet(runtime_id(&environment), environment.network_access).await };
            Err(match rollback {
                Ok(()) => error,
                Err(rollback) => format!(
                    "{error}; restoring the previous network connection failed: {rollback}"
                ),
            })
        }
    }
}

#[tauri::command]
pub async fn update_environment_gpu(
    environment_id: String,
    enabled: bool,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
) -> Result<PlatformState, String> {
    let lock = environment_network_lock(&environment_id).await;
    let _environment_guard = lock.lock().await;
    let guarded = store.environment(&environment_id)?;
    let _pool_guard = environment_container_policy_guard(&runtime, &guarded).await?;
    let environment = store.environment(&environment_id)?;
    if environment.status != EnvironmentStatus::Stopped {
        return Err("Stop the environment before changing shared GPU access".into());
    }
    if environment.kind == EnvironmentKind::MicroVm {
        return Err(
            "Shared GPU graphics are unavailable for headless direct-kernel microVMs".into(),
        );
    }
    if environment.gpu_access == enabled {
        return store.snapshot();
    }
    let container_reconfigured = match provider(&environment) {
        RuntimeProviderKind::CloudSsh => return Err("Cloud hardware is managed outside Yougori".into()),
        RuntimeProviderKind::YougoriOci | RuntimeProviderKind::YougoriCuda => {
            runtime
                .update_container_configuration(
                    runtime_id(&environment),
                    environment.network_access,
                    enabled,
                    environment.network_access,
                    environment.gpu_access,
                    environment.container_command.as_deref().unwrap_or_default(),
                    &environment.resource_policy,
                )
                .await?;
            true
        }
        RuntimeProviderKind::Qemu => false,
        RuntimeProviderKind::NativeSandbox => {
            return Err("Shared GPU graphics are unavailable for Computer Branches".into());
        }
    };
    let persisted = store.mutate(|state| {
        state
            .environments
            .iter_mut()
            .find(|item| item.id == environment_id)
            .ok_or("Environment not found")?
            .gpu_access = enabled;
        Ok(())
    });
    match persisted {
        Ok(state) => Ok(state),
        Err(error) if container_reconfigured => {
            let rollback = runtime
                .update_container_configuration(
                    runtime_id(&environment),
                    environment.network_access,
                    environment.gpu_access,
                    environment.network_access,
                    enabled,
                    environment.container_command.as_deref().unwrap_or_default(),
                    &environment.resource_policy,
                )
                .await;
            Err(match rollback {
                Ok(()) => error,
                Err(rollback) => format!(
                    "{error}; restoring the previous container GPU policy failed: {rollback}"
                ),
            })
        }
        Err(error) => Err(error),
    }
}

#[tauri::command]
pub async fn list_environment_folders(
    environment_id: String,
    path: String,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
) -> Result<serde_json::Value, String> {
    if (!path.is_empty() && !path.starts_with('/')) || path.len() > 4096 || path.contains(['\0', '\\'])
        || path.split('/').any(|part| part == "..") {
        return Err("Choose an absolute folder path inside the environment".into());
    }
    let environment = store.environment(&environment_id)?;
    if environment.status != EnvironmentStatus::Running {
        return Err("Start or connect this environment to browse its folders".into());
    }
    if environment.kind == EnvironmentKind::FullVm {
        return Err("This full VM has no Yougori guest file agent. Browse its own files in the VM; it can still access selected folders from other nodes.".into());
    }
    let mut candidates = Vec::new();
    let explicit_path = !path.is_empty();
    if explicit_path { candidates.push(path); }
    else if environment.runtime.starts_with("shared://tunnel/") { candidates.push("/".into()); }
    else {
        let cwd = match environment.kind {
            EnvironmentKind::Cloud => if let Ok(session) = runtime.cloud.session(&environment.id).await {
                session.request("exec", serde_json::json!({"command":"pwd"})).await.ok()
                    .and_then(|value| value["stdout"].as_str().map(str::to_owned))
            } else { None },
            EnvironmentKind::Container => runtime.execute_container_command(runtime_id(&environment), "pwd").await.ok()
                .map(|result| result.stdout),
            EnvironmentKind::MicroVm => runtime.execute_micro_workload_command(runtime_id(&environment), "pwd").await.ok()
                .map(|result| result.stdout),
            _ => None,
        };
        if let Some(cwd) = cwd {
            let cwd = cwd.trim();
            if cwd.starts_with('/') && cwd.len() <= 4096 && !cwd.contains(['\0', '\\'])
                && !cwd.split('/').any(|part| part == "..") { candidates.push(cwd.into()); }
        }
        candidates.extend(["/workspace", "/app", "/home", "/root", "/"].into_iter().map(str::to_owned));
    }
    for candidate in candidates {
        let result = if environment.runtime.starts_with("shared://tunnel/") {
            crate::remote_access::request_saved(&environment, "files", serde_json::json!({"operation":"list","path":candidate.trim_start_matches('/')})).await
        } else {
            runtime.workspace_request(&environment, "/v1/remote/files", serde_json::json!({
                "id":runtime_id(&environment), "root":"/", "path":candidate.trim_start_matches('/'),
                "operation":"list", "readOnly":true
            })).await
        };
        if let Ok(result) = result {
            if let Some(entries) = result["entries"].as_array() {
                let visible_entries = entries.iter().filter(|entry| entry["name"].as_str().is_some() && entry["directory"].is_boolean())
                    .take(5000).cloned().collect::<Vec<_>>();
                return Ok(serde_json::json!({"path":candidate,"entries":visible_entries}));
            }
        }
        if explicit_path { break; }
    }
    Err("The environment's folders could not be opened. Start it and try again.".into())
}

#[tauri::command]
pub async fn request_connected_files(
    environment_id: String,
    request: serde_json::Value,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
) -> Result<serde_json::Value, String> {
    let state = store.snapshot()?;
    let environment = state.environments.iter().find(|item| item.id == environment_id)
        .ok_or("Environment not found")?;
    if environment.status != EnvironmentStatus::Running { return Err("Connect this environment to access shared files".into()); }
    let connection_id = request["connectionId"].as_str().ok_or("Choose a connection")?;
    let connection = state.connections.iter().find(|item| item.id == connection_id)
        .ok_or("Connection not found")?;
    if !connection.active || connection.enforcement_status != Some(EnforcementStatus::Enforced)
        || (connection.source_id != environment_id && connection.target_id != environment_id) {
        return Err("This environment has no active access to that connection".into());
    }
    runtime.desktop_connected_files_request(&environment_id, request).await
}

#[tauri::command]
pub async fn create_connection(
    request: CreateConnectionRequest,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
) -> Result<PlatformState, String> {
    let _serial = connection_operations().lock().await;
    if request.source_id == request.target_id {
        return Err("An environment cannot connect to itself".into());
    }
    if request.selected_folders.len() > 8 {
        return Err("Choose at most eight folders for one connection".into());
    }
    if !request.selected_folders.is_empty() && !request.permissions.contains(&PermissionKind::Data) {
        return Err("Selected folders require Data access".into());
    }
    let mut selected_paths = HashSet::new();
    for folder in &request.selected_folders {
        if folder.environment_id != request.source_id && folder.environment_id != request.target_id {
            return Err("A selected folder must belong to one of these environments".into());
        }
        crate::runtime::connection_files::validate_selected_folder_path(&folder.path)?;
        if !selected_paths.insert((&folder.environment_id, &folder.path)) {
            return Err("The same folder was selected twice".into());
        }
    }
    if request.permissions.is_empty() {
        if !request.commands { return Err("Select at least one capability".into()); }
    }
    let ports = request
        .ports
        .iter()
        .map(|port| {
            port.parse::<u16>()
                .ok()
                .filter(|value| *value > 0)
                .ok_or_else(|| "Ports must be valid values between 1 and 65535".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let grants_ports = request.permissions.contains(&PermissionKind::Ports);
    let grants_network = request.permissions.contains(&PermissionKind::Network);
    if let Some(port) = request.ssh_port {
        if port == 0 || (!grants_network && !(grants_ports && ports.contains(&port))) {
            return Err("SSH requires its TCP port to be explicitly allowed on this connection".into());
        }
    }
    if grants_ports && ports.is_empty() && !grants_network {
        return Err("Enter at least one TCP port, or grant full network access".into());
    }
    if !grants_ports && !ports.is_empty() {
        return Err("TCP ports were supplied without the Ports permission".into());
    }
    if ports.iter().collect::<HashSet<_>>().len() != ports.len() {
        return Err("Each allowed TCP port may only be listed once".into());
    }
    if let Some(volume) = request.volume.as_deref() {
        let volume = volume.trim();
        if volume.len() > 80
            || !volume
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err("Shared volume names may use up to 80 letters, numbers, dots, dashes, or underscores".into());
        }
    }
    let state = store.snapshot()?;
    let existing_connection = state.connections.iter().find(|connection| {
        (connection.source_id == request.source_id && connection.target_id == request.target_id)
            || (connection.source_id == request.target_id && connection.target_id == request.source_id)
    }).cloned();
    let source = state
        .environments
        .iter()
        .find(|item| item.id == request.source_id)
        .ok_or("Source environment not found")?;
    let target = state
        .environments
        .iter()
        .find(|item| item.id == request.target_id)
        .ok_or("Target environment not found")?;
    if [&source.id, &target.id].iter().any(|id| state.neocloud_deployments.get(*id).is_some_and(|deployment| deployment.product == "serverless")) {
        return Err("A serverless model API has no private VM network interface. Connect to its HTTPS endpoint from your application instead".into());
    }
    for endpoint in [source, target] {
        if !matches!(endpoint.kind, EnvironmentKind::Container | EnvironmentKind::MicroVm | EnvironmentKind::FullVm | EnvironmentKind::Cloud) {
            return Err("Connections require containers, MicroVMs or VMs".into());
        }
    }
    let remote_source = source.runtime.starts_with("shared://tunnel/");
    let remote_target = target.runtime.starts_with("shared://tunnel/");
    if remote_source && remote_target {
        return Err("Connect one shared environment to one environment on this computer".into());
    }
    if !request.selected_folders.is_empty() && (remote_source || remote_target) {
        return Err("Selected guest folders across a shared-environment tunnel are not available yet. Use the shared node's Files view for its owner's approved folder.".into());
    }
    if request.selected_folders.iter().any(|folder| {
        [source, target].iter().any(|env| env.id == folder.environment_id && env.kind == EnvironmentKind::FullVm)
    }) {
        return Err("A full VM needs a Yougori guest file agent before one of its folders can be selected. It can still access folders selected in other environments through this connection.".into());
    }
    if [source, target].iter().any(|env| crate::peer_sharing::is_shared(env) && !env.runtime.starts_with("shared://tunnel/")) {
        return Err("This older sharing invitation cannot carry private connections. Import the environment through its Cloudflare share link.".into());
    }
    let mut remote_fabric_id = None;
    if remote_source || remote_target {
        if request.permissions.iter().any(|permission| !matches!(permission, PermissionKind::Network | PermissionKind::Ports)) {
            return Err("Shared environment connections support network and TCP ports. Transfer files through its Files view.".into());
        }
        let remote = if remote_source { source } else { target };
        let capabilities = crate::remote_access::request_saved(remote, "inspect", serde_json::json!({})).await?;
        if capabilities["permission"] != "control" {
            return Err("Ask the owner for a Full Control share before connecting it to another environment".into());
        }
        if !request.permissions.is_empty() {
            let fabric_id = capabilities["fabricId"].as_str().filter(|id| crate::remote_access::bridge::valid_id(id)).ok_or("The owner has no private network adapter for this share")?;
            remote_fabric_id = Some((remote.id.clone(), fabric_id.to_owned()));
        }
        if !request.permissions.is_empty() && state.connections.iter().any(|connection| (connection.source_id == remote.id || connection.target_id == remote.id)
            && existing_connection.as_ref().is_none_or(|existing| existing.id != connection.id)) {
            return Err("This shared environment already has a private connection. Disconnect it before connecting another node.".into());
        }
    }
    if !container_connection(&state, &request.source_id, &request.target_id)
        && request.permissions.contains(&PermissionKind::Secrets) {
        return Err("Secret-directory sharing requires two containers on the same engine. Use Data for a cross-engine or VM connection folder.".into());
    }
    if let Some(previous) = existing_connection {
        let previous_running = previous.active && state.environments.iter().filter(|environment| {
            environment.id == previous.source_id || environment.id == previous.target_id
        }).all(|environment| environment.status == EnvironmentStatus::Running);
        if previous_running {
            runtime.remove_environment_connection(&previous.id,
                connection_runtime_id(&state, &previous.source_id),
                connection_runtime_id(&state, &previous.target_id),
                container_connection(&state, &previous.source_id, &previous.target_id)).await?;
        }
        let endpoints_running = source.status == EnvironmentStatus::Running && target.status == EnvironmentStatus::Running;
        let applied = if previous.active && endpoints_running {
            runtime.apply_environment_connection_with_folders(&previous.id, source, target,
                &request.direction, &request.permissions, &ports, &request.selected_folders, request.commands).await.map(Some)
        } else { Ok(None) };
        let rule_id = match applied {
            Ok(rule_id) => rule_id,
            Err(error) => {
                if previous_running {
                    let old_source = state.environments.iter().find(|environment| environment.id == previous.source_id).unwrap();
                    let old_target = state.environments.iter().find(|environment| environment.id == previous.target_id).unwrap();
                    let old_ports = previous.ports.iter().filter_map(|port| port.parse::<u16>().ok()).collect::<Vec<_>>();
                    if let Err(rollback) = runtime.apply_environment_connection_with_folders(&previous.id, old_source, old_target,
                        &previous.direction, &previous.permissions, &old_ports, &previous.selected_folders, previous.commands).await {
                        let _ = store.mutate(|state| {
                            if let Some(connection) = state.connections.iter_mut().find(|connection| connection.id == previous.id) {
                                connection.enforcement_status = Some(EnforcementStatus::Error);
                                connection.last_error = Some(format!("Updating this connection failed: {error}; restoring it failed: {rollback}"));
                            }
                            Ok(())
                        });
                        return Err(format!("Updating this connection failed: {error}; restoring it failed: {rollback}"));
                    }
                }
                return Err(error);
            }
        };
        let persisted = store.mutate(|state| {
            let connection = state.connections.iter_mut().find(|connection| connection.id == previous.id)
                .ok_or("Connection was removed while editing")?;
            connection.source_id = request.source_id.clone();
            connection.target_id = request.target_id.clone();
            connection.direction = request.direction.clone();
            connection.permissions = request.permissions.clone();
            connection.ports = request.ports.clone();
            connection.commands = request.commands;
            connection.selected_folders = request.selected_folders.clone();
            connection.ssh_port = request.ssh_port;
            connection.volume = request.volume.clone().filter(|value| !value.trim().is_empty());
            connection.enforcement_status = Some(if rule_id.is_some() { EnforcementStatus::Enforced } else { EnforcementStatus::Pending });
            connection.provider_rule_ids = rule_id.into_iter().collect();
            connection.last_error = None;
            if let Some((remote_id, fabric_id)) = &remote_fabric_id {
                if let Some(remote) = state.environments.iter_mut().find(|environment| &environment.id == remote_id) {
                    remote.runtime_id = Some(fabric_id.clone());
                }
            }
            Ok(())
        });
        if let Err(error) = persisted {
            let mut rollback_errors = Vec::new();
            if previous.active && endpoints_running {
                if let Err(rollback) = runtime.remove_environment_connection(&previous.id,
                    connection_runtime_id(&state, &request.source_id), connection_runtime_id(&state, &request.target_id),
                    container_connection(&state, &request.source_id, &request.target_id)).await {
                    rollback_errors.push(rollback);
                }
            }
            if previous_running {
                let old_source = state.environments.iter().find(|environment| environment.id == previous.source_id).unwrap();
                let old_target = state.environments.iter().find(|environment| environment.id == previous.target_id).unwrap();
                let old_ports = previous.ports.iter().filter_map(|port| port.parse::<u16>().ok()).collect::<Vec<_>>();
                if let Err(rollback) = runtime.apply_environment_connection_with_folders(&previous.id, old_source, old_target,
                    &previous.direction, &previous.permissions, &old_ports, &previous.selected_folders, previous.commands).await {
                    rollback_errors.push(rollback);
                }
            }
            if !rollback_errors.is_empty() {
                let message = format!("Saving this connection failed: {error}; restoring it failed: {}", rollback_errors.join("; "));
                let _ = store.mutate(|state| {
                    if let Some(connection) = state.connections.iter_mut().find(|connection| connection.id == previous.id) {
                        connection.enforcement_status = Some(EnforcementStatus::Error);
                        connection.last_error = Some(message.clone());
                    }
                    Ok(())
                });
                return Err(message);
            }
            return Err(error);
        }
        return persisted;
    }
    let id = format!("conn-{}", Uuid::new_v4());
    let endpoints_running =
        source.status == EnvironmentStatus::Running && target.status == EnvironmentStatus::Running;
    let rule_id = if endpoints_running {
        Some(
            runtime
                .apply_environment_connection_with_folders(
                    &id,
                    source,
                    target,
                    &request.direction,
                    &request.permissions,
                    &ports,
                    &request.selected_folders,
                    request.commands,
                )
                .await?,
        )
    } else {
        None
    };
    let has_rule = rule_id.is_some();
    let persisted = store.mutate(|state| {
        if ![&request.source_id, &request.target_id].iter().all(|id| state.environments.iter().any(|e| &e.id == *id)) {
            return Err("A selected environment was deleted while connecting".into());
        }
        state.connections.push(Connection {
            id: id.clone(),
            source_id: request.source_id.clone(),
            target_id: request.target_id.clone(),
            direction: request.direction.clone(),
            permissions: request.permissions.clone(),
            ports: request.ports.clone(),
            commands: request.commands,
            selected_folders: request.selected_folders.clone(),
            ssh_port: request.ssh_port,
            volume: request
                .volume
                .clone()
                .filter(|value| !value.trim().is_empty()),
            active: true,
            created_at: now(),
            enforcement_status: Some(if rule_id.is_some() {
                EnforcementStatus::Enforced
            } else {
                EnforcementStatus::Pending
            }),
            provider_rule_ids: rule_id.into_iter().collect(),
            last_error: None,
        });
        if let Some((remote_id, fabric_id)) = &remote_fabric_id {
            if let Some(remote) = state.environments.iter_mut().find(|environment| &environment.id == remote_id) {
                remote.runtime_id = Some(fabric_id.clone());
            }
        }
        Ok(())
    });
    if persisted.is_err() && has_rule {
        let _ = runtime
            .remove_environment_connection(&id, connection_runtime_id(&state, &request.source_id), connection_runtime_id(&state, &request.target_id), container_connection(&state, &request.source_id, &request.target_id))
            .await;
    }
    persisted
}

#[tauri::command]
pub async fn set_connection_active(
    connection_id: String,
    active: bool,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
) -> Result<PlatformState, String> {
    let _serial = connection_operations().lock().await;
    let state = store.snapshot()?;
    let connection = state
        .connections
        .iter()
        .find(|item| item.id == connection_id)
        .cloned()
        .ok_or("Connection not found")?;
    if !active {
        runtime
            .remove_environment_connection(
                &connection.id,
                connection_runtime_id(&state, &connection.source_id),
                connection_runtime_id(&state, &connection.target_id),
                container_connection(&state, &connection.source_id, &connection.target_id),
            )
            .await?;
    }
    let persisted = store.mutate(|state| {
        let connection = state
            .connections
            .iter_mut()
            .find(|item| item.id == connection_id)
            .ok_or("Connection not found")?;
        connection.active = active;
        connection.enforcement_status = Some(EnforcementStatus::Pending);
        connection.provider_rule_ids.clear();
        connection.last_error = None;
        Ok(())
    });
    if let Err(error) = persisted {
        if !active {
            let rollback = reconcile_connections_locked(&store, &runtime).await;
            return Err(match rollback {
                Ok(()) => error,
                Err(rollback) => {
                    format!("{error}; restoring the removed connection rule failed: {rollback}")
                }
            });
        }
        return Err(error);
    }
    if active {
        reconcile_connections_locked(&store, &runtime).await?;
    }
    store.snapshot()
}

#[tauri::command]
pub async fn delete_connection(
    connection_id: String,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
) -> Result<PlatformState, String> {
    let _serial = connection_operations().lock().await;
    let state = store.snapshot()?;
    let connection = state
        .connections
        .iter()
        .find(|item| item.id == connection_id)
        .ok_or("Connection not found")?;
    runtime
        .remove_environment_connection(&connection.id, connection_runtime_id(&state, &connection.source_id), connection_runtime_id(&state, &connection.target_id), container_connection(&state, &connection.source_id, &connection.target_id))
        .await?;
    let persisted = store.mutate(|state| {
        state.connections.retain(|item| item.id != connection_id);
        Ok(())
    });
    if let Err(error) = persisted {
        let rollback = reconcile_connections_locked(&store, &runtime).await;
        return Err(match rollback {
            Ok(()) => error,
            Err(rollback) => {
                format!("{error}; restoring the removed connection rule failed: {rollback}")
            }
        });
    }
    persisted
}

fn snapshot_environment_state(
    environment: &Environment,
    provider: Option<RuntimeProviderKind>,
) -> SnapshotEnvironmentState {
    SnapshotEnvironmentState {
        runtime: environment.runtime.clone(),
        provider,
        runtime_path: environment.runtime_path.clone(),
        container_command: environment.container_command.clone(),
        network_access: environment.network_access,
        gpu_access: environment.gpu_access,
        description: environment.description.clone(),
        branch_type: environment.branch_type.clone(),
        resource_policy: environment.resource_policy.clone(),
        sandbox_policy: environment.sandbox_policy.clone(),
    }
}

#[tauri::command]
pub async fn create_snapshot(
    environment_id: String,
    name: String,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
    backup: State<'_, BackupManager>,
) -> Result<PlatformState, String> {
    let lock = environment_network_lock(&environment_id).await;
    let _guard = lock.lock().await;
    let snapshot_name = name.trim();
    if snapshot_name.is_empty() || snapshot_name.len() > 100 {
        return Err("Snapshot name must be between 1 and 100 characters".into());
    }
    let state = store.snapshot()?;
    factory_reset::ensure_complete(&state, &environment_id)?;
    let environment = state
        .environments
        .iter()
        .find(|item| item.id == environment_id)
        .cloned()
        .ok_or("Environment not found")?;
    let id = format!("snap-{}", Uuid::new_v4());
    let (provider_snapshot_id, artifact_path, size_bytes, checksum) = match provider(&environment) {
        RuntimeProviderKind::CloudSsh => return Err("Cloud nodes do not have local snapshots".into()),
        RuntimeProviderKind::YougoriOci | RuntimeProviderKind::YougoriCuda => {
            let artifact = runtime
                .create_container_snapshot(
                    runtime_id(&environment),
                    &id,
                    &environment.runtime,
                    environment.container_command.as_deref().unwrap_or_default(),
                )
                .await?;
            (
                Some(artifact.provider_snapshot_id),
                Some(artifact.path.to_string_lossy().into_owned()),
                artifact.size_bytes,
                Some(artifact.checksum_sha256),
            )
        }
        RuntimeProviderKind::Qemu => {
            if runtime.vm_security_enabled(runtime_id(&environment))? {
                // A TPM snapshot must carry identity + firmware with the disk.
                // Export enforces a stopped VM; restore uses the existing
                // artifact transaction path rather than disk-only loadvm.
                let artifact = runtime.export_vm_disk(runtime_id(&environment), &vm_disk(&environment)?, std::path::Path::new(&environment.runtime), &id).await?;
                (None, Some(artifact.path.to_string_lossy().into_owned()), artifact.size_bytes, Some(artifact.checksum_sha256))
            } else {
                let size = runtime
                    .create_vm_snapshot(runtime_id(&environment), &vm_disk(&environment)?, &id)
                    .await?;
                (Some(id.clone()), None, size, None)
            }
        }
        RuntimeProviderKind::NativeSandbox => {
            return Err("Snapshots for native application sandboxes are not available yet".into());
        }
    };
    let connections = state
        .connections
        .iter()
        .filter(|item| item.source_id == environment_id || item.target_id == environment_id)
        .cloned()
        .collect();
    let snapshot = Snapshot {
        id,
        environment_id: environment_id.clone(),
        name: snapshot_name.into(),
        created_at: now(),
        size_gb: size_bytes as f64 / 1_073_741_824.0,
        delta_gb: size_bytes as f64 / 1_073_741_824.0,
        encrypted: false,
        status: SnapshotStatus::Ready,
        provider_snapshot_id,
        artifact_path,
        artifact_size_bytes: Some(size_bytes),
        checksum_sha256: checksum,
        environment_state: Some(snapshot_environment_state(&environment, Some(provider(&environment)))),
        connections: Some(connections),
    };
    if let Err(error) = store.mutate(|state| {
        state.snapshots.insert(0, snapshot.clone());
        Ok(())
    }) {
        let cleanup = cleanup_snapshot_resources(&snapshot, &state, &runtime, &backup)
            .await
            .err();
        return Err(match cleanup {
            Some(cleanup) => format!("{error}; rollback snapshot: {cleanup}"),
            None => error,
        });
    }
    enforce_snapshot_retention(&store, &runtime, &backup).await
}

#[tauri::command]
pub async fn delete_snapshot(
    snapshot_id: String,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
    backup: State<'_, BackupManager>,
) -> Result<PlatformState, String> {
    let state = store.snapshot()?;
    let snapshot = state
        .snapshots
        .iter()
        .find(|item| item.id == snapshot_id)
        .cloned()
        .ok_or("Snapshot not found")?;
    cleanup_snapshot_resources(&snapshot, &state, &runtime, &backup).await?;
    store.mutate(|state| {
        state.snapshots.retain(|item| item.id != snapshot_id);
        Ok(())
    })
}

#[tauri::command]
pub async fn restore_snapshot(
    snapshot_id: String,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
) -> Result<PlatformState, String> {
    let restore_id = store.snapshot()?.snapshots.iter().find(|snapshot| snapshot.id == snapshot_id)
        .map(|snapshot| snapshot.environment_id.clone()).ok_or("Snapshot not found")?;
    let network_lock = environment_network_lock(&restore_id).await;
    let _network_serial = network_lock.lock().await;
    let state = store.snapshot()?;
    factory_reset::ensure_complete(&state, &restore_id)?;
    let snapshot = state
        .snapshots
        .iter()
        .find(|item| item.id == snapshot_id)
        .cloned()
        .ok_or("Snapshot not found")?;
    let environment = state
        .environments
        .iter()
        .find(|item| item.id == snapshot.environment_id)
        .cloned()
        .ok_or("Environment not found")?;
    let restored_policy = snapshot
        .environment_state
        .as_ref()
        .map(|snapshot| &snapshot.resource_policy)
        .unwrap_or(&environment.resource_policy);
    if provider(&environment).is_container() {
        validate_container_policy_capacity(restored_policy, &state.host)?;
    }
    let restore_runtime_id = runtime_id(&environment).to_owned();
    let mut vm_disk_restore_pending = false;
    match provider(&environment) {
        RuntimeProviderKind::CloudSsh => return Err("Cloud nodes do not have local snapshots".into()),
        RuntimeProviderKind::YougoriOci | RuntimeProviderKind::YougoriCuda => {
            // Exported OCI snapshots are deliberately evicted from the tiny guest
            // after the host has verified them. Re-import on demand before restore.
            runtime.register_snapshot_provider(&snapshot.id, &provider(&environment))?;
            if let Some(artifact_path) = snapshot.artifact_path.as_deref() {
                runtime
                    .import_container_snapshot(&snapshot.id, &PathBuf::from(artifact_path))
                    .await?;
            }
            runtime
                .restore_container_snapshot(
                    runtime_id(&environment),
                    &snapshot.id,
                    &environment.runtime,
                    environment.container_command.as_deref().unwrap_or_default(),
                    snapshot
                        .environment_state
                        .as_ref()
                        .map(|item| item.network_access)
                        .unwrap_or(environment.network_access),
                    snapshot
                        .environment_state
                        .as_ref()
                        .map(|item| item.gpu_access)
                        .unwrap_or(environment.gpu_access),
                )
                .await?;
            runtime
                .update_container_resources(
                    runtime_id(&environment),
                    restored_policy.cpu.preferred,
                    restored_policy.memory_gb.preferred,
                )
                .await?;
        }
        RuntimeProviderKind::Qemu => {
            if snapshot.provider_snapshot_id.is_some() {
                let live_full_vm = environment.kind == EnvironmentKind::FullVm
                    && matches!(environment.status, EnvironmentStatus::Running | EnvironmentStatus::Paused);
                let restored_network = snapshot.environment_state.as_ref().map(|saved| saved.network_access).unwrap_or(environment.network_access);
                if live_full_vm && !restored_network {
                    runtime.update_vm_internet(runtime_id(&environment), false).await?;
                }
                runtime
                    .restore_vm_snapshot(
                        runtime_id(&environment),
                        &vm_disk(&environment)?,
                        &snapshot.id,
                    )
                    .await?;
                if live_full_vm {
                    runtime.update_vm_internet(runtime_id(&environment), restored_network).await?;
                }
            } else if let Some(artifact_path) = snapshot.artifact_path.as_deref() {
                begin_vm_restore_intent(&store, runtime_id(&environment))?;
                if let Err(error) = runtime
                    .install_vm_backup(runtime_id(&environment), &PathBuf::from(artifact_path))
                    .await
                {
                    let clear = clear_vm_restore_intent(&store, runtime_id(&environment)).err();
                    return Err(match clear {
                        Some(clear) => {
                            format!("{error}; clearing the VM restore intent also failed: {clear}")
                        }
                        None => error,
                    });
                }
                vm_disk_restore_pending = true;
            } else {
                return Err("virtual machine snapshot has no restorable provider state".into());
            }
        }
        RuntimeProviderKind::NativeSandbox => {
            return Err("Snapshots for native application sandboxes are not available yet".into());
        }
    }
    let persisted = store.mutate(|state| {
        let environment = state
            .environments
            .iter_mut()
            .find(|item| item.id == snapshot.environment_id)
            .ok_or("Environment not found")?;
        if provider(environment).is_container() {
            environment.status = EnvironmentStatus::Stopped;
            environment.cpu_usage = 0.0;
            environment.memory_usage_gb = 0.0;
        }
        environment.storage_delta_gb = snapshot.delta_gb;
        if let Some(environment_state) = snapshot.environment_state.clone() {
            environment.runtime = environment_state.runtime;
            environment.provider = environment_state.provider;
            environment.runtime_path = environment_state.runtime_path;
            environment.container_command = environment_state.container_command;
            environment.network_access = environment_state.network_access;
            environment.gpu_access = environment_state.gpu_access;
            environment.description = environment_state.description;
            environment.branch_type = environment_state.branch_type;
            environment.resource_policy = environment_state.resource_policy;
            environment.sandbox_policy = environment_state.sandbox_policy;
        }
        if let Some(connections) = snapshot.connections.clone() {
            let environment_ids: HashSet<_> = state
                .environments
                .iter()
                .map(|item| item.id.clone())
                .collect();
            state.connections.retain(|item| {
                item.source_id != snapshot.environment_id
                    && item.target_id != snapshot.environment_id
            });
            state
                .connections
                .extend(connections.into_iter().filter(|item| {
                    environment_ids.contains(&item.source_id)
                        && environment_ids.contains(&item.target_id)
                }));
        }
        if vm_disk_restore_pending {
            state
                .pending_vm_restores
                .retain(|id| id != &restore_runtime_id);
        }
        scheduler::schedule(state);
        Ok(())
    });
    if let Err(error) = persisted {
        if vm_disk_restore_pending {
            let mut errors = vec![error];
            if let Err(rollback) = runtime
                .rollback_vm_backup_install(runtime_id(&environment))
                .await
            {
                errors.push(format!(
                    "restoring the previous VM disk also failed: {rollback}"
                ));
            }
            if let Err(clear) = clear_vm_restore_intent(&store, runtime_id(&environment)) {
                errors.push(format!("clearing the VM restore intent failed: {clear}"));
            }
            return Err(errors.join("; "));
        }
        return Err(error);
    }
    if vm_disk_restore_pending {
        runtime
            .finalize_vm_backup_install(runtime_id(&environment))
            .await?;
    }
    reconcile_connections(&store, &runtime).await?;
    store.snapshot()
}

#[tauri::command]
pub async fn add_backup_destination(
    request: AddDestinationRequest,
    store: State<'_, PlatformStore>,
    backup: State<'_, BackupManager>,
) -> Result<PlatformState, String> {
    let name = request.name.trim();
    if name.is_empty() || name.len() > 80 {
        return Err("Destination name must be between 1 and 80 characters".into());
    }
    if request.location.trim().is_empty() || request.secret_key.trim().is_empty() {
        return Err("Storage URL and provider secret are required".into());
    }
    if request.provider != BackupProvider::GoogleCloud && request.access_key.trim().is_empty() {
        return Err("The selected provider requires an access identifier".into());
    }
    let id = format!("dest-{}", Uuid::new_v4());
    backup.verify_and_store(&id, &request).await?;
    let result = store.mutate(|state| {
        state.destinations.push(BackupDestination {
            id: id.clone(),
            name: name.into(),
            provider: request.provider.clone(),
            location: request.location.trim().into(),
            encrypted: true,
            connected: true,
            last_verified_at: now(),
        });
        Ok(())
    });
    if result.is_err() {
        let _ = backup.delete_credentials(&id);
    }
    result
}

#[tauri::command]
pub fn delete_backup_destination(
    destination_id: String,
    store: State<'_, PlatformStore>,
    backup: State<'_, BackupManager>,
) -> Result<PlatformState, String> {
    if !store
        .snapshot()?
        .destinations
        .iter()
        .any(|item| item.id == destination_id)
    {
        return Err("Backup destination not found".into());
    }
    backup.delete_credentials(&destination_id)?;
    store.mutate(|state| {
        state.destinations.retain(|item| item.id != destination_id);
        state
            .backup_runs
            .retain(|item| item.destination_id != destination_id);
        Ok(())
    })
}

#[tauri::command]
pub async fn run_backup(
    environment_id: String,
    destination_id: String,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
    backup: State<'_, BackupManager>,
) -> Result<PlatformState, String> {
    let lock = environment_network_lock(&environment_id).await;
    let _guard = lock.lock().await;
    let state = store.snapshot()?;
    factory_reset::ensure_complete(&state, &environment_id)?;
    let environment = state
        .environments
        .iter()
        .find(|item| item.id == environment_id)
        .cloned()
        .ok_or("Environment not found")?;
    let destination = state
        .destinations
        .iter()
        .find(|item| item.id == destination_id)
        .cloned()
        .ok_or("Backup destination not found")?;
    if !destination.connected {
        return Err("Backup destination is not connected".into());
    }
    if environment.kind == EnvironmentKind::MicroVm
        && environment.runtime != BUILTIN_MICRO_VM_SOURCE
    {
        return Err(
            "Cloud backup for a custom microVM is unavailable because its kernel and initramfs are external; use a local snapshot or the built-in Alpine profile"
                .into(),
        );
    }
    let snapshot_id = format!("snap-{}", Uuid::new_v4());
    let backup_id = format!("backup-{}", Uuid::new_v4());
    let (provider_snapshot_id, artifact_path, size_bytes, checksum, source_path) = match provider(
        &environment,
    ) {
        RuntimeProviderKind::CloudSsh => return Err("Cloud nodes do not have local disk backups. Use selected shared folders or your provider's backups.".into()),
        RuntimeProviderKind::YougoriOci | RuntimeProviderKind::YougoriCuda => {
            let artifact = runtime
                .create_container_snapshot(
                    runtime_id(&environment),
                    &snapshot_id,
                    &environment.runtime,
                    environment.container_command.as_deref().unwrap_or_default(),
                )
                .await?;
            (
                Some(artifact.provider_snapshot_id),
                Some(artifact.path.to_string_lossy().into_owned()),
                artifact.size_bytes,
                Some(artifact.checksum_sha256),
                artifact.path,
            )
        }
        RuntimeProviderKind::Qemu => {
            let disk = vm_disk(&environment)?;
            let secure = runtime.vm_security_enabled(runtime_id(&environment))?;
            let previous_status = environment.status.clone();
            if matches!(
                previous_status,
                EnvironmentStatus::Running | EnvironmentStatus::Paused
            ) {
                runtime.vm_action(runtime_id(&environment), "stop").await?;
            }
            let export = async {
                if !secure {
                    runtime
                        .create_vm_snapshot(runtime_id(&environment), &disk, &snapshot_id)
                        .await?;
                }
                match runtime
                    .export_vm_disk(
                        runtime_id(&environment),
                        &disk,
                        &PathBuf::from(&environment.runtime),
                        &snapshot_id,
                    )
                    .await
                {
                    Ok(artifact) => Ok(artifact),
                    Err(error) => {
                        if !secure {
                            let _ = runtime
                                .delete_vm_snapshot(runtime_id(&environment), &disk, &snapshot_id)
                                .await;
                        }
                        Err(error)
                    }
                }
            }
            .await;
            let restart =
                restart_vm_after_maintenance(&runtime, &environment, &previous_status).await;
            let artifact = match (export, restart) {
                (Ok(artifact), Ok(())) => artifact,
                (Err(error), Ok(())) => return Err(error),
                (Ok(artifact), Err(restart_error)) => {
                    let _ = runtime.remove_snapshot_artifact(&artifact.path).await;
                    if !secure {
                        let _ = runtime
                            .delete_vm_snapshot(runtime_id(&environment), &disk, &snapshot_id)
                            .await;
                    }
                    let _ = store.mutate(|state| {
                        if let Some(item) = state
                            .environments
                            .iter_mut()
                            .find(|item| item.id == environment_id)
                        {
                            item.status = EnvironmentStatus::Error;
                            item.last_error = Some(restart_error.clone());
                        }
                        Ok(())
                    });
                    return Err(format!(
                            "the backup was prepared, but the virtual machine could not be restarted: {restart_error}"
                        ));
                }
                (Err(export_error), Err(restart_error)) => {
                    let _ = store.mutate(|state| {
                        if let Some(item) = state
                            .environments
                            .iter_mut()
                            .find(|item| item.id == environment_id)
                        {
                            item.status = EnvironmentStatus::Error;
                            item.last_error = Some(restart_error.clone());
                        }
                        Ok(())
                    });
                    return Err(format!(
                            "{export_error}; the virtual machine also failed to restart: {restart_error}"
                        ));
                }
            };
            (
                (!secure).then(|| snapshot_id.clone()),
                Some(artifact.path.to_string_lossy().into_owned()),
                artifact.size_bytes,
                Some(artifact.checksum_sha256),
                artifact.path,
            )
        }
        RuntimeProviderKind::NativeSandbox => {
            return Err("Backups for native application sandboxes are not available yet".into());
        }
    };
    let connections = state
        .connections
        .iter()
        .filter(|item| item.source_id == environment_id || item.target_id == environment_id)
        .cloned()
        .collect::<Vec<_>>();
    let snapshot = Snapshot {
        id: snapshot_id,
        environment_id: environment_id.clone(),
        name: format!("Backup · {}", Utc::now().format("%b %-d, %H:%M")),
        created_at: now(),
        size_gb: size_bytes as f64 / 1_073_741_824.0,
        delta_gb: size_bytes as f64 / 1_073_741_824.0,
        encrypted: false,
        status: SnapshotStatus::Ready,
        provider_snapshot_id,
        artifact_path,
        artifact_size_bytes: Some(size_bytes),
        checksum_sha256: checksum,
        environment_state: Some(snapshot_environment_state(&environment, Some(provider(&environment)))),
        connections: Some(connections.clone()),
    };
    let started_at = now();
    if let Err(error) = store.mutate(|state| {
        state.snapshots.insert(0, snapshot.clone());
        state.backup_runs.insert(
            0,
            BackupRun {
                id: backup_id.clone(),
                environment_id: environment_id.clone(),
                destination_id: destination_id.clone(),
                created_at: started_at,
                completed_at: None,
                transferred_gb: 0.0,
                deduplicated_gb: 0.0,
                status: BackupRunStatus::Running,
                remote_object: None,
                checksum_sha256: None,
                last_error: None,
            },
        );
        state.backup_runs.truncate(MAX_BACKUP_HISTORY);
        Ok(())
    }) {
        let cleanup = cleanup_snapshot_resources(&snapshot, &state, &runtime, &backup)
            .await
            .err();
        return Err(match cleanup {
            Some(cleanup) => format!("{error}; rollback backup snapshot: {cleanup}"),
            None => error,
        });
    }
    let upload = backup
        .upload(
            &destination,
            &backup_id,
            &snapshot,
            &environment,
            &connections,
            state.settings.bandwidth_limit_mbps,
            &source_path,
        )
        .await;
    let upload_result = match upload {
        Ok(upload) => store
            .mutate(|state| {
                let run = state
                    .backup_runs
                    .iter_mut()
                    .find(|item| item.id == backup_id)
                    .ok_or("Backup history entry disappeared")?;
                run.completed_at = Some(now());
                run.transferred_gb = upload.transferred_bytes as f64 / 1_073_741_824.0;
                run.deduplicated_gb = upload.deduplicated_bytes as f64 / 1_073_741_824.0;
                run.status = BackupRunStatus::Complete;
                run.remote_object = Some(upload.remote_object);
                run.checksum_sha256 = Some(upload.checksum_sha256);
                run.last_error = None;
                Ok(())
            })
            .map(|_| ()),
        Err(error) => {
            let persisted = store.mutate(|state| {
                if let Some(run) = state
                    .backup_runs
                    .iter_mut()
                    .find(|item| item.id == backup_id)
                {
                    run.completed_at = Some(now());
                    run.status = BackupRunStatus::Failed;
                    run.last_error = Some(error.clone());
                }
                Ok(())
            });
            Err(match persisted {
                Ok(_) => error,
                Err(persist_error) => {
                    format!("{error}; recording the failed backup also failed: {persist_error}")
                }
            })
        }
    };
    let retention = enforce_snapshot_retention(&store, &runtime, &backup).await;
    match (upload_result, retention) {
        (Ok(()), Ok(state)) => Ok(state),
        (Err(error), Ok(_)) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(retention_error)) => Err(format!(
            "{error}; snapshot retention also failed: {retention_error}"
        )),
    }
}

#[tauri::command]
pub async fn restore_backup(
    backup_id: String,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
    backup: State<'_, BackupManager>,
) -> Result<PlatformState, String> {
    let state = store.snapshot()?;
    let run = state
        .backup_runs
        .iter()
        .find(|item| item.id == backup_id)
        .cloned()
        .ok_or("Backup history entry not found")?;
    if run.status != BackupRunStatus::Complete {
        return Err("Only a completed backup can be restored".into());
    }
    let destination = state
        .destinations
        .iter()
        .find(|item| item.id == run.destination_id)
        .cloned()
        .ok_or("The backup destination is no longer connected")?;
    let remote_object = run
        .remote_object
        .as_deref()
        .ok_or("Backup history is missing its remote manifest path")?;
    let manifest_checksum = run
        .checksum_sha256
        .as_deref()
        .ok_or("Backup history is missing its manifest checksum")?;
    let restored = backup
        .download(&destination, &run.id, remote_object, manifest_checksum)
        .await?;
    if restored.environment.id != run.environment_id
        || restored.snapshot.environment_id != run.environment_id
    {
        let _ = backup
            .delete_restore_artifact(&restored.artifact_path)
            .await;
        return Err("backup manifest environment does not match backup history".into());
    }
    install_restored_backup(restored, &store, &runtime, &backup).await
}

pub(crate) async fn install_restored_backup(
    restored: crate::backup::BackupRestore,
    store: &PlatformStore,
    runtime: &RuntimeManager,
    backup: &BackupManager,
) -> Result<PlatformState, String> {
    let lock = environment_network_lock(&restored.environment.id).await;
    let _guard = lock.lock().await;
    let state = store.snapshot()?;
    let target_id = restored.environment.id.clone();
    if let Err(error) = factory_reset::ensure_complete(&state, &target_id) {
        let _ = backup.delete_restore_artifact(&restored.artifact_path).await;
        return Err(error);
    }
    if restored.environment.kind == EnvironmentKind::MicroVm
        && restored.environment.runtime != BUILTIN_MICRO_VM_SOURCE
    {
        let _ = backup
            .delete_restore_artifact(&restored.artifact_path)
            .await;
        return Err(
            "This custom microVM backup does not contain its external kernel and initramfs and cannot be restored safely"
                .into(),
        );
    }
    let restored_provider = provider(&restored.environment);
    if restored_provider.is_container() {
        if let Err(error) =
            validate_container_policy_capacity(&restored.environment.resource_policy, &state.host)
        {
            let _ = backup
                .delete_restore_artifact(&restored.artifact_path)
                .await;
            return Err(error);
        }
    }
    if let Some(existing) = state
        .environments
        .iter()
        .find(|item| item.id == target_id)
    {
        if provider(existing) != restored_provider {
            let _ = backup
                .delete_restore_artifact(&restored.artifact_path)
                .await;
            return Err("the existing environment uses a different runtime provider".into());
        }
        if matches!(
            existing.status,
            EnvironmentStatus::Running | EnvironmentStatus::Paused
        ) {
            let stop_result = match restored_provider {
                RuntimeProviderKind::CloudSsh => return Err("Cloud nodes cannot be restored from a local VM backup".into()),
                RuntimeProviderKind::YougoriOci | RuntimeProviderKind::YougoriCuda => {
                    runtime
                        .container_action(runtime_id(existing), "stop", existing.network_access)
                        .await
                }
                RuntimeProviderKind::Qemu => runtime.vm_action(runtime_id(existing), "stop").await,
                RuntimeProviderKind::NativeSandbox => {
                    runtime.stop_native_sandbox(runtime_id(existing)).await
                }
            };
            if let Err(error) = stop_result {
                if !error.contains("not running") {
                    let _ = backup
                        .delete_restore_artifact(&restored.artifact_path)
                        .await;
                    return Err(format!("stop environment before restore: {error}"));
                }
            }
        }
    }
    for connection in state
        .connections
        .iter()
        .filter(|item| item.source_id == target_id || item.target_id == target_id)
    {
        let _ = runtime
            .remove_environment_connection(
                &connection.id,
                connection_runtime_id(&state, &connection.source_id),
                connection_runtime_id(&state, &connection.target_id),
                container_connection(&state, &connection.source_id, &connection.target_id),
            )
            .await;
    }

    let mut environment = restored.environment;
    environment.status = EnvironmentStatus::Stopped;
    environment.runtime_id = Some(environment.id.clone());
    environment.control_endpoint = None;
    environment.console_endpoint = None;
    environment.last_error = None;
    environment.cpu_usage = 0.0;
    environment.memory_usage_gb = 0.0;
    environment.network_rx_mbps = 0.0;
    environment.resource_policy.cpu.current = 0.0;
    environment.resource_policy.memory_gb.current = 0.0;

    let mut vm_backup_install_pending = false;
    let (provider_snapshot_id, artifact_path, artifact_size, checksum) = match restored_provider {
        RuntimeProviderKind::CloudSsh => return Err("Cloud nodes cannot be restored from a local VM backup".into()),
        RuntimeProviderKind::YougoriOci | RuntimeProviderKind::YougoriCuda => {
            runtime.register_container_provider(&environment.id, &restored_provider)?;
            runtime.register_snapshot_provider(&restored.snapshot.id, &restored_provider)?;
            let imported = runtime
                .import_container_snapshot(&restored.snapshot.id, &restored.artifact_path)
                .await?;
            runtime
                .restore_container_snapshot(
                    &environment.id,
                    &restored.snapshot.id,
                    &environment.runtime,
                    environment.container_command.as_deref().unwrap_or_default(),
                    environment.network_access,
                    environment.gpu_access,
                )
                .await?;
            runtime
                .update_container_resources(
                    &environment.id,
                    environment.resource_policy.cpu.preferred,
                    environment.resource_policy.memory_gb.preferred,
                )
                .await?;
            let _ = backup
                .delete_restore_artifact(&restored.artifact_path)
                .await;
            (
                Some(imported.provider_snapshot_id),
                imported.path,
                imported.size_bytes,
                Some(imported.checksum_sha256),
            )
        }
        RuntimeProviderKind::Qemu => {
            begin_vm_restore_intent(&store, &environment.id)?;
            let disk_path = match runtime
                .install_vm_backup(&environment.id, &restored.artifact_path)
                .await
            {
                Ok(path) => path,
                Err(error) => {
                    let clear = clear_vm_restore_intent(&store, &environment.id).err();
                    let cleanup = backup
                        .delete_restore_artifact(&restored.artifact_path)
                        .await
                        .err();
                    return Err([Some(error), clear, cleanup]
                        .into_iter()
                        .flatten()
                        .collect::<Vec<_>>()
                        .join("; "));
                }
            };
            vm_backup_install_pending = true;
            let setup = async {
                if environment.kind == EnvironmentKind::ComputerBranch {
                    runtime.ensure_computer_branch_boot(&environment.id).await?;
                }
                environment.runtime_path = Some(disk_path.to_string_lossy().into_owned());
                if environment.kind == EnvironmentKind::MicroVm {
                    runtime
                        .restore_builtin_micro_vm_manifest(&environment.id)
                        .await?;
                    environment.runtime = BUILTIN_MICRO_VM_SOURCE.into();
                } else {
                    // A full-VM cloud artifact is a standalone disk. Boot it directly so a
                    // removed installation ISO or original backing disk is not needed.
                    environment.runtime = disk_path.to_string_lossy().into_owned();
                }
                let metadata =
                    tokio::fs::metadata(&restored.artifact_path)
                        .await
                        .map_err(|error| {
                            format!("inspect restored virtual machine artifact: {error}")
                        })?;
                Ok::<_, String>((
                    None,
                    restored.artifact_path.clone(),
                    metadata.len(),
                    restored.snapshot.checksum_sha256.clone(),
                ))
            }
            .await;
            match setup {
                Ok(result) => result,
                Err(error) => {
                    let rollback = runtime
                        .rollback_vm_backup_install(&environment.id)
                        .await
                        .err();
                    let cleanup = backup
                        .delete_restore_artifact(&restored.artifact_path)
                        .await
                        .err();
                    let clear = clear_vm_restore_intent(&store, &environment.id).err();
                    return Err([Some(error), rollback, cleanup, clear]
                        .into_iter()
                        .flatten()
                        .collect::<Vec<_>>()
                        .join("; "));
                }
            }
        }
        RuntimeProviderKind::NativeSandbox => {
            let _ = backup
                .delete_restore_artifact(&restored.artifact_path)
                .await;
            return Err("Restoring native application sandbox backups is not available yet".into());
        }
    };
    environment.storage_delta_gb = artifact_size as f64 / 1_073_741_824.0;

    let mut snapshot = restored.snapshot;
    snapshot.environment_id = environment.id.clone();
    snapshot.status = SnapshotStatus::Ready;
    snapshot.encrypted = false;
    snapshot.provider_snapshot_id = provider_snapshot_id;
    snapshot.artifact_path = Some(artifact_path.to_string_lossy().into_owned());
    snapshot.artifact_size_bytes = Some(artifact_size);
    snapshot.checksum_sha256 = checksum;
    snapshot.environment_state = Some(snapshot_environment_state(&environment, environment.provider.clone()));

    let environment_id = environment.id.clone();
    let snapshot_id = snapshot.id.clone();
    let restored_connections = restored.connections;
    let persisted = store.mutate(|state| {
        if state.environments.iter().any(|item| {
            item.id != environment_id && item.name.eq_ignore_ascii_case(&environment.name)
        }) {
            environment.name = format!("{} (restored)", environment.name);
        }
        if let Some(existing) = state
            .environments
            .iter_mut()
            .find(|item| item.id == environment_id)
        {
            *existing = environment.clone();
        } else {
            state.environments.insert(0, environment.clone());
        }
        state.snapshots.retain(|item| item.id != snapshot_id);
        state.snapshots.insert(0, snapshot.clone());
        state
            .connections
            .retain(|item| item.source_id != environment_id && item.target_id != environment_id);
        let environment_ids = state
            .environments
            .iter()
            .map(|item| item.id.clone())
            .collect::<HashSet<_>>();
        for mut connection in restored_connections.clone() {
            if environment_ids.contains(&connection.source_id)
                && environment_ids.contains(&connection.target_id)
            {
                connection.enforcement_status = Some(EnforcementStatus::Pending);
                connection.provider_rule_ids.clear();
                connection.last_error = None;
                state.connections.push(connection);
            }
        }
        if vm_backup_install_pending {
            state.pending_vm_restores.retain(|id| id != &environment_id);
        }
        scheduler::schedule(state);
        Ok(())
    });
    if let Err(error) = persisted {
        let mut errors = vec![error];
        if vm_backup_install_pending {
            if let Err(error) = runtime.rollback_vm_backup_install(&environment_id).await {
                errors.push(format!(
                    "restoring the previous VM disk also failed: {error}"
                ));
            }
            if let Err(error) = clear_vm_restore_intent(&store, &environment_id) {
                errors.push(format!("clearing the VM restore intent failed: {error}"));
            }
        } else if restored_provider.is_container() {
            if let Ok(current) = store.snapshot() {
                if let Err(error) =
                    cleanup_snapshot_resources(&snapshot, &current, &runtime, &backup).await
                {
                    errors.push(format!("rollback restored container snapshot: {error}"));
                }
            }
        }
        if let Err(error) = backup
            .delete_restore_artifact(&restored.artifact_path)
            .await
        {
            errors.push(error);
        }
        return Err(errors.join("; "));
    }
    if vm_backup_install_pending {
        runtime.finalize_vm_backup_install(&environment_id).await?;
    }
    reconcile_connections(&store, &runtime).await?;
    enforce_snapshot_retention(&store, &runtime, &backup).await
}

#[tauri::command]
pub async fn update_settings(
    settings: AppSettings,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
    backup: State<'_, BackupManager>,
) -> Result<PlatformState, String> {
    let revision = store.snapshot()?.settings_revision;
    let saved = crate::lifecycle::save_settings(settings, revision, &store).await?;
    // The settings commit succeeded even if subsequent snapshot cleanup fails.
    // Do not invite clients to repeat a completed update as a failed mutation.
    if let Err(error) = enforce_snapshot_retention(&store, &runtime, &backup).await {
        eprintln!("Settings saved; snapshot retention cleanup needs attention: {}", crate::lifecycle::safe_diagnostic(&error));
    }
    Ok(saved)
}

pub(crate) fn collect_host_metrics(previous: &HostMetrics, runtime_root: &std::path::Path) -> HostMetrics {
    let sampler = HOST_SAMPLER.get_or_init(|| Mutex::new(HostSampler::new()));
    let mut sampler = sampler
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let gpu_usage_percent = sampler.refresh();
    let runtime_disk = crate::runtime::storage::runtime_disk(&sampler.disks, runtime_root);
    let (total_storage, available_storage, storage_drive) = runtime_disk
        .map(|disk| (disk.total_space(), disk.available_space(), Some(disk.mount_point().display().to_string())))
        .unwrap_or((0, 0, None));
    let used_cpu = f64::from(sampler.system.global_cpu_usage());
    let total_memory = sampler.system.total_memory() as f64 / 1_073_741_824.0;
    let used_memory = sampler.system.used_memory() as f64 / 1_073_741_824.0;
    let memory_percent = if total_memory > 0.0 {
        used_memory / total_memory * 100.0
    } else {
        0.0
    };
    let mut cpu_history = previous
        .cpu_history
        .iter()
        .copied()
        .rev()
        .take(11)
        .collect::<Vec<_>>();
    cpu_history.reverse();
    cpu_history.push(used_cpu);
    let mut gpu_history = previous
        .gpu_history
        .iter()
        .copied()
        .rev()
        .take(11)
        .collect::<Vec<_>>();
    gpu_history.reverse();
    if let Some(gpu_usage) = gpu_usage_percent {
        gpu_history.push(gpu_usage);
    }
    let mut memory_history = previous
        .memory_history
        .iter()
        .copied()
        .rev()
        .take(11)
        .collect::<Vec<_>>();
    memory_history.reverse();
    memory_history.push(memory_percent);
    HostMetrics {
        hostname: if sampler.hostname.is_empty() {
            previous.hostname.clone()
        } else {
            sampler.hostname.clone()
        },
        os: if sampler.os.is_empty() {
            previous.os.clone()
        } else {
            sampler.os.clone()
        },
        cpu_model: if sampler.cpu_model.is_empty() {
            previous.cpu_model.clone()
        } else {
            sampler.cpu_model.clone()
        },
        total_cpu: sampler.system.cpus().len().max(1),
        used_cpu_percent: used_cpu,
        gpu_usage_percent,
        total_memory_gb: total_memory,
        used_memory_gb: used_memory,
        total_storage_gb: total_storage as f64 / 1_073_741_824.0,
        used_storage_gb: total_storage.saturating_sub(available_storage) as f64 / 1_073_741_824.0,
        storage_drive,
        storage_drives: crate::runtime::storage::host_drives(&sampler.disks),
        storage_saved_gb: previous.storage_saved_gb,
        pressure: scheduler::pressure(used_cpu, memory_percent),
        cpu_history,
        gpu_history,
        memory_history,
        updated_at: now(),
    }
}

#[tauri::command]
pub async fn refresh_host_metrics(
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
) -> Result<PlatformState, String> {
    let mut lost_cloud = Vec::new();
    for environment in store.snapshot()?.environments.iter().filter(|e|e.kind==EnvironmentKind::Cloud && !crate::peer_sharing::is_shared(e) && e.status==EnvironmentStatus::Running) {
        if !runtime.cloud.connected(&environment.id).await { lost_cloud.push(environment.id.clone()); }
    }
    if !lost_cloud.is_empty() {
        store.mutate_ephemeral(|state| {for e in &mut state.environments {if lost_cloud.contains(&e.id) {e.status=EnvironmentStatus::Error;e.last_error=Some("SSH connection was interrupted. Retry Connect. The cloud server was not stopped.".into());}} Ok(())})?;
        reconcile_connections(&store,&runtime).await?;
    }
    // Compute and apply one container allocation at a time. Otherwise a
    // telemetry request holding an older policy can undo a concurrent Save.
    let cuda_capacity = runtime.cuda_capacity().await.ok();
    let state = store.mutate_ephemeral(|state| {
        let metrics = collect_host_metrics(&state.host, runtime.storage_root());
        scheduler::update_metrics(state, metrics);
        if let Some((cpus, memory)) = cuda_capacity { scheduler::limit_cuda_pool(state, cpus, memory)?; }
        Ok(())
    })?;
    let running_containers = state
        .environments
        .iter()
        .filter(|environment| {
            environment.status == EnvironmentStatus::Running
                && provider(environment).is_container()
        })
        .collect::<Vec<_>>();
    // Failure of a provider or missing secondary drive is confined to its own
    // pool. Read-only samples do not hold lifecycle/configuration locks.
    let mut pools: std::collections::BTreeMap<String, Vec<String>> = std::collections::BTreeMap::new();
    let mut telemetry_by_id = HashMap::new();
    for environment in &running_containers {
        let id = runtime_id(environment).to_owned();
        match runtime.environment_storage_root(&id) {
            Ok(root) => { pools.entry(format!("{}:{:?}", root.display(), provider(environment))).or_default().push(id); }
            Err(error) => { telemetry_by_id.insert(id, Err(error)); }
        }
    }
    let samples = futures_util::future::join_all(pools.into_values().map(|ids| {
        let runtime = &runtime;
        async move { let sample = runtime.container_telemetry(&ids).await; (ids, sample) }
    })).await;
    for (ids, sample) in samples {
        match sample {
            Ok(entries) => { for entry in entries { telemetry_by_id.insert(entry.id.clone(), Ok(entry)); } }
            Err(error) => { for id in ids { telemetry_by_id.insert(id, Err(error.clone())); } }
        }
    }
    struct ContainerRefresh {
        id: String,
        last_opened_at: Option<String>,
        exited: bool,
        clean_exit: bool,
        last_error: Option<Option<String>>,
        stats: Option<(f64, f64, f64)>,
    }
    let mut container_refreshes = Vec::with_capacity(running_containers.len());
    for environment in running_containers {
        let root = match runtime.environment_storage_root(runtime_id(environment)) {
            Ok(root) => root,
            Err(error) => {
                container_refreshes.push(ContainerRefresh { id: environment.id.clone(), last_opened_at: environment.last_opened_at.clone(), exited:false, clean_exit:false, last_error:Some(Some(error)), stats:None });
                continue;
            }
        };
        let lock = container_policy_lock(&root, &provider(environment)).await;
        // Background telemetry never queues ahead of lifecycle/configuration.
        let Ok(_pool_guard) = lock.try_lock_owned() else { continue; };
        let Some(current) = store.snapshot()?.environments.into_iter().find(|current| current.id == environment.id && current.status == EnvironmentStatus::Running && current.last_opened_at == environment.last_opened_at) else { continue; };
        let environment = &current;
        let mut refresh = ContainerRefresh {
            id: environment.id.clone(),
            last_opened_at: environment.last_opened_at.clone(),
            exited: false,
            clean_exit: false,
            last_error: None,
            stats: None,
        };
        let telemetry = match telemetry_by_id.get(runtime_id(environment)) {
            Some(Ok(telemetry)) => telemetry,
            Some(Err(error)) => {
                refresh.last_error = Some(Some(error.clone()));
                container_refreshes.push(refresh);
                continue;
            },
            None => {
                refresh.last_error = Some(Some("The container runtime omitted this environment from its pool telemetry".into()));
                container_refreshes.push(refresh);
                continue;
            },
        };
        if telemetry.paused {
            // Snapshot pauses are temporary. Keep the node healthy and avoid
            // changing resource limits until its processes resume.
            continue;
        }
        if !telemetry.running {
            match runtime.container_exit_detail(runtime_id(environment)).await {
                Ok(None) => continue, // The sample caught a pause or a restart.
                Ok(Some((success,message))) => {
                    refresh.exited = true;
                    refresh.clean_exit = success;
                    refresh.last_error = Some(if success{None}else{Some(message)});
                }
                Err(error) => refresh.last_error = Some(Some(error)),
            }
            container_refreshes.push(refresh);
            continue;
        }
        if environment.resource_policy.dynamic
            && resource_update_needed(
                runtime_id(environment),
                environment.resource_policy.cpu.current,
                environment.resource_policy.memory_gb.current,
            )
        {
            let Ok(_resource_claim) = resource_admission::reserve_update(&store, environment) else { continue; };
            let result = apply_scheduled_resource_limits(&runtime, environment).await;
            refresh.last_error = Some(result.err());
        }
        refresh.stats = Some((
            telemetry.stats.cpu_percent,
            telemetry.stats.memory_bytes as f64 / 1_073_741_824.0,
            telemetry.stats.network_rx_mbps,
        ));
        container_refreshes.push(refresh);
    }
    if !container_refreshes.is_empty() {
        store.mutate_ephemeral(|state| {
            for refresh in &container_refreshes {
                let Some(environment) = state
                    .environments
                    .iter_mut()
                    .find(|environment| environment.id == refresh.id)
                else {
                    continue;
                };
                if environment.status != EnvironmentStatus::Running || environment.last_opened_at != refresh.last_opened_at {
                    continue;
                }
                if refresh.exited {
                    environment.status = if refresh.clean_exit{EnvironmentStatus::Stopped}else{EnvironmentStatus::Error};
                    environment.cpu_usage = 0.0;
                    environment.memory_usage_gb = 0.0;
                    environment.network_rx_mbps = 0.0;
                }
                if let Some(last_error) = &refresh.last_error {
                    environment.last_error = last_error.clone();
                }
                if let Some((cpu, memory, network)) = refresh.stats {
                    environment.cpu_usage = cpu;
                    environment.memory_usage_gb = memory;
                    environment.network_rx_mbps = network;
                }
            }
            Ok(())
        })?;
    }
    for environment in state.environments.iter().filter(|environment| {
        environment.status == EnvironmentStatus::Running
            && provider(environment) == RuntimeProviderKind::NativeSandbox
    }) {
        let running = runtime
            .native_sandbox_is_running(runtime_id(environment))
            .await;
        let id = environment.id.clone();
        match running {
            Ok(false) => {
                store.mutate_ephemeral(|state| {
                    if let Some(item) = state
                        .environments
                        .iter_mut()
                        .find(|item| item.id == id && item.status == EnvironmentStatus::Running)
                    {
                        item.status = EnvironmentStatus::Stopped;
                        item.last_error = None;
                        item.cpu_usage = 0.0;
                        item.memory_usage_gb = 0.0;
                        item.network_rx_mbps = 0.0;
                        item.resource_policy.cpu.current = 0.0;
                        item.resource_policy.memory_gb.current = 0.0;
                    }
                    Ok(())
                })?;
                continue;
            }
            Err(error) => {
                store.mutate_ephemeral(|state| {
                    if let Some(item) = state
                        .environments
                        .iter_mut()
                        .find(|item| item.id == id && item.status == EnvironmentStatus::Running)
                    {
                        item.last_error = Some(error.clone());
                    }
                    Ok(())
                })?;
                continue;
            }
            Ok(true) => {}
        }
        let resource_result = if environment.resource_policy.dynamic
            && resource_update_needed(
                runtime_id(environment),
                environment.resource_policy.cpu.current,
                environment.resource_policy.memory_gb.current,
            ) {
            let Ok(_resource_claim) = resource_admission::reserve_update(&store, environment) else { continue; };
            let result = apply_scheduled_resource_limits(&runtime, environment).await;
            result
        } else {
            Ok(())
        };
        let stats = runtime
            .native_sandbox_process_stats(runtime_id(environment))
            .await;
        let id = environment.id.clone();
        store.mutate_ephemeral(|state| {
            if let Some(item) = state
                .environments
                .iter_mut()
                .find(|item| item.id == id && item.status == EnvironmentStatus::Running)
            {
                item.last_error = resource_result.as_ref().err().cloned();
                if let Ok(stats) = &stats {
                    item.cpu_usage = stats.cpu_percent;
                    item.memory_usage_gb = stats.memory_bytes as f64 / 1_073_741_824.0;
                }
            }
            Ok(())
        })?;
    }
    for environment in state.environments.iter().filter(|environment| {
        environment.status == EnvironmentStatus::Running
            && provider(environment) == RuntimeProviderKind::Qemu
    }) {
        let power = runtime.vm_power_state(runtime_id(environment)).await;
        let id = environment.id.clone();
        store.mutate_ephemeral(|state| {
            if let Some(item) = state
                .environments
                .iter_mut()
                .find(|item| item.id == id && item.status == EnvironmentStatus::Running)
            {
                match &power {
                    Ok(crate::runtime::VmPowerState::Running) => {}
                    Ok(power) => {
                        let stopped = *power == crate::runtime::VmPowerState::Stopped;
                        item.status = if stopped { EnvironmentStatus::Stopped } else { EnvironmentStatus::Error };
                        item.last_error = (!stopped).then(|| "The virtual machine exited unexpectedly".into());
                        item.cpu_usage = 0.0;
                        item.memory_usage_gb = 0.0;
                        item.network_rx_mbps = 0.0;
                        item.resource_policy.cpu.current = 0.0;
                        item.resource_policy.memory_gb.current = 0.0;
                        item.console_endpoint = None;
                        item.control_endpoint = None;
                    }
                    Err(error) => item.last_error = Some(error.clone()),
                }
            }
            Ok(())
        })?;
        if power == Ok(crate::runtime::VmPowerState::Running) {
            if let Ok(stats) = runtime.vm_process_stats(runtime_id(environment)).await {
                let id = environment.id.clone();
                store.mutate_ephemeral(|state| {
                    if let Some(item) = state
                        .environments
                        .iter_mut()
                        .find(|item| item.id == id && item.status == EnvironmentStatus::Running)
                    {
                        item.cpu_usage = stats.cpu_percent;
                        item.memory_usage_gb = stats.memory_bytes as f64 / 1_073_741_824.0;
                    }
                    Ok(())
                })?;
            }
        }
        if power != Ok(crate::runtime::VmPowerState::Running)
            || scheduler::fixed_vm_resources(environment)
            || !environment.resource_policy.dynamic
            || !resource_update_needed(
                runtime_id(environment),
                environment.resource_policy.cpu.current,
                environment.resource_policy.memory_gb.current,
            )
        {
            continue;
        }
        let Ok(_resource_claim) = resource_admission::reserve_update(&store, environment) else { continue; };
        let result = apply_scheduled_resource_limits(&runtime, environment).await;
        let id = environment.id.clone();
        store.mutate_ephemeral(|state| {
            if let Some(item) = state
                .environments
                .iter_mut()
                .find(|item| item.id == id && item.status == EnvironmentStatus::Running)
            {
                item.last_error = result.as_ref().err().cloned();
            }
            Ok(())
        })?;
    }
    if storage_refresh_due() {
        let storage_state = store.snapshot()?;
        let mut storage_saved_bytes = 0_u64;
        for environment in storage_state
            .environments
            .iter()
            .filter(|environment| provider(environment) == RuntimeProviderKind::Qemu)
        {
            let Some(path) = environment.runtime_path.as_deref() else {
                continue;
            };
            if let Ok(usage) = runtime.vm_storage_usage(&PathBuf::from(path)).await {
                storage_saved_bytes = storage_saved_bytes
                    .saturating_add(usage.logical_bytes.saturating_sub(usage.physical_bytes));
                let id = environment.id.clone();
                store.mutate_ephemeral(|state| {
                    if let Some(item) = state.environments.iter_mut().find(|item| item.id == id) {
                        item.storage_delta_gb = usage.physical_bytes as f64 / 1_073_741_824.0;
                    }
                    Ok(())
                })?;
            }
        }
        store.mutate_ephemeral(|state| {
            state.host.storage_saved_gb = storage_saved_bytes as f64 / 1_073_741_824.0;
            Ok(())
        })?;
    }
    store.snapshot()
}

#[tauri::command]
pub async fn get_guest_session(
    environment_id: String,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
) -> Result<GuestSession, String> {
    let environment = store.environment(&environment_id)?;
    if environment.status != EnvironmentStatus::Running {
        return Err("Start the environment before opening it".into());
    }
    if crate::peer_sharing::is_shared(&environment) {
        let result=crate::peer_sharing::remote(&environment,"inspect",serde_json::json!({})).await?;
        return Ok(GuestSession{kind:if result["permission"]=="control"{GuestSessionKind::HeadlessTerminal}else{GuestSessionKind::HeadlessSerial},websocket_url:None,password:None,message:"Shared remote environment; capabilities are enforced by its owner".into()});
    }
    match provider(&environment) {
        RuntimeProviderKind::YougoriOci | RuntimeProviderKind::YougoriCuda => Ok(GuestSession {
            kind: GuestSessionKind::ContainerTerminal,
            websocket_url: None,
            password: None,
            message: "Commands execute inside this isolated OCI environment".into(),
        }),
        RuntimeProviderKind::CloudSsh => {
            runtime.cloud.session(&environment.id).await?;
            Ok(GuestSession {kind:GuestSessionKind::HeadlessTerminal,websocket_url:None,password:None,message:"Authenticated SSH terminal on your existing cloud server".into()})
        },
        RuntimeProviderKind::Qemu => {
            let console = runtime.vm_console(runtime_id(&environment)).await?;
            if console.headless {
                return Ok(GuestSession {
                    kind: if console.guest_control_available {
                        GuestSessionKind::HeadlessTerminal
                    } else {
                        GuestSessionKind::HeadlessSerial
                    },
                    websocket_url: None,
                    password: None,
                    message: if console.guest_control_available {
                        "Commands execute through the authenticated microVM guest agent".into()
                    } else {
                        "Direct-kernel microVM serial console (read-only)".into()
                    },
                });
            }
            Ok(GuestSession {
                kind: GuestSessionKind::EmbeddedVnc,
                websocket_url: Some(console.websocket_url),
                password: Some(console.password),
                message: "Direct local display session".into(),
            })
        }
        RuntimeProviderKind::NativeSandbox => Ok(GuestSession {
            kind: GuestSessionKind::NativeApplication,
            websocket_url: None,
            password: None,
            message: "The isolated application is running in its native Windows window".into(),
        }),
    }
}

#[tauri::command]
pub async fn read_environment_console(
    environment_id: String,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
) -> Result<String, String> {
    let environment = store.environment(&environment_id)?;
    if environment.kind != EnvironmentKind::MicroVm
        || provider(&environment) != RuntimeProviderKind::Qemu
    {
        if crate::peer_sharing::is_shared(&environment) {return serde_json::from_value(crate::peer_sharing::remote(&environment,"console",serde_json::json!({})).await?).map_err(|e|e.to_string());}
        return Err("Serial output is only available for microVMs".into());
    }
    if environment.status != EnvironmentStatus::Running {
        return Err("Start the microVM before reading its console".into());
    }
    let console = runtime.vm_console(runtime_id(&environment)).await?;
    let path = console
        .serial_log_path
        .ok_or("The microVM did not provide a serial log")?;
    let mut file = tokio::fs::File::open(&path)
        .await
        .map_err(|error| format!("open microVM serial console {}: {error}", path.display()))?;
    let length = file
        .metadata()
        .await
        .map_err(|error| format!("inspect microVM serial console: {error}"))?
        .len();
    const MAX_CONSOLE_BYTES: u64 = 256 * 1024;
    if length > MAX_CONSOLE_BYTES {
        file.seek(SeekFrom::Start(length - MAX_CONSOLE_BYTES))
            .await
            .map_err(|error| format!("seek microVM serial console: {error}"))?;
    }
    let mut bytes = Vec::with_capacity(length.min(MAX_CONSOLE_BYTES) as usize);
    file.take(MAX_CONSOLE_BYTES)
        .read_to_end(&mut bytes)
        .await
        .map_err(|error| format!("read microVM serial console: {error}"))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[tauri::command]
pub async fn execute_environment_command(
    request: ExecuteCommandRequest,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
) -> Result<CommandResult, String> {
    let command = request.command.trim();
    if command.is_empty() || command.len() > 32 * 1024 {
        return Err("Command must be between 1 and 32768 characters".into());
    }
    let environment = store.environment(&request.environment_id)?;
    if environment.status != EnvironmentStatus::Running {
        return Err("The environment is not running".into());
    }
    if crate::peer_sharing::is_shared(&environment) {return serde_json::from_value(crate::peer_sharing::remote(&environment,"exec",serde_json::json!({"command":command})).await?).map_err(|e|e.to_string());}
    match provider(&environment) {
        RuntimeProviderKind::YougoriOci | RuntimeProviderKind::YougoriCuda => {
            runtime
                .execute_container_command(runtime_id(&environment), command)
                .await
        }
        RuntimeProviderKind::CloudSsh => {
            let result = runtime.cloud.session(&environment.id).await?.request("exec",serde_json::json!({"command":command})).await?;
            Ok(CommandResult{exit_code:result["exitCode"].as_i64().unwrap_or(1) as i32,stdout:result["stdout"].as_str().unwrap_or("").into(),stderr:result["stderr"].as_str().unwrap_or("").into()})
        },
        RuntimeProviderKind::Qemu if environment.kind == EnvironmentKind::MicroVm => {
            runtime
                .execute_micro_workload_command(runtime_id(&environment), command)
                .await
        }
        RuntimeProviderKind::Qemu => {
            let ssh = request.ssh.as_ref().ok_or("Full VM commands require an SSH server in the guest and request.ssh with username, identityFile, hostKey and optional port. Verify the host key in the guest console first.")?;
            runtime.execute_vm_ssh(&environment, ssh, command).await
        }
        RuntimeProviderKind::NativeSandbox => Err(
            "Use the isolated application's native window to interact with this environment".into(),
        ),
    }
}

/// Execute only against the other endpoint of an explicitly granted direct
/// connection. The source ID is part of the request so callers cannot borrow
/// another node's grant or traverse A -> B -> C.
#[tauri::command]
pub async fn execute_connected_command(
    request: ExecuteConnectedCommandRequest,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
) -> Result<CommandResult, String> {
    let target_id = {
        let state = store.snapshot()?;
        let connection = state.connections.iter().find(|c| c.id == request.connection_id)
            .ok_or("Connection not found")?;
        if !connection.active || connection.enforcement_status != Some(EnforcementStatus::Enforced) {
            return Err("This connection is not active and ready".into());
        }
        if !connection.commands { return Err("This connection does not allow commands".into()); }
        let target_id = if connection.source_id == request.source_id {
            &connection.target_id
        } else if connection.target_id == request.source_id && connection.direction == ConnectionDirection::Bidirectional {
            &connection.source_id
        } else {
            return Err("Commands are not allowed in this direction".into());
        };
        for id in [&request.source_id, target_id] {
            let environment = state.environments.iter().find(|env| &env.id == id)
                .ok_or("A connected environment no longer exists")?;
            if environment.status != EnvironmentStatus::Running {
                return Err("Both connected environments must be running".into());
            }
        }
        target_id.clone()
    };
    if request.command.trim().is_empty() || request.command.len() > 32 * 1024 {
        return Err("Command must be between 1 and 32768 characters".into());
    }
    execute_environment_command(ExecuteCommandRequest {
        environment_id: target_id,
        command: request.command,
        ssh: request.ssh,
    }, store, runtime).await
}

pub(crate) async fn reconcile_connections(
    store: &PlatformStore,
    runtime: &RuntimeManager,
) -> Result<(), String> {
    let _serial = connection_operations().lock().await;
    reconcile_connections_locked(store, runtime).await
}

async fn reconcile_connections_locked(store: &PlatformStore, runtime: &RuntimeManager) -> Result<(),String> {
    let state = store.snapshot()?;
    for connection in state.connections.iter().filter(|item| item.active) {
        let Some(source) = state
            .environments
            .iter()
            .find(|item| item.id == connection.source_id)
        else {
            continue;
        };
        let Some(target) = state
            .environments
            .iter()
            .find(|item| item.id == connection.target_id)
        else {
            continue;
        };
        if source.status != EnvironmentStatus::Running
            || target.status != EnvironmentStatus::Running
        {
            continue;
        }
        let ports = connection
            .ports
            .iter()
            .filter_map(|port| port.parse::<u16>().ok())
            .collect::<Vec<_>>();
        let result = runtime
            .apply_environment_connection_with_folders(
                &connection.id,
                source,
                target,
                &connection.direction,
                &connection.permissions,
                &ports,
                &connection.selected_folders,
                connection.commands,
            )
            .await;
        let id = connection.id.clone();
        store.mutate(|state| {
            if let Some(item) = state.connections.iter_mut().find(|item| item.id == id) {
                match &result {
                    Ok(rule_id) => {
                        item.enforcement_status = Some(EnforcementStatus::Enforced);
                        item.provider_rule_ids = vec![rule_id.clone()];
                        item.last_error = None;
                    }
                    Err(error) => {
                        item.enforcement_status = Some(EnforcementStatus::Error);
                        item.provider_rule_ids.clear();
                        item.last_error = Some(error.clone());
                    }
                }
            }
            Ok(())
        })?;
        result?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deletion_cleanup_warnings_do_not_turn_committed_deletion_into_failure() {
        let result = EnvironmentDeletionResult {
            state: PlatformState::empty().unwrap(),
            storage_cleanup: StorageCleanupResult { warnings: vec!["Cached images were kept for safety".into()], ..Default::default() },
        };
        let json = serde_json::to_value(result).unwrap();
        assert_eq!(json["environments"].as_array().unwrap().len(), 0);
        assert_eq!(json["storageCleanup"]["warnings"][0], "Cached images were kept for safety");
        let restored: PlatformState = serde_json::from_value(json).unwrap();
        assert!(restored.environments.is_empty());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn gpu_usage_uses_the_busiest_physical_engine() {
        let samples = vec![
            ("pid_1_luid_a_phys_0_eng_0_engtype_3D".to_owned(), 31.5),
            ("pid_2_luid_b_phys_0_eng_0_engtype_3D".to_owned(), 17.0),
            ("pid_1_luid_a_phys_0_eng_1_engtype_Copy".to_owned(), 8.0),
        ];
        assert_eq!(gpu_usage_from_samples(&samples), Some(48.5));
        assert_eq!(
            gpu_usage_from_samples(&[("pid_1_phys_0_eng_0".to_owned(), 125.0)]),
            Some(100.0)
        );
        assert_eq!(gpu_usage_from_samples(&[]), None);
    }

    #[cfg(target_os = "windows")]
    #[test]
    #[ignore = "reads the host Windows GPU performance counters"]
    fn windows_gpu_sampler_returns_a_bounded_measurement() {
        let mut sampler = GpuSampler::new().expect("Windows GPU Engine counter is unavailable");
        std::thread::sleep(Duration::from_millis(100));
        let usage = sampler
            .sample()
            .expect("Windows GPU Engine counter returned no data");
        assert!((0.0..=100.0).contains(&usage), "GPU usage was {usage}");
        eprintln!("host GPU usage: {usage:.2}%");
    }

    #[test]
    fn environment_window_routes_are_bounded_and_injection_safe() {
        let (label, location) = environment_window_parts("env-1234_abcd").unwrap();
        assert_eq!(label, "environment-env-1234_abcd");
        assert_eq!(
            location,
            PathBuf::from("index.html?environment=env-1234_abcd")
        );
        for invalid in [
            "",
            "other",
            "../outside",
            "env?other=true",
            "env space",
            "env#fragment",
        ] {
            assert!(
                environment_window_parts(invalid).is_err(),
                "accepted {invalid}"
            );
        }
        assert!(environment_window_parts(&format!("env-{}", "a".repeat(77))).is_err());
    }

    #[test]
    fn rejects_invalid_resource_ranges() {
        assert!(validate_range(
            "CPU",
            &CreateResourceRange {
                min: 4.0,
                preferred: 2.0,
                max: 8.0
            }
        )
        .is_err());
        assert!(validate_range(
            "CPU",
            &CreateResourceRange {
                min: 1.0,
                preferred: 2.0,
                max: 8.0
            }
        )
        .is_ok());
    }
}
