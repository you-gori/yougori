//! CORE-01 adapters of the host probe class over the latest inventory (S01).
//!
//! An adapter never runs anything: it reads the inventory [`super::collect`] last
//! produced and the runtimes the engine bound, and turns them into one observation. Its
//! freshness counts from when that collection started, so evidence never looks newer than
//! the queries behind it; an inventory older than the capability's freshness yields "not
//! tested", asking for a new collection.

use std::collections::BTreeMap;
use std::fmt;
use std::num::NonZeroU32;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use serde::Serialize;

use crate::foundation::evidence::{
    Capability, ComputePlatform, ConfigurationFingerprint, HostChange, Observation, OsKind,
    ProbeAdapter, RuntimeSubject, SourceClass, Subject, SupportDetail, UnknownReason,
    UnsupportedReason,
};
use crate::foundation::ids::{Clock, Digest, ExecutionCategory, MonotonicTime};

use super::fingerprint::{gpu_fingerprint, not_collected, runtime_fingerprint};
use super::inventory::{DriverModel, GpuInventory, HostInventory, InventoryProblem, MAX_GPUS};

/// How long a GPU's free memory stays fresh; it changes as soon as anything allocates.
pub const GPU_MEMORY_FRESH_FOR: Duration = Duration::from_secs(5);
/// How long a runtime's compute platform stays fresh.
pub const COMPUTE_PLATFORM_FRESH_FOR: Duration = Duration::from_secs(600);
/// How long a runtime's observed execution category stays fresh.
pub const RUNTIME_CATEGORY_FRESH_FOR: Duration = Duration::from_secs(60);
/// How long a runtime's peer topology stays fresh.
pub const PEER_TOPOLOGY_FRESH_FOR: Duration = Duration::from_secs(600);
/// How long a sleep cycle stays evidence about its runtime: what the backend release did in
/// this runtime's process does not change while it runs, and a day bounds it.
pub const SLEEP_CYCLE_FRESH_FOR: Duration = Duration::from_secs(24 * 60 * 60);
/// The least GPU memory a park by sleep must be seen to return, and a wake to take again, for
/// the weights to count as discarded and reloaded.
pub const SLEEP_DISCARD_MIN_BYTES: u64 = 256 * 1024 * 1024;

/// One sleep cycle of a runtime the engine bound, as the engine saw it (G01/G02; CORE-01
/// sleep-mode weight discarding): the GPU memory in use the host probe read before the runner
/// parked by sleep, once it parked and once it was bound again after waking; the runner's
/// own wake stages (milliseconds on its clock); and how long it slept.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SleepCycle {
    pub used_before_bytes: u64,
    pub used_parked_bytes: u64,
    pub used_awake_bytes: u64,
    pub engine_wake_ms: f64,
    pub weight_reload_ms: f64,
    pub slept_ms: u64,
    /// When the engine recorded it, on the evidence registry's clock.
    #[serde(skip)]
    pub recorded_at: MonotonicTime,
}

impl SleepCycle {
    /// The memory the park returned and the wake took again, as the host probe saw it.
    pub fn returned_and_retaken(&self) -> (u64, u64) {
        (
            self.used_before_bytes
                .saturating_sub(self.used_parked_bytes),
            self.used_awake_bytes.saturating_sub(self.used_parked_bytes),
        )
    }
}

/// The oldest compute capability WSL CUDA accepts, Pascal (6.0), as the CUDA runtime's
/// own prerequisite check requires.
const WSL_MIN_COMPUTE: (u32, u32) = (6, 0);

/// Why a runtime could not be bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum BindingError {
    /// Only runtimes this host runs itself are observed here; a VM sandbox's evidence
    /// comes from its backend and a provider container's from its provider.
    NotLocal {
        category: ExecutionCategory,
    },
    TooManyDevices,
    RepeatedDevice,
}

impl fmt::Display for BindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotLocal { category } => write!(
                f,
                "a {} is not observed by this host's probes",
                category.label()
            ),
            Self::TooManyDevices => write!(f, "a runtime binds at most {MAX_GPUS} GPUs"),
            Self::RepeatedDevice => f.write_str("a runtime binds each GPU once"),
        }
    }
}

impl std::error::Error for BindingError {}

/// A local runtime the engine itself launched, with the GPUs it gave it in rank order
/// (none for a CPU-only runtime). The engine binds a runtime when it starts it in the
/// local CUDA runtime and unbinds it when it stops; that host-side record, with the CUDA
/// runtime's own status, is what the runtime adapters observe.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeBinding {
    runtime: RuntimeSubject,
    devices: Vec<Digest>,
}

impl RuntimeBinding {
    /// Binds `runtime` to `devices`. Only the shared-kernel GPU runtime (the WSL 2 CUDA
    /// runtime, VM-D4) runs locally and is observed here.
    pub fn new(runtime: RuntimeSubject, devices: Vec<Digest>) -> Result<Self, BindingError> {
        if runtime.category != ExecutionCategory::SharedKernelGpuRuntime {
            return Err(BindingError::NotLocal {
                category: runtime.category,
            });
        }
        if devices.len() > MAX_GPUS {
            return Err(BindingError::TooManyDevices);
        }
        for (index, device) in devices.iter().enumerate() {
            if devices[..index].contains(device) {
                return Err(BindingError::RepeatedDevice);
            }
        }
        Ok(Self { runtime, devices })
    }

    pub fn runtime(&self) -> &RuntimeSubject {
        &self.runtime
    }

    pub fn devices(&self) -> &[Digest] {
        &self.devices
    }
}

/// What the adapters read: the latest inventory and the bound runtimes, by subject
/// identity.
#[derive(Default)]
pub(super) struct Observed {
    pub(super) inventory: Option<HostInventory>,
    pub(super) bindings: BTreeMap<Digest, RuntimeBinding>,
    /// The latest sleep cycle the engine recorded of a bound runtime, by its identity.
    pub(super) sleep_cycles: BTreeMap<Digest, SleepCycle>,
}

pub(super) type SharedObserved = Arc<RwLock<Observed>>;

/// An observation made without an inventory, or when the shared state cannot be read.
fn not_tested() -> Observation {
    Observation::unknown(not_collected(), Duration::ZERO, UnknownReason::NotTested)
}

fn inconsistent() -> Observation {
    Observation::unknown(
        not_collected(),
        Duration::ZERO,
        UnknownReason::InconsistentReport,
    )
}

/// How much of `fresh_for` is left for observations from `inventory`, on `clock`.
fn remaining<C: Clock>(clock: &C, inventory: &HostInventory, fresh_for: Duration) -> Duration {
    fresh_for.saturating_sub(clock.now().saturating_duration_since(inventory.started_at))
}

/// Builds an observation under `configuration`, or "not tested" when the inventory is
/// too old to back it.
fn observation(
    configuration: ConfigurationFingerprint,
    fresh_for: Duration,
    result: Result<SupportDetail, Result<UnsupportedReason, UnknownReason>>,
) -> Observation {
    if fresh_for.is_zero() {
        return Observation::unknown(configuration, Duration::ZERO, UnknownReason::NotTested);
    }
    match result {
        Ok(detail) => Observation::supported(configuration, fresh_for, detail),
        Err(Ok(reason)) => Observation::unsupported(configuration, fresh_for, reason),
        Err(Err(reason)) => Observation::unknown(configuration, fresh_for, reason),
    }
}

/// A GPU inventory that could not answer: no NVIDIA tool or platform means the feature
/// is absent; anything else is inconclusive.
fn unavailable(problem: InventoryProblem) -> Result<UnsupportedReason, UnknownReason> {
    match problem {
        InventoryProblem::ToolMissing | InventoryProblem::NotOnThisPlatform => {
            Ok(UnsupportedReason::FeatureAbsent)
        }
        _ => Err(UnknownReason::Inconclusive),
    }
}

/// Free and total memory of one GPU of this machine (`GpuFreeMemory`, host probe only).
pub(super) struct GpuMemoryProbe<C: Clock> {
    pub(super) clock: Arc<C>,
    pub(super) observed: SharedObserved,
}

impl<C: Clock> ProbeAdapter for GpuMemoryProbe<C> {
    fn capability(&self) -> Capability {
        Capability::GpuFreeMemory
    }

    fn source(&self) -> SourceClass {
        SourceClass::HostProbe
    }

    fn host_changes(&self) -> Vec<HostChange> {
        Vec::new()
    }

    /// GPUs of this machine, or any GPU while no machine is known, so its evidence reads
    /// "not tested" rather than having no adapter.
    fn observes(&self, subject: &Subject) -> bool {
        let Subject::GpuDevice(gpu) = subject else {
            return false;
        };
        let Ok(observed) = self.observed.read() else {
            return true;
        };
        observed
            .inventory
            .as_ref()
            .and_then(|inventory| inventory.machine.digest())
            .is_none_or(|machine| machine == gpu.machine)
    }

    fn observe(&self, subject: &Subject) -> Observation {
        let Subject::GpuDevice(subject) = subject else {
            return inconsistent();
        };
        let Ok(observed) = self.observed.read() else {
            return not_tested();
        };
        let Some(inventory) = observed.inventory.as_ref() else {
            return not_tested();
        };
        if inventory.machine.digest() != Some(subject.machine) {
            return inconsistent();
        }
        let fresh_for = remaining(&*self.clock, inventory, GPU_MEMORY_FRESH_FOR);
        let devices = match &inventory.gpus {
            GpuInventory::Devices { devices } => devices,
            GpuInventory::Unavailable { problem } => {
                return match super::fingerprint::host_fingerprint(inventory) {
                    Ok(configuration) => {
                        observation(configuration, fresh_for, Err(unavailable(*problem)))
                    }
                    Err(_) => inconsistent(),
                };
            }
        };
        let Some(gpu) = devices.iter().find(|gpu| gpu.device == subject.device) else {
            return match super::fingerprint::host_fingerprint(inventory) {
                Ok(configuration) => observation(
                    configuration,
                    fresh_for,
                    Err(Err(UnknownReason::Unreachable)),
                ),
                Err(_) => inconsistent(),
            };
        };
        match gpu_fingerprint(inventory, gpu) {
            Ok(configuration) => observation(
                configuration,
                fresh_for,
                Ok(SupportDetail::GpuMemory {
                    free_bytes: gpu.free_bytes,
                    total_bytes: gpu.total_bytes,
                }),
            ),
            Err(_) => inconsistent(),
        }
    }
}

/// Which runtime capability a [`RuntimeProbe`] observes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RuntimeFacet {
    ComputePlatform,
    Category,
    PeerTopology,
}

impl RuntimeFacet {
    pub(super) const ALL: [Self; 3] = [Self::ComputePlatform, Self::Category, Self::PeerTopology];

    pub(super) fn capability(self) -> Capability {
        match self {
            Self::ComputePlatform => Capability::ComputePlatform,
            Self::Category => Capability::RuntimeCategory,
            Self::PeerTopology => Capability::PeerTopology,
        }
    }

    pub(super) fn fresh_for(self) -> Duration {
        match self {
            Self::ComputePlatform => COMPUTE_PLATFORM_FRESH_FOR,
            Self::Category => RUNTIME_CATEGORY_FRESH_FOR,
            Self::PeerTopology => PEER_TOPOLOGY_FRESH_FOR,
        }
    }
}

/// One capability of the runtimes the engine bound: their compute platform, execution
/// category or peer topology, from the inventory and the CUDA runtime's status.
pub(super) struct RuntimeProbe<C: Clock> {
    pub(super) facet: RuntimeFacet,
    pub(super) clock: Arc<C>,
    pub(super) observed: SharedObserved,
}

type Outcome = Result<SupportDetail, Result<UnsupportedReason, UnknownReason>>;

impl<C: Clock> RuntimeProbe<C> {
    /// The local CUDA runtime is ready to run CUDA work, or why not.
    fn cuda_ready(
        inventory: &HostInventory,
    ) -> Result<(), Result<UnsupportedReason, UnknownReason>> {
        let Some(cuda) = inventory.cuda_runtime else {
            return Err(Err(UnknownReason::NotTested));
        };
        if !cuda.supported || !cuda.installed {
            return Err(Ok(UnsupportedReason::FeatureAbsent));
        }
        if cuda.update_available {
            return Err(Err(UnknownReason::Inconclusive));
        }
        Ok(())
    }

    fn compute_platform(inventory: &HostInventory, binding: &RuntimeBinding) -> Outcome {
        Self::cuda_ready(inventory)?;
        if binding.devices().is_empty() {
            return Ok(SupportDetail::ComputePlatform {
                platform: ComputePlatform::Cpu,
            });
        }
        let devices = match &inventory.gpus {
            GpuInventory::Devices { devices } => devices,
            GpuInventory::Unavailable { problem } => return Err(unavailable(*problem)),
        };
        let windows = inventory
            .os
            .as_ref()
            .is_some_and(|os| os.kind == OsKind::Windows);
        for device in binding.devices() {
            let Some(gpu) = devices.iter().find(|gpu| gpu.device == *device) else {
                return Err(Err(UnknownReason::Unreachable));
            };
            let capable = gpu
                .compute_version()
                .is_some_and(|version| version >= WSL_MIN_COMPUTE);
            let driver_model_fits = !windows || gpu.driver_model == DriverModel::Wddm;
            if !capable || !driver_model_fits {
                return Err(Ok(UnsupportedReason::FeatureAbsent));
            }
        }
        Ok(SupportDetail::ComputePlatform {
            platform: ComputePlatform::Cuda,
        })
    }

    fn category(inventory: &HostInventory, binding: &RuntimeBinding) -> Outcome {
        Self::cuda_ready(inventory)?;
        match inventory.cuda_runtime {
            Some(cuda) if cuda.running => Ok(SupportDetail::RuntimeCategory {
                category: binding.runtime().category,
            }),
            _ => Err(Err(UnknownReason::Unreachable)),
        }
    }

    fn peer_topology(inventory: &HostInventory, binding: &RuntimeBinding) -> Outcome {
        match binding.devices() {
            [] => Err(Ok(UnsupportedReason::FeatureAbsent)),
            [device] => {
                if inventory.gpu(device).is_some() {
                    Ok(SupportDetail::PeerTopology {
                        device_count: NonZeroU32::MIN,
                        paths: Vec::new(),
                    })
                } else {
                    Err(Err(UnknownReason::Unreachable))
                }
            }
            // Peer access is probed, never assumed (FAST-02): exercising a copy between
            // two GPUs is O07's hardware work.
            _ => Err(Err(UnknownReason::NotTested)),
        }
    }
}

impl<C: Clock> ProbeAdapter for RuntimeProbe<C> {
    fn capability(&self) -> Capability {
        self.facet.capability()
    }

    fn source(&self) -> SourceClass {
        SourceClass::HostProbe
    }

    fn host_changes(&self) -> Vec<HostChange> {
        Vec::new()
    }

    /// Exactly the runtimes the engine bound.
    fn observes(&self, subject: &Subject) -> bool {
        let Subject::Runtime(runtime) = subject else {
            return false;
        };
        self.observed.read().is_ok_and(|observed| {
            observed
                .bindings
                .get(&subject.identity())
                .is_some_and(|binding| binding.runtime() == runtime)
        })
    }

    fn observe(&self, subject: &Subject) -> Observation {
        let Ok(observed) = self.observed.read() else {
            return not_tested();
        };
        let Some(binding) = observed.bindings.get(&subject.identity()) else {
            return inconsistent();
        };
        let Some(inventory) = observed.inventory.as_ref() else {
            return not_tested();
        };
        let Ok(configuration) = runtime_fingerprint(inventory, binding) else {
            return inconsistent();
        };
        let fresh_for = remaining(&*self.clock, inventory, self.facet.fresh_for());
        let outcome = match self.facet {
            RuntimeFacet::ComputePlatform => Self::compute_platform(inventory, binding),
            RuntimeFacet::Category => Self::category(inventory, binding),
            RuntimeFacet::PeerTopology => Self::peer_topology(inventory, binding),
        };
        observation(configuration, fresh_for, outcome)
    }
}

/// Sleep-mode weight discarding of the runtimes the engine bound, from the sleep cycle it
/// recorded of each (G01/G02): supported, as the backend mode of the runtime's release, when
/// the host probe saw the park return and the wake take again at least
/// [`SLEEP_DISCARD_MIN_BYTES`]; unsupported when the park returned less (the weights stayed);
/// inconclusive when the park returned them but the wake did not take memory again.
pub(super) struct SleepCycleProbe<C: Clock> {
    pub(super) clock: Arc<C>,
    pub(super) observed: SharedObserved,
}

impl<C: Clock> ProbeAdapter for SleepCycleProbe<C> {
    fn capability(&self) -> Capability {
        Capability::SleepWeightDiscard
    }

    fn source(&self) -> SourceClass {
        SourceClass::HostProbe
    }

    fn host_changes(&self) -> Vec<HostChange> {
        Vec::new()
    }

    /// The bound runtimes with a recorded sleep cycle.
    fn observes(&self, subject: &Subject) -> bool {
        let Subject::Runtime(runtime) = subject else {
            return false;
        };
        self.observed.read().is_ok_and(|observed| {
            let identity = subject.identity();
            observed.sleep_cycles.contains_key(&identity)
                && observed
                    .bindings
                    .get(&identity)
                    .is_some_and(|binding| binding.runtime() == runtime)
        })
    }

    fn observe(&self, subject: &Subject) -> Observation {
        let Subject::Runtime(runtime) = subject else {
            return inconsistent();
        };
        let Ok(observed) = self.observed.read() else {
            return not_tested();
        };
        let identity = subject.identity();
        let (Some(binding), Some(cycle)) = (
            observed.bindings.get(&identity),
            observed.sleep_cycles.get(&identity),
        ) else {
            return inconsistent();
        };
        let Some(inventory) = observed.inventory.as_ref() else {
            return not_tested();
        };
        let Ok(configuration) = runtime_fingerprint(inventory, binding) else {
            return inconsistent();
        };
        let age = self
            .clock
            .now()
            .saturating_duration_since(cycle.recorded_at);
        let fresh_for = SLEEP_CYCLE_FRESH_FOR.saturating_sub(age);
        let (returned, retaken) = cycle.returned_and_retaken();
        let outcome = if returned < SLEEP_DISCARD_MIN_BYTES {
            Err(Ok(UnsupportedReason::FeatureAbsent))
        } else if retaken < SLEEP_DISCARD_MIN_BYTES {
            Err(Err(UnknownReason::Inconclusive))
        } else {
            Ok(SupportDetail::BackendMode {
                release: runtime.release.clone(),
            })
        };
        observation(configuration, fresh_for, outcome)
    }
}

/// The adapters this module registers, over one shared view and one clock.
pub(super) fn adapters<C: Clock + 'static>(
    clock: &Arc<C>,
    observed: &SharedObserved,
) -> Vec<Box<dyn ProbeAdapter>> {
    let mut adapters: Vec<Box<dyn ProbeAdapter>> = vec![Box::new(GpuMemoryProbe {
        clock: Arc::clone(clock),
        observed: Arc::clone(observed),
    })];
    for facet in RuntimeFacet::ALL {
        adapters.push(Box::new(RuntimeProbe {
            facet,
            clock: Arc::clone(clock),
            observed: Arc::clone(observed),
        }));
    }
    adapters.push(Box::new(SleepCycleProbe {
        clock: Arc::clone(clock),
        observed: Arc::clone(observed),
    }));
    adapters
}
