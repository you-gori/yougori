//! Warm pools (GPU part §3.8: "Do not fork a process after CUDA initialization as a
//! generic warm-worker strategy. Warm pools must respect backend process and driver
//! initialization rules. Distinguish CPU-only import warming from retaining an already
//! initialized GPU worker.").
//!
//! A CPU-only import-warmed process and a retained GPU worker are different types kept in
//! different sets. The first holds no driver context and can still be placed on any
//! device; the second initialized its driver on one device and serves only there. Nothing
//! is forked from a process whose GPU driver is initialized, whether CUDA or another, and
//! an unknown driver state counts as initialized. Forking even a CPU-only process needs a
//! recorded process rule for the exact release; none is recorded, so warm processes start
//! fresh.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::foundation::evidence::{BackendRelease, GpuDeviceSubject};

/// Whether a process holds an initialized GPU driver context, as observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriverState {
    /// Observed with no GPU driver context: the backend was only imported.
    NotInitialized,
    /// Observed with an initialized GPU driver context.
    Initialized,
    /// Not observed, or inconclusive; treated as initialized.
    Unknown,
}

/// A process's place in one warm pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct WorkerId(u64);

impl WorkerId {
    /// The pool's number for the process.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for WorkerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "worker {}", self.0)
    }
}

/// A process warmed by importing its backend on the CPU only: no GPU driver context, no
/// device and no model state (GPU part §3.8: "CPU-only import warming"). It still has to
/// initialize its driver and load its model before it serves.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ImportWarmProcess {
    id: WorkerId,
    release: BackendRelease,
}

impl ImportWarmProcess {
    /// The process's place in the pool.
    pub fn id(&self) -> WorkerId {
        self.id
    }

    /// The backend release it imported.
    pub fn release(&self) -> &BackendRelease {
        &self.release
    }
}

/// A worker whose GPU driver is initialized on one device, kept for reuse there (GPU part
/// §3.8: "retaining an already initialized GPU worker"). It is never forked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RetainedGpuWorker {
    id: WorkerId,
    release: BackendRelease,
    device: GpuDeviceSubject,
}

impl RetainedGpuWorker {
    /// The worker's place in the pool.
    pub fn id(&self) -> WorkerId {
        self.id
    }

    /// The backend release it runs.
    pub fn release(&self) -> &BackendRelease {
        &self.release
    }

    /// The device its driver was initialized on.
    pub fn device(&self) -> &GpuDeviceSubject {
        &self.device
    }
}

/// Recorded process rules of backend releases (GPU part §3.8: "Warm pools must respect
/// backend process and driver initialization rules").
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ProcessRules {
    fork_before_driver_initialization: BTreeSet<BackendRelease>,
}

impl ProcessRules {
    /// The rules the plan records: none, so no release is forked and warm processes start
    /// fresh.
    pub fn recorded() -> Self {
        Self::default()
    }

    /// Rules recording that CPU-only import-warmed processes of exactly these releases may
    /// be forked before any driver initialization.
    pub fn permitting_fork_before_driver_initialization(
        releases: impl IntoIterator<Item = BackendRelease>,
    ) -> Self {
        Self {
            fork_before_driver_initialization: releases.into_iter().collect(),
        }
    }

    /// Whether a CPU-only import-warmed process of `release` may be forked.
    pub fn permits_fork_before_driver_initialization(&self, release: &BackendRelease) -> bool {
        self.fork_before_driver_initialization.contains(release)
    }
}

/// Why a warm pool refused an operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum WarmPoolRefusal {
    /// The process's GPU driver is initialized, so it is never forked. An import-warmed
    /// process observed this way also leaves the pool: it is no longer CPU-only.
    ForkAfterDriverInitialization { worker: WorkerId },
    /// The driver state is unknown and counts as initialized. An import-warmed process
    /// observed this way also leaves the pool.
    DriverStateUnknown,
    /// No recorded rule makes fork safe for this release, even before driver
    /// initialization; start a fresh process instead.
    ForkNotRecorded { release: BackendRelease },
    /// A process with an initialized driver is not CPU-only import warming.
    NotCpuOnly,
    /// A process without an initialized driver is not a retained GPU worker.
    DriverNotInitialized,
    /// The pool holds no such process.
    UnknownWorker { worker: WorkerId },
    /// The pool has used every worker number.
    Exhausted,
}

impl fmt::Display for WarmPoolRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ForkAfterDriverInitialization { worker } => write!(
                f,
                "{worker} has an initialized GPU driver and is never forked; start a fresh \
                 process instead"
            ),
            Self::DriverStateUnknown => f.write_str(
                "the process's GPU driver state is unknown, so it counts as initialized",
            ),
            Self::ForkNotRecorded { release } => write!(
                f,
                "no recorded process rule makes forking {release} safe; start a fresh process \
                 instead"
            ),
            Self::NotCpuOnly => f.write_str(
                "a process with an initialized GPU driver is not CPU-only import warming",
            ),
            Self::DriverNotInitialized => f.write_str(
                "a process without an initialized GPU driver is not a retained GPU worker",
            ),
            Self::UnknownWorker { worker } => write!(f, "the pool holds no {worker}"),
            Self::Exhausted => f.write_str("the pool has used every worker number"),
        }
    }
}

impl std::error::Error for WarmPoolRefusal {}

/// What a warm pool holds, each kind counted on its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct WarmPoolReport {
    /// CPU-only import-warmed processes, which still initialize a driver and load a model.
    pub cpu_import_warm: usize,
    /// Retained workers with an initialized GPU driver.
    pub retained_gpu_workers: usize,
}

/// Warm processes kept ready on one machine (GPU part §3.8).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WarmPool {
    rules: ProcessRules,
    next: u64,
    import_warm: BTreeMap<WorkerId, ImportWarmProcess>,
    retained: BTreeMap<WorkerId, RetainedGpuWorker>,
}

impl WarmPool {
    /// An empty pool under `rules`.
    pub fn new(rules: ProcessRules) -> Self {
        Self {
            rules,
            next: 0,
            import_warm: BTreeMap::new(),
            retained: BTreeMap::new(),
        }
    }

    /// Adds a process that imported `release` and was observed with no GPU driver
    /// context.
    pub fn add_import_warm(
        &mut self,
        release: BackendRelease,
        observed: DriverState,
    ) -> Result<WorkerId, WarmPoolRefusal> {
        match observed {
            DriverState::NotInitialized => {}
            DriverState::Initialized => return Err(WarmPoolRefusal::NotCpuOnly),
            DriverState::Unknown => return Err(WarmPoolRefusal::DriverStateUnknown),
        }
        let id = self.next_id()?;
        self.import_warm
            .insert(id, ImportWarmProcess { id, release });
        Ok(id)
    }

    /// Adds a worker of `release` observed with its GPU driver initialized on `device`.
    pub fn add_retained_gpu(
        &mut self,
        release: BackendRelease,
        device: GpuDeviceSubject,
        observed: DriverState,
    ) -> Result<WorkerId, WarmPoolRefusal> {
        match observed {
            DriverState::Initialized => {}
            DriverState::NotInitialized => return Err(WarmPoolRefusal::DriverNotInitialized),
            DriverState::Unknown => return Err(WarmPoolRefusal::DriverStateUnknown),
        }
        let id = self.next_id()?;
        self.retained.insert(
            id,
            RetainedGpuWorker {
                id,
                release,
                device,
            },
        );
        Ok(id)
    }

    /// Forks the CPU-only import-warmed process `parent` into another one, `observed`
    /// being the parent's driver state now. Never for a retained GPU worker or a parent
    /// now observed initialized or unknown, and only where a recorded rule permits fork
    /// for the parent's release.
    pub fn fork(
        &mut self,
        parent: WorkerId,
        observed: DriverState,
    ) -> Result<WorkerId, WarmPoolRefusal> {
        if self.retained.contains_key(&parent) {
            return Err(WarmPoolRefusal::ForkAfterDriverInitialization { worker: parent });
        }
        let release = match self.import_warm.get(&parent) {
            Some(process) => process.release.clone(),
            None => return Err(WarmPoolRefusal::UnknownWorker { worker: parent }),
        };
        match observed {
            DriverState::NotInitialized => {}
            DriverState::Initialized => {
                self.import_warm.remove(&parent);
                return Err(WarmPoolRefusal::ForkAfterDriverInitialization { worker: parent });
            }
            DriverState::Unknown => {
                self.import_warm.remove(&parent);
                return Err(WarmPoolRefusal::DriverStateUnknown);
            }
        }
        if !self
            .rules
            .permits_fork_before_driver_initialization(&release)
        {
            return Err(WarmPoolRefusal::ForkNotRecorded { release });
        }
        let id = self.next_id()?;
        self.import_warm
            .insert(id, ImportWarmProcess { id, release });
        Ok(id)
    }

    /// Takes a retained GPU worker of exactly `release` initialized on exactly `device`. A
    /// CPU-only import-warmed process never stands in for one.
    pub fn take_retained(
        &mut self,
        release: &BackendRelease,
        device: &GpuDeviceSubject,
    ) -> Option<RetainedGpuWorker> {
        let id = self
            .retained
            .values()
            .find(|worker| worker.release == *release && worker.device == *device)
            .map(|worker| worker.id)?;
        self.retained.remove(&id)
    }

    /// Takes a CPU-only import-warmed process of exactly `release`.
    pub fn take_import_warm(&mut self, release: &BackendRelease) -> Option<ImportWarmProcess> {
        let id = self
            .import_warm
            .values()
            .find(|process| process.release == *release)
            .map(|process| process.id)?;
        self.import_warm.remove(&id)
    }

    /// What the pool holds, each kind counted on its own.
    pub fn report(&self) -> WarmPoolReport {
        WarmPoolReport {
            cpu_import_warm: self.import_warm.len(),
            retained_gpu_workers: self.retained.len(),
        }
    }

    fn next_id(&mut self) -> Result<WorkerId, WarmPoolRefusal> {
        let id = WorkerId(self.next);
        self.next = self.next.checked_add(1).ok_or(WarmPoolRefusal::Exhausted)?;
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{llama_cpp, vllm_0_29_0, vllm_0_31_0};
    use super::*;
    use crate::foundation::ids::digest;

    fn device(name: &str) -> GpuDeviceSubject {
        GpuDeviceSubject {
            machine: digest("yougori/test/machine/v1", &[b"m1"]),
            device: digest("yougori/test/device/v1", &[name.as_bytes()]),
        }
    }

    fn forking_pool() -> WarmPool {
        WarmPool::new(ProcessRules::permitting_fork_before_driver_initialization(
            [vllm_0_31_0()],
        ))
    }

    #[test]
    fn nothing_is_forked_after_driver_initialization() {
        let mut pool = forking_pool();
        let retained = pool
            .add_retained_gpu(vllm_0_31_0(), device("gpu0"), DriverState::Initialized)
            .unwrap();
        for observed in [
            DriverState::NotInitialized,
            DriverState::Initialized,
            DriverState::Unknown,
        ] {
            assert_eq!(
                pool.fork(retained, observed),
                Err(WarmPoolRefusal::ForkAfterDriverInitialization { worker: retained })
            );
        }

        // An import-warmed process that has since initialized its driver is refused and
        // leaves the CPU-only set; so does one whose state is unknown.
        let initialized = pool
            .add_import_warm(vllm_0_31_0(), DriverState::NotInitialized)
            .unwrap();
        let refusal = pool
            .fork(initialized, DriverState::Initialized)
            .unwrap_err();
        assert_eq!(
            refusal,
            WarmPoolRefusal::ForkAfterDriverInitialization {
                worker: initialized
            }
        );
        assert!(refusal.to_string().contains("never forked"));
        assert_eq!(
            pool.fork(initialized, DriverState::NotInitialized),
            Err(WarmPoolRefusal::UnknownWorker {
                worker: initialized
            })
        );
        let unknown = pool
            .add_import_warm(vllm_0_31_0(), DriverState::NotInitialized)
            .unwrap();
        assert_eq!(
            pool.fork(unknown, DriverState::Unknown),
            Err(WarmPoolRefusal::DriverStateUnknown)
        );
        assert_eq!(pool.report().cpu_import_warm, 0);

        let clean = pool
            .add_import_warm(vllm_0_31_0(), DriverState::NotInitialized)
            .unwrap();
        let child = pool.fork(clean, DriverState::NotInitialized).unwrap();
        assert_ne!(child, clean);
        assert_eq!(
            pool.report(),
            WarmPoolReport {
                cpu_import_warm: 2,
                retained_gpu_workers: 1
            }
        );
    }

    #[test]
    fn fork_needs_a_recorded_process_rule_for_the_exact_release() {
        let mut pool = WarmPool::new(ProcessRules::recorded());
        let process = pool
            .add_import_warm(vllm_0_31_0(), DriverState::NotInitialized)
            .unwrap();
        let refusal = pool.fork(process, DriverState::NotInitialized).unwrap_err();
        assert_eq!(
            refusal,
            WarmPoolRefusal::ForkNotRecorded {
                release: vllm_0_31_0()
            }
        );
        assert!(refusal.to_string().contains("start a fresh process"));

        let mut pool = forking_pool();
        let other = pool
            .add_import_warm(vllm_0_29_0(), DriverState::NotInitialized)
            .unwrap();
        assert_eq!(
            pool.fork(other, DriverState::NotInitialized),
            Err(WarmPoolRefusal::ForkNotRecorded {
                release: vllm_0_29_0()
            })
        );
        assert!(!ProcessRules::recorded().permits_fork_before_driver_initialization(&vllm_0_31_0()));
    }

    #[test]
    fn cpu_import_warming_is_not_a_retained_gpu_worker() {
        let mut pool = WarmPool::new(ProcessRules::recorded());
        assert_eq!(
            pool.add_import_warm(vllm_0_31_0(), DriverState::Initialized),
            Err(WarmPoolRefusal::NotCpuOnly)
        );
        assert_eq!(
            pool.add_retained_gpu(vllm_0_31_0(), device("gpu0"), DriverState::NotInitialized),
            Err(WarmPoolRefusal::DriverNotInitialized)
        );
        for add in [
            pool.add_import_warm(vllm_0_31_0(), DriverState::Unknown),
            pool.add_retained_gpu(vllm_0_31_0(), device("gpu0"), DriverState::Unknown),
        ] {
            assert_eq!(add, Err(WarmPoolRefusal::DriverStateUnknown));
        }

        let warm = pool
            .add_import_warm(vllm_0_31_0(), DriverState::NotInitialized)
            .unwrap();
        assert_eq!(pool.take_retained(&vllm_0_31_0(), &device("gpu0")), None);
        assert_eq!(
            pool.report(),
            WarmPoolReport {
                cpu_import_warm: 1,
                retained_gpu_workers: 0
            }
        );
        let process = pool.take_import_warm(&vllm_0_31_0()).unwrap();
        assert_eq!(process.id(), warm);
        assert_eq!(process.release(), &vllm_0_31_0());
        assert_eq!(pool.take_import_warm(&vllm_0_31_0()), None);
    }

    #[test]
    fn a_retained_worker_serves_only_its_release_and_device() {
        let mut pool = WarmPool::new(ProcessRules::recorded());
        let id = pool
            .add_retained_gpu(vllm_0_31_0(), device("gpu0"), DriverState::Initialized)
            .unwrap();
        assert_eq!(pool.take_retained(&vllm_0_31_0(), &device("gpu1")), None);
        assert_eq!(pool.take_retained(&llama_cpp(), &device("gpu0")), None);
        let worker = pool.take_retained(&vllm_0_31_0(), &device("gpu0")).unwrap();
        assert_eq!(worker.id(), id);
        assert_eq!(worker.device(), &device("gpu0"));
        assert_eq!(worker.release(), &vllm_0_31_0());
        assert_eq!(pool.report().retained_gpu_workers, 0);
        assert_eq!(
            serde_json::to_value(pool.report()).unwrap(),
            serde_json::json!({"cpu_import_warm": 0, "retained_gpu_workers": 0})
        );
    }

    #[test]
    fn worker_numbers_never_wrap() {
        let mut pool = WarmPool::new(ProcessRules::recorded());
        pool.next = u64::MAX;
        assert_eq!(
            pool.add_import_warm(vllm_0_31_0(), DriverState::NotInitialized),
            Err(WarmPoolRefusal::Exhausted)
        );
        assert_eq!(pool.report().cpu_import_warm, 0);
    }
}
