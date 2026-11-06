//! The production owner of this computer's CORE-01 registry (S01).
//!
//! [`EvidenceService`] keeps the subjects it knows with the configuration each was last
//! observed under. Installing an inventory, binding or unbinding a runtime reconciles
//! them: a subject that disappeared loses its evidence, a subject whose fingerprint
//! changed loses the evidence observed under the old one (CORE-01: changed configurations
//! invalidate relevant evidence), and every known subject is observed again. Its
//! [`EvidenceStatus`] lists every observed capability with its current verdict and every
//! capability it has no producer for with the open task that owns it.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLockWriteGuard};
use std::time::Duration;

use serde::Serialize;

use crate::foundation::evidence::{
    Capability, ConfigurationFingerprint, EvidenceEnvelope, EvidenceRefusal, GpuDeviceSubject,
    ProbeRegistry, RegistryError, Remedy, Requirement, RuntimeSubject, Satisfied, Subject,
};
use crate::foundation::ids::{Clock, Digest, MonotonicTime};
use crate::sandbox_contract::provider_evidence::{
    register_provider_adapters, ProviderReport, ProviderReports, RecordOutcome, ReportError,
};

use super::adapters::{
    adapters, Observed, RuntimeBinding, RuntimeFacet, SharedObserved, SleepCycle,
    GPU_MEMORY_FRESH_FOR, SLEEP_CYCLE_FRESH_FOR,
};
use super::fingerprint::{gpu_fingerprint, host_fingerprint, runtime_fingerprint};
use super::inventory::{GpuInventory, HostInventory};

/// A capability this module has no producer for, with the open task that owns it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Uncovered {
    pub capability: Capability,
    /// Which subjects are meant; the rest of the capability may be covered here.
    pub scope: &'static str,
    pub open_task: &'static str,
    pub reason: &'static str,
}

/// Every capability or part of one this host's probes do not observe.
pub const UNCOVERED: &[Uncovered] = &[
    Uncovered {
        capability: Capability::HypervisorAvailable,
        scope: "every hypervisor",
        open_task: "M08",
        reason:
            "The sandbox probes' hypervisor adapter (H06) runs through M08's host check runner.",
    },
    Uncovered {
        capability: Capability::PerimeterRuleEnforced,
        scope: "every perimeter rule",
        open_task: "M10",
        reason: "Needs the installed perimeter and its controlled must-probe (M10, M08).",
    },
    Uncovered {
        capability: Capability::HypervisorConfigurationMatches,
        scope: "every hypervisor process",
        open_task: "M08",
        reason: "The sandbox probes' adapter (VM-CP-02, 03) runs through M08's host check runner.",
    },
    Uncovered {
        capability: Capability::HypervisorConfined,
        scope: "every hypervisor process",
        open_task: "M08",
        reason: "The sandbox probes' adapter (VM-CP-04) runs through M08's host check runner.",
    },
    Uncovered {
        capability: Capability::BootedImageMatchesManifest,
        scope: "every sandbox boot",
        open_task: "M08",
        reason:
            "The sandbox probes' adapter (VM-CP-05, 17, 23) runs through M08's host check runner.",
    },
    Uncovered {
        capability: Capability::DestinationPolicyEnforced,
        scope: "every transport broker",
        open_task: "M08",
        reason: "The sandbox probes' adapter (VM-CP-07, 08) runs through M08's host check runner.",
    },
    Uncovered {
        capability: Capability::NoGuestNetworkDevice,
        scope: "every sandbox boot",
        open_task: "M08",
        reason: "The sandbox probes' adapter (VM-CP-09) runs through M08's host check runner.",
    },
    Uncovered {
        capability: Capability::CredentialAbsentFromScannedLocations,
        scope: "every credential scan",
        open_task: "M08",
        reason: "The sandbox probes' adapter (VM-CP-12) runs through M08's host check runner.",
    },
    Uncovered {
        capability: Capability::CloneIdentityReset,
        scope: "every golden snapshot",
        open_task: "M08",
        reason: "The sandbox probes' adapter (VM-CP-21) runs through M08's host check runner.",
    },
    Uncovered {
        capability: Capability::DeviceAssignmentIsolated,
        scope: "every GPU device",
        open_task: "M08",
        reason: "The sandbox probes' adapter (VM-CP-31) runs through M08's host check runner.",
    },
    Uncovered {
        capability: Capability::RuntimeCategory,
        scope: "local VM sandboxes and per-sandbox VMs on remote hosts",
        open_task: "M02",
        reason: "M02 backend; management evidence (M16).",
    },
    Uncovered {
        capability: Capability::ComputePlatform,
        scope: "local VM sandboxes, per-sandbox VMs on remote hosts and the native macOS runner",
        open_task: "G02",
        reason: "Observed by the backend or provider that runs them (G02, M02, M11).",
    },
    Uncovered {
        capability: Capability::PeerTopology,
        scope: "runtimes with more than one GPU",
        open_task: "O07",
        reason: "Peer access must be exercised between the GPUs, never assumed (FAST-02).",
    },
    Uncovered {
        capability: Capability::GpuPeerAccess,
        scope: "every GPU pair",
        open_task: "O07",
        reason: "Needs a peer copy exercised between the two GPUs.",
    },
    Uncovered {
        capability: Capability::CudaIpcLegacy,
        scope: "every runtime",
        open_task: "O07",
        reason: "Needs a legacy CUDA IPC export and import exercised.",
    },
    Uncovered {
        capability: Capability::CudaIpcVmmShareableHandle,
        scope: "every runtime",
        open_task: "O07",
        reason: "Needs a CUDA VMM handle exported and imported.",
    },
    Uncovered {
        capability: Capability::CudaVmmAllocation,
        scope: "every allocation",
        open_task: "O06",
        reason: "Needs the driver asked for the exact handle type's granularity on the device.",
    },
    Uncovered {
        capability: Capability::GpuDirectStorage,
        scope: "every runtime",
        open_task: "O06",
        reason: "Needs a GPUDirect Storage read exercised.",
    },
    Uncovered {
        capability: Capability::IoUring,
        scope: "every runtime",
        open_task: "O06",
        reason:
            "Needs the runtime's own kernel to set up a ring; the WSL kernel is not the host's.",
    },
    Uncovered {
        capability: Capability::ExecuteWhileLoad,
        scope: "every runtime",
        open_task: "O06",
        reason: "Needs execute-while-load run with its dependencies met.",
    },
    Uncovered {
        capability: Capability::CudaCheckpoint,
        scope: "every runtime",
        open_task: "O08",
        reason: "Needs a CUDA checkpoint and restore exercised.",
    },
    Uncovered {
        capability: Capability::ZeroCopyPreload,
        scope: "every runtime",
        open_task: "G02",
        reason: "A backend mode is recorded by the backend release that ran it.",
    },
    Uncovered {
        capability: Capability::SleepWeightOffload,
        scope: "every runtime",
        open_task: "G02",
        reason: "A backend mode is recorded by the backend release that ran it.",
    },
    Uncovered {
        capability: Capability::SleepWeightDiscard,
        scope: "runtimes that have not parked by sleep and woken while bound",
        open_task: "G02",
        reason: "Observed by the engine on a bound vLLM runtime that parks by sleep (level 2) and wakes: the host probe sees the park return its memory and the wake take it again. Other runners do not sleep.",
    },
    Uncovered {
        capability: Capability::CheckpointCompatibility,
        scope: "every checkpoint",
        open_task: "G02",
        reason: "Needs the checkpoint measured on its engine and hardware class.",
    },
    Uncovered {
        capability: Capability::KvGrowth,
        scope: "every runtime",
        open_task: "G06",
        reason: "Reported by the backend release that maps its KV pool in increments. No pinned runner does so; each runner's status (`model_status` capabilities.kvGrowth) says why, as the launch's own fact, not host evidence.",
    },
    Uncovered {
        capability: Capability::AdapterLimits,
        scope: "every runtime",
        open_task: "G06",
        reason: "Reported by the backend release that serves unmerged adapters. vLLM launches the owner enabled them for (`model_adapters --action enable`) serve them within its pool; their slot and rank limits are the launch's own facts in `model_status` capabilities.adapters, and their memory has not been measured, so no host evidence covers them.",
    },
];

/// What one reconciliation did.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallReport {
    /// The inventory started before the one in force, so it was not installed.
    pub superseded: bool,
    pub removed_subjects: usize,
    pub changed_configurations: usize,
    pub dropped_evidence: usize,
    pub observed: usize,
    /// Observations the registry refused, with why.
    pub refused: Vec<(Capability, String)>,
}

/// Whether the latest evidence satisfies the requirement the status states for it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Verdict {
    Satisfied,
    Refused {
        refusal: EvidenceRefusal,
        remedy: Remedy,
    },
    /// No inventory has been collected, so no configuration is known to require.
    NotCollected,
}

/// One capability of one subject.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusEntry {
    pub capability: Capability,
    pub subject: Subject,
    pub configuration: Option<ConfigurationFingerprint>,
    pub evidence: Option<EvidenceEnvelope>,
    pub verdict: Verdict,
}

/// Everything this host's probes observe, and what they leave to others.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceStatus {
    pub inventory: Option<HostInventory>,
    pub inventory_age_ms: Option<u64>,
    pub entries: Vec<StatusEntry>,
    pub uncovered: &'static [Uncovered],
}

#[derive(Clone, Debug)]
struct Known {
    subject: Subject,
    configuration: Option<ConfigurationFingerprint>,
    capabilities: Vec<Capability>,
}

/// The engine's CORE-01 registry for this computer, with the adapters of this module.
pub struct EvidenceService<C: Clock + 'static> {
    clock: Arc<C>,
    registry: ProbeRegistry<Arc<C>>,
    observed: SharedObserved,
    known: BTreeMap<Digest, Known>,
    /// Provider reports (M11's provider API adapters, `sandbox_contract::provider_evidence`)
    /// on this registry's clock: provider resources, and the runtimes of reported provider
    /// instances, which this module's host adapters never claim.
    provider_reports: Arc<ProviderReports<C>>,
}

/// How long evidence of `capability` stays usable: its observation's freshness bound.
fn max_age(capability: Capability) -> Duration {
    if capability == Capability::SleepWeightDiscard {
        return SLEEP_CYCLE_FRESH_FOR;
    }
    RuntimeFacet::ALL
        .into_iter()
        .find(|facet| facet.capability() == capability)
        .map_or(GPU_MEMORY_FRESH_FOR, RuntimeFacet::fresh_for)
}

impl<C: Clock + 'static> EvidenceService<C> {
    /// A service on `clock` with every adapter of this module registered.
    pub fn new(clock: Arc<C>) -> Result<Self, RegistryError> {
        let observed = SharedObserved::default();
        let mut registry = ProbeRegistry::new(Arc::clone(&clock));
        for adapter in adapters(&clock, &observed) {
            registry.register(adapter)?;
        }
        let provider_reports = Arc::new(ProviderReports::new(Arc::clone(&clock)));
        register_provider_adapters(&mut registry, &provider_reports)?;
        Ok(Self {
            clock,
            registry,
            observed,
            known: BTreeMap::new(),
            provider_reports,
        })
    }

    /// The provider report store, for the provider transport to record into through
    /// [`Self::record_provider_report`] (or a `ReportingPort`, then
    /// [`Self::invalidate_after`]).
    pub fn provider_reports(&self) -> &Arc<ProviderReports<C>> {
        &self.provider_reports
    }

    /// Records what a provider call that started at `started_at` reported, and drops the
    /// evidence observed under the instance's previous report when it changed.
    pub fn record_provider_report(
        &mut self,
        report: ProviderReport,
        started_at: MonotonicTime,
    ) -> Result<RecordOutcome, ReportError> {
        let outcome = self.provider_reports.record(report, started_at)?;
        self.invalidate_after(outcome);
        Ok(outcome)
    }

    /// Drops the evidence a changed provider report superseded; returns how many
    /// envelopes went. Other outcomes change nothing.
    pub fn invalidate_after(&mut self, outcome: RecordOutcome) -> usize {
        match outcome {
            RecordOutcome::Changed { previous, .. } => {
                self.registry.invalidate_configuration(previous)
            }
            RecordOutcome::New { .. }
            | RecordOutcome::Refreshed { .. }
            | RecordOutcome::Superseded { .. } => 0,
        }
    }

    /// Observes `capability` of `subject` now through the one adapter that claims it, such
    /// as a provider subject after its report was recorded.
    pub fn observe(
        &mut self,
        capability: Capability,
        subject: &Subject,
    ) -> Result<&EvidenceEnvelope, RegistryError> {
        self.registry.refresh(capability, subject)
    }

    /// Forgets the report about a provider instance, such as after the provider confirmed
    /// its termination, and drops the evidence observed under it; returns how many
    /// envelopes went.
    pub fn forget_provider_report(&mut self, instance: &Digest) -> usize {
        self.provider_reports
            .forget(instance)
            .map_or(0, |configuration| {
                self.registry.invalidate_configuration(configuration)
            })
    }

    /// The time on this service's clock, taken before a collection starts.
    pub fn now(&self) -> MonotonicTime {
        self.clock.now()
    }

    /// The registry, for consumers that evaluate requirements or read evidence.
    pub fn registry(&self) -> &ProbeRegistry<Arc<C>> {
        &self.registry
    }

    fn observed(&self) -> RwLockWriteGuard<'_, Observed> {
        // The adapters only read; a panic while holding the lock left nothing half
        // written, so the state is still usable.
        self.observed
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Installs `inventory` and observes everything again; an inventory that started
    /// before the one in force is not installed.
    pub fn install(&mut self, inventory: HostInventory) -> InstallReport {
        {
            let mut observed = self.observed();
            if observed
                .inventory
                .as_ref()
                .is_some_and(|current| inventory.started_at < current.started_at)
            {
                return InstallReport {
                    superseded: true,
                    ..InstallReport::default()
                };
            }
            observed.inventory = Some(inventory);
        }
        self.reconcile()
    }

    /// Binds a runtime the engine launched locally, and observes it.
    pub fn bind_runtime(&mut self, binding: RuntimeBinding) -> InstallReport {
        let identity = Subject::Runtime(binding.runtime().clone()).identity();
        self.observed().bindings.insert(identity, binding);
        self.reconcile()
    }

    /// Unbinds a runtime that stopped; its evidence is dropped.
    pub fn unbind_runtime(&mut self, runtime: &RuntimeSubject) -> InstallReport {
        let identity = Subject::Runtime(runtime.clone()).identity();
        {
            let mut observed = self.observed();
            observed.bindings.remove(&identity);
            observed.sleep_cycles.remove(&identity);
        }
        self.reconcile()
    }

    /// Records a sleep cycle the engine saw on a runtime it bound (G01/G02), stamped now on
    /// this service's clock, and observes it; refused for a runtime not bound.
    pub fn record_sleep_cycle(
        &mut self,
        runtime: &RuntimeSubject,
        mut cycle: SleepCycle,
    ) -> Result<InstallReport, String> {
        let identity = Subject::Runtime(runtime.clone()).identity();
        cycle.recorded_at = self.clock.now();
        {
            let mut observed = self.observed();
            if !observed
                .bindings
                .get(&identity)
                .is_some_and(|binding| binding.runtime() == runtime)
            {
                return Err(
                    "The runtime is not bound to host evidence; its sleep cycle is not recorded."
                        .into(),
                );
            }
            observed.sleep_cycles.insert(identity, cycle);
        }
        Ok(self.reconcile())
    }

    /// The sleep cycles recorded of the runtimes bound now, with their runtimes.
    pub fn sleep_cycles(&self) -> Vec<(RuntimeSubject, SleepCycle)> {
        let observed = self
            .observed
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        observed
            .sleep_cycles
            .iter()
            .filter_map(|(identity, cycle)| {
                let binding = observed.bindings.get(identity)?;
                Some((binding.runtime().clone(), cycle.clone()))
            })
            .collect()
    }

    /// Observes every known subject again from the inventory in force.
    pub fn refresh(&mut self) -> InstallReport {
        self.reconcile()
    }

    /// The subjects the current inventory and bindings name. GPUs keep being named while
    /// the GPU query cannot answer, so their evidence turns explicitly unavailable rather
    /// than vanishing.
    fn current(&self) -> BTreeMap<Digest, Known> {
        let observed = self
            .observed
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut current = BTreeMap::new();
        let inventory = observed.inventory.as_ref();
        if let Some(inventory) = inventory {
            if let Some(machine) = inventory.machine.digest() {
                match &inventory.gpus {
                    GpuInventory::Devices { devices } => {
                        for gpu in devices {
                            let subject = Subject::GpuDevice(GpuDeviceSubject {
                                machine,
                                device: gpu.device,
                            });
                            current.insert(
                                subject.identity(),
                                Known {
                                    subject,
                                    configuration: gpu_fingerprint(inventory, gpu).ok(),
                                    capabilities: vec![Capability::GpuFreeMemory],
                                },
                            );
                        }
                    }
                    GpuInventory::Unavailable { .. } => {
                        let configuration = host_fingerprint(inventory).ok();
                        for (identity, known) in &self.known {
                            if matches!(&known.subject, Subject::GpuDevice(gpu) if gpu.machine == machine)
                            {
                                current.insert(
                                    *identity,
                                    Known {
                                        configuration,
                                        ..known.clone()
                                    },
                                );
                            }
                        }
                    }
                }
            }
        }
        for (identity, binding) in &observed.bindings {
            let mut capabilities: Vec<Capability> = RuntimeFacet::ALL
                .into_iter()
                .map(RuntimeFacet::capability)
                .collect();
            if observed.sleep_cycles.contains_key(identity) {
                capabilities.push(Capability::SleepWeightDiscard);
            }
            current.insert(
                *identity,
                Known {
                    subject: Subject::Runtime(binding.runtime().clone()),
                    configuration: inventory
                        .and_then(|inventory| runtime_fingerprint(inventory, binding).ok()),
                    capabilities,
                },
            );
        }
        current
    }

    fn reconcile(&mut self) -> InstallReport {
        let current = self.current();
        let mut report = InstallReport::default();
        for (identity, old) in &self.known {
            match current.get(identity) {
                None => {
                    report.removed_subjects += 1;
                    report.dropped_evidence += self.registry.invalidate_subject(&old.subject);
                }
                Some(new) if new.configuration != old.configuration => {
                    report.changed_configurations += 1;
                    if let Some(configuration) = old.configuration {
                        report.dropped_evidence +=
                            self.registry.invalidate_configuration(configuration);
                    }
                }
                Some(_) => {}
            }
        }
        self.known = current;
        for known in self.known.values() {
            for capability in &known.capabilities {
                match self.registry.refresh(*capability, &known.subject) {
                    Ok(_) => report.observed += 1,
                    Err(error) => report.refused.push((*capability, error.to_string())),
                }
            }
        }
        report
    }

    /// The requirement this service states for `capability` of `subject`: evidence from
    /// at least the capability's weakest source, no older than its observation's
    /// freshness bound, under the configuration in force. A subject this host's adapters
    /// do not know is stated through the provider reports (`ProviderReports::requirement`,
    /// with the provider capabilities' own freshness). `None` for a subject neither
    /// knows, or before any inventory.
    pub fn requirement(&self, capability: Capability, subject: &Subject) -> Option<Requirement> {
        let Some(known) = self.known.get(&subject.identity()) else {
            return self.provider_reports.requirement(capability, subject).ok();
        };
        let configuration = known.configuration?;
        Some(Requirement::new(
            capability,
            subject.clone(),
            capability.weakest_source(),
            max_age(capability),
            configuration,
        ))
    }

    /// Evaluates `requirement` against this computer's evidence now.
    pub fn evaluate(&self, requirement: &Requirement) -> Result<Satisfied, EvidenceRefusal> {
        self.registry.evaluate(requirement)
    }

    /// Every observed capability with its verdict, and what is left to other tasks.
    pub fn status(&self) -> EvidenceStatus {
        let mut entries = Vec::new();
        for known in self.known.values() {
            for capability in &known.capabilities {
                let verdict = match self.requirement(*capability, &known.subject) {
                    None => Verdict::NotCollected,
                    Some(requirement) => match self.evaluate(&requirement) {
                        Ok(_) => Verdict::Satisfied,
                        Err(refusal) => Verdict::Refused {
                            remedy: refusal.remedy(),
                            refusal,
                        },
                    },
                };
                entries.push(StatusEntry {
                    capability: *capability,
                    subject: known.subject.clone(),
                    configuration: known.configuration,
                    evidence: self.registry.latest(*capability, &known.subject).cloned(),
                    verdict,
                });
            }
        }
        let inventory = self
            .observed
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .inventory
            .clone();
        let inventory_age_ms = inventory.as_ref().map(|inventory| {
            let age = self.now().saturating_duration_since(inventory.started_at);
            u64::try_from(age.as_millis()).unwrap_or(u64::MAX)
        });
        EvidenceStatus {
            inventory,
            inventory_age_ms,
            entries,
            uncovered: UNCOVERED,
        }
    }
}
