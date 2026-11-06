//! Production producers of CORE-01 evidence about this computer (S01;
//! docs/combined-gpu-memory-and-vm-sandbox-plan.md: the S2 CORE-01 row, GPU-W00 "supply
//! bounded GPU probe adapters to CORE-01, with dry-run descriptions and separate
//! real-hardware execution" and GPU-W02 "add GPU/backend-specific observations ... to
//! CORE-01; keep inference-runner identity distinct from VmBackend identity").
//!
//! The work splits into the separate real-hardware execution and the adapters:
//!
//! - [`collect`] runs a fixed [`plan`] of bounded, read-only host queries (machine
//!   identity, operating system build, the NVIDIA GPU inventory): each spawned directly
//!   with no shell, hidden, with a deadline and an output bound, and killed and reaped
//!   when either is exceeded. [`plan`] describes the same queries without running them,
//!   for a dry run.
//! - [`HostInventory`] is what one collection observed, already parsed and checked, and
//!   named by the same machine and device digests host admission uses
//!   (`model_runner/optimizer/capacity/probe.rs`), so ledger and evidence speak of the
//!   same subjects; raw identifiers never leave the parser.
//! - The adapters observe only the latest inventory; they never run anything. They are
//!   CORE-01 [`ProbeAdapter`](crate::foundation::evidence::ProbeAdapter)s of the host
//!   probe class: free and total memory per GPU, and for a local runtime its compute
//!   platform, its execution category and its peer topology.
//! - [`EvidenceService`] owns the [`ProbeRegistry`](crate::foundation::evidence::ProbeRegistry).
//!   Installing a new inventory drops the evidence of every subject whose configuration
//!   fingerprint changed or that disappeared (CORE-01: changed configurations invalidate
//!   relevant evidence) and observes everything again. Its status names, for every
//!   capability, either the current evidence with its verdict or the open task whose
//!   producer it waits for, so nothing is silently unavailable.
//! - The engine's automation method `host_evidence` shows the status, refreshes it, or
//!   lists the plan.
//!
//! Hypervisor, perimeter and guest checks belong to the sandbox probes (H06/M08), provider
//! observations to the provider adapters (M11/M16), and capabilities that need a CUDA or
//! backend operation exercised to the GPU packages (G02, O06, O07); see [`UNCOVERED`].

mod adapters;
mod collect;
mod engine;
mod fingerprint;
mod inventory;
mod service;

#[cfg(test)]
mod tests;

pub use adapters::{
    BindingError, RuntimeBinding, SleepCycle, COMPUTE_PLATFORM_FRESH_FOR, GPU_MEMORY_FRESH_FOR,
    PEER_TOPOLOGY_FRESH_FOR, RUNTIME_CATEGORY_FRESH_FOR, SLEEP_CYCLE_FRESH_FOR,
    SLEEP_DISCARD_MIN_BYTES,
};
pub use collect::{collect, plan, Query, QueryDescription, QueryOutcome};
pub(crate) use engine::{
    bind_runtime, dispatch, inventory_and_now, record_sleep_cycle, record_unbound, unbind_runtime,
};

/// The `host_evidence` desktop command, for the host evidence view
/// (`src/components/security/host-evidence.tsx`): the same answer as the automation method
/// (`status`, the default; `refresh`; `plan`).
#[tauri::command]
pub async fn host_evidence(
    app: crate::AppHandle,
    action: Option<String>,
) -> Result<serde_json::Value, String> {
    engine::dispatch(app, action).await
}
pub use fingerprint::{gpu_fingerprint, host_fingerprint, runtime_fingerprint};
pub use inventory::{
    device_digest, machine_digest, parse_gpus, parse_os_release, parse_registry_value,
    CudaRuntimeFacts, DriverModel, GpuDevice, GpuInventory, HostInventory, InventoryProblem,
    MachineIdentity, MigMode, OsFacts, MACHINE_DOMAIN, MAX_GPUS, NVIDIA_DEVICE_DOMAIN,
};
pub use service::{
    EvidenceService, EvidenceStatus, InstallReport, StatusEntry, Uncovered, Verdict, UNCOVERED,
};
