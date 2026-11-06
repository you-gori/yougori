//! The sandbox port (VM part §6.1, §6.4, §6.6): the VM-side effects the coordination
//! protocol asks of the RUNTIME backend. The protocol only calls it, and tests use a fake;
//! no VM backend lives here.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::capacity::ReservationKey;
use super::identity::{PerimeterId, SandboxGenerations, VmInstanceId};
use super::recovery::{RestoredVmReport, SnapshotManifest};
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{ExecutionId, SandboxBootGeneration, TenantId};

/// One operation of the [`SandboxPort`] that can fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortOperation {
    PreparePerimeter,
    CreateVm,
    RestoreVm,
    TerminateVm,
    TeardownPerimeter,
    ListVms,
}

impl fmt::Display for PortOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PreparePerimeter => "prepare the perimeter",
            Self::CreateVm => "create the VM",
            Self::RestoreVm => "restore the VM",
            Self::TerminateVm => "terminate the VM",
            Self::TeardownPerimeter => "remove the perimeter",
            Self::ListVms => "list the VMs",
        })
    }
}

/// A failure the backend reported for one operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortFailure {
    pub operation: PortOperation,
    /// The backend's own description, kept as reported.
    pub detail: String,
}

impl fmt::Display for PortFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "could not {}: {}", self.operation, self.detail)
    }
}

impl std::error::Error for PortFailure {}

/// One boot of one sandbox, as the backend receives it.
///
/// The backend treats a repeated request for the same execution and generations as the
/// same object, so retrying a step never creates a second one (VM part §6.1: every
/// transition is idempotent).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootRequest {
    pub execution: ExecutionId,
    pub tenant: TenantId,
    pub generations: SandboxGenerations,
    /// The sandbox reservation the boot runs within (S10: reserve before creating).
    pub reservation: ReservationKey,
}

/// What the backend observed about a VM's readiness.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "readiness", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum Readiness {
    Ready,
    NotReady { detail: String },
}

crate::foundation::strict_serde::strict_tag!(Readiness, "readiness");

/// A readiness observation and its source. Only a host probe is host-observed readiness
/// (VM part §6.1; S10 line 181: optional optimizations never replace it).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessReport {
    pub source: SourceClass,
    pub readiness: Readiness,
}

/// A VM the backend manages, found by its stable handle and never by a stored PID (VM part
/// §6.4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedVm {
    pub vm: VmInstanceId,
    pub execution: ExecutionId,
    pub boot: SandboxBootGeneration,
}

/// What the coordination protocol asks of the VM backend (RUNTIME; VM part §6.1).
///
/// Every method acts on host-created handles. Terminating or removing something that is
/// already gone succeeds.
pub trait SandboxPort {
    /// Prepares the perimeter for one boot (§6.1 perimeter_ready).
    fn prepare_perimeter(&mut self, request: &BootRequest) -> Result<PerimeterId, PortFailure>;

    /// Boots a fresh VM inside `perimeter` (§6.1 VM_created). A failure leaves no VM
    /// behind: the backend removes a partial one before it reports the failure, so the
    /// failure is the host's observation that nothing was created.
    fn create_vm(
        &mut self,
        request: &BootRequest,
        perimeter: &PerimeterId,
    ) -> Result<VmInstanceId, PortFailure>;

    /// Restores a VM from `snapshot` inside `perimeter`. The restored VM is verified
    /// before it receives authority (S10 line 181). A failure leaves no VM behind, as for
    /// [`SandboxPort::create_vm`].
    fn restore_vm(
        &mut self,
        request: &BootRequest,
        perimeter: &PerimeterId,
        snapshot: &SnapshotManifest,
    ) -> Result<VmInstanceId, PortFailure>;

    /// Observes whether the VM is ready (§6.1 boot_evidence_checked).
    fn observe_readiness(
        &mut self,
        vm: &VmInstanceId,
        boot: SandboxBootGeneration,
    ) -> ReadinessReport;

    /// The restored-VM verification hook (S10 line 181; VM part §6.6): what the host found
    /// in the restored VM.
    fn inspect_restored_vm(
        &mut self,
        vm: &VmInstanceId,
        boot: SandboxBootGeneration,
    ) -> RestoredVmReport;

    /// Terminates the VM through its handle.
    fn terminate_vm(&mut self, vm: &VmInstanceId) -> Result<(), PortFailure>;

    /// Removes the perimeter.
    fn teardown_perimeter(&mut self, perimeter: &PerimeterId) -> Result<(), PortFailure>;

    /// Every VM the backend manages, for reconciliation.
    fn list_vms(&mut self) -> Result<Vec<ObservedVm>, PortFailure>;
}
