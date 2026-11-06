//! The backend port (VM part §6.1, §6.4, §6.6): what the lifecycle asks of a VM backend
//! (launch, stop, snapshot, restore, handle identity check), and the bridge that presents
//! it to the coordinator as its [`SandboxPort`]. The real backend contract is adapted to
//! this port at integration; the tests use a scripted fake.
//!
//! Every VM is reached through a host-created [`VmHandle`] whose identity is checked
//! before any stop: a stored number that another process may have taken is never acted
//! on (§6.4 "never terminate an unrelated process because a stored PID was reused").

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::foundation::coordination::{
    BootRequest, ObservedVm, PerimeterId, PortFailure, PortOperation, ReadinessReport,
    RestoredVmReport, SandboxPort, SnapshotManifest, SnapshotOrigin, VmInstanceId,
};
use crate::foundation::ids::{Digest, ExecutionId, SandboxBootGeneration};

/// One operation of the [`VmBackend`] that can fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendOperation {
    PreparePerimeter,
    Launch,
    Restore,
    Stop,
    Snapshot,
    CheckHandle,
    TeardownPerimeter,
    List,
}

impl fmt::Display for BackendOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PreparePerimeter => "prepare the perimeter",
            Self::Launch => "launch the VM",
            Self::Restore => "restore the VM",
            Self::Stop => "stop the VM",
            Self::Snapshot => "take the snapshot",
            Self::CheckHandle => "check the handle",
            Self::TeardownPerimeter => "remove the perimeter",
            Self::List => "list the VMs",
        })
    }
}

/// A failure the backend reported, kept as reported.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendFailure {
    pub operation: BackendOperation,
    pub detail: String,
}

impl fmt::Display for BackendFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "could not {}: {}", self.operation, self.detail)
    }
}

impl std::error::Error for BackendFailure {}

/// A stable handle to one VM the host created (§6.4: pidfds, Job or process handles,
/// framework VM objects). It names the sandbox and boot it was created for and carries
/// the backend's own identity token, so a check can tell the VM from whatever reused its
/// underlying number. It is never a bare PID.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmHandle {
    pub vm: VmInstanceId,
    pub execution: ExecutionId,
    pub boot: SandboxBootGeneration,
    /// The backend's identity token for the object behind the handle.
    pub token: Digest,
}

impl VmHandle {
    /// The handle as the coordinator reconciles it.
    pub fn observed(&self) -> ObservedVm {
        ObservedVm {
            vm: self.vm,
            execution: self.execution.clone(),
            boot: self.boot,
        }
    }
}

/// What a handle identity check found (§6.4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "identity", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum HandleIdentity {
    /// The object behind the handle is the VM the handle was created for.
    Matches,
    /// The object is gone; stopping it again succeeds.
    Gone,
    /// The object behind the handle's underlying number is not the VM the handle was
    /// created for. It is never acted on.
    Reused { holder: Option<ExecutionId> },
}

crate::foundation::strict_serde::strict_tag!(HandleIdentity, "identity");

/// What a stop did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopOutcome {
    Stopped,
    AlreadyGone,
}

/// Whether the backend can reset a restored clone's state as §6.6 requires.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reset", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum StateReset {
    Supported,
    /// Cloning cannot be made safe on this backend; a checkout cold-boots (§6.6 "choose
    /// cold boot when the application state cannot be safely reset").
    Unsupported {
        detail: String,
    },
}

crate::foundation::strict_serde::strict_tag!(StateReset, "reset");

/// What the backend supports; nothing is assumed (§6.6 "do not assume every backend
/// supports identical snapshot, hotplug or restore behavior").
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendCapabilities {
    pub snapshot_restore: bool,
    pub state_reset: StateReset,
}

/// What the lifecycle asks of a VM backend (VM part §6.1, §6.4, §6.6). Every method acts
/// on host-created handles; stopping or removing something already gone succeeds.
pub trait VmBackend {
    /// What this backend supports.
    fn capabilities(&self) -> BackendCapabilities;

    /// Prepares the perimeter for one boot (§6.1 perimeter_ready).
    fn prepare_perimeter(&mut self, request: &BootRequest) -> Result<PerimeterId, BackendFailure>;

    /// Boots a fresh VM inside `perimeter` (§6.1 VM_created). A failure leaves no VM
    /// behind.
    fn launch(
        &mut self,
        request: &BootRequest,
        perimeter: &PerimeterId,
    ) -> Result<VmHandle, BackendFailure>;

    /// Restores a VM from `snapshot` inside `perimeter` (§6.6). A failure leaves no VM
    /// behind.
    fn restore(
        &mut self,
        request: &BootRequest,
        perimeter: &PerimeterId,
        snapshot: &SnapshotManifest,
    ) -> Result<VmHandle, BackendFailure>;

    /// Observes whether the VM is ready (§6.1 boot_evidence_checked).
    fn observe_readiness(&mut self, handle: &VmHandle) -> ReadinessReport;

    /// What the host found in a restored VM, for verification before authority (§6.6).
    fn inspect_restored(&mut self, handle: &VmHandle) -> RestoredVmReport;

    /// Whether the object behind the handle is still the VM it was created for (§6.4).
    fn check_handle(&mut self, handle: &VmHandle) -> HandleIdentity;

    /// Stops the VM behind the handle. The caller checks the handle first.
    fn stop(&mut self, handle: &VmHandle) -> Result<StopOutcome, BackendFailure>;

    /// Takes a snapshot of the VM, recording when it was taken (§6.6).
    fn snapshot(
        &mut self,
        handle: &VmHandle,
        origin: SnapshotOrigin,
    ) -> Result<SnapshotManifest, BackendFailure>;

    /// Removes the perimeter.
    fn teardown_perimeter(&mut self, perimeter: &PerimeterId) -> Result<(), BackendFailure>;

    /// Every VM the backend manages, by its handle, for reconciliation (§6.1).
    fn list(&mut self) -> Result<Vec<VmHandle>, BackendFailure>;
}

/// The handles of the VMs the supervisor manages, by VM identity. Persisted, and checked
/// against the backend at recovery before any is acted on.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandleTable {
    handles: BTreeMap<VmInstanceId, VmHandle>,
}

impl HandleTable {
    pub fn get(&self, vm: &VmInstanceId) -> Option<&VmHandle> {
        self.handles.get(vm)
    }

    pub fn insert(&mut self, handle: VmHandle) {
        self.handles.insert(handle.vm, handle);
    }

    pub fn remove(&mut self, vm: &VmInstanceId) -> Option<VmHandle> {
        self.handles.remove(vm)
    }

    pub fn iter(&self) -> impl Iterator<Item = &VmHandle> {
        self.handles.values()
    }

    pub fn len(&self) -> usize {
        self.handles.len()
    }

    pub fn is_empty(&self) -> bool {
        self.handles.is_empty()
    }
}

fn port_failure(operation: PortOperation, failure: BackendFailure) -> PortFailure {
    PortFailure {
        operation,
        detail: failure.to_string(),
    }
}

/// The backend as the coordinator's [`SandboxPort`]: it keeps the handle table, checks a
/// handle's identity before every stop and records what it stopped and what it refused.
pub(crate) struct Bridge<'a, B: VmBackend + ?Sized> {
    backend: &'a mut B,
    handles: &'a mut HandleTable,
    /// VMs stopped through their handles, in order.
    pub(crate) stopped: Vec<VmInstanceId>,
    /// Handles whose underlying object was reused by something else; never stopped.
    pub(crate) reused: Vec<(VmInstanceId, HandleIdentity)>,
}

impl<'a, B: VmBackend + ?Sized> Bridge<'a, B> {
    pub(crate) fn new(backend: &'a mut B, handles: &'a mut HandleTable) -> Self {
        Self {
            backend,
            handles,
            stopped: Vec::new(),
            reused: Vec::new(),
        }
    }

    fn handle(&self, vm: &VmInstanceId, boot: SandboxBootGeneration) -> Option<VmHandle> {
        self.handles
            .get(vm)
            .filter(|handle| handle.boot == boot)
            .cloned()
    }

    /// Stops `vm` through its handle after an identity check. A VM without a handle, or
    /// whose object is gone, counts as already stopped. A handle whose object was reused
    /// is refused and never acted on (§6.4).
    pub(crate) fn stop_checked(&mut self, vm: &VmInstanceId) -> Result<StopOutcome, PortFailure> {
        let Some(handle) = self.handles.get(vm).cloned() else {
            return Ok(StopOutcome::AlreadyGone);
        };
        match self.backend.check_handle(&handle) {
            HandleIdentity::Matches => {
                let outcome = self
                    .backend
                    .stop(&handle)
                    .map_err(|failure| port_failure(PortOperation::TerminateVm, failure))?;
                self.handles.remove(vm);
                self.stopped.push(*vm);
                Ok(outcome)
            }
            HandleIdentity::Gone => {
                self.handles.remove(vm);
                Ok(StopOutcome::AlreadyGone)
            }
            identity @ HandleIdentity::Reused { .. } => {
                self.reused.push((*vm, identity.clone()));
                Err(PortFailure {
                    operation: PortOperation::TerminateVm,
                    detail: format!(
                        "the object behind the handle of VM {vm} was reused; it was not \
                         stopped ({identity:?})"
                    ),
                })
            }
        }
    }
}

impl<'a, B: VmBackend + ?Sized> SandboxPort for Bridge<'a, B> {
    fn prepare_perimeter(&mut self, request: &BootRequest) -> Result<PerimeterId, PortFailure> {
        self.backend
            .prepare_perimeter(request)
            .map_err(|failure| port_failure(PortOperation::PreparePerimeter, failure))
    }

    fn create_vm(
        &mut self,
        request: &BootRequest,
        perimeter: &PerimeterId,
    ) -> Result<VmInstanceId, PortFailure> {
        let handle = self
            .backend
            .launch(request, perimeter)
            .map_err(|failure| port_failure(PortOperation::CreateVm, failure))?;
        let vm = handle.vm;
        self.handles.insert(handle);
        Ok(vm)
    }

    fn restore_vm(
        &mut self,
        request: &BootRequest,
        perimeter: &PerimeterId,
        snapshot: &SnapshotManifest,
    ) -> Result<VmInstanceId, PortFailure> {
        let handle = self
            .backend
            .restore(request, perimeter, snapshot)
            .map_err(|failure| port_failure(PortOperation::RestoreVm, failure))?;
        let vm = handle.vm;
        self.handles.insert(handle);
        Ok(vm)
    }

    fn observe_readiness(
        &mut self,
        vm: &VmInstanceId,
        boot: SandboxBootGeneration,
    ) -> ReadinessReport {
        match self.handle(vm, boot) {
            Some(handle) => self.backend.observe_readiness(&handle),
            None => ReadinessReport {
                source: crate::foundation::evidence::SourceClass::HostProbe,
                readiness: crate::foundation::coordination::Readiness::NotReady {
                    detail: format!("no handle for VM {vm} at boot generation {boot}"),
                },
            },
        }
    }

    fn inspect_restored_vm(
        &mut self,
        vm: &VmInstanceId,
        boot: SandboxBootGeneration,
    ) -> RestoredVmReport {
        match self.handle(vm, boot) {
            Some(handle) => self.backend.inspect_restored(&handle),
            None => RestoredVmReport {
                vm: *vm,
                boot,
                snapshot: crate::foundation::coordination::SnapshotId::new(Digest::from_bytes(
                    [0; 32],
                )),
                guest_identity: Digest::from_bytes([0; 32]),
                actions: Default::default(),
                attached_volumes: Default::default(),
                policy: crate::foundation::ids::PolicyEpoch::FIRST,
                image_profile: Digest::from_bytes([0; 32]),
                presented_epochs: Default::default(),
                source: crate::foundation::evidence::SourceClass::Fixture,
            },
        }
    }

    fn terminate_vm(&mut self, vm: &VmInstanceId) -> Result<(), PortFailure> {
        self.stop_checked(vm).map(|_| ())
    }

    fn teardown_perimeter(&mut self, perimeter: &PerimeterId) -> Result<(), PortFailure> {
        self.backend
            .teardown_perimeter(perimeter)
            .map_err(|failure| port_failure(PortOperation::TeardownPerimeter, failure))
    }

    fn list_vms(&mut self) -> Result<Vec<ObservedVm>, PortFailure> {
        let handles = self
            .backend
            .list()
            .map_err(|failure| port_failure(PortOperation::ListVms, failure))?;
        let mut observed = Vec::with_capacity(handles.len());
        for handle in handles {
            observed.push(handle.observed());
            self.handles.insert(handle);
        }
        Ok(observed)
    }
}
