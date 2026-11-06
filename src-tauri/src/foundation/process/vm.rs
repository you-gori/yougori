//! VM host processes under the sandbox lifecycle (S04; S2 CORE-04; VM part §6.1, §6.3,
//! §6.4; VM-CP-19).
//!
//! A VM backend that runs each VM as a host process keeps those processes in a
//! [`VmProcesses`] table, and [`ObservedTermination`] presents the backend to the
//! coordinator as its [`SandboxPort`]. The coordinator's termination, revocation, rollback
//! and recovery all end a VM through [`SandboxPort::terminate_vm`] and find live VMs through
//! [`SandboxPort::list_vms`], so the end of a VM is decided in one place: a VM counts as
//! terminated only on the host's [`TerminationProof`] that its process and every process of
//! its job ended. Without it the termination stalls, and the coordinator releases nothing
//! still in use (its `TerminationStalled`). Recovery never treats as gone a VM whose
//! process the host still holds alive, and never as alive one whose end the host observed.
//! A VM whose process the host does not hold, or whose process the host sees ended, is
//! never ready, so it never gets authority. Model runners are not held here: a model
//! activation's process belongs to the model side's [`RunnerProcesses`](super::RunnerProcesses)
//! (S3.1).

use std::collections::BTreeMap;
use std::fmt;

use serde::Serialize;

use super::handle::{Escalation, HostProcess};
use super::identity::ProcessRole;
use super::proof::{NoProof, TerminationProof};
use super::settle::BoundProcesses;
use crate::foundation::coordination::{
    BootRequest, ObservedVm, PerimeterId, PortFailure, PortOperation, Readiness, ReadinessReport,
    RestoredVmReport, SandboxPort, SnapshotManifest, VmInstanceId,
};
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::SandboxBootGeneration;

/// Why a process was not held, as a VM's host process or as a model runner. The refused
/// process is dropped, which kills it with its job.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum BindRefusal {
    /// Only a VM host process is held in [`VmProcesses`]; a model runner belongs to the
    /// model side (S3.1).
    NotAVmHost { role: ProcessRole },
    /// The VM has a host process already, or had one whose end was proven: a VM instance
    /// is bound once.
    AlreadyBound { vm: VmInstanceId },
    /// Only a model runner is held in [`RunnerProcesses`](super::RunnerProcesses); a VM's
    /// host process belongs to the sandbox lifecycle (S3.1).
    NotAModelRunner { role: ProcessRole },
    /// The runner role is bound to a process the host has not seen end: one live process
    /// per model activation and GPU allocation.
    RunnerStillRunning { role: ProcessRole },
}

impl fmt::Display for BindRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAVmHost { role } => write!(f, "{role} is not a VM host process"),
            Self::AlreadyBound { vm } => write!(f, "VM {vm} already has its host process"),
            Self::NotAModelRunner { role } => write!(f, "{role} is not a model runner"),
            Self::RunnerStillRunning { role } => {
                write!(f, "{role} is bound to a process that has not ended")
            }
        }
    }
}

impl std::error::Error for BindRefusal {}

/// The host processes of the VMs a backend started, each held for its whole life, and the
/// proofs of those that ended (VM part §6.4).
#[derive(Debug)]
pub struct VmProcesses {
    escalation: Escalation,
    running: BTreeMap<VmInstanceId, HostProcess>,
    ended: BTreeMap<VmInstanceId, TerminationProof>,
}

impl VmProcesses {
    /// An empty table that ends VMs with `escalation`.
    pub fn new(escalation: Escalation) -> Self {
        Self {
            escalation,
            running: BTreeMap::new(),
            ended: BTreeMap::new(),
        }
    }

    /// Holds `process` as the host process of the VM its role names, and returns that VM.
    pub fn bind(&mut self, process: HostProcess) -> Result<VmInstanceId, BindRefusal> {
        let ProcessRole::VmHost { vm, .. } = process.role() else {
            return Err(BindRefusal::NotAVmHost {
                role: process.role().clone(),
            });
        };
        let vm = *vm;
        if self.running.contains_key(&vm) || self.ended.contains_key(&vm) {
            return Err(BindRefusal::AlreadyBound { vm });
        }
        self.running.insert(vm, process);
        Ok(vm)
    }

    /// The host process of `vm`, while it is held and its end is not proven.
    pub fn process(&self, vm: &VmInstanceId) -> Option<&HostProcess> {
        self.running.get(vm)
    }

    /// The proof that `vm`'s host process ended, once the host observed it.
    pub fn proof(&self, vm: &VmInstanceId) -> Option<&TerminationProof> {
        self.ended.get(vm)
    }

    /// Looks at every held process once, without waiting or killing; each the host now
    /// observes ended, with every process of its job, moves to the proven. Returns those
    /// VMs.
    pub fn refresh(&mut self) -> Vec<VmInstanceId> {
        let proven: Vec<(VmInstanceId, TerminationProof)> = self
            .running
            .iter()
            .filter_map(|(vm, process)| process.check_ended().ok().map(|proof| (*vm, proof)))
            .collect();
        proven
            .into_iter()
            .map(|(vm, proof)| {
                self.running.remove(&vm);
                self.ended.insert(vm, proof);
                vm
            })
            .collect()
    }

    /// Whether the host holds a process for `vm` of boot `boot` that it sees running now,
    /// looking once without waiting. One that ended, one whose child alone still runs, and
    /// one the host cannot observe are not held.
    fn holds(&self, vm: &VmInstanceId, boot: SandboxBootGeneration) -> bool {
        self.running.get(vm).is_some_and(|process| {
            matches!(process.role(), ProcessRole::VmHost { boot: bound, .. } if *bound == boot)
                && process.check_ended() == Err(NoProof::StillRunning)
        })
    }

    /// Ends `vm`'s host process with the table's escalation and keeps the proof. Refused
    /// for a VM whose process the host does not hold.
    fn end(&mut self, vm: &VmInstanceId) -> Result<(), String> {
        if self.ended.contains_key(vm) {
            return Ok(());
        }
        let Some(process) = self.running.get(vm) else {
            return Err(format!(
                "the host holds no process handle for VM {vm}, so its end cannot be observed"
            ));
        };
        let proof = process
            .terminate(self.escalation)
            .map_err(|no_proof: NoProof| {
                format!("the host did not observe the end of VM {vm}'s process: {no_proof}")
            })?;
        self.running.remove(vm);
        self.ended.insert(*vm, proof);
        Ok(())
    }

    /// The VMs whose processes the host holds, as reconciliation sees them.
    fn held(&self) -> impl Iterator<Item = ObservedVm> + '_ {
        self.running
            .values()
            .filter_map(|process| match process.role() {
                ProcessRole::VmHost {
                    execution,
                    vm,
                    boot,
                } => Some(ObservedVm {
                    vm: *vm,
                    execution: execution.clone(),
                    boot: *boot,
                }),
                ProcessRole::ModelRunner { .. }
                | ProcessRole::GuestRelay { .. }
                | ProcessRole::SandboxExecutor { .. }
                | ProcessRole::SandboxSupervisor { .. } => None,
            })
    }
}

impl BoundProcesses for VmProcesses {
    /// Whether the proof is of the process held, or proven ended, for the VM its role
    /// names.
    fn binds(&self, proof: &TerminationProof) -> bool {
        let ProcessRole::VmHost { vm, .. } = proof.role() else {
            return false;
        };
        let bound = self
            .running
            .get(vm)
            .map(|process| (process.identity(), process.role()))
            .or_else(|| {
                self.ended
                    .get(vm)
                    .map(|ended| (ended.identity(), ended.role()))
            });
        bound == Some((proof.identity(), proof.role()))
    }
}

/// A VM backend whose VMs run as host processes it started through [`HostProcess`] and
/// holds in its [`VmProcesses`].
pub trait ProcessBackedVms: SandboxPort {
    /// The backend's VM host processes.
    fn vm_processes(&mut self) -> &mut VmProcesses;
}

/// The backend `B` as the coordinator's [`SandboxPort`], with every VM's end observed by
/// the host (S04; VM part §6.4).
///
/// - Terminating a VM asks the backend first, which may stop it gracefully, then ends its
///   host process through [`HostProcess::terminate`]. Only the proof that the process and
///   every process of its job ended lets the termination succeed; otherwise it fails and
///   the coordinator stalls without releasing anything. A VM whose process the host does
///   not hold fails the same way. Once proven, terminating again only asks the backend.
/// - Listing VMs, for recovery, drops those whose end the host observed and adds those
///   whose process the host holds alive but the backend no longer lists.
/// - A VM whose process the host does not hold, for the boot asked about, or sees ended,
///   is not ready; an ended one moves to the proven first.
pub struct ObservedTermination<'a, B: ProcessBackedVms + ?Sized> {
    backend: &'a mut B,
}

impl<'a, B: ProcessBackedVms + ?Sized> ObservedTermination<'a, B> {
    /// The port over `backend`.
    pub fn new(backend: &'a mut B) -> Self {
        Self { backend }
    }
}

impl<B: ProcessBackedVms + ?Sized> SandboxPort for ObservedTermination<'_, B> {
    fn prepare_perimeter(&mut self, request: &BootRequest) -> Result<PerimeterId, PortFailure> {
        self.backend.prepare_perimeter(request)
    }

    fn create_vm(
        &mut self,
        request: &BootRequest,
        perimeter: &PerimeterId,
    ) -> Result<VmInstanceId, PortFailure> {
        self.backend.create_vm(request, perimeter)
    }

    fn restore_vm(
        &mut self,
        request: &BootRequest,
        perimeter: &PerimeterId,
        snapshot: &SnapshotManifest,
    ) -> Result<VmInstanceId, PortFailure> {
        self.backend.restore_vm(request, perimeter, snapshot)
    }

    fn observe_readiness(
        &mut self,
        vm: &VmInstanceId,
        boot: SandboxBootGeneration,
    ) -> ReadinessReport {
        let processes = self.backend.vm_processes();
        processes.refresh();
        if !processes.holds(vm, boot) {
            return ReadinessReport {
                source: SourceClass::HostProbe,
                readiness: Readiness::NotReady {
                    detail: format!(
                        "the host holds no running process for VM {vm} of boot generation {boot}"
                    ),
                },
            };
        }
        self.backend.observe_readiness(vm, boot)
    }

    fn inspect_restored_vm(
        &mut self,
        vm: &VmInstanceId,
        boot: SandboxBootGeneration,
    ) -> RestoredVmReport {
        self.backend.inspect_restored_vm(vm, boot)
    }

    fn terminate_vm(&mut self, vm: &VmInstanceId) -> Result<(), PortFailure> {
        let asked = self.backend.terminate_vm(vm);
        self.backend
            .vm_processes()
            .end(vm)
            .map_err(|detail| PortFailure {
                operation: PortOperation::TerminateVm,
                detail,
            })?;
        asked
    }

    fn teardown_perimeter(&mut self, perimeter: &PerimeterId) -> Result<(), PortFailure> {
        self.backend.teardown_perimeter(perimeter)
    }

    fn list_vms(&mut self) -> Result<Vec<ObservedVm>, PortFailure> {
        let mut listed = self.backend.list_vms()?;
        let processes = self.backend.vm_processes();
        processes.refresh();
        listed.retain(|found| processes.proof(&found.vm).is_none());
        let unlisted: Vec<ObservedVm> = processes
            .held()
            .filter(|held| !listed.iter().any(|found| found.vm == held.vm))
            .collect();
        listed.extend(unlisted);
        Ok(listed)
    }
}
