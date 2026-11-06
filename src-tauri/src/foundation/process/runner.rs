//! Model runner processes under the model activations (S04; S2 CORE-04; S3.1).
//!
//! The role a process runs for is what its starter bound at spawn, so two processes could
//! be started for the same model activation and GPU allocation, as by a retry. Settling
//! the runner's leases and reservations on the end of the wrong one would free what the
//! live one still uses. [`RunnerProcesses`] binds each runner role to exactly one process
//! at a time, and [`settle_leases`](super::settle_leases) and
//! [`release_runner_reservations`](super::release_runner_reservations) accept only the
//! proof of that bound process. A role is bound again only once the host saw its process
//! end. VM host processes are not held here: they belong to the sandbox lifecycle's
//! [`VmProcesses`](super::VmProcesses) (S3.1).

use std::collections::BTreeMap;

use super::handle::HostProcess;
use super::identity::ProcessRole;
use super::proof::TerminationProof;
use super::settle::BoundProcesses;
use super::vm::BindRefusal;
use crate::foundation::coordination::ModelId;
use crate::foundation::ids::{ExecutionId, GpuAllocationGeneration, ModelActivationGeneration};

/// One runner role: the model activation and GPU allocation of one model under one
/// execution.
type RunnerKey = (
    ExecutionId,
    ModelId,
    ModelActivationGeneration,
    GpuAllocationGeneration,
);

fn runner_key(role: &ProcessRole) -> Option<RunnerKey> {
    match role {
        ProcessRole::ModelRunner {
            execution,
            model,
            generations,
        } => Some((
            execution.clone(),
            *model,
            generations.activation,
            generations.gpu_allocation,
        )),
        ProcessRole::VmHost { .. }
        | ProcessRole::GuestRelay { .. }
        | ProcessRole::SandboxExecutor { .. }
        | ProcessRole::SandboxSupervisor { .. } => None,
    }
}

/// The model runner processes the host started, each runner role bound to one process,
/// held for its whole life (VM part §6.4).
#[derive(Debug, Default)]
pub struct RunnerProcesses {
    bound: BTreeMap<RunnerKey, HostProcess>,
}

impl RunnerProcesses {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Holds `process` as the one process of its runner role. Refused for a VM host
    /// process, and while the process bound to the role before has not been seen to end
    /// with every process of its job. One that ended is replaced, and its proof binds no
    /// more: settle what it held before binding its successor.
    pub fn bind(&mut self, process: HostProcess) -> Result<(), BindRefusal> {
        let Some(key) = runner_key(process.role()) else {
            return Err(BindRefusal::NotAModelRunner {
                role: process.role().clone(),
            });
        };
        if let Some(bound) = self.bound.get(&key) {
            if bound.check_ended().is_err() {
                return Err(BindRefusal::RunnerStillRunning {
                    role: process.role().clone(),
                });
            }
        }
        self.bound.insert(key, process);
        Ok(())
    }

    /// The process bound to `role`, if any.
    pub fn process(&self, role: &ProcessRole) -> Option<&HostProcess> {
        runner_key(role).and_then(|key| self.bound.get(&key))
    }
}

impl BoundProcesses for RunnerProcesses {
    /// Whether the proof is of the process bound to the runner role it names.
    fn binds(&self, proof: &TerminationProof) -> bool {
        self.process(proof.role())
            .is_some_and(|bound| bound.identity() == proof.identity())
    }
}
