//! The end of a sandbox boot's VM host processes, before its root is torn down (VM part
//! §6.4: "Use stable process/VM handles ... Never terminate an unrelated process because a
//! stored PID was reused"; §6.5: security revocation must not wait for recursive cleanup,
//! and deleting an overlay is logical cleanup; VM-W24, VM-W26; VM-CP-19;
//! docs/combined-plan-leftover-tasks.md S04 and M13).
//!
//! A VM's host process holds the sandbox root's overlay and scratch open and writes to them
//! while it runs, so teardown deletes nothing of a boot's root while any VM host process
//! journaled for that boot ([`RootJournal::record_vm_process`]) lacks host evidence of its
//! end. The evidence is the host's own, through `foundation::process`, never a guest report
//! or a stored PID:
//!
//! - a [`TerminationProof`] held by the table that bound the process
//!   ([`VmProcesses::proof`], checked with [`BoundProcesses::binds`]): the host saw the
//!   process handle signalled, read its exit code and found no process left in its job;
//! - or, when no table holds a proof (the engine that held the handle is gone, as after a
//!   restart), the PID no longer naming the process: no process holds it, or another process
//!   does ([`IdentityCheck::Gone`] or [`IdentityCheck::Reused`]). A Windows process object
//!   outlives its exit while any handle to it is open, so a PID that names no process or
//!   another process means the process ended and every handle to it closed. Its job was
//!   kill-on-close with no breakaway, so the close of the last handle to the job ended
//!   everything it started (§6.4's OS-enforced child cleanup). A reused PID is only looked
//!   at, never signalled.
//!
//! A process the PID still names, with no proof, refuses teardown with nothing deleted:
//! ending it is the coordinator's part, through `foundation::process`'s
//! [`ObservedTermination`](crate::foundation::process::ObservedTermination), which ends a VM
//! only through the handle the host holds. So does a proof of another process than the one
//! journaled for the VM, and a host that cannot observe the process (the process module
//! refuses on a platform it does not support yet).
//!
//! [`RootJournal::record_vm_process`]: super::RootJournal::record_vm_process

use std::fmt;

use serde::Serialize;

use super::cleanup::{CleanupRefusal, ManagedProcess};
use super::root_journal::RootJournalFailure;
use crate::foundation::coordination::VmInstanceId;
use crate::foundation::process::{
    BoundProcesses, Ending, IdentityCheck, ProcessError, ProcessIdentity, ProcessRole,
    TerminationProof, VmProcesses,
};

/// What the host knows of the end of VM host processes.
pub trait VmProcessEnds {
    /// The host's proof that the host process of `vm` ended, from the table that bound it,
    /// when it holds one.
    fn proof(&self, vm: &VmInstanceId) -> Option<&TerminationProof>;

    /// What the host finds at `identity`'s PID now.
    fn check(&self, identity: &ProcessIdentity) -> Result<IdentityCheck, ProcessError>;
}

/// The host's own evidence: the proofs in the [`VmProcesses`] table the engine holds now
/// (empty after a restart), and the host's observation of each PID.
#[derive(Debug)]
pub struct HostVmEnds<'a> {
    vms: &'a VmProcesses,
}

impl<'a> HostVmEnds<'a> {
    /// The evidence of the table `vms`.
    pub fn new(vms: &'a VmProcesses) -> Self {
        Self { vms }
    }
}

impl VmProcessEnds for HostVmEnds<'_> {
    fn proof(&self, vm: &VmInstanceId) -> Option<&TerminationProof> {
        self.vms.proof(vm).filter(|proof| self.vms.binds(proof))
    }

    fn check(&self, identity: &ProcessIdentity) -> Result<IdentityCheck, ProcessError> {
        identity.check()
    }
}

/// How the host knows a VM host process ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "evidence", rename_all = "snake_case")]
pub enum ProcessEndEvidence {
    /// The host saw the process handle signalled and its job empty.
    Proven { exit_code: u32, ending: Ending },
    /// No proof is held, and the PID no longer names the process: it names no process
    /// (`gone`) or another one (`reused`, never signalled).
    NoLongerHeld { check: IdentityCheck },
}

/// A VM host process of the boot, and how the host knows it ended.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EndedVmProcess {
    pub vm: VmInstanceId,
    pub identity: ProcessIdentity,
    pub evidence: ProcessEndEvidence,
}

/// Why a VM host process of the boot does not count as ended.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum VmProcessRefusal {
    /// The PID still names the process, and no proof of its end is held.
    Running,
    /// The proof held for the VM is of another process than the one journaled.
    ProofOfAnother { proven: ProcessIdentity },
    /// The host could not observe the process.
    Unobservable { error: ProcessError },
    /// Not a VM's host process.
    NotAVmHost,
}

impl fmt::Display for VmProcessRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Running => f.write_str("it still runs, and no proof of its end is held"),
            Self::ProofOfAnother { proven } => {
                write!(f, "the proof held for its VM is of {proven}")
            }
            Self::Unobservable { error } => write!(f, "the host could not observe it: {error}"),
            Self::NotAVmHost => f.write_str("it is not the host process of a VM"),
        }
    }
}

/// Why a VM host process does not fit a boot's journal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VmProcessProblem {
    /// Not a VM's host process.
    NotAVmHost,
    /// Bound to another execution or boot than the journal's.
    OtherBoot,
    /// The process, or a process of the same VM, is journaled already.
    AlreadyJournaled,
    /// The root never committed, or its teardown began: a VM is started only on a
    /// committed root that is not being torn down.
    NotLaunchable,
}

impl fmt::Display for VmProcessProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotAVmHost => "it is not the host process of a VM",
            Self::OtherBoot => "it runs for another execution or boot",
            Self::AlreadyJournaled => "it, or a process of its VM, is journaled already",
            Self::NotLaunchable => "the root is not committed, or is being torn down",
        })
    }
}

/// Why a VM host process could not be journaled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VmProcessRecordError {
    /// Nothing was journaled.
    Problem(VmProcessProblem),
    /// The journal could not be written; nothing was registered.
    Journal(RootJournalFailure),
    /// Journaled, but V05 refused the registration; a restore registers it again.
    Refused(CleanupRefusal),
}

impl fmt::Display for VmProcessRecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Problem(problem) => write!(f, "{problem}"),
            Self::Journal(failure) => write!(f, "{failure}"),
            Self::Refused(refusal) => write!(f, "{refusal}"),
        }
    }
}

impl std::error::Error for VmProcessRecordError {}

/// Whether `process` may be journaled for `execution`'s boot `boot` beside `journaled`.
pub(super) fn check_journalable(
    process: &ManagedProcess,
    execution: &crate::foundation::ids::ExecutionId,
    boot: crate::foundation::ids::SandboxBootGeneration,
    journaled: &[ManagedProcess],
) -> Result<(), VmProcessProblem> {
    let ProcessRole::VmHost {
        execution: bound,
        vm,
        boot: bound_boot,
    } = &process.role
    else {
        return Err(VmProcessProblem::NotAVmHost);
    };
    if bound != execution || *bound_boot != boot {
        return Err(VmProcessProblem::OtherBoot);
    }
    let duplicate = journaled.iter().any(|other| {
        other.identity == process.identity
            || matches!(&other.role, ProcessRole::VmHost { vm: other_vm, .. } if other_vm == vm)
    });
    if duplicate {
        return Err(VmProcessProblem::AlreadyJournaled);
    }
    Ok(())
}

/// How each of `processes` ended, in order, or the first that has no host evidence of its
/// end, with why.
pub(super) fn ended_vm_processes(
    processes: &[ManagedProcess],
    ends: &dyn VmProcessEnds,
) -> Result<Vec<EndedVmProcess>, (ProcessIdentity, VmProcessRefusal)> {
    let mut ended = Vec::with_capacity(processes.len());
    for process in processes {
        let identity = process.identity;
        let ProcessRole::VmHost { vm, .. } = &process.role else {
            return Err((identity, VmProcessRefusal::NotAVmHost));
        };
        let evidence = match ends.proof(vm) {
            Some(proof) if proof.identity() == identity && proof.role() == &process.role => {
                ProcessEndEvidence::Proven {
                    exit_code: proof.exit_code(),
                    ending: proof.ending(),
                }
            }
            Some(proof) => {
                return Err((
                    identity,
                    VmProcessRefusal::ProofOfAnother {
                        proven: proof.identity(),
                    },
                ))
            }
            None => match ends.check(&identity) {
                Ok(check @ (IdentityCheck::Gone | IdentityCheck::Reused)) => {
                    ProcessEndEvidence::NoLongerHeld { check }
                }
                Ok(IdentityCheck::Same) => return Err((identity, VmProcessRefusal::Running)),
                Err(error) => return Err((identity, VmProcessRefusal::Unobservable { error })),
            },
        };
        ended.push(EndedVmProcess {
            vm: *vm,
            identity,
            evidence,
        });
    }
    Ok(ended)
}
