//! Staged owner resource return (S10 line 185; S7 line 131).
//!
//! When the owner wants a GPU back from background work, the return goes in stages: deny
//! new background work; drain, or cancel at a boundary the runtime supports; then release
//! or reassign the resource through the runtime's real mechanism. Freezing a process frees
//! no GPU allocation, so a pause is never a hand-back, and a VM with an exclusively
//! assigned GPU is terminated and its device reset before reassignment. Request stop,
//! VRAM release and foreground impact are measured separately, after the fact; no fixed
//! time is promised.
//!
//! A release by process exit is the host's observation, so it needs the host's proof
//! (S04; docs/combined-plan-leftover-tasks.md S04: "obtain host proof of old-process
//! termination"). [`Coordinator::release_resource_on_exit`] takes the
//! [`TerminationProof`] of each process that held the resource, checked through the
//! [`BoundProcesses`] table that holds the process for its role: the runner of each of the
//! execution's model activations, or, with none, the host process of its current VM. The
//! proof of a process the table does not hold for its role, such as a second process
//! started for the role or the old process of a role bound again to a replacement, and a
//! proof of another role are refused ([`ExitRefusal`]). A plain
//! [`Coordinator::release_resource`] by process exit is refused.

use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::capacity::{CapacityPort, CapacityRefusal, ResourceKind, ReturnHold};
use super::coordinator::Coordinator;
use super::identity::{ModelGenerations, ModelId, VmInstanceId};
use super::lease::{CancelCause, LeaseRefusal};
use super::model::{ModelRefusal, RetireReason};
use super::sandbox::SandboxState;
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{
    Clock, Digest, ExecutionId, GpuDeviceKey, LeaseId, MonotonicTime, SandboxBootGeneration,
};
use crate::foundation::process::{BoundProcesses, ProcessIdentity, ProcessRole, TerminationProof};

/// How the GPU is assigned to the background work.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GpuAssignment {
    /// Shared with the host, such as a background labelled runtime (S7 line 131).
    Shared,
    /// Assigned exclusively to one VM; it follows device reset and ownership rules (S10
    /// line 185).
    ExclusiveToVm,
}

/// A point at which the runtime can stop work cleanly; the runtime declares which it
/// supports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CancellationBoundary {
    BetweenRequests,
    BetweenBatches,
    BetweenDecodeSteps,
}

/// A device reset as observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceReset {
    pub device: GpuDeviceKey,
    /// Only a host probe counts.
    pub source: SourceClass,
}

/// How the resource is released or reassigned (S10 line 185: by the runtime's real
/// mechanism).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mechanism", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum ReleaseMechanism {
    /// The runtime frees its GPU allocations itself, such as by unloading the model.
    RuntimeFree,
    /// The runtime process exits, which frees its allocations.
    ProcessExit,
    /// Freezing the process. It frees no GPU allocation, so it is never accepted.
    ProcessPause,
    /// The VM was terminated and its exclusively assigned device reset, so the device can
    /// be reassigned.
    TerminateResetReassign { reset: DeviceReset },
}

crate::foundation::strict_serde::strict_tag!(ReleaseMechanism, "mechanism");

/// The stage a return has reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReturnStage {
    /// New background work is denied; work in flight drains or is cancelled.
    NewWorkDenied,
    /// No work remains in flight: the request-stop event.
    WorkStopped,
    /// The resource was released or reassigned: the VRAM-release event.
    Released,
}

/// A foreground measurement taken during the return.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForegroundImpact {
    pub baseline_latency: Duration,
    pub observed_latency: Duration,
}

/// The three measurements, each taken separately and only when it happened (S7 line 131).
/// They are measured after the fact; nothing here is a promise.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReturnMeasurements {
    /// From the request until no background work remained.
    pub request_stop: Option<Duration>,
    /// From the request until the resource was released.
    pub vram_release: Option<Duration>,
    pub foreground_impact: Option<ForegroundImpact>,
    /// From the request until the foreground measurement was taken.
    pub foreground_measured_after: Option<Duration>,
}

/// The session state a moved request carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRepresentation {
    pub model: ModelId,
    /// The format of the KV and request state.
    pub format: Digest,
}

/// Moving a live request to another worker instead of cancelling it (S10 line 185).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionMove {
    pub source: SessionRepresentation,
    /// The representation the target is authorized to accept, if any.
    pub target_authorized: Option<SessionRepresentation>,
    pub transfer_time_needed: Duration,
    pub transfer_time_available: Duration,
}

/// Why a session cannot move.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum SessionMoveRefusal {
    TargetNotAuthorized,
    RepresentationMismatch,
    NotEnoughTransferTime {
        needed: Duration,
        available: Duration,
    },
}

crate::foundation::strict_serde::strict_tag!(SessionMoveRefusal, "refusal");

/// Moving live KV and request state needs a matching authorized session representation
/// and enough transfer time (S10 line 185).
pub fn check_session_move(plan: &SessionMove) -> Result<(), Vec<SessionMoveRefusal>> {
    let mut refusals = Vec::new();
    match plan.target_authorized {
        None => refusals.push(SessionMoveRefusal::TargetNotAuthorized),
        Some(accepted) if accepted != plan.source => {
            refusals.push(SessionMoveRefusal::RepresentationMismatch)
        }
        Some(_) => {}
    }
    if plan.transfer_time_needed > plan.transfer_time_available {
        refusals.push(SessionMoveRefusal::NotEnoughTransferTime {
            needed: plan.transfer_time_needed,
            available: plan.transfer_time_available,
        });
    }
    if refusals.is_empty() {
        Ok(())
    } else {
        Err(refusals)
    }
}

/// Why a process exit did not release a returning resource (S04; S3.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "exit_refusal", rename_all = "snake_case", deny_unknown_fields)]
#[serde(remote = "Self")]
pub enum ExitRefusal {
    /// A process exit releases only on the host's proof, through
    /// [`Coordinator::release_resource_on_exit`].
    ProofRequired,
    /// The proof is not of the process the binding table holds for its role: one never
    /// bound, a second process started for the role, or the old process of a role bound
    /// again to a replacement.
    NotTheBoundProcess { identity: ProcessIdentity },
    /// The proof is of a process whose role is not this return's: another execution's, a
    /// runner of none of its activations that hold memory, or the host process of another
    /// VM or boot.
    OtherRole { role: ProcessRole },
    /// The proof is of the execution's VM host process, but the memory is the model
    /// activations', held by their runners: the end of a VM's process never settles a
    /// runner's (S3.1).
    OtherAuthority { role: ProcessRole },
    /// No proof shows that the runner of this activation ended, so its memory may still be
    /// in use.
    RunnerNotProven {
        model: ModelId,
        generations: ModelGenerations,
    },
    /// No proof shows that the host process of the execution's VM, of this boot, ended.
    VmNotProven {
        vm: Option<VmInstanceId>,
        boot: SandboxBootGeneration,
    },
}

crate::foundation::strict_serde::strict_tag!(ExitRefusal, "exit_refusal");

impl fmt::Display for ExitRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProofRequired => f.write_str(
                "a process exit releases the resource only on the host's proof that the \
                 process ended",
            ),
            Self::NotTheBoundProcess { identity } => {
                write!(f, "{identity} is not the process bound to its role")
            }
            Self::OtherRole { role } => write!(f, "the proof is of {role}, not of this return"),
            Self::OtherAuthority { role } => write!(
                f,
                "the proof is of {role}, which does not hold the model activations' memory"
            ),
            Self::RunnerNotProven { model, generations } => write!(
                f,
                "the end of the runner of model {model}, {generations}, was not proven"
            ),
            Self::VmNotProven { vm: Some(vm), boot } => write!(
                f,
                "the end of the host process of VM {vm}, boot generation {boot}, was not proven"
            ),
            Self::VmNotProven { vm: None, boot } => write!(
                f,
                "the execution has no VM of boot generation {boot} whose end could be proven"
            ),
        }
    }
}

impl std::error::Error for ExitRefusal {}

/// A step of the return, for refusals.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReturnStep {
    CancelAtBoundary,
    MoveSession,
    Release,
    Finish,
}

/// Why a return step was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "return_refusal", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum ReturnRefusal {
    UnknownExecution {
        execution: ExecutionId,
    },
    AlreadyInProgress,
    NotInProgress,
    /// The runtime does not support cancelling there.
    UnsupportedBoundary {
        boundary: CancellationBoundary,
        supported: BTreeSet<CancellationBoundary>,
    },
    /// The stages run in order: deny, drain or cancel, then release.
    OutOfOrder {
        stage: ReturnStage,
        step: ReturnStep,
    },
    /// Freezing a process frees no GPU allocation (S10 line 185; S7 line 131: a process
    /// pause is not a GPU hand-back).
    PauseIsNotRelease,
    /// The mechanism does not release this kind of assignment.
    MechanismNotForAssignment {
        assignment: GpuAssignment,
        mechanism: ReleaseMechanism,
    },
    /// An exclusively assigned GPU is reassigned only after its VM terminated.
    VmNotTerminated {
        state: SandboxState,
    },
    ResetNotHostObserved {
        source: SourceClass,
    },
    LeaseOfOtherExecution {
        lease: LeaseId,
    },
    SessionMove {
        refusals: Vec<SessionMoveRefusal>,
    },
    /// A release by process exit without the host's proof that the right processes ended.
    ProcessExit {
        refusal: ExitRefusal,
    },
    /// The ledger refused the hold or a release.
    Capacity {
        refusal: CapacityRefusal,
    },
    Lease {
        refusal: LeaseRefusal,
    },
    Model {
        refusal: ModelRefusal,
    },
}

crate::foundation::strict_serde::strict_tag!(ReturnRefusal, "return_refusal");

impl fmt::Display for ReturnRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownExecution { execution } => write!(f, "execution {execution} is unknown"),
            Self::AlreadyInProgress => f.write_str("a resource return is already in progress"),
            Self::NotInProgress => f.write_str("no resource return is in progress"),
            Self::UnsupportedBoundary { boundary, .. } => {
                write!(f, "the runtime cannot cancel {boundary:?}")
            }
            Self::OutOfOrder { stage, step } => write!(
                f,
                "cannot {step:?} at stage {stage:?}; deny new work, drain or cancel, then release"
            ),
            Self::PauseIsNotRelease => f.write_str(
                "pausing a process frees none of its GPU allocations and is not a hand-back",
            ),
            Self::MechanismNotForAssignment { assignment, .. } => match assignment {
                GpuAssignment::ExclusiveToVm => f.write_str(
                    "an exclusively assigned GPU returns only by terminating its VM, resetting \
                     the device and reassigning it",
                ),
                GpuAssignment::Shared => {
                    f.write_str("a shared GPU returns through the runtime's own release")
                }
            },
            Self::VmNotTerminated { state } => write!(
                f,
                "the VM must be terminated before its GPU is reassigned; it is {state}"
            ),
            Self::ResetNotHostObserved { source } => {
                write!(
                    f,
                    "the device reset was reported by a {source}, not the host"
                )
            }
            Self::LeaseOfOtherExecution { lease } => {
                write!(f, "lease {lease} belongs to another execution")
            }
            Self::SessionMove { refusals } => {
                write!(f, "the session cannot move: {refusals:?}")
            }
            Self::ProcessExit { refusal } => write!(f, "{refusal}"),
            Self::Capacity { refusal } => write!(f, "{refusal}"),
            Self::Lease { refusal } => write!(f, "{refusal}"),
            Self::Model { refusal } => write!(f, "{refusal}"),
        }
    }
}

impl std::error::Error for ReturnRefusal {}

/// One staged return in progress (S10 line 185).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceReturn {
    execution: ExecutionId,
    assignment: GpuAssignment,
    boundaries: BTreeSet<CancellationBoundary>,
    held: BTreeSet<ResourceKind>,
    hold: ReturnHold,
    requested_at: MonotonicTime,
    stage: ReturnStage,
    work_stopped_at: Option<MonotonicTime>,
    released_at: Option<MonotonicTime>,
    mechanism: Option<ReleaseMechanism>,
    foreground: Option<(MonotonicTime, ForegroundImpact)>,
    cancelled: Vec<LeaseId>,
    moved: Vec<LeaseId>,
}

impl ResourceReturn {
    /// The execution whose resource returns.
    pub fn execution(&self) -> &ExecutionId {
        &self.execution
    }

    /// How the GPU is assigned.
    pub fn assignment(&self) -> GpuAssignment {
        self.assignment
    }

    /// The resources the ledger holds for the owner: new background reservations of them
    /// are denied host-wide until the return finishes.
    pub fn held(&self) -> &BTreeSet<ResourceKind> {
        &self.held
    }

    /// The ledger hold that denies new background reservations of the held resources
    /// host-wide (S10 line 185). It is persisted, and recovery ends it.
    pub fn hold(&self) -> ReturnHold {
        self.hold
    }

    /// The stage reached.
    pub fn stage(&self) -> ReturnStage {
        self.stage
    }

    /// Leases cancelled at a boundary.
    pub fn cancelled(&self) -> &[LeaseId] {
        &self.cancelled
    }

    /// Leases whose session moved to another worker.
    pub fn moved(&self) -> &[LeaseId] {
        &self.moved
    }

    /// How the resource was released, once it was.
    pub fn mechanism(&self) -> Option<ReleaseMechanism> {
        self.mechanism
    }

    /// What has been measured so far.
    pub fn measurements(&self) -> ReturnMeasurements {
        let since = |at: MonotonicTime| at.saturating_duration_since(self.requested_at);
        ReturnMeasurements {
            request_stop: self.work_stopped_at.map(since),
            vram_release: self.released_at.map(since),
            foreground_impact: self.foreground.map(|(_, impact)| impact),
            foreground_measured_after: self.foreground.map(|(at, _)| since(at)),
        }
    }
}

/// A finished return.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReturnReport {
    pub execution: ExecutionId,
    pub assignment: GpuAssignment,
    pub mechanism: ReleaseMechanism,
    pub measurements: ReturnMeasurements,
    pub cancelled: Vec<LeaseId>,
    pub moved: Vec<LeaseId>,
}

impl<C: Clock, P: CapacityPort> Coordinator<C, P> {
    fn return_mut(
        &mut self,
        execution: &ExecutionId,
    ) -> Result<&mut ResourceReturn, ReturnRefusal> {
        self.returns
            .get_mut(execution)
            .ok_or(ReturnRefusal::NotInProgress)
    }

    /// Stage 1: new background work is denied from now on, under `execution` by the
    /// coordinator and on the `held` resources host-wide by a ledger hold. The runtime
    /// declares the boundaries at which it can cancel work.
    pub fn begin_resource_return(
        &mut self,
        execution: &ExecutionId,
        assignment: GpuAssignment,
        boundaries: BTreeSet<CancellationBoundary>,
        held: BTreeSet<ResourceKind>,
    ) -> Result<ReturnStage, ReturnRefusal> {
        if !self.sandboxes.contains_key(execution) {
            return Err(ReturnRefusal::UnknownExecution {
                execution: execution.clone(),
            });
        }
        if self.returns.contains_key(execution) {
            return Err(ReturnRefusal::AlreadyInProgress);
        }
        let hold = self
            .capacity
            .begin_hold(&held)
            .map_err(|refusal| ReturnRefusal::Capacity { refusal })?;
        let now = self.monotonic_now();
        self.returns.insert(
            execution.clone(),
            ResourceReturn {
                execution: execution.clone(),
                assignment,
                boundaries,
                held,
                hold,
                requested_at: now,
                stage: ReturnStage::NewWorkDenied,
                work_stopped_at: None,
                released_at: None,
                mechanism: None,
                foreground: None,
                cancelled: Vec::new(),
                moved: Vec::new(),
            },
        );
        self.poll_resource_return(execution)
    }

    /// Stage 2: cancels `lease` at a boundary the runtime supports. The holder stops by the
    /// lease's declared bound.
    pub fn cancel_at_boundary(
        &mut self,
        execution: &ExecutionId,
        lease: LeaseId,
        boundary: CancellationBoundary,
    ) -> Result<MonotonicTime, ReturnRefusal> {
        let now = self.monotonic_now();
        self.check_return_lease(execution, lease, ReturnStep::CancelAtBoundary)?;
        let operation = self.return_mut(execution)?;
        if !operation.boundaries.contains(&boundary) {
            return Err(ReturnRefusal::UnsupportedBoundary {
                boundary,
                supported: operation.boundaries.clone(),
            });
        }
        let cancelled = self.leases.cancel_where(
            |candidate| candidate.id() == lease,
            CancelCause::ResourceReturn,
            now,
        );
        let Some(cancellation) = cancelled.first() else {
            return Err(ReturnRefusal::Lease {
                refusal: LeaseRefusal::NotCancelling,
            });
        };
        let bound_at = cancellation.bound_at;
        self.return_mut(execution)?.cancelled.push(lease);
        Ok(bound_at)
    }

    /// Stage 2, instead of cancelling: the request's live state moved to another worker,
    /// which needs a matching authorized session representation and enough transfer time.
    pub fn move_session(
        &mut self,
        execution: &ExecutionId,
        lease: LeaseId,
        plan: &SessionMove,
    ) -> Result<ReturnStage, ReturnRefusal> {
        self.check_return_lease(execution, lease, ReturnStep::MoveSession)?;
        check_session_move(plan).map_err(|refusals| ReturnRefusal::SessionMove { refusals })?;
        let now = self.monotonic_now();
        self.leases
            .release(lease, now)
            .map_err(|refusal| ReturnRefusal::Lease { refusal })?;
        self.return_mut(execution)?.moved.push(lease);
        self.poll_resource_return(execution)
    }

    fn check_return_lease(
        &mut self,
        execution: &ExecutionId,
        lease: LeaseId,
        step: ReturnStep,
    ) -> Result<(), ReturnRefusal> {
        let stage = self.return_mut(execution)?.stage;
        if stage != ReturnStage::NewWorkDenied {
            return Err(ReturnRefusal::OutOfOrder { stage, step });
        }
        let record = self.leases.get(lease).ok_or(ReturnRefusal::Lease {
            refusal: LeaseRefusal::UnknownLease { lease },
        })?;
        if record.lease().parent() != execution {
            return Err(ReturnRefusal::LeaseOfOtherExecution { lease });
        }
        Ok(())
    }

    /// Records the request-stop event once no lease of `execution` may still be in use.
    pub fn poll_resource_return(
        &mut self,
        execution: &ExecutionId,
    ) -> Result<ReturnStage, ReturnRefusal> {
        let now = self.monotonic_now();
        let busy = self
            .leases
            .records()
            .any(|record| record.lease().parent() == execution && record.may_be_in_use(now));
        let operation = self.return_mut(execution)?;
        if operation.stage == ReturnStage::NewWorkDenied && !busy {
            operation.stage = ReturnStage::WorkStopped;
            operation.work_stopped_at = Some(now);
        }
        Ok(operation.stage)
    }

    /// Stage 3: the resource is released or reassigned through the runtime's real
    /// mechanism (S10 line 185). A pause is refused; a shared GPU returns through the
    /// runtime's own release; an exclusively assigned GPU returns only after its VM
    /// terminated and the host observed the device reset. A shared GPU released by its
    /// process's exit needs the host's proof: [`Coordinator::release_resource_on_exit`].
    pub fn release_resource(
        &mut self,
        execution: &ExecutionId,
        mechanism: ReleaseMechanism,
    ) -> Result<ReturnMeasurements, ReturnRefusal> {
        let stage = self.poll_resource_return(execution)?;
        if stage != ReturnStage::WorkStopped {
            return Err(ReturnRefusal::OutOfOrder {
                stage,
                step: ReturnStep::Release,
            });
        }
        let assignment = self.return_mut(execution)?.assignment;
        match (assignment, mechanism) {
            (_, ReleaseMechanism::ProcessPause) => return Err(ReturnRefusal::PauseIsNotRelease),
            (GpuAssignment::Shared, ReleaseMechanism::RuntimeFree) => {
                self.return_model_memory(execution, SourceClass::GuestReport)?;
            }
            (GpuAssignment::Shared, ReleaseMechanism::ProcessExit) => {
                return Err(ReturnRefusal::ProcessExit {
                    refusal: ExitRefusal::ProofRequired,
                })
            }
            (GpuAssignment::ExclusiveToVm, ReleaseMechanism::TerminateResetReassign { reset }) => {
                let state = self
                    .sandboxes
                    .get(execution)
                    .map(|sandbox| sandbox.state())
                    .ok_or(ReturnRefusal::UnknownExecution {
                        execution: execution.clone(),
                    })?;
                if state != SandboxState::Stopped {
                    return Err(ReturnRefusal::VmNotTerminated { state });
                }
                if reset.source != SourceClass::HostProbe {
                    return Err(ReturnRefusal::ResetNotHostObserved {
                        source: reset.source,
                    });
                }
            }
            (assignment, mechanism) => {
                return Err(ReturnRefusal::MechanismNotForAssignment {
                    assignment,
                    mechanism,
                })
            }
        }
        let now = self.monotonic_now();
        let operation = self.return_mut(execution)?;
        operation.stage = ReturnStage::Released;
        operation.released_at = Some(now);
        operation.mechanism = Some(mechanism);
        Ok(operation.measurements())
    }

    /// Stage 3 for a shared GPU whose runtime process exited (S10 line 185; S04): released
    /// only on the host's proof that each process holding it ended, each the process
    /// `bound` holds for its role (see the module documentation). Every activation of the
    /// execution's models that is not retired, or whose GPU memory is still counted, needs
    /// the proof of its own runner; when there is none, the proof of the host process of
    /// the execution's current VM and boot is needed. Nothing is released on a refusal.
    /// Its memory is then released as the host observed it.
    pub fn release_resource_on_exit<B: BoundProcesses + ?Sized>(
        &mut self,
        execution: &ExecutionId,
        bound: &B,
        proofs: &[&TerminationProof],
    ) -> Result<ReturnMeasurements, ReturnRefusal> {
        let stage = self.poll_resource_return(execution)?;
        if stage != ReturnStage::WorkStopped {
            return Err(ReturnRefusal::OutOfOrder {
                stage,
                step: ReturnStep::Release,
            });
        }
        let mechanism = ReleaseMechanism::ProcessExit;
        let assignment = self.return_mut(execution)?.assignment;
        if assignment != GpuAssignment::Shared {
            return Err(ReturnRefusal::MechanismNotForAssignment {
                assignment,
                mechanism,
            });
        }
        self.check_exit_proofs(execution, bound, proofs)
            .map_err(|refusal| ReturnRefusal::ProcessExit { refusal })?;
        self.return_model_memory(execution, SourceClass::HostProbe)?;
        let now = self.monotonic_now();
        let operation = self.return_mut(execution)?;
        operation.stage = ReturnStage::Released;
        operation.released_at = Some(now);
        operation.mechanism = Some(mechanism);
        Ok(operation.measurements())
    }

    /// Checks that `proofs` show the end of every process holding `execution`'s shared
    /// GPU, each bound to its role in `bound` (see
    /// [`Coordinator::release_resource_on_exit`]).
    fn check_exit_proofs<B: BoundProcesses + ?Sized>(
        &self,
        execution: &ExecutionId,
        bound: &B,
        proofs: &[&TerminationProof],
    ) -> Result<(), ExitRefusal> {
        let runners: Vec<(ModelId, ModelGenerations)> = self
            .models
            .iter()
            .filter(|((owner, _), _)| owner == execution)
            .flat_map(|((_, model), models)| {
                models
                    .activations()
                    .iter()
                    .filter(|activation| {
                        !activation.state().is_retired() || activation.gpu_reservation_counted()
                    })
                    .map(|activation| (*model, activation.generations()))
            })
            .collect();
        let sandbox = self.sandboxes.get(execution);
        let vm = sandbox.and_then(|sandbox| sandbox.vm());
        let boot = sandbox.map_or(SandboxBootGeneration::FIRST, |sandbox| {
            sandbox.generations().boot
        });
        let mut proven: Vec<(ModelId, ModelGenerations)> = Vec::new();
        let mut vm_proven = false;
        for proof in proofs {
            if !bound.binds(proof) {
                return Err(ExitRefusal::NotTheBoundProcess {
                    identity: proof.identity(),
                });
            }
            let role = proof.role();
            if role.execution() != execution {
                return Err(ExitRefusal::OtherRole { role: role.clone() });
            }
            match role {
                ProcessRole::ModelRunner {
                    model, generations, ..
                } if runners.contains(&(*model, *generations)) => {
                    proven.push((*model, *generations));
                }
                ProcessRole::VmHost { .. } if !runners.is_empty() => {
                    return Err(ExitRefusal::OtherAuthority { role: role.clone() });
                }
                ProcessRole::VmHost {
                    vm: ended,
                    boot: ended_boot,
                    ..
                } if Some(*ended) == vm && *ended_boot == boot => vm_proven = true,
                _ => return Err(ExitRefusal::OtherRole { role: role.clone() }),
            }
        }
        if let Some((model, generations)) = runners
            .iter()
            .find(|runner| !proven.contains(runner))
            .copied()
        {
            return Err(ExitRefusal::RunnerNotProven { model, generations });
        }
        if runners.is_empty() && !vm_proven {
            return Err(ExitRefusal::VmNotProven { vm, boot });
        }
        Ok(())
    }

    /// The runtime's real mechanism freed its GPU memory, as `observed` saw: its
    /// activations retire, every holding they used is released, retained and promised ones
    /// included, and the GPU holdings' releases are confirmed. Host memory holdings stay
    /// counted until their own release is observed.
    fn return_model_memory(
        &mut self,
        execution: &ExecutionId,
        observed: SourceClass,
    ) -> Result<(), ReturnRefusal> {
        let refused = |refusal| ReturnRefusal::Model { refusal };
        let mut freed: Vec<ModelId> = Vec::new();
        for ((owner, model), models) in self.models.iter_mut() {
            if owner == execution {
                models.retire_all(RetireReason::ReturnedToOwner);
                freed.push(*model);
            }
        }
        for model in freed {
            self.settle_holdings(execution, model, true)
                .map_err(refused)?;
            self.confirm_gpu_holdings(execution, model, observed)
                .map_err(refused)?;
        }
        Ok(())
    }

    /// Records the foreground measurement, taken separately from the other two.
    pub fn record_foreground_impact(
        &mut self,
        execution: &ExecutionId,
        impact: ForegroundImpact,
    ) -> Result<(), ReturnRefusal> {
        let now = self.monotonic_now();
        self.return_mut(execution)?.foreground = Some((now, impact));
        Ok(())
    }

    /// Ends a released return and its ledger hold; background work may start again
    /// afterwards.
    pub fn finish_resource_return(
        &mut self,
        execution: &ExecutionId,
    ) -> Result<ReturnReport, ReturnRefusal> {
        let operation = self.return_mut(execution)?;
        let (stage, mechanism, hold) = (operation.stage, operation.mechanism, operation.hold);
        let Some(mechanism) = mechanism.filter(|_| stage == ReturnStage::Released) else {
            return Err(ReturnRefusal::OutOfOrder {
                stage,
                step: ReturnStep::Finish,
            });
        };
        self.capacity
            .end_hold(hold)
            .map_err(|refusal| ReturnRefusal::Capacity { refusal })?;
        let operation = self.return_mut(execution)?;
        let report = ReturnReport {
            execution: execution.clone(),
            assignment: operation.assignment,
            mechanism,
            measurements: operation.measurements(),
            cancelled: operation.cancelled.clone(),
            moved: operation.moved.clone(),
        };
        self.returns.remove(execution);
        Ok(report)
    }

    /// The return in progress for `execution`, if any.
    pub fn resource_return(&self, execution: &ExecutionId) -> Option<&ResourceReturn> {
        self.returns.get(execution)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::digest;

    fn representation(format: &str) -> SessionRepresentation {
        SessionRepresentation {
            model: ModelId::new(digest("yougori/test/model/v1", &[b"m"])),
            format: digest("yougori/test/format/v1", &[format.as_bytes()]),
        }
    }

    #[test]
    fn a_session_moves_only_with_a_matching_authorized_representation_and_time() {
        let plan = SessionMove {
            source: representation("kv-a"),
            target_authorized: Some(representation("kv-a")),
            transfer_time_needed: Duration::from_millis(40),
            transfer_time_available: Duration::from_millis(50),
        };
        assert_eq!(check_session_move(&plan), Ok(()));
        let unauthorized = SessionMove {
            target_authorized: None,
            ..plan
        };
        assert_eq!(
            check_session_move(&unauthorized),
            Err(vec![SessionMoveRefusal::TargetNotAuthorized])
        );
        let mismatched = SessionMove {
            target_authorized: Some(representation("kv-b")),
            transfer_time_needed: Duration::from_millis(60),
            ..plan
        };
        assert_eq!(
            check_session_move(&mismatched),
            Err(vec![
                SessionMoveRefusal::RepresentationMismatch,
                SessionMoveRefusal::NotEnoughTransferTime {
                    needed: Duration::from_millis(60),
                    available: Duration::from_millis(50)
                }
            ])
        );
    }
}
