//! Settling what an ended process held, on the host's proof of its end (S04; S2 CORE-03,
//! CORE-04; S3.1; VM part §6.3).
//!
//! A replacement runner reporting that the old one is gone is not the host's observation:
//! only a [`TerminationProof`] of the old process itself settles the old generation. Each
//! settlement checks that the proof is of the process bound to its role
//! ([`BoundProcesses`]: [`VmProcesses`](super::VmProcesses) or
//! [`RunnerProcesses`]), so the end of a second process started for the same role never
//! settles what the bound one holds, and that it names the process whose leases or grants
//! it closes, under the right authority: the end of a VM's process never settles a model
//! runner's leases or grants, and a runner's end never settles a VM's (S3.1). The VM
//! lifecycle's own termination and recovery go through
//! [`ObservedTermination`](super::ObservedTermination).

use std::collections::BTreeSet;
use std::fmt;

use serde::Serialize;

use super::identity::{ProcessAuthority, ProcessIdentity, ProcessRole};
use super::proof::TerminationProof;
use super::runner::RunnerProcesses;
use crate::foundation::coordination::{
    CapacityPort, CapacityRefusal, Coordinator, LeaseRefusal, ModelBinding, ReleaseOutcome,
    ReservationKey, ReservationPurpose,
};
use crate::foundation::ids::{Clock, LeaseId};

/// A table that binds each role to the one process it was started for.
pub trait BoundProcesses {
    /// Whether `proof` is of the process bound to the role the proof names.
    fn binds(&self, proof: &TerminationProof) -> bool;
}

/// Why a proof did not settle what was asked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "settle_refusal", rename_all = "snake_case")]
pub enum SettleRefusal {
    /// The proof is of a process under another authority (S3.1).
    OtherAuthority {
        expected: ProcessAuthority,
        role: ProcessRole,
    },
    /// The proof is not of the process bound to its role, such as a second process
    /// started for the same model activation.
    NotTheBoundProcess {
        identity: ProcessIdentity,
    },
    /// The lease is not bound to the ended process's execution and generations.
    LeaseNotOfProcess {
        lease: LeaseId,
    },
    /// The lease is named twice.
    DuplicateLease {
        lease: LeaseId,
    },
    Lease {
        refusal: LeaseRefusal,
    },
    Capacity {
        refusal: CapacityRefusal,
    },
}

impl fmt::Display for SettleRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OtherAuthority { expected, role } => write!(
                f,
                "the proof is of {role}, which does not run under {expected}"
            ),
            Self::NotTheBoundProcess { identity } => {
                write!(f, "{identity} is not the process bound to its role")
            }
            Self::LeaseNotOfProcess { lease } => {
                write!(f, "lease {lease} was not issued to the ended process")
            }
            Self::DuplicateLease { lease } => write!(f, "lease {lease} is named twice"),
            Self::Lease { refusal } => write!(f, "{refusal}"),
            Self::Capacity { refusal } => write!(f, "{refusal}"),
        }
    }
}

impl std::error::Error for SettleRefusal {}

/// Closes `leases`, which the process the proof names held, as done: the process and
/// every process of its job ended, so nothing acts under them any more (VM part §6.3 step
/// 3: an enforcement acknowledgment). An active lease is released and a cancelling one
/// acknowledged, so a revocation waiting for them proceeds. The proof must be of the
/// process `bound` holds for its role. A VM host process's leases are the leases of its
/// execution and boot generation bound to no model activation; a model runner's, those
/// bound to its model activation and GPU allocation. Every lease is checked, and named
/// once, before any is closed, so a refusal closes none. Returns the leases closed, in
/// order.
pub fn settle_leases<C: Clock, P: CapacityPort, B: BoundProcesses + ?Sized>(
    coordinator: &mut Coordinator<C, P>,
    bound: &B,
    proof: &TerminationProof,
    leases: &[LeaseId],
) -> Result<Vec<LeaseId>, SettleRefusal> {
    if !bound.binds(proof) {
        return Err(SettleRefusal::NotTheBoundProcess {
            identity: proof.identity(),
        });
    }
    let mut named = BTreeSet::new();
    for &lease in leases {
        if !named.insert(lease) {
            return Err(SettleRefusal::DuplicateLease { lease });
        }
        let record = coordinator
            .lease_record(lease)
            .ok_or(SettleRefusal::Lease {
                refusal: LeaseRefusal::UnknownLease { lease },
            })?;
        let issued = record.lease();
        let held = issued.parent() == proof.role().execution()
            && match proof.role() {
                ProcessRole::VmHost { boot, .. } => {
                    issued.sandbox().boot == *boot && issued.model().is_none()
                }
                ProcessRole::ModelRunner {
                    model, generations, ..
                } => {
                    issued.model()
                        == Some(ModelBinding {
                            model: *model,
                            generations: *generations,
                        })
                }
                // A guest relay, the executor and the supervisor hold no lease: their ends
                // settle nothing.
                ProcessRole::GuestRelay { .. }
                | ProcessRole::SandboxExecutor { .. }
                | ProcessRole::SandboxSupervisor { .. } => false,
            };
        if !held {
            return Err(SettleRefusal::LeaseNotOfProcess { lease });
        }
    }
    for &lease in leases {
        coordinator
            .release_lease(lease)
            .map_err(|refusal| SettleRefusal::Lease { refusal })?;
    }
    Ok(leases.to_vec())
}

/// Closes the reservations of the model runner the proof names, as the host observed
/// them freed: the GPU reservation of its GPU allocation and the host memory reservation
/// of its activation, each derived from the generations bound when the runner started
/// (S2 CORE-03: a host-level reservation closes only on a host observation). Each is
/// cancelled, and, while the ledger still counts it, its release confirmed with the
/// proof's source. A reservation the ledger does not hold is reported as not held. A
/// replacement runner's own proof derives its own reservations, never the old runner's,
/// and the proof must be of the process `runners` binds to the role, never of a second
/// process started for the same generations. A ledger refusal stops before the
/// reservations after it; every step is idempotent, so a retry with the same proof
/// finishes them.
pub fn release_runner_reservations<P: CapacityPort>(
    capacity: &mut P,
    runners: &RunnerProcesses,
    proof: &TerminationProof,
) -> Result<Vec<(ReservationKey, ReleaseOutcome)>, SettleRefusal> {
    let ProcessRole::ModelRunner {
        execution,
        model,
        generations,
    } = proof.role()
    else {
        return Err(SettleRefusal::OtherAuthority {
            expected: ProcessAuthority::ModelActivation,
            role: proof.role().clone(),
        });
    };
    if !runners.binds(proof) {
        return Err(SettleRefusal::NotTheBoundProcess {
            identity: proof.identity(),
        });
    }
    let purposes = [
        ReservationPurpose::ModelGpu {
            model: *model,
            gpu_allocation: generations.gpu_allocation,
        },
        ReservationPurpose::ModelHost {
            model: *model,
            activation: generations.activation,
        },
    ];
    let refused = |refusal| SettleRefusal::Capacity { refusal };
    let mut settled = Vec::with_capacity(purposes.len());
    for purpose in purposes {
        let key = ReservationKey::derive(execution, &purpose);
        let outcome = match capacity.release(&key).map_err(refused)? {
            ReleaseOutcome::Pending => capacity
                .confirm_release(&key, proof.source())
                .map_err(refused)?,
            outcome => outcome,
        };
        settled.push((key, outcome));
    }
    Ok(settled)
}
