//! Lifecycle-owned parents (S03; CORE-03 parent/child budgets bound to CORE-04's parent
//! lifecycle, docs/combined-gpu-memory-and-vm-sandbox-plan.md S2 lines 212–213; GPU-W02
//! line 1181: "Bind model activation/allocation/session identities ... to the CORE-04
//! parent lifecycle contract"; GPU part §3.6, line 748).
//!
//! A parent reservation can be owned by the lifecycle it serves: one execution, one boot
//! of a VM sandbox, or one activation generation of one model, each under its tenant
//! ([`Lifecycle`]). The reservation keeps that lifecycle's tenant and execution. What the
//! lifecycle owns follows it:
//!
//! - While it is live, children are carved from its parents as from any other.
//! - When it drains ([`LifecycleEnd::Draining`], GPU part §3.6 step 6: drain requests
//!   holding old-generation leases), everything already carved keeps running, but nothing
//!   new is carved from its parents or from anything carved from them, and its waiting
//!   requests are refused. Waiting child requests are refused when the queue is next
//!   served.
//! - When it ends or is revoked ([`LifecycleEnd::Completed`], [`LifecycleEnd::Revoked`];
//!   INT-02), each parent it owns is cancelled with everything carved from it: what was
//!   never created returns at once, and what exists counts until a source with authority
//!   observes its release, so no child outlives its parent and no false free capacity
//!   appears (S10 line 185). A shared extent the lifecycle owns is released even while
//!   holders remain; they lose it.
//!
//! A lifecycle that drained or ended is remembered, so a late request cannot bind to it
//! again; at most [`MAX_ENDED_LIFECYCLES`] are kept once nothing they own is open, the
//! oldest forgotten first. Activating again gets a new generation (CORE-04), which is a
//! new lifecycle.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use super::ownership::{GrowthRefusal, OwnershipError};
use super::{Admission, Ledger, ReleaseOutcome};
use crate::foundation::ids::{
    Clock, Digest, ExecutionId, ModelActivationGeneration, MonotonicTime, SandboxBootGeneration,
    TenantId,
};
use crate::foundation::ledger::{
    LedgerError, ParentField, QueueTicket, ReservationId, ReservationRequest, ReservationState,
};

/// How many drained or ended lifecycles that own nothing open one ledger remembers.
pub const MAX_ENDED_LIFECYCLES: usize = 4_096;

/// Which part of an execution's life owns a reservation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LifecycleScope {
    /// The execution as a whole (CORE-04's parent execution).
    Execution,
    /// One boot of a VM sandbox; every boot or restore gets a new one.
    SandboxBoot { boot: SandboxBootGeneration },
    /// One activation generation of one model, by the digest of the model's identity;
    /// activating again gets a new generation (GPU part §3.6).
    ModelActivation {
        model: Digest,
        generation: ModelActivationGeneration,
    },
}

/// The lifecycle that owns a parent reservation: one scope of one execution, under its
/// tenant.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Lifecycle {
    pub tenant: TenantId,
    pub execution: ExecutionId,
    pub scope: LifecycleScope,
}

impl Lifecycle {
    /// The whole of `execution`.
    pub fn execution(tenant: TenantId, execution: ExecutionId) -> Self {
        Self {
            tenant,
            execution,
            scope: LifecycleScope::Execution,
        }
    }

    /// One boot of the VM sandbox `execution` runs.
    pub fn sandbox_boot(
        tenant: TenantId,
        execution: ExecutionId,
        boot: SandboxBootGeneration,
    ) -> Self {
        Self {
            tenant,
            execution,
            scope: LifecycleScope::SandboxBoot { boot },
        }
    }

    /// One activation generation of `model` under `execution`.
    pub fn model_activation(
        tenant: TenantId,
        execution: ExecutionId,
        model: Digest,
        generation: ModelActivationGeneration,
    ) -> Self {
        Self {
            tenant,
            execution,
            scope: LifecycleScope::ModelActivation { model, generation },
        }
    }
}

impl fmt::Display for Lifecycle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let execution = &self.execution;
        match self.scope {
            LifecycleScope::Execution => write!(f, "execution {execution}")?,
            LifecycleScope::SandboxBoot { boot } => {
                write!(f, "boot {boot} of execution {execution}")?
            }
            LifecycleScope::ModelActivation { model, generation } => {
                let hex = model.to_hex();
                write!(
                    f,
                    "activation {generation} of model {} in execution {execution}",
                    hex.get(..12).unwrap_or(&hex)
                )?
            }
        }
        write!(f, " of tenant {}", self.tenant)
    }
}

/// How a lifecycle stops serving.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleEnd {
    /// It drains: what it holds keeps running, and nothing new is carved from it.
    Draining,
    /// It ended as planned.
    Completed,
    /// Its authority revoked it (CORE-04; INT-02).
    Revoked,
}

impl fmt::Display for LifecycleEnd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Draining => "is draining",
            Self::Completed => "ended",
            Self::Revoked => "was revoked",
        })
    }
}

/// Where a lifecycle is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleStatus {
    Live,
    Draining {
        since: MonotonicTime,
    },
    /// Ended or revoked; terminal.
    Ended {
        end: LifecycleEnd,
        at: MonotonicTime,
    },
}

impl fmt::Display for LifecycleStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Live => f.write_str("is live"),
            Self::Draining { .. } => f.write_str("is draining"),
            Self::Ended { end, .. } => end.fmt(f),
        }
    }
}

/// What draining, ending or revoking a lifecycle did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LifecycleReport {
    pub lifecycle: Lifecycle,
    /// Where it is now; a lifecycle that ended stays ended.
    pub status: LifecycleStatus,
    /// The open parent reservations it owned when called, in order.
    pub parents: Vec<ReservationId>,
    /// Parents closed at once with everything carved from them: never created.
    pub released: Vec<ReservationId>,
    /// Parents now releasing: their workloads exist, so they and what was carved from them
    /// count until a source with authority observes the release.
    pub releasing: Vec<ReservationId>,
    /// Its own requests that were waiting for capacity, refused.
    pub withdrawn: Vec<QueueTicket>,
}

/// The lifecycles of one ledger and what they own.
#[derive(Debug, Default)]
pub(super) struct Lifecycles {
    status: BTreeMap<Lifecycle, LifecycleStatus>,
    owners: BTreeMap<ReservationId, Lifecycle>,
    /// Owned requests waiting in the queue, bound when the queue grants them.
    pending: BTreeMap<QueueTicket, Lifecycle>,
    /// Drained or ended lifecycles, oldest first.
    ended: VecDeque<Lifecycle>,
}

impl Lifecycles {
    fn status_of(&self, lifecycle: &Lifecycle) -> LifecycleStatus {
        self.status
            .get(lifecycle)
            .copied()
            .unwrap_or(LifecycleStatus::Live)
    }
}

/// A reservation keeps the tenant and execution of the lifecycle that owns it.
fn check_provenance(
    tenant: &TenantId,
    execution: &ExecutionId,
    lifecycle: &Lifecycle,
) -> Result<(), LedgerError> {
    let field = if *tenant != lifecycle.tenant {
        ParentField::Tenant
    } else if *execution != lifecycle.execution {
        ParentField::Execution
    } else {
        return Ok(());
    };
    Err(OwnershipError::LifecycleMismatch { field }.into())
}

impl<C: Clock> Ledger<C> {
    /// Reserves as [`Self::reserve`] does, for a parent `lifecycle` owns. The request
    /// keeps the lifecycle's tenant and execution, and the lifecycle must be live. A
    /// request that waits in the queue is owned once granted; it is refused when the
    /// lifecycle drains or ends first.
    pub fn reserve_owned(
        &mut self,
        request: ReservationRequest,
        lifecycle: Lifecycle,
    ) -> Result<Admission, LedgerError> {
        check_provenance(
            &request.provenance.tenant,
            &request.provenance.execution,
            &lifecycle,
        )?;
        self.require_live(&lifecycle)?;
        let admission = self.reserve(request)?;
        let lifecycles = &mut self.ownership.lifecycles;
        match &admission {
            Admission::Granted(reservation) => {
                lifecycles.owners.insert(*reservation, lifecycle);
            }
            Admission::Queued { ticket, .. } => {
                lifecycles.pending.insert(*ticket, lifecycle);
            }
        }
        Ok(admission)
    }

    /// Makes `lifecycle` the owner of an open reservation that is not releasing. The
    /// reservation keeps the lifecycle's tenant and execution, and the lifecycle must be
    /// live. Idempotent; another lifecycle's reservation is refused.
    pub fn bind_lifecycle(
        &mut self,
        reservation: ReservationId,
        lifecycle: Lifecycle,
    ) -> Result<(), LedgerError> {
        self.run(|ledger, _| {
            let record = ledger.open_record(reservation)?;
            if record.state == ReservationState::Releasing {
                return Err(LedgerError::ParentNotOpen {
                    parent: reservation,
                });
            }
            check_provenance(
                &record.provenance.tenant,
                &record.provenance.execution,
                &lifecycle,
            )?;
            ledger.require_live(&lifecycle)?;
            match ledger.owner_of(reservation) {
                Some(owner) if *owner == lifecycle => Ok(()),
                Some(owner) => Err(OwnershipError::AlreadyOwned {
                    reservation,
                    lifecycle: owner.clone(),
                }
                .into()),
                None => {
                    ledger
                        .ownership
                        .lifecycles
                        .owners
                        .insert(reservation, lifecycle);
                    Ok(())
                }
            }
        })
    }

    /// Drains, ends or revokes `lifecycle` (see the module documentation). Its waiting
    /// requests are refused; on an end or a revocation every parent it owns is cancelled
    /// with everything carved from it. Idempotent: a lifecycle that ended stays ended, and
    /// one never seen is recorded, so nothing binds to it later.
    pub fn end_lifecycle(&mut self, lifecycle: &Lifecycle, end: LifecycleEnd) -> LifecycleReport {
        self.run(|ledger, now| {
            ledger.resolve_pending_owners();
            let status = ledger.mark_lifecycle(lifecycle, end, now);
            let withdrawn = ledger.withdraw_owned_requests(lifecycle, status, now);
            let parents = ledger.lifecycle_parents(lifecycle);
            let mut report = LifecycleReport {
                lifecycle: lifecycle.clone(),
                status,
                parents: parents.clone(),
                released: Vec::new(),
                releasing: Vec::new(),
                withdrawn,
            };
            if matches!(status, LifecycleStatus::Ended { .. }) {
                for parent in parents {
                    match ledger.release_owned(parent, now) {
                        Ok(ReleaseOutcome::Released { .. }) => report.released.push(parent),
                        Ok(ReleaseOutcome::Pending) => report.releasing.push(parent),
                        Ok(ReleaseOutcome::AlreadyClosed) | Err(_) => {}
                    }
                }
            }
            report
        })
    }

    /// Where `lifecycle` is; `None` when this ledger does not know it (it owns nothing
    /// open and never drained or ended, or it was forgotten).
    pub fn lifecycle_status(&self, lifecycle: &Lifecycle) -> Option<LifecycleStatus> {
        self.ownership
            .lifecycles
            .status
            .get(lifecycle)
            .copied()
            .or_else(|| {
                let lifecycles = &self.ownership.lifecycles;
                (lifecycles.owners.values().any(|owner| owner == lifecycle)
                    || lifecycles.pending.values().any(|owner| owner == lifecycle))
                .then_some(LifecycleStatus::Live)
            })
    }

    /// The open reservations `lifecycle` owns, in order.
    pub fn lifecycle_parents(&self, lifecycle: &Lifecycle) -> Vec<ReservationId> {
        self.open
            .keys()
            .copied()
            .filter(|reservation| self.owner_of(*reservation) == Some(lifecycle))
            .collect()
    }

    /// The lifecycle that owns an open reservation, when one does.
    pub fn lifecycle_of(&self, reservation: ReservationId) -> Option<&Lifecycle> {
        self.owner_of(reservation)
    }

    /// Why nothing new is carved from `reservation` because of the lifecycle that owns it.
    pub(super) fn lifecycle_refusal(&self, reservation: ReservationId) -> Option<GrowthRefusal> {
        let lifecycle = self.owner_of(reservation)?;
        match self.ownership.lifecycles.status_of(lifecycle) {
            LifecycleStatus::Live => None,
            LifecycleStatus::Draining { since } => Some(GrowthRefusal::LifecycleDraining {
                lifecycle: lifecycle.clone(),
                since,
            }),
            LifecycleStatus::Ended { end, at } => Some(GrowthRefusal::LifecycleEnded {
                lifecycle: lifecycle.clone(),
                end,
                at,
            }),
        }
    }

    /// Binds the owned requests the queue granted since, and drops those it refused.
    pub(super) fn resolve_pending_owners(&mut self) {
        if self.ownership.lifecycles.pending.is_empty() {
            return;
        }
        let left: Vec<QueueTicket> = self
            .ownership
            .lifecycles
            .pending
            .keys()
            .copied()
            .filter(|ticket| self.queue_position(*ticket).is_none())
            .collect();
        for ticket in left {
            let granted = self
                .open
                .values()
                .find(|record| record.ticket == Some(ticket))
                .map(|record| record.id);
            let lifecycles = &mut self.ownership.lifecycles;
            if let (Some(lifecycle), Some(reservation)) =
                (lifecycles.pending.remove(&ticket), granted)
            {
                lifecycles.owners.insert(reservation, lifecycle);
            }
        }
    }

    /// Forgets the owners of closed reservations, live lifecycles that own nothing, and
    /// the oldest drained or ended lifecycles beyond [`MAX_ENDED_LIFECYCLES`] that own
    /// nothing open.
    pub(super) fn forget_lifecycles(&mut self) {
        let open = &self.open;
        let lifecycles = &mut self.ownership.lifecycles;
        lifecycles
            .owners
            .retain(|reservation, _| open.contains_key(reservation));
        let owning: BTreeSet<Lifecycle> = lifecycles
            .owners
            .values()
            .chain(lifecycles.pending.values())
            .cloned()
            .collect();
        lifecycles.status.retain(|lifecycle, status| {
            *status != LifecycleStatus::Live || owning.contains(lifecycle)
        });
        while lifecycles.ended.len() > MAX_ENDED_LIFECYCLES {
            let Some(index) = lifecycles
                .ended
                .iter()
                .position(|lifecycle| !owning.contains(lifecycle))
            else {
                break;
            };
            if let Some(lifecycle) = lifecycles.ended.remove(index) {
                lifecycles.status.remove(&lifecycle);
            }
        }
    }

    /// The lifecycle that owns an open reservation: bound to it, or granted from the
    /// queue for an owned request not yet bound.
    fn owner_of(&self, reservation: ReservationId) -> Option<&Lifecycle> {
        let record = self.open.get(&reservation)?;
        let lifecycles = &self.ownership.lifecycles;
        lifecycles.owners.get(&reservation).or_else(|| {
            record
                .ticket
                .and_then(|ticket| lifecycles.pending.get(&ticket))
        })
    }

    fn require_live(&self, lifecycle: &Lifecycle) -> Result<(), LedgerError> {
        match self.ownership.lifecycles.status_of(lifecycle) {
            LifecycleStatus::Live => Ok(()),
            status => Err(OwnershipError::LifecycleNotLive {
                lifecycle: lifecycle.clone(),
                status,
            }
            .into()),
        }
    }

    /// Records the lifecycle's new status and returns it; an ended lifecycle stays ended.
    fn mark_lifecycle(
        &mut self,
        lifecycle: &Lifecycle,
        end: LifecycleEnd,
        now: MonotonicTime,
    ) -> LifecycleStatus {
        let lifecycles = &mut self.ownership.lifecycles;
        let current = lifecycles.status_of(lifecycle);
        let next = match (current, end) {
            (LifecycleStatus::Ended { .. }, _)
            | (LifecycleStatus::Draining { .. }, LifecycleEnd::Draining) => current,
            (_, LifecycleEnd::Draining) => LifecycleStatus::Draining { since: now },
            (_, end) => LifecycleStatus::Ended { end, at: now },
        };
        if current == LifecycleStatus::Live && next != LifecycleStatus::Live {
            lifecycles.ended.push_back(lifecycle.clone());
        }
        lifecycles.status.insert(lifecycle.clone(), next);
        next
    }

    /// Refuses the lifecycle's requests still waiting in the queue.
    fn withdraw_owned_requests(
        &mut self,
        lifecycle: &Lifecycle,
        status: LifecycleStatus,
        now: MonotonicTime,
    ) -> Vec<QueueTicket> {
        let tickets: Vec<QueueTicket> = self
            .ownership
            .lifecycles
            .pending
            .iter()
            .filter(|(_, owner)| *owner == lifecycle)
            .map(|(ticket, _)| *ticket)
            .collect();
        let mut withdrawn = Vec::new();
        for ticket in tickets {
            self.ownership.lifecycles.pending.remove(&ticket);
            let Some(index) = self.queue.iter().position(|entry| entry.ticket == ticket) else {
                continue;
            };
            if let Some(entry) = self.queue.remove(index) {
                let error = LedgerError::Ownership(OwnershipError::LifecycleNotLive {
                    lifecycle: lifecycle.clone(),
                    status,
                });
                self.refuse_queued(entry, error, now);
                withdrawn.push(ticket);
            }
        }
        withdrawn
    }
}
