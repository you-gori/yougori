//! Delegated authority for a remote run, held by the host's CORE-04 coordinator (VM part
//! §6.2, §6.3; VM-W39; VM-P40; VM-D5).
//!
//! - A remote VM's authority is a CORE-04 service lease, child work of its parent VM
//!   sandbox. The host alone issues and renews it, through the coordinator, which never
//!   renews an expired, cancelled or stale lease, never past its maximum lifetime or the
//!   parent's authority, and never while its clock reads below its high-water mark. Every
//!   check goes through V05's [`ExpiryGuard`], which presents the lease to the coordinator
//!   with the coordinator's clock session and ends it on any refusal, so a lease once
//!   refused, including while the clock read below the mark, is never honoured again,
//!   after the clock recovers and across a restart too (§6.2: persist enough state to
//!   prevent clock rollback or snapshot restore from reviving expired rights).
//! - A remote provider container is a labelled runtime (VM-D5): its authority is the
//!   coordinator's labelled-runtime record under its own authorization epoch, granted by
//!   [`CoordinatorDelegation::authorize_labelled`] and ended by revoking it. It never gets
//!   the VM sandbox lifecycle or a lease.
//!
//! The remote side holds only a [`LeaseGrant`]: the authority it stands on and a time to
//! live. It has no way to renew.
//!
//! [`remote_authority_bound`] states how long a remote enforcement point that checks its
//! lease and cannot mint renewals may still act once the host stops renewing:
//! `lease_TTL + allowed_clock_uncertainty`, the bound of effects'
//! [`PostRevocationBounds`].

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use serde::Serialize;

use super::control::LeaseGrant;
use crate::foundation::coordination::{
    CapacityPort, CoordinationError, Coordinator, LabelledAuthorization, Lease, LeaseKind,
    LeaseRefusal, LeaseTerms, RevocationMilestone,
};
use crate::foundation::evidence::{
    AuthorityGrant, ClockSession, ProbeRegistry, RuntimeSubject, SourceClass,
};
use crate::foundation::ids::{
    AuthorizationEpoch, Clock, ExecutionId, LeaseId, MonotonicTime, OperationId,
};
use crate::sandbox_contract::effects::{
    BoundNotApplicable, EnforcementPoint, PostRevocationBounds,
};
use crate::sandbox_contract::files::{ClockSkewPolicy, ExpiryGuard, GuardState, LifetimeRefusal};

/// The host's delegation authority as the adapter uses it (CORE-04). Only the host
/// issues and renews; the remote side's requests reach it only through the adapter.
pub trait HostAuthority {
    /// The clock session every lease of this authority is stamped with.
    fn session(&self) -> ClockSession;

    /// The authority's clock now.
    fn now(&self) -> MonotonicTime;

    /// Issues a service lease under `parent`'s current authority.
    fn issue(
        &mut self,
        parent: &ExecutionId,
        operation: OperationId,
        terms: LeaseTerms,
    ) -> Result<Lease, LifetimeRefusal>;

    /// Renews `lease`, presented with the clock session it was issued on.
    fn renew(&mut self, lease: LeaseId, presented: ClockSession) -> Result<Lease, LifetimeRefusal>;

    /// Whether `lease` is honoured now; a refusal is final.
    fn check(&mut self, lease: LeaseId) -> Result<Lease, LifetimeRefusal>;

    /// The holder is done.
    fn release(&mut self, lease: LeaseId) -> Result<(), LifetimeRefusal>;

    /// The labelled runtime `execution`'s authority record (VM-D5): its exact runtime and
    /// the grant honoured now, or why none is.
    fn check_labelled(&mut self, execution: &ExecutionId) -> Result<LabelledGrant, LeaseRefusal>;

    /// Revokes the labelled runtime `execution`: its epoch advances, so the grant is never
    /// honoured again. Returns the epoch now in force.
    fn revoke_labelled(
        &mut self,
        execution: &ExecutionId,
    ) -> Result<AuthorizationEpoch, CoordinationError>;

    /// Records an external acknowledgment of §6.3, such as the provider stopping billing,
    /// on the revocation of the VM sandbox `execution`; `Ok(None)` when no revocation of it
    /// is in progress, so there is nothing to acknowledge.
    fn acknowledge_revocation(
        &mut self,
        execution: &ExecutionId,
        milestone: RevocationMilestone,
        source: SourceClass,
    ) -> Result<Option<MonotonicTime>, CoordinationError>;
}

/// A labelled runtime's authority as the coordinator records it now (VM-D5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LabelledGrant {
    /// The exact runtime, in its labelled category.
    pub runtime: RuntimeSubject,
    /// The authorization epoch in force.
    pub epoch: AuthorizationEpoch,
    pub grant: AuthorityGrant,
}

/// [`HostAuthority`] over the host's [`Coordinator`], shared with the VM lifecycle, with
/// V05's [`ExpiryGuard`] in front of every check and renewal.
pub struct CoordinatorDelegation<C: Clock, P: CapacityPort> {
    coordinator: Arc<Mutex<Coordinator<C, P>>>,
    guard: ExpiryGuard,
}

impl<C: Clock, P: CapacityPort> CoordinatorDelegation<C, P> {
    /// Delegation over the shared coordinator, with a fresh guard on its clock session.
    pub fn new(coordinator: Arc<Mutex<Coordinator<C, P>>>) -> Self {
        let session = coordinator
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .session();
        Self {
            coordinator,
            guard: ExpiryGuard::new(session),
        }
    }

    /// Restores a persisted guard onto the coordinator's clock session now, so leases seen
    /// ended before a restart stay ended (§6.2).
    pub fn restore(coordinator: Arc<Mutex<Coordinator<C, P>>>, state: GuardState) -> Self {
        let session = coordinator
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .session();
        Self {
            coordinator,
            guard: ExpiryGuard::restore(state, session),
        }
    }

    /// What to persist: the guard's clock session and the leases it saw refused (§6.2:
    /// persist enough state to prevent clock rollback or snapshot restore from reviving
    /// expired rights).
    pub fn guard_state(&self) -> &GuardState {
        self.guard.state()
    }

    /// Grants a labelled runtime's authority through the coordinator (VM-D5, INT-07): its
    /// category evidence is rechecked on `registry`, and a VM sandbox is refused.
    pub fn authorize_labelled<R: Clock>(
        &mut self,
        authorization: LabelledAuthorization,
        registry: &ProbeRegistry<R>,
    ) -> Result<AuthorityGrant, CoordinationError> {
        self.coordinator
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .authorize_labelled(authorization, registry)
    }
}

impl<C: Clock, P: CapacityPort> HostAuthority for CoordinatorDelegation<C, P> {
    fn session(&self) -> ClockSession {
        self.coordinator
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .session()
    }

    fn now(&self) -> MonotonicTime {
        self.coordinator
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .now()
    }

    fn issue(
        &mut self,
        parent: &ExecutionId,
        operation: OperationId,
        terms: LeaseTerms,
    ) -> Result<Lease, LifetimeRefusal> {
        let mut coordinator = self
            .coordinator
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        coordinator
            .start_child_work(parent, operation, LeaseKind::Service, terms)
            .map_err(LifetimeRefusal::from)
    }

    /// The guard checks the lease first, so an ended lease or a clock below the
    /// coordinator's high-water mark is refused before any renewal; the renewal itself goes
    /// through [`Coordinator::renew_presented_lease`] with the session the remote
    /// presented (§6.2).
    fn renew(&mut self, lease: LeaseId, presented: ClockSession) -> Result<Lease, LifetimeRefusal> {
        let mut coordinator = self
            .coordinator
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        self.guard.check(&coordinator, lease)?;
        match coordinator.renew_presented_lease(lease, presented) {
            Ok(renewed) => Ok(renewed),
            Err(refusal) => {
                // A refused renewal of a lease that is no longer honoured ends it for good.
                let _ = self.guard.check(&coordinator, lease);
                Err(LifetimeRefusal::Lease { refusal })
            }
        }
    }

    fn check(&mut self, lease: LeaseId) -> Result<Lease, LifetimeRefusal> {
        let coordinator = self
            .coordinator
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        self.guard.check(&coordinator, lease)
    }

    fn release(&mut self, lease: LeaseId) -> Result<(), LifetimeRefusal> {
        let mut coordinator = self
            .coordinator
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match coordinator.release_lease(lease) {
            Ok(()) | Err(LeaseRefusal::Released) => Ok(()),
            Err(refusal) => Err(LifetimeRefusal::Lease { refusal }),
        }
    }

    /// Reads the coordinator's labelled-runtime record through
    /// [`Coordinator::labelled_authority`], which honours the grant only on the
    /// coordinator's clock session, under the epoch in force, unexpired, and never while
    /// the clock reads below the coordinator's high-water mark.
    fn check_labelled(&mut self, execution: &ExecutionId) -> Result<LabelledGrant, LeaseRefusal> {
        let coordinator = self
            .coordinator
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let grant = coordinator.labelled_authority(execution)?;
        let record = coordinator.labelled_runtime(execution).ok_or_else(|| {
            LeaseRefusal::UnknownExecution {
                execution: execution.clone(),
            }
        })?;
        Ok(LabelledGrant {
            runtime: record.runtime().clone(),
            epoch: record.epoch(),
            grant,
        })
    }

    fn revoke_labelled(
        &mut self,
        execution: &ExecutionId,
    ) -> Result<AuthorizationEpoch, CoordinationError> {
        self.coordinator
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .revoke_labelled(execution)
    }

    fn acknowledge_revocation(
        &mut self,
        execution: &ExecutionId,
        milestone: RevocationMilestone,
        source: SourceClass,
    ) -> Result<Option<MonotonicTime>, CoordinationError> {
        let mut coordinator = self
            .coordinator
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match coordinator.acknowledge_revocation(execution, milestone, source) {
            Ok(at) => Ok(Some(at)),
            Err(CoordinationError::NotRevoking { .. }) => Ok(None),
            Err(error) => Err(error),
        }
    }
}

/// How long a remote enforcement point may still act after the host's last grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RemoteAuthorityBound {
    /// `lease_TTL + allowed_clock_uncertainty` (§2.5 lines 1821–1824).
    pub remaining_authorized_time: Duration,
    /// The host-clock moment after which the remote can no longer be acting under the
    /// grant.
    pub ends_by: MonotonicTime,
}

/// The bound for the last `grant`, sent at `granted_at` on the host clock, held by a
/// remote enforcement point that checks leases and cannot mint renewals. The remote
/// counts the time to live from receipt, so `skew`'s allowance is the clock uncertainty
/// and must cover delivery latency and clock-rate error as well as skew.
pub fn remote_authority_bound(
    grant: &LeaseGrant,
    granted_at: MonotonicTime,
    skew: &ClockSkewPolicy,
) -> Result<RemoteAuthorityBound, BoundNotApplicable> {
    let bounds = PostRevocationBounds::compute(
        EnforcementPoint {
            checks_leases: true,
            can_mint_renewals: false,
        },
        Duration::from_nanos(grant.ttl_nanos),
        Duration::from_secs(skew.max_skew_seconds),
        0,
        0,
    )?;
    Ok(RemoteAuthorityBound {
        remaining_authorized_time: bounds.remaining_authorized_time,
        ends_by: granted_at.saturating_add(bounds.remaining_authorized_time),
    })
}
