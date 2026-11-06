//! Home-side delegation over the VM service's existing coordinator and supervisor.
//! The handle is scoped to one real parent boot and only the child leases it issues.
use std::collections::BTreeSet;
use std::sync::Arc;

use super::state::{Core, Shared};
use super::{SandboxId, VmPorts, VmService, VmServiceError};
use crate::foundation::coordination::{
    CoordinationError, Lease, LeaseKind, LeaseRefusal, LeaseTerms, RevocationMilestone,
};
use crate::foundation::evidence::{ClockSession, SourceClass};
use crate::foundation::ids::{
    AuthorizationEpoch, Clock, ExecutionCategory, ExecutionId, LeaseId, MonotonicTime, OperationId,
};
use crate::sandbox::lifecycle::CallTerms;
use crate::sandbox_contract::files::{ExpiryGuard, LifetimeRefusal};
use crate::sandbox_contract::remote::{HostAuthority, LabelledGrant};

pub struct VmDelegation<P: VmPorts> {
    shared: Arc<Shared<P>>,
    parent: SandboxId,
    boot: crate::foundation::ids::SandboxBootGeneration,
    clock: P::Clock,
    session: ClockSession,
    guard: ExpiryGuard,
    issued: BTreeSet<LeaseId>,
    may_issue: bool,
}

fn refused(detail: impl ToString) -> LifetimeRefusal {
    LifetimeRefusal::HostPolicy {
        detail: detail.to_string(),
    }
}

impl<P: VmPorts> VmService<P> {
    pub fn delegation(&self, parent: &SandboxId) -> Result<VmDelegation<P>, VmServiceError> {
        self.delegation_bound(parent, None)
    }

    /// Recover an old remote cleanup intent on this engine's actual clock. The
    /// recorded parent need not still run, and this handle can NEVER issue work.
    pub fn cleanup_delegation(
        &self,
        parent: &SandboxId,
        boot: crate::foundation::ids::SandboxBootGeneration,
    ) -> Result<VmDelegation<P>, VmServiceError> {
        self.delegation_bound(parent, Some(boot))
    }

    fn delegation_bound(
        &self,
        parent: &SandboxId,
        recorded_boot: Option<crate::foundation::ids::SandboxBootGeneration>,
    ) -> Result<VmDelegation<P>, VmServiceError> {
        let core = self.shared.lock();
        let boot = match recorded_boot {
            Some(boot) => boot,
            None => core.ready_boot(parent)?.boot,
        };
        let host = core.host.as_ref().ok_or(VmServiceError::ShuttingDown)?;
        let session = host.supervisor().coordinator().session();
        Ok(VmDelegation {
            shared: Arc::clone(&self.shared),
            parent: parent.clone(),
            boot,
            clock: host.clock().clone(),
            session,
            guard: ExpiryGuard::new(session),
            issued: BTreeSet::new(),
            may_issue: recorded_boot.is_none(),
        })
    }
}

impl<P: VmPorts> VmDelegation<P> {
    pub fn parent_boot(&self) -> crate::foundation::ids::SandboxBootGeneration {
        self.boot
    }

    fn owns(&self, lease: LeaseId) -> Result<(), LifetimeRefusal> {
        if self.issued.contains(&lease) {
            Ok(())
        } else {
            Err(LifetimeRefusal::ForeignCall { lease })
        }
    }

    fn parent_ready(&self, core: &mut Core<P>) -> Result<(), LifetimeRefusal> {
        if core.ready_boot(&self.parent).map_err(refused)?.boot != self.boot {
            return Err(refused("delegation belongs to an earlier parent boot"));
        }
        // A remote parent cannot delegate past its own additional gate.
        core.authorize_remote(&self.parent).map_err(refused)?;
        let host = core
            .host
            .as_ref()
            .ok_or_else(|| refused("the parent engine ended"))?;
        if host.supervisor().coordinator().session() != self.session {
            return Err(refused("delegation belongs to an earlier clock session"));
        }
        Ok(())
    }

    fn end_owned(core: &mut Core<P>, lease: LeaseId) {
        if let Some(host) = core.host.as_mut() {
            host.with_supervisor(|supervisor, _, _| {
                let _ = supervisor.coordinator_mut().release_lease(lease);
            });
        }
        core.absorb_log();
    }
}

impl<P: VmPorts> HostAuthority for VmDelegation<P> {
    fn session(&self) -> ClockSession {
        self.session
    }
    fn now(&self) -> MonotonicTime {
        self.clock.now()
    }

    fn issue(
        &mut self,
        parent: &ExecutionId,
        operation: OperationId,
        terms: LeaseTerms,
    ) -> Result<Lease, LifetimeRefusal> {
        if !self.may_issue {
            return Err(refused(
                "this recovery handle permits cleanup only, never workload authority",
            ));
        }
        if parent != self.parent.execution() {
            return Err(refused("delegation belongs to another parent VM"));
        }
        terms
            .check()
            .map_err(|problem| LeaseRefusal::InvalidTerms { problem })?;
        if self.issued.len() >= 64 {
            return Err(refused("this delegation holds its child-lease limit"));
        }
        let mut core = self.shared.lock();
        self.parent_ready(&mut core)?;
        let host = core
            .host
            .as_mut()
            .ok_or_else(|| refused("the parent engine ended"))?;
        if host.supervisor().config().cancel_within > terms.cancel_within {
            return Err(refused(
                "the requested cancellation bound is shorter than this host guarantees",
            ));
        }
        let lease = host
            .authorize_work(
                parent,
                operation,
                LeaseKind::Service,
                CallTerms {
                    per_call: terms.term,
                    task: terms.max_lifetime,
                },
                BTreeSet::new(),
            )
            .map_err(refused)?;
        self.issued.insert(lease.id());
        core.absorb_log();
        self.shared.notify();
        Ok(lease)
    }

    fn renew(&mut self, lease: LeaseId, presented: ClockSession) -> Result<Lease, LifetimeRefusal> {
        self.owns(lease)?;
        let mut core = self.shared.lock();
        if let Err(error) = self.parent_ready(&mut core) {
            Self::end_owned(&mut core, lease);
            self.shared.notify();
            return Err(error);
        }
        let host = core
            .host
            .as_mut()
            .ok_or_else(|| refused("the parent engine ended"))?;
        let result = host.with_supervisor(|supervisor, backend, _| {
            self.guard.check(supervisor.coordinator(), lease)?;
            match supervisor.renew_observed_work(lease, presented, backend) {
                Ok(renewed) => self
                    .guard
                    .check(supervisor.coordinator(), lease)
                    .map(|_| renewed),
                Err(error) => {
                    // Any authority refusal is final for this handle, including lockdown.
                    // A maximum-lifetime renewal limit leaves a still-valid lease usable.
                    if matches!(
                        &error,
                        crate::sandbox::lifecycle::SupervisorError::Lease {
                            refusal: LeaseRefusal::RenewalLimitReached { .. }
                        }
                    ) {
                        return Err(refused(error));
                    }
                    let _ = supervisor.coordinator_mut().release_lease(lease);
                    let _ = self.guard.check(supervisor.coordinator(), lease);
                    Err(refused(error))
                }
            }
        });
        core.absorb_log();
        self.shared.notify();
        result
    }

    fn check(&mut self, lease: LeaseId) -> Result<Lease, LifetimeRefusal> {
        self.owns(lease)?;
        let mut core = self.shared.lock();
        if let Err(error) = self.parent_ready(&mut core) {
            Self::end_owned(&mut core, lease);
            self.shared.notify();
            return Err(error);
        }
        let host = core
            .host
            .as_mut()
            .ok_or_else(|| refused("the parent engine ended"))?;
        let result = host.with_supervisor(|supervisor, backend, _| {
            self.guard.check(supervisor.coordinator(), lease)?;
            if let Err(error) = supervisor.check_observed_work(lease, backend) {
                let _ = supervisor.coordinator_mut().release_lease(lease);
                let _ = self.guard.check(supervisor.coordinator(), lease);
                return Err(refused(error));
            }
            self.guard.check(supervisor.coordinator(), lease)
        });
        core.absorb_log();
        self.shared.notify();
        result
    }

    fn release(&mut self, lease: LeaseId) -> Result<(), LifetimeRefusal> {
        self.owns(lease)?;
        let mut core = self.shared.lock();
        let host = core
            .host
            .as_mut()
            .ok_or_else(|| refused("the parent engine ended"))?;
        let result = host
            .with_supervisor(|supervisor, _, _| supervisor.coordinator_mut().release_lease(lease));
        core.absorb_log();
        self.shared.notify();
        result.map_err(Into::into)
    }

    fn check_labelled(&mut self, execution: &ExecutionId) -> Result<LabelledGrant, LeaseRefusal> {
        Err(LeaseRefusal::UnknownExecution {
            execution: execution.clone(),
        })
    }
    fn revoke_labelled(
        &mut self,
        _execution: &ExecutionId,
    ) -> Result<AuthorizationEpoch, CoordinationError> {
        Err(CoordinationError::NotALabelledRuntime {
            category: ExecutionCategory::VmSandbox,
        })
    }
    fn acknowledge_revocation(
        &mut self,
        execution: &ExecutionId,
        milestone: RevocationMilestone,
        source: SourceClass,
    ) -> Result<Option<MonotonicTime>, CoordinationError> {
        if execution != self.parent.execution() {
            return Err(CoordinationError::UnknownExecution {
                execution: execution.clone(),
            });
        }
        let mut core = self.shared.lock();
        let host = core
            .host
            .as_mut()
            .ok_or_else(|| CoordinationError::UnknownExecution {
                execution: execution.clone(),
            })?;
        host.with_supervisor(|supervisor, _, _| {
            match supervisor
                .coordinator_mut()
                .acknowledge_revocation(execution, milestone, source)
            {
                Ok(at) => Ok(Some(at)),
                Err(CoordinationError::NotRevoking { .. }) => Ok(None),
                Err(error) => Err(error),
            }
        })
    }
}

impl<P: VmPorts> Drop for VmDelegation<P> {
    fn drop(&mut self) {
        let mut core = self.shared.lock();
        if let Some(host) = core.host.as_mut() {
            host.with_supervisor(|supervisor, _, _| {
                for lease in &self.issued {
                    let _ = supervisor.coordinator_mut().release_lease(*lease);
                }
            });
        }
        core.absorb_log();
        self.shared.notify();
    }
}
