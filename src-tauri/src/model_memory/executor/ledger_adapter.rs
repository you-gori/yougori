//! The reservation port over the committed CORE-03 ledger (T04,
//! [`crate::foundation::ledger`]).
//!
//! Destinations and bounded staging are reserved before a transfer starts, marked in use
//! once committed, and cancelled on completion, cancellation, retirement or close. The
//! ledger keeps counting a reservation that was in use until the host observes its
//! release, so giving one back never shows false free capacity; the executor never
//! confirms a release itself. Pinned staging is charged to pinned RAM and to host RAM,
//! because pinned bytes are host RAM too (GPU §2.7). A destination reserved within a
//! placement's reservation (P04) is the ledger child of that reservation, carved from
//! its amounts rather than from host capacity, so it is never counted twice; once its
//! bytes are delivered it is handed over: cancelled and its release confirmed by the
//! transfer's own report, which is enough for a child, so its amounts return to the
//! parent at once instead of staying counted until the parent closes (T15).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use super::model::Priority;
use super::ports::{
    CapacityLimit, CapacityRefusal, ReservationId, ReservationPort, ReservationRefusal,
    ReservationRequest, ReservedResource, RetryAdvice, UnknownReservation,
};
use crate::foundation::evidence::{GpuDeviceSubject, SourceClass};
use crate::foundation::ids::{Clock, ExecutionId, GpuDeviceKey, TenantId};
use crate::foundation::ledger::{
    self, Admission, Amounts, CapacityError, CostPurpose, DeviceId, HostResource, Ledger,
    LedgerError, Limit, Provenance, ReleaseOutcome, Requester, ResourceKey,
};

/// Who the executor's own staging is charged to: the ledger records every reservation
/// against an execution and a tenant (CORE-03 provenance).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagingAccount {
    pub execution: ExecutionId,
    pub tenant: TenantId,
}

/// The executor's reservations on the host's ledger (CORE-03).
///
/// Every request is made by [`Requester::Transfer`] for [`CostPurpose::Transfer`] and
/// does not wait: it is granted whole or refused with the limiting resource. Speculative
/// work reserves as background work, which an owner's resource-return hold denies.
pub struct LedgerReservations<C> {
    ledger: Arc<Mutex<Ledger<C>>>,
    staging: StagingAccount,
    granted: BTreeMap<ReservationId, ledger::ReservationId>,
}

impl<C: Clock> LedgerReservations<C> {
    /// Reserves on `ledger`, the one ledger of this host; staging is charged to
    /// `staging`.
    pub fn new(ledger: Arc<Mutex<Ledger<C>>>, staging: StagingAccount) -> Self {
        Self {
            ledger,
            staging,
            granted: BTreeMap::new(),
        }
    }

    /// The ledger reservation behind one of the executor's.
    pub fn ledger_reservation(&self, reservation: ReservationId) -> Option<ledger::ReservationId> {
        self.granted.get(&reservation).copied()
    }

    fn ledger(&self) -> MutexGuard<'_, Ledger<C>> {
        self.ledger.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Where the ledger counts a resource: VRAM per device, pinned or ordinary host RAM.
pub fn resource_key(resource: ReservedResource) -> ResourceKey {
    match resource {
        ReservedResource::DeviceMemory { device } => {
            ResourceKey::Vram(DeviceId::new(GpuDeviceSubject {
                machine: device.machine,
                device: device.device,
            }))
        }
        ReservedResource::PinnedHostMemory => ResourceKey::Host(HostResource::PinnedRam),
        ReservedResource::HostMemory => ResourceKey::Host(HostResource::Ram),
    }
}

/// What the ledger is charged for `bytes` of `resource`. Pinned bytes are host RAM too,
/// so a pinned reservation is charged to pinned RAM and to host RAM (GPU §2.7).
pub fn ledger_demand(resource: ReservedResource, bytes: u64) -> Amounts {
    let demand = Amounts::new().with(resource_key(resource), bytes);
    match resource {
        ReservedResource::PinnedHostMemory => {
            demand.with(resource_key(ReservedResource::HostMemory), bytes)
        }
        ReservedResource::DeviceMemory { .. } | ReservedResource::HostMemory => demand,
    }
}

fn reserved_resource(key: ResourceKey) -> Option<ReservedResource> {
    match key {
        ResourceKey::Vram(device) => Some(ReservedResource::DeviceMemory {
            device: GpuDeviceKey {
                machine: device.machine(),
                device: device.device(),
            },
        }),
        ResourceKey::Host(HostResource::PinnedRam) => Some(ReservedResource::PinnedHostMemory),
        ResourceKey::Host(HostResource::Ram) => Some(ReservedResource::HostMemory),
        ResourceKey::Host(_) | ResourceKey::GpuLoadSlots(_) => None,
    }
}

fn capacity_refusal(error: &CapacityError) -> ReservationRefusal {
    let limiting = error.limiting();
    let Some(resource) = reserved_resource(limiting.resource) else {
        return ReservationRefusal::Rejected {
            reason: error.to_string(),
        };
    };
    let limit = match limiting.limit {
        Limit::PhysicalCapacity => CapacityLimit::PhysicalCapacity,
        Limit::CapacityNotObserved => CapacityLimit::CapacityNotObserved,
        Limit::StaleHostObservation { .. } => CapacityLimit::StaleHostObservation,
        Limit::TenantBudget { .. } => CapacityLimit::TenantBudget,
        Limit::ParentReservation { .. } => CapacityLimit::ParentReservation,
        Limit::OwnerReturnHold { .. } => CapacityLimit::OwnerReturnHold,
    };
    ReservationRefusal::Capacity(CapacityRefusal {
        resource,
        limit,
        requested_bytes: limiting.requested,
        available_bytes: limiting.available,
        retry: if error.retry_can_progress() {
            RetryAdvice::CanProgress
        } else {
            RetryAdvice::CannotProgress
        },
    })
}

impl<C: Clock> ReservationPort for LedgerReservations<C> {
    fn reserve(
        &mut self,
        request: &ReservationRequest,
    ) -> Result<ReservationId, ReservationRefusal> {
        let provenance = Provenance {
            requester: Requester::Transfer,
            execution: request
                .execution
                .clone()
                .unwrap_or_else(|| self.staging.execution.clone()),
            operation: request.operation.clone(),
            tenant: request
                .tenant
                .clone()
                .unwrap_or_else(|| self.staging.tenant.clone()),
            purpose: CostPurpose::Transfer,
            retry_number: 0,
        };
        let priority = match request.priority {
            Priority::Foreground => ledger::Priority::Foreground,
            Priority::Speculative => ledger::Priority::Background,
        };
        let demand = ledger_demand(request.resource, request.bytes);
        let mut filed = ledger::ReservationRequest::new(provenance, priority, demand);
        if let Some(parent) = request.parent {
            filed = filed.within(parent);
        }
        let admission = self.ledger().reserve(filed);
        match admission {
            Ok(Admission::Granted(granted)) => {
                let reservation = ReservationId(granted.get());
                self.granted.insert(reservation, granted);
                Ok(reservation)
            }
            Ok(Admission::Queued { ticket, .. }) => {
                let withdrawn = self.ledger().cancel_queued(ticket);
                Err(ReservationRefusal::Rejected {
                    reason: format!(
                        "the ledger queued a request that asked not to wait ({ticket}; \
                         withdrawn: {withdrawn:?})"
                    ),
                })
            }
            Err(LedgerError::Capacity(error)) => Err(capacity_refusal(&error)),
            Err(error) => Err(ReservationRefusal::Rejected {
                reason: error.to_string(),
            }),
        }
    }

    fn begin_use(&mut self, reservation: ReservationId) -> Result<(), UnknownReservation> {
        let granted = self
            .granted
            .get(&reservation)
            .copied()
            .ok_or(UnknownReservation { reservation })?;
        self.ledger()
            .begin_create(granted)
            .map_err(|_| UnknownReservation { reservation })
    }

    fn release(&mut self, reservation: ReservationId) -> Result<(), UnknownReservation> {
        let granted = self
            .granted
            .remove(&reservation)
            .ok_or(UnknownReservation { reservation })?;
        match self.ledger().cancel(granted) {
            Ok(ReleaseOutcome::Released { .. } | ReleaseOutcome::Pending) => Ok(()),
            Ok(ReleaseOutcome::AlreadyClosed) | Err(_) => Err(UnknownReservation { reservation }),
        }
    }

    /// A child goes back to its parent at once: it is cancelled and its release is
    /// confirmed by the transfer's own report, a guest report, which the ledger accepts
    /// for a child (CORE-03). A host-level reservation is only cancelled, as by
    /// [`ReservationPort::release`].
    fn hand_over(&mut self, reservation: ReservationId) -> Result<(), UnknownReservation> {
        let granted = self
            .granted
            .remove(&reservation)
            .ok_or(UnknownReservation { reservation })?;
        let mut ledger = self.ledger();
        let child = ledger
            .reservation(granted)
            .is_some_and(|record| record.parent().is_some());
        match ledger.cancel(granted) {
            Ok(ReleaseOutcome::Pending) if child => {
                match ledger.confirm_release(granted, SourceClass::GuestReport) {
                    Ok(ReleaseOutcome::Released { .. }) => Ok(()),
                    Ok(ReleaseOutcome::Pending | ReleaseOutcome::AlreadyClosed) | Err(_) => {
                        Err(UnknownReservation { reservation })
                    }
                }
            }
            Ok(ReleaseOutcome::Released { .. } | ReleaseOutcome::Pending) => Ok(()),
            Ok(ReleaseOutcome::AlreadyClosed) | Err(_) => Err(UnknownReservation { reservation }),
        }
    }
}
