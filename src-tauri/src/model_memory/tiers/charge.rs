//! Charging tier reservations to the CORE-03 host ledger (T04; GPU §3.1 line 491: the
//! placement governor is a policy client of the ledger, never a second capacity
//! authority).
//!
//! Every tier byte that occupies host resources is reserved in the ledger before it is
//! created and given back through it. VRAM and local storage quota are requested
//! directly, VRAM under T08's
//! [`vram_resource`](crate::model_memory::residency::reservation::vram_resource) key.
//! Pinned and reclaimable host RAM go through T08's ledger adapter,
//! [`PlacementReservation`]: it admits a host plan model-side and asks for the plan's
//! peak host RAM and pinned RAM, so a pin is charged to both (decision T08: pinned pages
//! are host RAM, and the pinned pool is a cap inside it), while safety reserves and
//! observed occupancy stay with the ledger's supervisor reserve and unmanaged usage.
//!
//! The ledger decides whether capacity, the tenant's budget (a storage quota is a tenant
//! budget) or a parent reservation allows a request; a tier adds only its own accounting
//! rule. Requests never wait: they are granted whole or refused with the ledger's
//! actionable error.

use crate::foundation::ids::{Clock, ExecutionId, OperationId, TenantId};
use crate::foundation::ledger::{
    Admission, Amounts, CostPurpose, Ledger, LedgerError, Priority, Provenance, ReleaseOutcome,
    Requester, ReservationId, ReservationRequest,
};
use crate::model_memory::residency::host::HostPlan;
use crate::model_memory::residency::reservation::{PlacementError, PlacementReservation};

/// The parts of a reservation's provenance the caller supplies (CORE-03 accounting
/// provenance). The tier fills in the requester, tenant, execution and cost purpose
/// itself, so a caller cannot charge another tenant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerCharge {
    pub operation: OperationId,
    pub priority: Priority,
    /// Zero for an original attempt, n for the nth retry.
    pub retry_number: u32,
}

/// A reservation a tier gave back. The amounts of a created workload count until the
/// host observes their release, so the outcome is usually
/// [`ReleaseOutcome::Pending`] until the caller confirms it to the ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Released {
    pub bytes: u64,
    pub reservation: ReservationId,
    pub outcome: ReleaseOutcome,
}

/// Who a tier reservation is for.
pub(super) struct Charged<'a> {
    pub(super) tenant: &'a TenantId,
    pub(super) execution: &'a ExecutionId,
    pub(super) purpose: CostPurpose,
    /// The reservation to carve from, such as a runtime's own allocation (S3.2).
    pub(super) parent: Option<ReservationId>,
}

/// Why a host-memory charge was refused: T08's adapter would not build the request, or
/// the ledger refused it.
pub(super) enum HostCharge {
    Placement(PlacementError),
    Ledger(LedgerError),
}

fn provenance(charge: &LedgerCharge, charged: &Charged<'_>) -> Provenance {
    Provenance {
        requester: Requester::ModelPlacement,
        execution: charged.execution.clone(),
        operation: charge.operation.clone(),
        tenant: charged.tenant.clone(),
        purpose: charged.purpose,
        retry_number: charge.retry_number,
    }
}

/// Reserves `amounts` before creation and marks creation started.
pub(super) fn reserve_and_create<C: Clock>(
    ledger: &mut Ledger<C>,
    charge: &LedgerCharge,
    charged: Charged<'_>,
    amounts: Amounts,
) -> Result<ReservationId, LedgerError> {
    let mut request =
        ReservationRequest::new(provenance(charge, &charged), charge.priority, amounts);
    if let Some(parent) = charged.parent {
        request = request.within(parent);
    }
    let admission = ledger.reserve(request)?;
    create(ledger, admission)
}

/// Reserves the host RAM and pinned RAM of `plan` through T08's ledger adapter before
/// creation, and marks creation started. `plan` holds only the demand being added; what
/// is already held has reservations of its own.
pub(super) fn reserve_host_and_create<C: Clock>(
    ledger: &mut Ledger<C>,
    charge: &LedgerCharge,
    charged: Charged<'_>,
    plan: &HostPlan,
) -> Result<ReservationId, HostCharge> {
    let mut placement = PlacementReservation::new(
        provenance(charge, &charged),
        charge.priority,
        &[],
        Some(plan),
    )
    .map_err(HostCharge::Placement)?;
    if let Some(parent) = charged.parent {
        placement = placement.within(parent);
    }
    let admission = placement.reserve(ledger).map_err(HostCharge::Ledger)?;
    create(ledger, admission).map_err(HostCharge::Ledger)
}

/// Marks a granted reservation created. Tier requests never wait, so a queued one is
/// withdrawn and refused with what it was waiting for.
fn create<C: Clock>(
    ledger: &mut Ledger<C>,
    admission: Admission,
) -> Result<ReservationId, LedgerError> {
    match admission {
        Admission::Granted(reservation) => {
            if let Err(error) = ledger.begin_create(reservation) {
                // The grant was never used, so it returns at once.
                ledger.cancel(reservation)?;
                return Err(error);
            }
            Ok(reservation)
        }
        Admission::Queued {
            ticket,
            waiting_for,
            ..
        } => {
            ledger.cancel_queued(ticket)?;
            Err(LedgerError::Capacity(waiting_for))
        }
    }
}

/// Gives a reservation back through the ledger.
pub(super) fn release<C: Clock>(
    ledger: &mut Ledger<C>,
    reservation: ReservationId,
    bytes: u64,
) -> Result<Released, LedgerError> {
    let outcome = ledger.cancel(reservation)?;
    Ok(Released {
        bytes,
        reservation,
        outcome,
    })
}
