//! The reservation port over the CORE-03 ledger (task T04).
//!
//! Each part of a placement reservation, steady state and transition peak, is one
//! ledger reservation filed by the model-placement requester for the slot's parent
//! execution and the configured tenant, as a child of the runtime's parent reservation
//! when one is configured (S3.2, GPU part §3.1 line 491). Both parts are granted before
//! either is marked created, so a refusal of one returns the other at once. A granted
//! reservation is marked created immediately: the placement exists from step 1 on, and
//! the ledger's grant lifetime must not reclaim it while an old generation drains.
//!
//! Releases follow reclamation (§3.6 step 7). The ledger keeps counting released
//! amounts until a source with authority confirms the release: the runtime's own report
//! for a child, a host probe at host level. Releases the configured source cannot
//! confirm stay counted until [`LedgerPort::confirm_releases`] is called with one that
//! can, so reclaiming never yields false free capacity.
//!
//! A drain-first successor reserves only its excess over the predecessor's share at
//! once and takes over the predecessor's ledger reservations when the predecessor is
//! released, so that share never returns to the pool in between.

use std::collections::BTreeMap;

use super::keys::ReservationId;
use super::ports::{
    CapacityRefusal, ReservationGrant, ReservationPort, ReservationProblem, ReservationRefusal,
    ReservationRequest, ResourceDemand, ResourceKind, RetryOutlook,
};
use crate::foundation::evidence::{GpuDeviceSubject, SourceClass};
use crate::foundation::ids::{Clock, GpuDeviceKey, TenantId};
use crate::foundation::ledger::{
    self, Admission, Amounts, CostPurpose, DeviceId, HostResource, Ledger, LedgerError, Priority,
    Provenance, ReleaseOutcome, Requester, ResourceKey, RetryProspect,
};

/// How placement reservations are filed in the ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerPlacementConfig {
    /// The tenant whose budget host-level reservations are charged to.
    pub tenant: TenantId,
    pub priority: Priority,
    /// The runtime allocation the placements are carved from; `None` charges host
    /// capacity and the tenant budget directly.
    pub parent: Option<ledger::ReservationId>,
    /// The source that observes reclaimed memory as free when placement releases it.
    pub release_source: SourceClass,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Handle {
    held: Vec<(ledger::ReservationId, Amounts)>,
}

/// The mapping between port reservations and ledger reservations, kept across calls.
/// [`Self::port`] lends it a ledger for one slot operation.
#[derive(Clone, Debug)]
pub struct LedgerReservations {
    config: LedgerPlacementConfig,
    handles: BTreeMap<ReservationId, Handle>,
    /// Predecessor → the successor that takes over its share when it is released.
    handovers: BTreeMap<ReservationId, ReservationId>,
    unconfirmed: Vec<ledger::ReservationId>,
    next: u64,
}

impl LedgerReservations {
    /// No reservations yet, filed as `config` says.
    pub fn new(config: LedgerPlacementConfig) -> Self {
        Self {
            config,
            handles: BTreeMap::new(),
            handovers: BTreeMap::new(),
            unconfirmed: Vec::new(),
            next: 1,
        }
    }

    /// How reservations are filed.
    pub fn config(&self) -> &LedgerPlacementConfig {
        &self.config
    }

    /// The reservation port over `ledger` for one operation.
    pub fn port<'a, C: Clock>(&'a mut self, ledger: &'a mut Ledger<C>) -> LedgerPort<'a, C> {
        LedgerPort {
            state: self,
            ledger,
        }
    }

    /// The ledger reservations a port reservation stands for.
    pub fn ledger_reservations(&self, reservation: ReservationId) -> Vec<ledger::ReservationId> {
        self.handles
            .get(&reservation)
            .map(|handle| handle.held.iter().map(|(id, _)| *id).collect())
            .unwrap_or_default()
    }

    /// Released ledger reservations whose release no authoritative source has confirmed
    /// yet; their amounts still count.
    pub fn unconfirmed_releases(&self) -> &[ledger::ReservationId] {
        &self.unconfirmed
    }
}

/// [`ReservationPort`] over one borrowed [`Ledger`].
pub struct LedgerPort<'a, C: Clock> {
    state: &'a mut LedgerReservations,
    ledger: &'a mut Ledger<C>,
}

impl<C: Clock> LedgerPort<'_, C> {
    /// Confirms pending releases with an observation from `source`; releases `source`
    /// has no authority over stay pending. Returns how many were confirmed.
    pub fn confirm_releases(&mut self, source: SourceClass) -> usize {
        let pending = std::mem::take(&mut self.state.unconfirmed);
        let mut confirmed = 0;
        for reservation in pending {
            if self.ledger.confirm_release(reservation, source).is_ok() {
                confirmed += 1;
            } else {
                self.state.unconfirmed.push(reservation);
            }
        }
        confirmed
    }

    /// Grants one part without creating it; `None` for an empty part.
    fn grant(
        &mut self,
        request: &ReservationRequest,
        demand: &Amounts,
    ) -> Result<Option<(ledger::ReservationId, Amounts)>, ReservationRefusal> {
        if demand.is_empty() {
            return Ok(None);
        }
        let provenance = Provenance {
            requester: Requester::ModelPlacement,
            execution: request.execution.clone(),
            operation: request.operation.clone(),
            tenant: self.state.config.tenant.clone(),
            purpose: CostPurpose::Compute,
            retry_number: 0,
        };
        let mut filed =
            ledger::ReservationRequest::new(provenance, self.state.config.priority, demand.clone());
        if let Some(parent) = self.state.config.parent {
            filed = filed.within(parent);
        }
        match self.ledger.reserve(filed).map_err(refusal)? {
            Admission::Granted(id) => Ok(Some((id, demand.clone()))),
            Admission::Queued {
                ticket,
                waiting_for,
                ..
            } => {
                let _withdrawn = self.ledger.cancel_queued(ticket);
                Err(refusal(LedgerError::Capacity(waiting_for)))
            }
        }
    }

    /// Grants both parts, then marks both created; nothing stays granted on a refusal.
    fn grant_both(
        &mut self,
        request: &ReservationRequest,
        steady: &Amounts,
        peak: &Amounts,
    ) -> Result<GrantedParts, ReservationRefusal> {
        let steady = self.grant(request, steady)?;
        let peak = match self.grant(request, peak) {
            Ok(peak) => peak,
            Err(refused) => {
                if let Some((id, _)) = &steady {
                    self.release_ledger(*id);
                }
                return Err(refused);
            }
        };
        for (id, _) in steady.iter().chain(peak.iter()) {
            if let Err(error) = self.ledger.begin_create(*id) {
                for (id, _) in steady.iter().chain(peak.iter()) {
                    self.release_ledger(*id);
                }
                return Err(refusal(error));
            }
        }
        Ok(GrantedParts { steady, peak })
    }

    /// Releases one ledger reservation as reclaimed memory: before creation it returns
    /// at once; after creation the configured source must confirm the release.
    fn release_ledger(&mut self, reservation: ledger::ReservationId) {
        if let Ok(ReleaseOutcome::Pending) = self.ledger.cancel(reservation) {
            if self
                .ledger
                .confirm_release(reservation, self.state.config.release_source)
                .is_err()
            {
                self.state.unconfirmed.push(reservation);
            }
        }
    }

    fn handles_for(
        &mut self,
        steady: Option<Vec<(ledger::ReservationId, Amounts)>>,
        peak: Option<Vec<(ledger::ReservationId, Amounts)>>,
    ) -> ReservationGrant {
        let mut add = |held: Vec<(ledger::ReservationId, Amounts)>| {
            let id = ReservationId::new(self.state.next);
            self.state.next = self.state.next.saturating_add(1);
            self.state.handles.insert(id, Handle { held });
            id
        };
        ReservationGrant {
            steady: steady.map(&mut add),
            transition_peak: peak.map(&mut add),
        }
    }

    fn check_handles_left(&self) -> Result<(), ReservationRefusal> {
        if self.state.next > u64::MAX - 2 {
            return Err(ReservationRefusal::Refused {
                problem: ReservationProblem::Exhausted,
            });
        }
        Ok(())
    }
}

struct GrantedParts {
    steady: Option<(ledger::ReservationId, Amounts)>,
    peak: Option<(ledger::ReservationId, Amounts)>,
}

impl<C: Clock> ReservationPort for LedgerPort<'_, C> {
    fn reserve(
        &mut self,
        request: &ReservationRequest,
    ) -> Result<ReservationGrant, ReservationRefusal> {
        self.check_handles_left()?;
        let parts = self.grant_both(
            request,
            &to_amounts(&request.steady),
            &to_amounts(&request.transition_peak),
        )?;
        Ok(self.handles_for(
            parts.steady.map(|part| vec![part]),
            parts.peak.map(|part| vec![part]),
        ))
    }

    fn reserve_successor(
        &mut self,
        predecessor: ReservationId,
        request: &ReservationRequest,
    ) -> Result<ReservationGrant, ReservationRefusal> {
        self.check_handles_left()?;
        let Some(handle) = self.state.handles.get(&predecessor) else {
            return Err(ReservationRefusal::Refused {
                problem: ReservationProblem::UnknownPredecessor,
            });
        };
        if request.steady.is_empty() {
            return self.reserve(request);
        }
        let share = handle
            .held
            .iter()
            .flat_map(|(_, amounts)| amounts.iter())
            .fold(Amounts::new(), |share, (resource, amount)| {
                share.with(resource, amount)
            });
        let excess = to_amounts(&request.steady).excess_over(&share);
        let parts = self.grant_both(request, &excess, &to_amounts(&request.transition_peak))?;
        let grant = self.handles_for(
            Some(parts.steady.into_iter().collect()),
            parts.peak.map(|part| vec![part]),
        );
        if let Some(successor) = grant.steady {
            self.state.handovers.insert(predecessor, successor);
        }
        Ok(grant)
    }

    fn release(&mut self, reservation: ReservationId) {
        // A successor released first leaves the predecessor's share with it.
        self.state
            .handovers
            .retain(|_, successor| *successor != reservation);
        let Some(handle) = self.state.handles.remove(&reservation) else {
            return;
        };
        if let Some(successor) = self.state.handovers.remove(&reservation) {
            if let Some(target) = self.state.handles.get_mut(&successor) {
                target.held.extend(handle.held);
                return;
            }
        }
        for (id, _) in handle.held {
            self.release_ledger(id);
        }
    }
}

/// The ledger's key for a device placement names.
pub fn ledger_device(device: &GpuDeviceKey) -> DeviceId {
    DeviceId::new(GpuDeviceSubject {
        machine: device.machine,
        device: device.device,
    })
}

/// The ledger amounts of a demand. Pinned pages are host RAM, and the pinned pool is a
/// cap inside it, so pinned bytes are charged to both host RAM and pinned host RAM (GPU
/// part §2.7; the T08 and P02 decisions).
fn to_amounts(demand: &ResourceDemand) -> Amounts {
    demand
        .vram_bytes
        .iter()
        .fold(Amounts::new(), |amounts, (device, bytes)| {
            amounts.vram_bytes(ledger_device(device), *bytes)
        })
        .host_ram_bytes(
            demand
                .host_ram_bytes
                .saturating_add(demand.pinned_host_bytes),
        )
        .pinned_host_ram_bytes(demand.pinned_host_bytes)
}

fn resource_kind(resource: ResourceKey) -> Option<ResourceKind> {
    match resource {
        ResourceKey::Vram(device) => Some(ResourceKind::Vram {
            device: GpuDeviceKey {
                machine: device.machine(),
                device: device.device(),
            },
        }),
        ResourceKey::Host(HostResource::Ram) => Some(ResourceKind::HostRam),
        ResourceKey::Host(HostResource::PinnedRam) => Some(ResourceKind::PinnedHostRam),
        ResourceKey::Host(_) | ResourceKey::GpuLoadSlots(_) => None,
    }
}

fn outlook(prospect: RetryProspect) -> RetryOutlook {
    match prospect {
        RetryProspect::FitsAfterRelease { .. } => RetryOutlook::FitsAfterRelease,
        RetryProspect::ExceedsLimit { .. } => RetryOutlook::ExceedsCapacity,
        RetryProspect::AfterHostObservation => RetryOutlook::AfterHostObservation,
        RetryProspect::AfterHoldEnds => RetryOutlook::AfterHoldEnds,
    }
}

fn refusal(error: LedgerError) -> ReservationRefusal {
    let problem = match error {
        LedgerError::Capacity(capacity) => {
            let limiting = capacity.limiting();
            return match resource_kind(limiting.resource) {
                Some(resource) => ReservationRefusal::Capacity {
                    refusal: CapacityRefusal {
                        resource,
                        requested_bytes: limiting.requested,
                        available_bytes: limiting.available,
                        retry: outlook(limiting.prospect),
                    },
                },
                None => ReservationRefusal::Refused {
                    problem: ReservationProblem::UnexpectedResource,
                },
            };
        }
        LedgerError::EmptyDemand => ReservationProblem::EmptyDemand,
        LedgerError::ParentNotOpen { .. }
        | LedgerError::UnknownReservation { .. }
        | LedgerError::Closed { .. } => ReservationProblem::ParentUnavailable,
        LedgerError::ParentMismatch { .. } => ReservationProblem::ParentMismatch,
        LedgerError::ParentNotInUse { .. } => ReservationProblem::ParentNotCreated,
        LedgerError::NestingTooDeep { .. } => ReservationProblem::NestingTooDeep,
        LedgerError::ForeignDevice { .. } => ReservationProblem::ForeignDevice,
        LedgerError::IdentifiersExhausted => ReservationProblem::Exhausted,
        // Queue, hold, observation and reconciliation errors never answer a reservation
        // that does not wait; refuse rather than guess.
        _ => ReservationProblem::Unexpected,
    };
    ReservationRefusal::Refused { problem }
}
