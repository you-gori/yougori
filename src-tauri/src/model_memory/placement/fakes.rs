//! Fakes of the two ports for tests: a reservation ledger with fixed capacities and a
//! coordination module with per-slot generations, epochs and leases. They touch nothing
//! outside memory.

use std::collections::BTreeMap;

use super::keys::{ReservationId, SlotId};
use super::ports::{
    CapacityRefusal, CoordinationPort, CoordinationRefusal, LeaseRequest, LeaseStatus, Ports,
    PublicationRefusal, ReservationGrant, ReservationPort, ReservationRefusal, ReservationRequest,
    ResourceDemand, ResourceKind, RetryOutlook,
};
use crate::foundation::ids::{
    AuthorizationEpoch, ExecutionId, GpuAllocationGeneration, GpuDeviceKey, LeaseId,
    ModelActivationGeneration, MonotonicTime,
};

/// One call the fake ledger received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReservationCall {
    Reserve(ReservationRequest),
    Successor {
        predecessor: ReservationId,
        request: ReservationRequest,
    },
    Release(ReservationId),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Held {
    amounts: BTreeMap<ResourceKind, u64>,
    /// False once the share has passed to a successor.
    counted: bool,
    successor_of: Option<ReservationId>,
}

/// A ledger with fixed capacities that grants both parts of a request or neither.
#[derive(Clone, Debug, Default)]
pub struct FakeReservations {
    capacity: BTreeMap<ResourceKind, u64>,
    held: BTreeMap<ReservationId, Held>,
    next: u64,
    pub calls: Vec<ReservationCall>,
}

impl FakeReservations {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_vram(mut self, device: GpuDeviceKey, bytes: u64) -> Self {
        self.capacity.insert(ResourceKind::Vram { device }, bytes);
        self
    }

    pub fn with_host_ram(mut self, bytes: u64) -> Self {
        self.capacity.insert(ResourceKind::HostRam, bytes);
        self
    }

    /// Bytes of `kind` currently counted against capacity.
    pub fn used(&self, kind: ResourceKind) -> u64 {
        self.used_without(kind, None)
    }

    pub fn is_held(&self, reservation: ReservationId) -> bool {
        self.held.contains_key(&reservation)
    }

    pub fn held_count(&self) -> usize {
        self.held.len()
    }

    /// The requests the ledger granted or refused, in order.
    pub fn requests(&self) -> Vec<&ReservationRequest> {
        self.calls
            .iter()
            .filter_map(|call| match call {
                ReservationCall::Reserve(request) => Some(request),
                ReservationCall::Successor { request, .. } => Some(request),
                ReservationCall::Release(_) => None,
            })
            .collect()
    }

    pub fn released(&self) -> Vec<ReservationId> {
        self.calls
            .iter()
            .filter_map(|call| match call {
                ReservationCall::Release(id) => Some(*id),
                _ => None,
            })
            .collect()
    }

    fn used_without(&self, kind: ResourceKind, ignoring: Option<ReservationId>) -> u64 {
        self.held
            .iter()
            .filter(|(id, held)| held.counted && Some(**id) != ignoring)
            .map(|(_, held)| held.amounts.get(&kind).copied().unwrap_or(0))
            .sum()
    }

    fn check(
        &self,
        need: &BTreeMap<ResourceKind, u64>,
        ignoring: Option<ReservationId>,
    ) -> Result<(), CapacityRefusal> {
        for (kind, bytes) in need {
            let capacity = self.capacity.get(kind).copied().unwrap_or(0);
            let available = capacity.saturating_sub(self.used_without(*kind, ignoring));
            if *bytes > available {
                return Err(CapacityRefusal {
                    resource: *kind,
                    requested_bytes: *bytes,
                    available_bytes: available,
                    retry: if *bytes <= capacity {
                        RetryOutlook::FitsAfterRelease
                    } else {
                        RetryOutlook::ExceedsCapacity
                    },
                });
            }
        }
        Ok(())
    }

    fn grant(
        &mut self,
        request: &ReservationRequest,
        successor_of: Option<ReservationId>,
    ) -> ReservationGrant {
        let mut grant = ReservationGrant {
            steady: None,
            transition_peak: None,
        };
        let mut handover = successor_of;
        for (part, demand) in [(0, &request.steady), (1, &request.transition_peak)] {
            if demand.is_empty() {
                continue;
            }
            self.next += 1;
            let id = ReservationId::new(self.next);
            self.held.insert(
                id,
                Held {
                    amounts: amounts(demand),
                    counted: true,
                    successor_of: handover.take(),
                },
            );
            if part == 0 {
                grant.steady = Some(id);
            } else {
                grant.transition_peak = Some(id);
            }
        }
        grant
    }
}

fn amounts(demand: &ResourceDemand) -> BTreeMap<ResourceKind, u64> {
    let mut amounts = BTreeMap::new();
    for (device, bytes) in &demand.vram_bytes {
        if *bytes > 0 {
            amounts.insert(ResourceKind::Vram { device: *device }, *bytes);
        }
    }
    if demand.host_ram_bytes > 0 {
        amounts.insert(ResourceKind::HostRam, demand.host_ram_bytes);
    }
    if demand.pinned_host_bytes > 0 {
        amounts.insert(ResourceKind::PinnedHostRam, demand.pinned_host_bytes);
    }
    amounts
}

fn total(request: &ReservationRequest) -> BTreeMap<ResourceKind, u64> {
    let mut need = amounts(&request.steady);
    for (kind, bytes) in amounts(&request.transition_peak) {
        let entry = need.entry(kind).or_insert(0);
        *entry += bytes;
    }
    need
}

impl ReservationPort for FakeReservations {
    fn reserve(
        &mut self,
        request: &ReservationRequest,
    ) -> Result<ReservationGrant, ReservationRefusal> {
        self.calls.push(ReservationCall::Reserve(request.clone()));
        self.check(&total(request), None)
            .map_err(|refusal| ReservationRefusal::Capacity { refusal })?;
        Ok(self.grant(request, None))
    }

    fn reserve_successor(
        &mut self,
        predecessor: ReservationId,
        request: &ReservationRequest,
    ) -> Result<ReservationGrant, ReservationRefusal> {
        self.calls.push(ReservationCall::Successor {
            predecessor,
            request: request.clone(),
        });
        let handover = self.held.get(&predecessor).is_some_and(|held| held.counted);
        self.check(&total(request), handover.then_some(predecessor))
            .map_err(|refusal| ReservationRefusal::Capacity { refusal })?;
        if let Some(held) = self.held.get_mut(&predecessor).filter(|_| handover) {
            held.counted = false;
        }
        Ok(self.grant(request, handover.then_some(predecessor)))
    }

    fn release(&mut self, reservation: ReservationId) {
        self.calls.push(ReservationCall::Release(reservation));
        if let Some(held) = self.held.remove(&reservation) {
            if let Some(predecessor) = held.successor_of {
                if let Some(predecessor) = self.held.get_mut(&predecessor) {
                    predecessor.counted = true;
                }
            }
        }
    }
}

/// A granted lease as the fake records it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FakeLease {
    pub request: LeaseRequest,
    pub released: bool,
}

/// Per-slot generations, per-execution authorization epochs and leases.
#[derive(Clone, Debug, Default)]
pub struct FakeCoordination {
    activation: BTreeMap<SlotId, u64>,
    allocation: BTreeMap<SlotId, u64>,
    epochs: BTreeMap<ExecutionId, AuthorizationEpoch>,
    leases: BTreeMap<LeaseId, FakeLease>,
    next_lease: u64,
    pub published: Vec<ModelActivationGeneration>,
    pub abandoned: Vec<ModelActivationGeneration>,
}

impl FakeCoordination {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn authorize(&mut self, execution: &ExecutionId, epoch: AuthorizationEpoch) {
        self.epochs.insert(execution.clone(), epoch);
    }

    /// Raises the execution's authorization epoch, revoking every lease bound to the
    /// old one.
    pub fn revoke(&mut self, execution: &ExecutionId) -> Option<AuthorizationEpoch> {
        let epoch = self.epochs.get_mut(execution)?;
        *epoch = epoch.next()?;
        Some(*epoch)
    }

    /// Makes the next activation generation of `slot` be `next`, to imitate a
    /// misbehaving module that reissues a generation.
    pub fn reissue_activation_generation(&mut self, slot: SlotId, next: u64) {
        self.activation.insert(slot, next.saturating_sub(1));
    }

    pub fn lease(&self, lease: LeaseId) -> Option<&FakeLease> {
        self.leases.get(&lease)
    }

    pub fn unreleased_leases(&self) -> usize {
        self.leases.values().filter(|lease| !lease.released).count()
    }
}

impl CoordinationPort for FakeCoordination {
    fn next_activation_generation(
        &mut self,
        slot: &SlotId,
    ) -> Result<ModelActivationGeneration, CoordinationRefusal> {
        let counter = self.activation.entry(*slot).or_insert(0);
        *counter = counter
            .checked_add(1)
            .ok_or(CoordinationRefusal::GenerationsExhausted)?;
        Ok(ModelActivationGeneration::new(*counter))
    }

    fn next_allocation_generation(
        &mut self,
        slot: &SlotId,
        _device: &GpuDeviceKey,
    ) -> Result<GpuAllocationGeneration, CoordinationRefusal> {
        let counter = self.allocation.entry(*slot).or_insert(0);
        *counter = counter
            .checked_add(1)
            .ok_or(CoordinationRefusal::GenerationsExhausted)?;
        Ok(GpuAllocationGeneration::new(*counter))
    }

    fn grant_lease(
        &mut self,
        request: &LeaseRequest,
        now: MonotonicTime,
    ) -> Result<LeaseId, CoordinationRefusal> {
        let current = *self
            .epochs
            .get(&request.execution)
            .ok_or(CoordinationRefusal::NotAuthorized)?;
        if request.epoch != current {
            return Err(CoordinationRefusal::StaleAuthorization {
                presented: request.epoch,
                current,
            });
        }
        if request.expires_at <= now {
            return Err(CoordinationRefusal::ExpiryNotInFuture);
        }
        self.next_lease += 1;
        let id = LeaseId::new(self.next_lease);
        self.leases.insert(
            id,
            FakeLease {
                request: request.clone(),
                released: false,
            },
        );
        Ok(id)
    }

    fn lease_status(&self, lease: LeaseId, now: MonotonicTime) -> LeaseStatus {
        match self.leases.get(&lease) {
            None => LeaseStatus::Unknown,
            Some(lease) if lease.released => LeaseStatus::Released,
            Some(lease)
                if self.epochs.get(&lease.request.execution) != Some(&lease.request.epoch) =>
            {
                LeaseStatus::Revoked
            }
            Some(lease) if now >= lease.request.expires_at => LeaseStatus::Expired,
            Some(_) => LeaseStatus::Active,
        }
    }

    fn release_lease(&mut self, lease: LeaseId) {
        if let Some(lease) = self.leases.get_mut(&lease) {
            lease.released = true;
        }
    }

    fn check_result_publication(
        &self,
        lease: LeaseId,
        now: MonotonicTime,
    ) -> Result<(), PublicationRefusal> {
        let status = self.lease_status(lease, now);
        if !status.is_active() {
            return Err(PublicationRefusal::Lease { status });
        }
        let published = self
            .leases
            .get(&lease)
            .is_some_and(|lease| self.published.contains(&lease.request.generation));
        if published {
            Ok(())
        } else {
            Err(PublicationRefusal::AwaitingPublication)
        }
    }

    fn publish_generation(
        &mut self,
        slot: &SlotId,
        generation: ModelActivationGeneration,
    ) -> Result<(), CoordinationRefusal> {
        let issued = self.activation.get(slot).copied().unwrap_or(0);
        if generation.get() == 0 || generation.get() > issued {
            return Err(CoordinationRefusal::UnknownGeneration { generation });
        }
        self.published.push(generation);
        Ok(())
    }

    fn abandon_generation(&mut self, _slot: &SlotId, generation: ModelActivationGeneration) {
        if !self.abandoned.contains(&generation) {
            self.abandoned.push(generation);
        }
    }
}

/// The two fakes together.
#[derive(Clone, Debug, Default)]
pub struct FakePorts {
    pub reservations: FakeReservations,
    pub coordination: FakeCoordination,
}

impl FakePorts {
    pub fn ports(&mut self) -> Ports<'_> {
        Ports {
            reservations: &mut self.reservations,
            coordination: &mut self.coordination,
        }
    }
}
