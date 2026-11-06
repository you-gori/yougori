//! Both slot ports over the CORE-04 coordinator (task T09), for a model in a VM sandbox.
//!
//! The coordinator owns a model's activation and GPU allocation generations, the memory
//! its activations hold within the sandbox reservation (holdings, each a child
//! reservation), the request and preparation leases, and the retirement of drained
//! activations. [`CoordinatorPorts`] serves the slot's reservation and coordination
//! ports over it, for one model of one parent execution:
//!
//! - Step 1 begins a coordinator activation. Every immutable extent of the content is the
//!   model's weights, held apart from any activation's own memory
//!   ([`Coordinator::reserve_weights`], GPU part §2.7: shared weights count once): an
//!   extent another placement of the slot already holds is acquired as it is, and only an
//!   extent no placement holds is reserved, one holding per extent. The activation's own
//!   memory is the rest of its steady state (KV, contexts, graphs and workspaces) and its
//!   transition peak, allocated anew on each device, plus host and pinned memory. A
//!   resting placement activated again within its own memory reactivates its holdings
//!   with no new reservation. When versions cannot overlap, the successor acquires the
//!   weights they share and its own memory comes from its predecessor's own holdings in a
//!   drain-first handover, without returning to the ledger in between; weights only the
//!   successor reads must fit beside everything the predecessor holds, since weights are
//!   the model's and never handed over.
//! - Step 5 completes the coordinator activation; the one it replaces drains, and the
//!   coordinator retires it once no lease uses it.
//! - Serving and preparation leases are the coordinator's, carrying the parent's boot
//!   generation, policy epoch and authorization epoch and the model's generations; an
//!   early result publishes only once the coordinator has published its activation.
//! - Releasing a placement's steady reservation after reclamation (step 7) retires the
//!   coordinator activations that used the placement's memory and confirms the release
//!   through the coordinator, which closes, or hands over, what no other activation uses;
//!   then the weights of every extent no other placement holds are released, as the
//!   runtime's own report observed them freed.
//!
//! Holdings are kept until the placement releases them, because a parked placement keeps
//! its GPU memory until it is reclaimed. The transition peak is part of the activation's
//! new allocation and stays reserved until then, so a reactivation within the same memory
//! reserves only a larger peak than the placement already holds. A predecessor's own
//! memory never passes to a successor that overlaps it, so its KV and contexts stay its
//! own until it drains and is reclaimed.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use super::keys::{ExtentKey, ReservationId, SlotId};
use super::ports::{
    CapacityRefusal, CoordinationPort, CoordinationRefusal, LeaseKind, LeaseRequest, LeaseStatus,
    PlacementPorts, PublicationRefusal, ReservationGrant, ReservationPort, ReservationProblem,
    ReservationRefusal, ReservationRequest, ResourceDemand, ResourceKind, RetryOutlook,
};
use crate::foundation::coordination::{
    ActivationDemand, ActivationHandle, ActivationState, CapacityPort,
    CapacityRefusal as LedgerRefusal, Coordinator, GpuReservationState, HoldingId, LeaseRefusal,
    LeaseTerms, ModelId, ModelRefusal, ResourceKind as CoordinatedResource, Retention,
    RetryProspect,
};
use crate::foundation::evidence::{RuntimeSettings, SourceClass};
use crate::foundation::ids::{
    Clock, ExecutionId, GpuAllocationGeneration, GpuDeviceKey, LeaseId, ModelActivationGeneration,
    MonotonicTime,
};

/// The model and parent a slot's coordinator activations belong to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoordinatorBinding {
    /// The VM sandbox execution that owns the slot.
    pub execution: ExecutionId,
    /// The model, by the digest of its identity.
    pub model: ModelId,
    /// The settings the parent authorized; every activation runs with them.
    pub settings: RuntimeSettings,
    /// The bound within which a request stops after a cancellation (CORE-04 lease
    /// terms).
    pub cancel_within: Duration,
    /// The source that observes reclaimed memory as free; within the sandbox reservation
    /// the runtime's own report suffices.
    pub release_source: SourceClass,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Held {
    /// A placement's memory: the coordinator activations that used it, oldest first, and
    /// the largest transition peak reserved with it.
    Steady {
        users: Vec<ModelActivationGeneration>,
        peak: ResourceDemand,
    },
    /// A transition peak, part of its activation's new allocation and released with it.
    Folded,
}

impl Held {
    /// The coordinator activation that used the placement's memory last.
    fn latest(&self) -> Option<ModelActivationGeneration> {
        match self {
            Self::Steady { users, .. } => users.last().copied(),
            Self::Folded => None,
        }
    }
}

/// One immutable extent's weights, held apart from any activation, and the steady
/// reservations of the placements that hold the extent.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Weights {
    holding: HoldingId,
    holders: BTreeSet<ReservationId>,
}

/// The weights an activation acquires, with those reserved for it by this call, by extent.
type Weighed = (BTreeSet<HoldingId>, Vec<(ExtentKey, HoldingId)>);

/// What a slot keeps about its coordinator activations across calls.
/// [`Self::port`] lends it the coordinator for one slot operation.
#[derive(Clone, Debug)]
pub struct CoordinatorPlacement {
    binding: CoordinatorBinding,
    handles: BTreeMap<ReservationId, Held>,
    weights: BTreeMap<ExtentKey, Weights>,
    pending: Option<ActivationHandle>,
    current: Option<ActivationHandle>,
    next: u64,
}

impl CoordinatorPlacement {
    /// No activations yet, for the model and parent `binding` names.
    pub fn new(binding: CoordinatorBinding) -> Self {
        Self {
            binding,
            handles: BTreeMap::new(),
            weights: BTreeMap::new(),
            pending: None,
            current: None,
            next: 1,
        }
    }

    /// The model and parent the activations belong to.
    pub fn binding(&self) -> &CoordinatorBinding {
        &self.binding
    }

    /// Both ports over `coordinator` for one operation.
    pub fn port<'a, C: Clock, P: CapacityPort>(
        &'a mut self,
        coordinator: &'a mut Coordinator<C, P>,
    ) -> CoordinatorPorts<'a, C, P> {
        CoordinatorPorts {
            state: self,
            coordinator,
        }
    }

    /// The coordinator activations that used the memory a steady reservation stands
    /// for, oldest first.
    pub fn activations_of(&self, reservation: ReservationId) -> Vec<ModelActivationGeneration> {
        match self.handles.get(&reservation) {
            Some(Held::Steady { users, .. }) => users.clone(),
            _ => Vec::new(),
        }
    }

    /// What the coordinator granted the activation in progress.
    pub fn current(&self) -> Option<&ActivationHandle> {
        self.current.as_ref()
    }

    /// The holding of `extent`'s weights, while a placement of the slot holds the extent.
    pub fn weights_holding(&self, extent: &ExtentKey) -> Option<HoldingId> {
        self.weights.get(extent).map(|weights| weights.holding)
    }

    /// Every extent whose weights the slot holds, with its holding.
    pub fn weights(&self) -> BTreeMap<ExtentKey, HoldingId> {
        self.weights
            .iter()
            .map(|(extent, weights)| (*extent, weights.holding))
            .collect()
    }
}

/// [`ReservationPort`] and [`CoordinationPort`] over one borrowed [`Coordinator`].
pub struct CoordinatorPorts<'a, C: Clock, P: CapacityPort> {
    state: &'a mut CoordinatorPlacement,
    coordinator: &'a mut Coordinator<C, P>,
}

impl<C: Clock, P: CapacityPort> CoordinatorPorts<'_, C, P> {
    fn handle(&mut self, held: Held) -> ReservationId {
        let id = ReservationId::new(self.state.next);
        self.state.next = self.state.next.saturating_add(1);
        self.state.handles.insert(id, held);
        id
    }

    fn activation_state(&self, activation: ModelActivationGeneration) -> Option<ActivationState> {
        let binding = &self.state.binding;
        self.coordinator
            .model_activations(&binding.execution, binding.model)?
            .activation(activation)
            .map(|entry| entry.state())
    }

    /// Whether the coordinator still holds `holding` so that an activation of the parent's
    /// current boot and authorization epoch may acquire it.
    fn acquirable(&self, holding: HoldingId) -> bool {
        let binding = &self.state.binding;
        let Some(current) = self
            .coordinator
            .sandbox(&binding.execution)
            .map(|sandbox| sandbox.generations())
        else {
            return false;
        };
        self.coordinator
            .model_activations(&binding.execution, binding.model)
            .and_then(|activations| activations.holding(holding))
            .is_some_and(|entry| {
                entry.state() == GpuReservationState::Held
                    && entry.is_backed()
                    && entry.promised_to().is_none()
                    && entry.bound_to().boot == current.boot
                    && entry.bound_to().authorization == current.authorization
            })
    }

    /// The weights of `extents`: the holdings of extents the slot already holds, and a new
    /// holding reserved apart for each other extent. A refusal releases what this call
    /// reserved, so nothing is left behind.
    fn weights_for(
        &mut self,
        extents: &BTreeMap<ExtentKey, u64>,
    ) -> Result<Weighed, ReservationRefusal> {
        let binding = self.state.binding.clone();
        let mut acquire = BTreeSet::new();
        let mut fresh = Vec::new();
        for (extent, bytes) in extents {
            if let Some(weights) = self.state.weights.get(extent) {
                if self.acquirable(weights.holding) {
                    acquire.insert(weights.holding);
                    continue;
                }
            }
            let reserved = self.coordinator.reserve_weights(
                &binding.execution,
                binding.model,
                BTreeMap::from([(extent.device, *bytes)]),
            );
            match reserved.map(|holdings| holdings.get(&extent.device).copied()) {
                Ok(Some(holding)) => {
                    acquire.insert(holding);
                    fresh.push((*extent, holding));
                }
                Ok(None) => {
                    self.withdraw_weights(&fresh);
                    return Err(ReservationRefusal::Refused {
                        problem: ReservationProblem::Unexpected,
                    });
                }
                Err(refusal) => {
                    self.withdraw_weights(&fresh);
                    return Err(reservation_refusal(refusal, ReservationProblem::Unexpected));
                }
            }
        }
        Ok((acquire, fresh))
    }

    /// Releases weights this operation reserved before it was refused: nothing was ever
    /// created in them.
    fn withdraw_weights(&mut self, fresh: &[(ExtentKey, HoldingId)]) {
        let binding = self.state.binding.clone();
        for (_, holding) in fresh {
            let _released = self.coordinator.release_unused_holding(
                &binding.execution,
                binding.model,
                *holding,
                binding.release_source,
            );
        }
    }

    /// Records that the placement of `steady` holds every extent of `extents`, whose
    /// weights are the slot's or were reserved in `fresh`.
    fn hold_weights(
        &mut self,
        steady: ReservationId,
        extents: &BTreeMap<ExtentKey, u64>,
        fresh: Vec<(ExtentKey, HoldingId)>,
    ) {
        for (extent, holding) in fresh {
            self.state.weights.insert(
                extent,
                Weights {
                    holding,
                    holders: BTreeSet::new(),
                },
            );
        }
        for extent in extents.keys() {
            if let Some(weights) = self.state.weights.get_mut(extent) {
                weights.holders.insert(steady);
            }
        }
    }

    /// The placement of `steady` no longer holds its extents: the weights of every extent
    /// no other placement holds are released, as the runtime's own report observed them
    /// freed. A refusal keeps them, counted, for a later release.
    fn release_weights(&mut self, steady: ReservationId) {
        let binding = self.state.binding.clone();
        // Weights an earlier release left behind, refused while still in use, are retried.
        let unheld: Vec<(ExtentKey, HoldingId)> = self
            .state
            .weights
            .iter_mut()
            .filter_map(|(extent, weights)| {
                weights.holders.remove(&steady);
                weights
                    .holders
                    .is_empty()
                    .then_some((*extent, weights.holding))
            })
            .collect();
        for (extent, holding) in unheld {
            let released = self.coordinator.release_unused_holding(
                &binding.execution,
                binding.model,
                holding,
                binding.release_source,
            );
            if matches!(
                released,
                Ok(()) | Err(ModelRefusal::HoldingUnavailable { .. })
            ) {
                self.state.weights.remove(&extent);
            }
        }
    }

    /// An activation's own memory: every byte of steady state the extents' weights do not
    /// cover, and the transition peak, with the weights to acquire.
    fn own_demand(request: &ReservationRequest, acquire: BTreeSet<HoldingId>) -> ActivationDemand {
        let mut weights: BTreeMap<GpuDeviceKey, u64> = BTreeMap::new();
        for (extent, bytes) in &request.extents {
            let total = weights.entry(extent.device).or_insert(0);
            *total = total.saturating_add(*bytes);
        }
        let devices: BTreeSet<GpuDeviceKey> = request
            .steady
            .vram_bytes
            .keys()
            .chain(request.transition_peak.vram_bytes.keys())
            .copied()
            .collect();
        let gpu_memory_bytes = devices
            .into_iter()
            .map(|device| {
                let steady = request
                    .steady
                    .vram_bytes_on(&device)
                    .saturating_sub(weights.get(&device).copied().unwrap_or(0));
                (
                    device,
                    steady.saturating_add(request.transition_peak.vram_bytes_on(&device)),
                )
            })
            .filter(|(_, bytes)| *bytes > 0)
            .collect();
        ActivationDemand {
            gpu_memory_bytes,
            host_memory_bytes: request
                .steady
                .host_ram_bytes
                .saturating_add(request.transition_peak.host_ram_bytes),
            pinned_host_memory_bytes: request
                .steady
                .pinned_host_bytes
                .saturating_add(request.transition_peak.pinned_host_bytes),
            acquire,
            retention: Retention::KeepUntilReleased,
        }
    }

    /// Records a begun coordinator activation, and the handles the slot gets for it.
    fn granted(
        &mut self,
        handle: ActivationHandle,
        within: Option<ReservationId>,
        transition_peak: &ResourceDemand,
    ) -> ReservationGrant {
        let activation = handle.generations.activation;
        self.state.pending = Some(handle.clone());
        self.state.current = Some(handle);
        let steady = match within {
            Some(own) => {
                if let Some(Held::Steady { users, peak }) = self.state.handles.get_mut(&own) {
                    users.push(activation);
                    *peak = largest(peak, transition_peak);
                }
                None
            }
            None => Some(self.handle(Held::Steady {
                users: vec![activation],
                peak: transition_peak.clone(),
            })),
        };
        let peak = (!transition_peak.is_empty()).then(|| self.handle(Held::Folded));
        ReservationGrant {
            steady,
            transition_peak: peak,
        }
    }

    /// Retires `activation` unless it is retired already, then confirms through the
    /// coordinator that the memory it left is released. Memory another unretired
    /// activation uses stays; memory promised to a drain-first successor passes to it. A
    /// refusal leaves the memory counted, never falsely free.
    fn retire_and_confirm(&mut self, activation: ModelActivationGeneration) {
        let execution = self.state.binding.execution.clone();
        let model = self.state.binding.model;
        let _ended = match self.activation_state(activation) {
            Some(ActivationState::Loading) => self
                .coordinator
                .fail_activation(&execution, model, activation),
            Some(ActivationState::Active) => self
                .coordinator
                .evict(&execution, model, activation)
                .map(|_| ()),
            Some(ActivationState::Draining) => self
                .coordinator
                .retire_drained(&execution, model)
                .map(|_| ()),
            Some(ActivationState::Reclaiming | ActivationState::Retired { .. }) | None => Ok(()),
        };
        let _confirmed = self.coordinator.confirm_gpu_released(
            &execution,
            model,
            activation,
            self.state.binding.release_source,
        );
    }

    fn lease_terms(
        &self,
        request: &LeaseRequest,
        now: MonotonicTime,
    ) -> Result<LeaseTerms, CoordinationRefusal> {
        let binding = &self.state.binding;
        if request.execution != binding.execution {
            return Err(CoordinationRefusal::NotAuthorized);
        }
        let current = self
            .coordinator
            .sandbox(&binding.execution)
            .map(|sandbox| sandbox.generations().authorization)
            .ok_or(CoordinationRefusal::NotAuthorized)?;
        if request.epoch != current {
            return Err(CoordinationRefusal::StaleAuthorization {
                presented: request.epoch,
                current,
            });
        }
        let term = request
            .expires_at
            .checked_duration_since(now)
            .filter(|term| !term.is_zero())
            .ok_or(CoordinationRefusal::ExpiryNotInFuture)?;
        Ok(LeaseTerms {
            term,
            max_lifetime: term,
            cancel_within: binding.cancel_within,
        })
    }
}

impl<C: Clock, P: CapacityPort> ReservationPort for CoordinatorPorts<'_, C, P> {
    fn reserve(
        &mut self,
        request: &ReservationRequest,
    ) -> Result<ReservationGrant, ReservationRefusal> {
        if request.execution != self.state.binding.execution {
            return Err(ReservationRefusal::Refused {
                problem: ReservationProblem::ParentMismatch,
            });
        }
        let binding = self.state.binding.clone();
        if let Some(own) = request.within {
            // Activated again within the placement's own memory, which already holds a
            // transition peak: its holdings are reactivated as they are, and only a larger
            // peak than before is reserved anew.
            let unavailable = ReservationRefusal::Refused {
                problem: ReservationProblem::HoldingUnavailable,
            };
            let (from, held_peak) = match self.state.handles.get(&own) {
                Some(Held::Steady { users, peak }) => {
                    (users.last().copied().ok_or(unavailable)?, peak.clone())
                }
                _ => return Err(unavailable),
            };
            let extra = beyond(&request.transition_peak, &held_peak);
            let handle = if extra.is_empty() {
                self.coordinator.reactivate(
                    &binding.execution,
                    binding.model,
                    binding.settings,
                    from,
                )
            } else {
                let acquire = self
                    .coordinator
                    .model_activations(&binding.execution, binding.model)
                    .and_then(|activations| activations.activation(from))
                    .map(|activation| activation.holdings().clone())
                    .ok_or(unavailable)?;
                self.coordinator.begin_activation_with(
                    &binding.execution,
                    binding.model,
                    binding.settings,
                    ActivationDemand {
                        gpu_memory_bytes: extra
                            .vram_bytes
                            .iter()
                            .filter(|(_, bytes)| **bytes > 0)
                            .map(|(device, bytes)| (*device, *bytes))
                            .collect(),
                        host_memory_bytes: extra.host_ram_bytes,
                        pinned_host_memory_bytes: extra.pinned_host_bytes,
                        acquire,
                        retention: Retention::KeepUntilReleased,
                    },
                )
            }
            .map_err(|refusal| {
                reservation_refusal(refusal, ReservationProblem::HoldingUnavailable)
            })?;
            return Ok(self.granted(handle, Some(own), &request.transition_peak));
        }
        let (acquire, fresh) = self.weights_for(&request.extents)?;
        let demand = Self::own_demand(request, acquire);
        let handle = match self.coordinator.begin_activation_with(
            &binding.execution,
            binding.model,
            binding.settings,
            demand,
        ) {
            Ok(handle) => handle,
            Err(refusal) => {
                self.withdraw_weights(&fresh);
                return Err(reservation_refusal(refusal, ReservationProblem::Unexpected));
            }
        };
        let grant = self.granted(handle, None, &request.transition_peak);
        if let Some(steady) = grant.steady {
            self.hold_weights(steady, &request.extents, fresh);
        }
        Ok(grant)
    }

    /// The coordinator's drain-first handover: the predecessor stops admitting, and the
    /// memory it alone uses passes to the successor once its release is confirmed; only
    /// what that memory does not cover is reserved now. The weights both read are acquired
    /// as they are; weights only the successor reads are reserved apart now.
    fn reserve_successor(
        &mut self,
        predecessor: ReservationId,
        request: &ReservationRequest,
    ) -> Result<ReservationGrant, ReservationRefusal> {
        if request.execution != self.state.binding.execution {
            return Err(ReservationRefusal::Refused {
                problem: ReservationProblem::ParentMismatch,
            });
        }
        let previous = self
            .state
            .handles
            .get(&predecessor)
            .and_then(Held::latest)
            .ok_or(ReservationRefusal::Refused {
                problem: ReservationProblem::UnknownPredecessor,
            })?;
        let (acquire, fresh) = self.weights_for(&request.extents)?;
        let demand = Self::own_demand(request, acquire);
        let binding = self.state.binding.clone();
        let handle = match self.coordinator.begin_drain_first(
            &binding.execution,
            binding.model,
            binding.settings,
            demand,
            previous,
        ) {
            Ok(handle) => handle,
            Err(refusal) => {
                self.withdraw_weights(&fresh);
                return Err(reservation_refusal(
                    refusal,
                    ReservationProblem::UnknownPredecessor,
                ));
            }
        };
        let grant = self.granted(handle, None, &request.transition_peak);
        if let Some(steady) = grant.steady {
            self.hold_weights(steady, &request.extents, fresh);
        }
        Ok(grant)
    }

    fn release(&mut self, reservation: ReservationId) {
        if let Some(Held::Steady { users, .. }) = self.state.handles.remove(&reservation) {
            for activation in users {
                self.retire_and_confirm(activation);
            }
            self.release_weights(reservation);
        }
    }
}

impl<C: Clock, P: CapacityPort> CoordinationPort for CoordinatorPorts<'_, C, P> {
    /// The activation generation the coordinator handed out with the reservation just
    /// made; it comes only with one.
    fn next_activation_generation(
        &mut self,
        _slot: &SlotId,
    ) -> Result<ModelActivationGeneration, CoordinationRefusal> {
        self.state
            .pending
            .take()
            .map(|handle| handle.generations.activation)
            .ok_or(CoordinationRefusal::NoReservedGeneration)
    }

    /// The generation of the GPU allocation the activation in progress made on `device`.
    fn next_allocation_generation(
        &mut self,
        _slot: &SlotId,
        device: &GpuDeviceKey,
    ) -> Result<GpuAllocationGeneration, CoordinationRefusal> {
        self.state
            .current
            .as_ref()
            .and_then(|handle| handle.allocated.get(device).copied())
            .ok_or(CoordinationRefusal::NoReservedGeneration)
    }

    /// An extent lives in its weights' own allocation.
    fn extent_allocation(
        &mut self,
        slot: &SlotId,
        extent: &ExtentKey,
    ) -> Result<GpuAllocationGeneration, CoordinationRefusal> {
        match self
            .state
            .weights
            .get(extent)
            .map(|weights| weights.holding)
        {
            Some(HoldingId::Gpu { allocation }) => Ok(allocation),
            _ => self.next_allocation_generation(slot, &extent.device),
        }
    }

    fn grant_lease(
        &mut self,
        request: &LeaseRequest,
        now: MonotonicTime,
    ) -> Result<LeaseId, CoordinationRefusal> {
        let terms = self.lease_terms(request, now)?;
        let binding = &self.state.binding;
        let (execution, model) = (binding.execution.clone(), binding.model);
        match request.kind {
            LeaseKind::Serving => {
                let serving = self
                    .coordinator
                    .model_activations(&execution, model)
                    .and_then(|activations| activations.serving())
                    .map(|activation| activation.generations().activation);
                if serving != Some(request.generation) {
                    return Err(CoordinationRefusal::GenerationNotServing {
                        requested: request.generation,
                        serving,
                    });
                }
                self.coordinator
                    .admit_request(&execution, model, request.request.clone(), terms)
                    .map(|lease| lease.id())
                    .map_err(|refusal| lease_refusal(refusal, request.generation))
            }
            LeaseKind::Preparation => self
                .coordinator
                .admit_preparation_request(
                    &execution,
                    model,
                    request.generation,
                    request.request.clone(),
                    terms,
                )
                .map(|lease| lease.id())
                .map_err(|refusal| lease_refusal(refusal, request.generation)),
        }
    }

    fn lease_status(&self, lease: LeaseId, _now: MonotonicTime) -> LeaseStatus {
        status_of(self.coordinator.check_lease(lease).err())
    }

    fn check_result_publication(
        &self,
        lease: LeaseId,
        _now: MonotonicTime,
    ) -> Result<(), PublicationRefusal> {
        match self.coordinator.check_result_publication(lease) {
            Ok(_) => Ok(()),
            Err(LeaseRefusal::ActivationNotServing {
                state: Some(ActivationState::Loading),
                ..
            }) => Err(PublicationRefusal::AwaitingPublication),
            Err(refusal) => Err(PublicationRefusal::Lease {
                status: status_of(Some(refusal)),
            }),
        }
    }

    /// Releases a request lease; the coordinator retires any drained activation it was
    /// the last to use.
    fn release_lease(&mut self, lease: LeaseId) {
        let _finished = self.coordinator.finish_request(lease);
    }

    fn publish_generation(
        &mut self,
        _slot: &SlotId,
        generation: ModelActivationGeneration,
    ) -> Result<(), CoordinationRefusal> {
        let binding = &self.state.binding;
        let (execution, model) = (binding.execution.clone(), binding.model);
        self.coordinator
            .complete_activation(&execution, model, generation)
            .map(|_| ())
            .map_err(|refusal| lease_refusal(refusal, generation))
    }

    fn abandon_generation(&mut self, _slot: &SlotId, generation: ModelActivationGeneration) {
        if self.activation_state(generation) == Some(ActivationState::Loading) {
            let binding = &self.state.binding;
            let (execution, model) = (binding.execution.clone(), binding.model);
            let _failed = self
                .coordinator
                .fail_activation(&execution, model, generation);
        }
    }
}

impl<C: Clock, P: CapacityPort> PlacementPorts for CoordinatorPorts<'_, C, P> {
    fn reservations(&mut self) -> &mut dyn ReservationPort {
        self
    }

    fn coordination(&mut self) -> &mut dyn CoordinationPort {
        self
    }
}

/// What `wanted` needs beyond `held`, resource by resource.
fn beyond(wanted: &ResourceDemand, held: &ResourceDemand) -> ResourceDemand {
    ResourceDemand {
        vram_bytes: wanted
            .vram_bytes
            .iter()
            .map(|(device, bytes)| (*device, bytes.saturating_sub(held.vram_bytes_on(device))))
            .filter(|(_, bytes)| *bytes > 0)
            .collect(),
        host_ram_bytes: wanted.host_ram_bytes.saturating_sub(held.host_ram_bytes),
        pinned_host_bytes: wanted
            .pinned_host_bytes
            .saturating_sub(held.pinned_host_bytes),
    }
}

/// The larger of two demands, resource by resource.
fn largest(a: &ResourceDemand, b: &ResourceDemand) -> ResourceDemand {
    let mut vram_bytes = a.vram_bytes.clone();
    for (device, bytes) in &b.vram_bytes {
        let entry = vram_bytes.entry(*device).or_insert(0);
        *entry = (*entry).max(*bytes);
    }
    ResourceDemand {
        vram_bytes,
        host_ram_bytes: a.host_ram_bytes.max(b.host_ram_bytes),
        pinned_host_bytes: a.pinned_host_bytes.max(b.pinned_host_bytes),
    }
}

/// How a lease looks to the slot, from the coordinator's refusal to honour it.
fn status_of(refusal: Option<LeaseRefusal>) -> LeaseStatus {
    match refusal {
        None => LeaseStatus::Active,
        Some(LeaseRefusal::Expired { .. }) => LeaseStatus::Expired,
        Some(LeaseRefusal::Released) => LeaseStatus::Released,
        Some(LeaseRefusal::UnknownLease { .. }) => LeaseStatus::Unknown,
        Some(_) => LeaseStatus::Revoked,
    }
}

fn reservation_refusal(refusal: ModelRefusal, unknown: ReservationProblem) -> ReservationRefusal {
    let refused = |problem| ReservationRefusal::Refused { problem };
    match refusal {
        ModelRefusal::Capacity { refusal } => capacity_refusal(refusal),
        ModelRefusal::Parent { .. }
        | ModelRefusal::CategoryMismatch { .. }
        | ModelRefusal::AuthorityExceedsParent { .. }
        | ModelRefusal::NoSandboxReservation => refused(ReservationProblem::ParentNotAuthorized),
        ModelRefusal::HoldingUnavailable { .. } => refused(ReservationProblem::HoldingUnavailable),
        ModelRefusal::InvalidDemand { .. } => refused(ReservationProblem::InvalidDemand),
        ModelRefusal::UnknownModel { .. }
        | ModelRefusal::UnknownActivation { .. }
        | ModelRefusal::InvalidActivationTransition { .. } => refused(unknown),
        ModelRefusal::GenerationsExhausted => refused(ReservationProblem::Exhausted),
        _ => refused(ReservationProblem::Unexpected),
    }
}

fn capacity_refusal(refusal: LedgerRefusal) -> ReservationRefusal {
    let capacity = |resource, requested_bytes, available_bytes, retry| match resource_kind(resource)
    {
        Some(resource) => ReservationRefusal::Capacity {
            refusal: CapacityRefusal {
                resource,
                requested_bytes,
                available_bytes,
                retry,
            },
        },
        None => ReservationRefusal::Refused {
            problem: ReservationProblem::UnexpectedResource,
        },
    };
    match refusal {
        LedgerRefusal::Insufficient {
            resource,
            requested,
            available,
            retry,
            ..
        } => capacity(resource, requested, available, outlook(retry)),
        LedgerRefusal::ExceedsParentBudget {
            resource,
            requested,
            remaining,
            retry,
            ..
        } => capacity(resource, requested, remaining, outlook(retry)),
        LedgerRefusal::NotObserved { resource } => {
            capacity(resource, 0, 0, RetryOutlook::AfterHostObservation)
        }
        LedgerRefusal::OwnerReturnHold { resource } => {
            capacity(resource, 0, 0, RetryOutlook::AfterHoldEnds)
        }
        LedgerRefusal::QueueFull { resource } => {
            capacity(resource, 0, 0, RetryOutlook::FitsAfterRelease)
        }
        LedgerRefusal::UnknownParent { .. } => ReservationRefusal::Refused {
            problem: ReservationProblem::ParentUnavailable,
        },
        _ => ReservationRefusal::Refused {
            problem: ReservationProblem::Unexpected,
        },
    }
}

fn outlook(retry: RetryProspect) -> RetryOutlook {
    match retry {
        RetryProspect::CanProgress => RetryOutlook::FitsAfterRelease,
        RetryProspect::CannotProgress => RetryOutlook::ExceedsCapacity,
    }
}

fn resource_kind(resource: CoordinatedResource) -> Option<ResourceKind> {
    match resource {
        CoordinatedResource::GpuMemoryBytes { device } => Some(ResourceKind::Vram { device }),
        CoordinatedResource::HostMemoryBytes => Some(ResourceKind::HostRam),
        CoordinatedResource::PinnedHostMemoryBytes => Some(ResourceKind::PinnedHostRam),
        _ => None,
    }
}

fn lease_refusal(
    refusal: ModelRefusal,
    generation: ModelActivationGeneration,
) -> CoordinationRefusal {
    match refusal {
        ModelRefusal::Parent {
            refusal: LeaseRefusal::RevokedAuthorization { bound, current },
        } => CoordinationRefusal::StaleAuthorization {
            presented: bound,
            current,
        },
        ModelRefusal::Parent {
            refusal: LeaseRefusal::InvalidTerms { .. },
        } => CoordinationRefusal::ExpiryNotInFuture,
        ModelRefusal::NoServingActivation { .. } => CoordinationRefusal::GenerationNotServing {
            requested: generation,
            serving: None,
        },
        ModelRefusal::UnknownModel { .. } | ModelRefusal::UnknownActivation { .. } => {
            CoordinationRefusal::UnknownGeneration { generation }
        }
        ModelRefusal::InvalidActivationTransition { .. } => {
            CoordinationRefusal::GenerationNotReady { generation }
        }
        ModelRefusal::HandoverPending { predecessor } => {
            CoordinationRefusal::HandoverPending { predecessor }
        }
        ModelRefusal::PreparationAssigned { .. } => CoordinationRefusal::PreparationAssigned,
        ModelRefusal::GenerationsExhausted => CoordinationRefusal::GenerationsExhausted,
        _ => CoordinationRefusal::NotAuthorized,
    }
}
