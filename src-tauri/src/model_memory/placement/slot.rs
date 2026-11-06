//! One model slot (§3.6): its placements with their independent fields, the request
//! router, and the extents the placements hold. The activation protocol is in
//! `activation.rs` and execute-while-load in `early.rs`; both extend
//! [`PlacementSlot`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::activation::Activation;
use super::early::EarlyExecution;
use super::extents::{ExtentSpec, ExtentTable, FreedExtent};
use super::fields::{ArtifactProblem, ArtifactValidity, GpuResidency, ProcessLiveness};
use super::keys::{
    CompletionEventId, ExtentKey, PlacementKey, ProcessInstance, Rank, ReferenceId, ReservationId,
    SlotId, WeightPosition,
};
use super::ports::{
    CoordinationPort, LeaseKind, LeaseRequest, LeaseStatus, PlacementPorts, ReservationPort,
    ResourceDemand,
};
use super::reclaim::{GateError, ReclaimBlocked, ReclaimGate, ReferenceKind};
use super::router::{
    ActivationContent, AdmissionRequest, HeldLease, PauseRecord, RequestTicket, RouteRefusal,
    Router, TicketError,
};
use super::state::{Failure, FailureReason, IllegalTransition, PlacementState, StateKind};
use crate::foundation::ids::{
    Clock, ContentKey, ExecutionId, GpuDeviceKey, LeaseId, ModelActivationGeneration,
    MonotonicTime, OperationId, TenantId,
};
use crate::model_memory::identity::{
    AdapterIdentity, ArtifactIdentity, AuthorityBinding, ExecutionIdentity, PlacementIdentity,
    PlacementSpec,
};

/// Who a slot belongs to: model activations and their leases bind to the parent
/// execution and authorization epoch of `authority` (S3.1), and placement identities
/// name `tenant` as their owner (§3.2 item 5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotSpec {
    pub slot: SlotId,
    pub tenant: TenantId,
    pub authority: AuthorityBinding,
}

impl SlotSpec {
    /// The parent execution that owns the slot.
    pub fn owner(&self) -> &ExecutionId {
        self.authority.parent()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct HeldReservation {
    pub(super) id: ReservationId,
    pub(super) demand: ResourceDemand,
}

/// One placement record. Its content (identities and extents) is fixed when it is
/// created: a weight or adapter update is a new placement, never an in-place change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Placement {
    pub(super) state: PlacementState,
    pub(super) execution: ExecutionIdentity,
    pub(super) artifact_identity: ArtifactIdentity,
    pub(super) adapters: BTreeMap<u32, AdapterIdentity>,
    pub(super) artifact: ArtifactValidity,
    pub(super) process: ProcessLiveness,
    pub(super) layout: BTreeMap<Rank, GpuDeviceKey>,
    pub(super) components: BTreeMap<WeightPosition, ExtentSpec>,
    pub(super) steady: Option<HeldReservation>,
    pub(super) gate: ReclaimGate,
}

impl Placement {
    /// Each distinct extent of the content once, with its size.
    pub(super) fn unique_extents(&self) -> BTreeMap<ExtentKey, u64> {
        unique_extents(self.components.values())
    }
}

/// Each distinct extent once, with its size (tied positions share an extent).
pub(super) fn unique_extents<'a>(
    specs: impl Iterator<Item = &'a ExtentSpec>,
) -> BTreeMap<ExtentKey, u64> {
    specs.map(|spec| (spec.extent, spec.bytes)).collect()
}

/// A read-only view of one placement and its independent fields (§3.6 line 585).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PlacementView {
    pub key: PlacementKey,
    pub state: PlacementState,
    pub execution: ExecutionIdentity,
    pub artifact_identity: ArtifactIdentity,
    pub adapters: BTreeMap<u32, AdapterIdentity>,
    pub artifact: ArtifactValidity,
    pub process: ProcessLiveness,
    pub gpu: GpuResidency,
    /// The steady-state reservation the placement holds until it is reclaimed.
    pub steady_reservation: Option<ReservationId>,
    pub steady_demand: Option<ResourceDemand>,
    pub leases: usize,
    pub generations: Vec<ModelActivationGeneration>,
}

/// Whether the content of a placement could serve again without reloading (§3.6 line
/// 597: no instant rollback is promised once old resources were reclaimed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "rollback", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum RollbackOutlook {
    /// Every extent is resident and usable and the process is alive.
    Retained,
    /// The weights are resident, but no live process holds them; a process must start
    /// and attach first.
    RequiresProcess,
    /// Reclamation freed part of the content: serving it again means reloading.
    RequiresReload {
        missing_extents: usize,
        missing_bytes: u64,
        /// Whether a verified artifact can reconstruct the missing extents.
        reconstructible: bool,
    },
}

crate::foundation::strict_serde::strict_tag!(RollbackOutlook, "rollback");

/// What reclamation did (§3.6 step 7).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReclaimReport {
    pub placement: PlacementKey,
    /// Extents no other placement holds, now free.
    pub freed: Vec<FreedExtent>,
    /// Shared extents that stay resident for their other holders.
    pub retained_shared: Vec<ExtentKey>,
    pub released_reservation: Option<ReservationId>,
    pub rollback: RollbackOutlook,
}

/// A lease that ended without the request finishing normally.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndedLease {
    pub request: OperationId,
    pub generation: ModelActivationGeneration,
    pub lease: LeaseId,
    pub status: LeaseStatus,
}

/// Progress of draining one placement's old-generation leases (§3.6 step 6).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DrainStatus {
    /// Leases the coordination module ended (expired or revoked); their requests must
    /// be stopped by the caller.
    pub ended: Vec<EndedLease>,
    pub remaining_leases: usize,
}

impl DrainStatus {
    /// Whether no old-generation lease remains (step 6 complete).
    pub fn is_drained(&self) -> bool {
        self.remaining_leases == 0
    }
}

/// Why a slot operation was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum SlotError {
    UnknownPlacement {
        placement: PlacementKey,
    },
    Transition {
        transition: IllegalTransition,
    },
    /// The placement takes part in the activation in progress.
    InActivation {
        placement: PlacementKey,
    },
    /// Old-generation leases are still held (§3.6 step 6).
    LeasesHeld {
        placement: PlacementKey,
        leases: usize,
    },
    /// Process references or GPU completion events still use the memory (step 7).
    ReclaimBlocked {
        blocked: ReclaimBlocked,
    },
    Gate {
        error: GateError,
    },
    /// The placement still holds extents or a reservation.
    NotReclaimed {
        placement: PlacementKey,
    },
    ProcessAlreadyAlive {
        placement: PlacementKey,
    },
    /// The placement holds no GPU memory for work or references.
    NotResident {
        placement: PlacementKey,
    },
    /// Only a resting placement (materialized, parked or failed) is reclaimed.
    NotReclaimable {
        placement: PlacementKey,
        state: StateKind,
    },
    /// Only a draining placement's leases are ended at a drain deadline.
    NotDraining {
        placement: PlacementKey,
        state: StateKind,
    },
}

crate::foundation::strict_serde::strict_tag!(SlotError, "kind");

impl fmt::Display for SlotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownPlacement { placement } => write!(f, "placement {placement} is unknown"),
            Self::Transition { transition } => transition.fmt(f),
            Self::InActivation { placement } => {
                write!(
                    f,
                    "placement {placement} is part of the activation in progress"
                )
            }
            Self::LeasesHeld { placement, leases } => write!(
                f,
                "placement {placement} still has {leases} request lease(s) to drain"
            ),
            Self::ReclaimBlocked { blocked } => blocked.fmt(f),
            Self::Gate { error } => error.fmt(f),
            Self::NotReclaimed { placement } => write!(
                f,
                "placement {placement} still holds GPU memory or a reservation"
            ),
            Self::ProcessAlreadyAlive { placement } => {
                write!(f, "placement {placement} already has a live process")
            }
            Self::NotResident { placement } => {
                write!(f, "placement {placement} holds no GPU memory")
            }
            Self::NotReclaimable { placement, state } => {
                write!(
                    f,
                    "placement {placement} is {state}; only resting placements are reclaimed"
                )
            }
            Self::NotDraining { placement, state } => write!(
                f,
                "placement {placement} is {state}; only a draining placement's leases end at \
                 a drain deadline"
            ),
        }
    }
}

impl std::error::Error for SlotError {}

impl From<IllegalTransition> for SlotError {
    fn from(transition: IllegalTransition) -> Self {
        Self::Transition { transition }
    }
}

/// One model slot: placements, extents and the request router (§3.6).
pub struct PlacementSlot<C: Clock> {
    pub(super) spec: SlotSpec,
    pub(super) clock: C,
    pub(super) placements: BTreeMap<PlacementKey, Placement>,
    pub(super) extents: ExtentTable,
    pub(super) router: Router,
    pub(super) activation: Option<Activation>,
    pub(super) early: Option<EarlyExecution>,
    pub(super) pause: Option<PauseRecord>,
    pub(super) last_failure: Option<(PlacementKey, Failure)>,
    /// The weights each adapter identity named for each execution (line 599).
    pub(super) adapter_contents:
        BTreeMap<(ExecutionIdentity, AdapterIdentity), BTreeSet<ContentKey>>,
    pub(super) next_placement: u64,
}

impl<C: Clock> PlacementSlot<C> {
    /// An empty slot for `spec` that reads time from `clock`.
    pub fn new(spec: SlotSpec, clock: C) -> Self {
        Self {
            spec,
            clock,
            placements: BTreeMap::new(),
            extents: ExtentTable::default(),
            router: Router::default(),
            activation: None,
            early: None,
            pause: None,
            last_failure: None,
            adapter_contents: BTreeMap::new(),
            next_placement: 1,
        }
    }

    /// Who the slot belongs to and the authority it is bound to.
    pub fn spec(&self) -> &SlotSpec {
        &self.spec
    }

    pub(super) fn now(&self) -> MonotonicTime {
        self.clock.now()
    }

    /// One placement's state and independent fields (§3.6 line 585).
    pub fn placement(&self, key: PlacementKey) -> Option<PlacementView> {
        self.placements.get(&key).map(|placement| PlacementView {
            key,
            state: placement.state,
            execution: placement.execution,
            artifact_identity: placement.artifact_identity,
            adapters: placement.adapters.clone(),
            artifact: placement.artifact,
            process: placement.process,
            gpu: self.extents.residency_of(key),
            steady_reservation: placement.steady.as_ref().map(|steady| steady.id),
            steady_demand: placement
                .steady
                .as_ref()
                .map(|steady| steady.demand.clone()),
            leases: self.router.leases_of(key),
            generations: self
                .router
                .generations_of(key)
                .into_iter()
                .map(|(generation, _)| generation)
                .collect(),
        })
    }

    /// Every placement not yet retired, in creation order.
    pub fn placement_keys(&self) -> Vec<PlacementKey> {
        self.placements.keys().copied().collect()
    }

    /// The generation new requests are admitted to, if any.
    pub fn published(&self) -> Option<&ActivationContent> {
        self.router
            .published()
            .and_then(|generation| self.router.entry(generation))
            .map(|entry| &entry.content)
    }

    /// The content of a generation that is still serving or draining.
    pub fn content(&self, generation: ModelActivationGeneration) -> Option<&ActivationContent> {
        self.router.entry(generation).map(|entry| &entry.content)
    }

    /// The placement identity of each rank of a generation that is still serving or
    /// draining (§3.2 item 5, task T07): artifact and execution identity, the rank's
    /// device, the slot's tenant and authority binding, the activation generation, the
    /// newest allocation generation of the placement's memory on that device, and the
    /// leases holding the generation now. It changes when any of them changes.
    pub fn placement_identities(
        &self,
        generation: ModelActivationGeneration,
    ) -> Option<BTreeMap<Rank, PlacementIdentity>> {
        let entry = self.router.entry(generation)?;
        let placement = self.placements.get(&entry.placement)?;
        let leases: BTreeSet<LeaseId> = entry.leases.values().map(|held| held.lease).collect();
        let mut identities = BTreeMap::new();
        for (rank, device) in &placement.layout {
            let allocation = placement
                .components
                .values()
                .filter(|spec| spec.extent.device == *device)
                .filter_map(|spec| self.extents.get(&spec.extent))
                .filter(|extent| extent.holders.contains(&entry.placement))
                .map(|extent| extent.allocation)
                .max()?;
            let spec = PlacementSpec {
                artifact: placement.artifact_identity,
                execution: placement.execution,
                device: *device,
                owner: self.spec.tenant.clone(),
                authority: self.spec.authority.clone(),
                activation: generation,
                allocation,
                leases: leases.clone(),
            };
            identities.insert(*rank, spec.identity());
        }
        Some(identities)
    }

    /// When a generation that is still serving or draining was published.
    pub fn published_at(&self, generation: ModelActivationGeneration) -> Option<MonotonicTime> {
        self.router
            .entry(generation)
            .map(|entry| entry.published_at)
    }

    /// The pause in effect, if serving is paused (§3.6 line 597).
    pub fn active_pause(&self) -> Option<&PauseRecord> {
        self.pause.as_ref()
    }

    /// The latest failure with its stage and reason (line 583), until that placement is
    /// retired.
    pub fn last_failure(&self) -> Option<&(PlacementKey, Failure)> {
        self.last_failure.as_ref()
    }

    pub(super) fn get(&self, key: PlacementKey) -> Result<&Placement, SlotError> {
        self.placements
            .get(&key)
            .ok_or(SlotError::UnknownPlacement { placement: key })
    }

    pub(super) fn get_mut(&mut self, key: PlacementKey) -> Result<&mut Placement, SlotError> {
        self.placements
            .get_mut(&key)
            .ok_or(SlotError::UnknownPlacement { placement: key })
    }

    /// Admits a request to the published generation under a serving lease bound to the
    /// slot's parent execution, the request's authorization epoch and that generation
    /// (S3.1). The request keeps this generation until it finishes, whatever is
    /// published later.
    pub fn admit(
        &mut self,
        request: &AdmissionRequest,
        coordination: &mut dyn CoordinationPort,
    ) -> Result<RequestTicket, RouteRefusal> {
        if request.execution != *self.spec.owner() {
            return Err(RouteRefusal::ForeignExecution {
                owner: self.spec.owner().clone(),
            });
        }
        if let Some(bound) = self.spec.authority.epoch() {
            if request.epoch != bound {
                return Err(RouteRefusal::AuthorityMismatch {
                    presented: request.epoch,
                    bound: Some(bound),
                });
            }
        }
        let Some(generation) = self.router.published() else {
            return Err(match &self.pause {
                Some(pause) => RouteRefusal::Paused {
                    since: pause.started_at,
                    reason: pause.reason,
                },
                None => RouteRefusal::NotServing,
            });
        };
        let entry = self
            .router
            .entry(generation)
            .ok_or(RouteRefusal::NotServing)?;
        entry
            .supported
            .check(&request.shape)
            .map_err(|refusal| RouteRefusal::NotReadyForShape { refusal })?;
        if let Some(adapter) = request.adapter {
            if !entry.content.adapters.values().any(|held| *held == adapter) {
                return Err(RouteRefusal::AdapterNotPublished { adapter });
            }
        }
        let early_holds = self
            .early
            .as_ref()
            .is_some_and(|early| early.request == request.request && !early.ended);
        if early_holds || self.router.holds_request(&request.request) {
            return Err(RouteRefusal::DuplicateRequest {
                request: request.request.clone(),
            });
        }
        let placement = entry.placement;
        let now = self.now();
        let lease = coordination
            .grant_lease(
                &LeaseRequest {
                    slot: self.spec.slot,
                    kind: LeaseKind::Serving,
                    request: request.request.clone(),
                    execution: request.execution.clone(),
                    epoch: request.epoch,
                    generation,
                    expires_at: request.lease_expires_at,
                },
                now,
            )
            .map_err(|refusal| RouteRefusal::LeaseRefused { refusal })?;
        if let Some(entry) = self.router.entry_mut(generation) {
            entry.leases.insert(
                request.request.clone(),
                HeldLease {
                    kind: LeaseKind::Serving,
                    lease,
                },
            );
        }
        Ok(RequestTicket {
            request: request.request.clone(),
            kind: LeaseKind::Serving,
            generation,
            lease,
            placement,
        })
    }

    /// Ends a request and releases its lease.
    pub fn finish(
        &mut self,
        ticket: &RequestTicket,
        coordination: &mut dyn CoordinationPort,
    ) -> Result<(), TicketError> {
        if let Some(entry) = self.router.entry_mut(ticket.generation) {
            let holds = entry
                .leases
                .get(&ticket.request)
                .is_some_and(|held| held.lease == ticket.lease && held.kind == ticket.kind);
            if holds {
                entry.leases.remove(&ticket.request);
                coordination.release_lease(ticket.lease);
                if self
                    .early
                    .as_ref()
                    .is_some_and(|early| early.request == ticket.request)
                {
                    self.early = None;
                }
                return Ok(());
            }
        }
        let early_holds = self.early.as_ref().is_some_and(|early| {
            !early.ended
                && !early.lease_in_router
                && early.request == ticket.request
                && early.lease == ticket.lease
                && early.generation == ticket.generation
        });
        if early_holds {
            coordination.release_lease(ticket.lease);
            self.early = None;
            return Ok(());
        }
        Err(TicketError::UnknownTicket)
    }

    /// The extent a request reads at `position`: always its own generation's.
    pub fn weight_for(
        &self,
        ticket: &RequestTicket,
        position: WeightPosition,
    ) -> Result<ExtentKey, TicketError> {
        if let Some(entry) = self.router.entry(ticket.generation) {
            let holds = entry
                .leases
                .get(&ticket.request)
                .is_some_and(|held| held.lease == ticket.lease);
            if holds {
                return entry
                    .content
                    .components
                    .get(&position)
                    .copied()
                    .ok_or(TicketError::UnknownPosition { position });
            }
        }
        let early = self.early.as_ref().filter(|early| {
            !early.ended
                && early.request == ticket.request
                && early.lease == ticket.lease
                && early.generation == ticket.generation
        });
        match (early, &self.activation) {
            (Some(_), Some(activation)) if activation.generation == ticket.generation => activation
                .components
                .get(&position)
                .map(|spec| spec.extent)
                .ok_or(TicketError::UnknownPosition { position }),
            _ => Err(TicketError::UnknownTicket),
        }
    }

    /// Refuses weights that are not those of the request's generation (line 599).
    pub fn check_weight(
        &self,
        ticket: &RequestTicket,
        position: WeightPosition,
        offered: ExtentKey,
    ) -> Result<(), TicketError> {
        let expected = self.weight_for(ticket, position)?;
        if offered != expected {
            return Err(TicketError::MixedGenerations {
                generation: ticket.generation,
                position,
                expected,
                offered,
            });
        }
        Ok(())
    }

    /// Drops leases the coordination module no longer reports active, across every
    /// generation. Their requests must be stopped by the caller; reclamation still waits
    /// for their GPU work (step 7).
    pub fn reconcile_leases(&mut self, coordination: &dyn CoordinationPort) -> Vec<EndedLease> {
        let placements: Vec<PlacementKey> = self.placements.keys().copied().collect();
        placements
            .into_iter()
            .flat_map(|placement| self.reconcile_placement(placement, coordination))
            .collect()
    }

    fn reconcile_placement(
        &mut self,
        placement: PlacementKey,
        coordination: &dyn CoordinationPort,
    ) -> Vec<EndedLease> {
        let now = self.now();
        let mut ended = Vec::new();
        for (generation, leases) in self.router.generations_of(placement) {
            for (request, lease) in leases {
                let status = coordination.lease_status(lease, now);
                if status.is_active() {
                    continue;
                }
                if let Some(entry) = self.router.entry_mut(generation) {
                    entry.leases.remove(&request);
                }
                ended.push(EndedLease {
                    request,
                    generation,
                    lease,
                    status,
                });
            }
        }
        ended
    }

    /// Stops a serving placement from admitting requests, for example to park an idle
    /// model: serving → draining. Its leases drain as in step 6.
    pub fn begin_draining(&mut self, key: PlacementKey) -> Result<(), SlotError> {
        if self.activation_uses(key) {
            return Err(SlotError::InActivation { placement: key });
        }
        let next = self.get(key)?.state.next(StateKind::Draining)?;
        if self
            .router
            .published()
            .and_then(|generation| self.router.entry(generation))
            .is_some_and(|entry| entry.placement == key)
        {
            self.router.unpublish();
        }
        self.get_mut(key)?.state = next;
        Ok(())
    }

    /// Step 6: reconciles a placement's leases and reports what still drains.
    pub fn drain_status(
        &mut self,
        key: PlacementKey,
        coordination: &dyn CoordinationPort,
    ) -> Result<DrainStatus, SlotError> {
        self.get(key)?;
        let ended = self.reconcile_placement(key, coordination);
        Ok(DrainStatus {
            ended,
            remaining_leases: self.router.leases_of(key),
        })
    }

    /// Step 6 with a bound: ends every lease still held on a draining placement's
    /// generations once its drain deadline has passed. Each lease is released through the
    /// coordination authority, so its request's result checks fail from now on and the
    /// caller must stop it; reclamation still waits for its GPU work (step 7). Returns the
    /// ended leases.
    pub fn end_leases(
        &mut self,
        key: PlacementKey,
        coordination: &mut dyn CoordinationPort,
    ) -> Result<Vec<EndedLease>, SlotError> {
        let state = self.get(key)?.state.kind();
        if state != StateKind::Draining {
            return Err(SlotError::NotDraining {
                placement: key,
                state,
            });
        }
        let mut ended = Vec::new();
        for (generation, leases) in self.router.generations_of(key) {
            for (request, lease) in leases {
                coordination.release_lease(lease);
                if let Some(entry) = self.router.entry_mut(generation) {
                    entry.leases.remove(&request);
                }
                if self
                    .early
                    .as_ref()
                    .is_some_and(|early| early.request == request && early.lease == lease)
                {
                    self.early = None;
                }
                ended.push(EndedLease {
                    request,
                    generation,
                    lease,
                    status: LeaseStatus::Released,
                });
            }
        }
        Ok(ended)
    }

    /// Draining → parked once no old-generation lease remains. Parking frees nothing:
    /// a parked placement keeps its GPU weights until it is reclaimed.
    pub fn park(&mut self, key: PlacementKey) -> Result<(), SlotError> {
        let next = self.get(key)?.state.next(StateKind::Parked)?;
        let leases = self.router.leases_of(key);
        if leases > 0 {
            return Err(SlotError::LeasesHeld {
                placement: key,
                leases,
            });
        }
        self.router.remove_generations_of(key);
        self.get_mut(key)?.state = next;
        Ok(())
    }

    /// Records a process reference to a placement's memory.
    pub fn hold_reference(
        &mut self,
        key: PlacementKey,
        reference: ReferenceId,
        kind: ReferenceKind,
    ) -> Result<(), SlotError> {
        self.require_resident(key)?;
        self.get_mut(key)?
            .gate
            .hold(reference, kind)
            .map_err(|error| SlotError::Gate { error })
    }

    /// Records that a process closed its reference to a placement's memory.
    pub fn drop_reference(
        &mut self,
        key: PlacementKey,
        reference: ReferenceId,
    ) -> Result<(), SlotError> {
        self.get_mut(key)?
            .gate
            .drop_reference(reference)
            .map_err(|error| SlotError::Gate { error })
    }

    /// Records GPU work enqueued on a placement's memory.
    pub fn enqueue_work(
        &mut self,
        key: PlacementKey,
        event: CompletionEventId,
    ) -> Result<(), SlotError> {
        self.require_resident(key)?;
        self.get_mut(key)?
            .gate
            .enqueue(event)
            .map_err(|error| SlotError::Gate { error })
    }

    /// Records that the GPU work behind `event` completed.
    pub fn complete_work(
        &mut self,
        key: PlacementKey,
        event: CompletionEventId,
    ) -> Result<(), SlotError> {
        self.get_mut(key)?
            .gate
            .complete(event)
            .map_err(|error| SlotError::Gate { error })
    }

    /// Step 7: reclaims a resting placement once no lease, process reference or pending
    /// GPU completion event remains. Extents shared with other placements stay resident;
    /// the rest are freed and the placement's reservation is released.
    pub fn reclaim(
        &mut self,
        key: PlacementKey,
        reservations: &mut dyn ReservationPort,
    ) -> Result<ReclaimReport, SlotError> {
        let placement = self.get(key)?;
        let state = placement.state.kind();
        if !matches!(
            state,
            StateKind::Materialized | StateKind::Parked | StateKind::Failed
        ) {
            return Err(SlotError::NotReclaimable {
                placement: key,
                state,
            });
        }
        if self.activation_uses(key) {
            return Err(SlotError::InActivation { placement: key });
        }
        let leases = self.router.leases_of(key);
        if leases > 0 {
            return Err(SlotError::LeasesHeld {
                placement: key,
                leases,
            });
        }
        placement
            .gate
            .check()
            .map_err(|blocked| SlotError::ReclaimBlocked { blocked })?;

        let released = self.extents.release_holder(key);
        self.router.remove_generations_of(key);
        let steady = self.get_mut(key)?.steady.take();
        if let Some(steady) = &steady {
            reservations.release(steady.id);
        }
        Ok(ReclaimReport {
            placement: key,
            freed: released.freed,
            retained_shared: released.retained,
            released_reservation: steady.map(|steady| steady.id),
            rollback: self.rollback_outlook(key)?,
        })
    }

    /// Removes a resting placement that holds nothing any more: materialized, parked or
    /// failed → absent.
    pub fn retire(&mut self, key: PlacementKey) -> Result<(), SlotError> {
        let placement = self.get(key)?;
        placement.state.next(StateKind::Absent)?;
        if self.activation_uses(key) {
            return Err(SlotError::InActivation { placement: key });
        }
        let leases = self.router.leases_of(key);
        if leases > 0 {
            return Err(SlotError::LeasesHeld {
                placement: key,
                leases,
            });
        }
        placement
            .gate
            .check()
            .map_err(|blocked| SlotError::ReclaimBlocked { blocked })?;
        if placement.steady.is_some() || self.extents.residency_of(key).is_resident() {
            return Err(SlotError::NotReclaimed { placement: key });
        }
        self.placements.remove(&key);
        if self
            .last_failure
            .as_ref()
            .is_some_and(|(failed, _)| *failed == key)
        {
            self.last_failure = None;
        }
        Ok(())
    }

    /// Whether this placement's content could serve again without a reload.
    pub fn rollback_outlook(&self, key: PlacementKey) -> Result<RollbackOutlook, SlotError> {
        let placement = self.get(key)?;
        let mut missing_extents = 0;
        let mut missing_bytes: u64 = 0;
        for (extent, bytes) in placement.unique_extents() {
            if !self.extents.is_usable(&extent) {
                missing_extents += 1;
                missing_bytes = missing_bytes.saturating_add(bytes);
            }
        }
        Ok(if missing_extents > 0 {
            RollbackOutlook::RequiresReload {
                missing_extents,
                missing_bytes,
                reconstructible: placement
                    .artifact
                    .is_verified_as(&placement.artifact_identity),
            }
        } else if !placement.process.is_alive() {
            RollbackOutlook::RequiresProcess
        } else {
            RollbackOutlook::Retained
        })
    }

    /// Records that a new runtime process attached to a placement that has none. Its GPU
    /// residency and allocation generations stay as they are (§3.6 line 585).
    pub fn record_process_started(
        &mut self,
        key: PlacementKey,
        instance: ProcessInstance,
    ) -> Result<(), SlotError> {
        let placement = self.get_mut(key)?;
        if placement.process.is_alive() {
            return Err(SlotError::ProcessAlreadyAlive { placement: key });
        }
        placement.process = ProcessLiveness::Alive { instance };
        Ok(())
    }

    /// Records that a placement's process exited. GPU residency is a separate field and
    /// does not change here. A serving placement stops admitting at once and fails
    /// while draining; a placement under activation fails that activation.
    pub fn record_process_exit(
        &mut self,
        key: PlacementKey,
        ports: &mut dyn PlacementPorts,
    ) -> Result<Option<Failure>, SlotError> {
        let now = self.now();
        let placement = self.get(key)?;
        let ProcessLiveness::Alive { instance } = placement.process else {
            return Ok(None);
        };
        let exited = ProcessLiveness::Exited { instance, at: now };
        if self.activation_placement() == Some(key) {
            self.get_mut(key)?.process = exited;
            return Ok(self
                .abort_activation(FailureReason::ProcessExited, ports)
                .failure);
        }
        let failure = match placement.state.kind() {
            StateKind::Serving => {
                let mut state = placement.state.next(StateKind::Draining)?;
                let failure = state.fail(FailureReason::ProcessExited, now)?;
                if self
                    .router
                    .published()
                    .and_then(|generation| self.router.entry(generation))
                    .is_some_and(|entry| entry.placement == key)
                {
                    self.router.unpublish();
                }
                self.get_mut(key)?.state = state;
                Some(failure)
            }
            StateKind::Draining => {
                let mut state = placement.state;
                let failure = state.fail(FailureReason::ProcessExited, now)?;
                self.get_mut(key)?.state = state;
                Some(failure)
            }
            _ => None,
        };
        self.get_mut(key)?.process = exited;
        if let Some(failure) = failure {
            self.last_failure = Some((key, failure));
        }
        Ok(failure)
    }

    /// Records that a placement's artifact is no longer valid. Serving from weights that
    /// were verified when loaded continues; materializing or activating from the artifact
    /// is refused until it is verified again, and an activation in progress fails.
    pub fn record_artifact_invalid(
        &mut self,
        key: PlacementKey,
        problem: ArtifactProblem,
        ports: &mut dyn PlacementPorts,
    ) -> Result<Option<Failure>, SlotError> {
        let placement = self.get_mut(key)?;
        placement.artifact = ArtifactValidity::Invalid {
            artifact: placement.artifact_identity,
            problem,
        };
        if self.activation_placement() == Some(key) {
            return Ok(self
                .abort_activation(FailureReason::ArtifactInvalid, ports)
                .failure);
        }
        Ok(None)
    }

    /// Records that a placement's artifact was verified again.
    pub fn record_artifact_verified(&mut self, key: PlacementKey) -> Result<(), SlotError> {
        let placement = self.get_mut(key)?;
        placement.artifact = ArtifactValidity::Verified {
            artifact: placement.artifact_identity,
        };
        Ok(())
    }

    /// Work and references need memory: a placement holding no GPU extents takes none.
    fn require_resident(&self, key: PlacementKey) -> Result<(), SlotError> {
        self.get(key)?;
        if self.extents.residency_of(key).is_resident() {
            Ok(())
        } else {
            Err(SlotError::NotResident { placement: key })
        }
    }

    pub(super) fn activation_placement(&self) -> Option<PlacementKey> {
        self.activation
            .as_ref()
            .map(|activation| activation.placement)
    }

    /// Whether the activation in progress creates or reuses this placement.
    pub(super) fn activation_uses(&self, key: PlacementKey) -> bool {
        self.activation_placement() == Some(key)
    }
}
