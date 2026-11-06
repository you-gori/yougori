//! Boundary 2 of GPU §3.1: the placement governor.
//!
//! Responsibility: capacity, admission, leases, priorities and transfer budgets. Must not
//! own: tensor kernels or model-specific forward methods; its signatures carry only
//! demands, grants, generations and leases, never tensors or a forward call.
//!
//! The governor is a policy client of the CORE-03 host ledger, never a second capacity
//! authority (line 491). [`LedgerPolicyGovernor`] keeps no capacity count of its own, and
//! drives every activation through P04's activation slot ([`PlacementSlot`]) over the
//! coordinator ports ([`CoordinatorPorts`]), the documented path for a model in a VM
//! sandbox:
//!
//! - each placement of a model in a runner has one slot per authorization epoch, bound to
//!   the runner's parent execution and that epoch (S3.1), whose coordinator activations
//!   reserve GPU memory as children of the sandbox reservation, with their generations, so
//!   the ledger decides whether an activation fits;
//! - an activation runs the seven steps of §3.6 in its slot: step 1 reserves the T08 demand
//!   as the steady state, step 2 acquires or allocates the immutable extents the flow then
//!   marks usable as they are made, steps 3 and 4 record the runner's validation and its
//!   readiness for the declared shape, and step 5 publishes in one step through the
//!   coordinator;
//! - the immutable extents are the model's weights, held by the coordinator apart from any
//!   activation, one holding per extent: a later generation acquires the weights it shares
//!   and reserves only new ones, so weights count once across any sequence of generations,
//!   while each generation's own memory (KV, contexts, graphs) stays its own until its
//!   placement is reclaimed. A slot shares weights only among its own placements, so state
//!   shared with another model's placement counts twice while both live; neither is ever
//!   uncounted;
//! - versions overlap when both fit. When they do not and the activation or its placement
//!   consents, serving pauses for a reload (GPU-W05 line 110): the old generation stops
//!   admitting, its requests keep their leases until they finish or a bounded drain
//!   deadline ends them, the runner frees the old KV and contexts, whose memory passes to
//!   the new generation, and the new generation loads. The pause is visible with its
//!   reason and an estimate of when serving resumes ([`ReloadStatus`]); without consent
//!   the activation is refused, never paused silently. A failed activation that overlapped
//!   leaves the old generation serving; one that drained first says that the old serving
//!   state is gone and whether it can come back without a reload ([`AbandonedActivation`]).
//!   A paused reload continues on a retried admission or through
//!   [`LedgerPolicyGovernor::resume_reloads`] once its preconditions return, within a
//!   bound, and never once its generation was superseded or its authority revoked;
//! - with a model lifecycle stream configured, every decision the governor makes in a slot
//!   is recorded through CORE-06 under its operation (S06), and a record the stream refuses
//!   is reported, never a reason to change the decision;
//! - execution leases are the slot router's serving leases and the one preparation lease
//!   its execute-while-load assignment, all the coordinator's leases bound to the parent
//!   execution, its authorization epoch and the generation (S3.1, line 601), and work
//!   computed ahead is recorded in the slot, which refuses a part whose extent is not
//!   usable. Each lease carries the KV its request may write, admitted against the
//!   generation's KV pool from the request's shape (GPU-W10 line 182, [`super::kv`]); a
//!   backend that grows its KV commits the pool in increments carved from the generation's
//!   own reservation, and a request past the pool waits or is refused with a typed reason;
//! - a released placement is reclaimed through the slot (step 7), which confirms the
//!   release through the coordinator, so its record and the ledger agree;
//! - bounded transfer staging is a ledger reservation carved from the same sandbox
//!   reservation (S3.2), and each transfer lands in the memory that holds it: weights in
//!   their own holding, other state in the generation's own memory, each a destination
//!   whose ledger reservation the executor carves from.
//!
//! Its own policy only narrows: a transfer limit refuses, a staging cap bounds, a drain
//! deadline is bounded, and a request's priority must be its runtime's, because a child
//! reservation takes its parent's priority (CORE-03). A [`LedgerGrant`], a
//! [`PendingActivation`] and both kinds of lease are made only in this module, from what
//! the ledger, the slot and the coordinator granted, and none can be copied, so whatever a
//! governor admits is backed by live reservations.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use serde::{Serialize, Serializer};

use super::catalog::{ExtentRef, VerifiedRepresentation};
use super::declaration::{NodeId, StateIdentity};
use super::demand::{ActivationDemand, DeviceBudget};
use super::kv::{kv_bytes, KvPlan, KvPool, KvRefusal, KvSpec};
use crate::foundation::coordination::{
    CapacityPort, Coordinator, GpuDemand, HoldingId, HoldingMemory, Lease, LeaseRefusal,
    LeaseState, LedgerCapacity, ModelGenerations, ModelId, ModelRefusal, ReservationKey,
    ReservationPriority, SandboxLifecycle, SharedLedger,
};
use crate::foundation::evidence::{ArtifactVerification, RuntimeSettings, SourceClass};
use crate::foundation::ids::{
    AuthorizationEpoch, Clock, ContentKey, Digest, DigestBuilder, ExecutionCategory, ExecutionId,
    GpuAllocationGeneration, GpuDeviceKey, LeaseId, ModelActivationGeneration, MonotonicTime,
    OperationId, TenantId,
};
use crate::foundation::ledger::{
    Admission as LedgerAdmission, Amounts, CapacityError, CostPurpose, HostResource, Ledger,
    LedgerError, Limit, Priority, Provenance, ReleaseOutcome, Requester, ReservationId,
    ReservationRecord, ReservationRequest, ResourceKey, RetryProspect,
};
use crate::model_memory::identity::{
    AuthorityBinding, CurrentResidency, ExecutionIdentity, Residency,
};
use crate::model_memory::placement::{
    ActivationError, ActivationIdentity, ActivationRequest as SlotActivation,
    AdmissionRequest as SlotAdmission, ArtifactValidity, AssignedRequest, Component,
    CoordinatorBinding, CoordinatorPlacement, CoordinatorPorts, EarlyRefusal, ExtentKey,
    ExtentSpec, PauseReason, PauseRecord, PlacementChoice, PlacementKey as SlotPlacement,
    PlacementSlot, ProcessInstance, Rank, ReadinessReport, RequestShape, RequestTicket,
    ResourceDemand, RollbackOutlook, RouteRefusal, ShapeRefusal, SlotError, SlotId, SlotSpec,
    StateKind, SupportedShape, TicketError, TransitionMode, TransitionPreference, ValidationReport,
    WeightPosition,
};

mod kv_pool;
mod lifecycle;
mod resume;

pub use kv_pool::{KvIncrement, KvScratch, KvTrimRefusal, KvTrimWork};
pub use lifecycle::{LifecycleDecision, RecordingReport, UnrecordedDecision, MAX_UNRECORDED};
pub use resume::{EndedReload, ReloadEnd, ReloadResumption, MAX_ENDED_RELOADS};

/// Pinned host RAM, where transfer staging lives.
pub const STAGING: ResourceKey = ResourceKey::Host(HostResource::PinnedRam);

/// Host RAM. Pinned pages are host RAM, and the pinned pool is a cap inside it (§2.7
/// line 446; decisions T08 and P02), so every pinned byte is charged to both.
pub const HOST_RAM: ResourceKey = ResourceKey::Host(HostResource::Ram);

/// The ledger key of one GPU's VRAM.
pub fn vram_key(device: GpuDeviceKey) -> ResourceKey {
    ResourceKey::vram(device)
}

/// The runtime that owns a placement: one runner instance on one device.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct PlacementOwner {
    pub device: GpuDeviceKey,
    pub instance: u32,
}

/// One model placed in one runner (GPU §3.2 item 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct PlacementKey {
    pub owner: PlacementOwner,
    pub model: ExecutionIdentity,
}

impl PlacementKey {
    /// Digest domain of [`PlacementKey::model_id`].
    pub const MODEL_DOMAIN: &'static str = "yougori/model-memory/boundaries/placement-model/v1";

    /// Digest domain of the P04 slot a placement has in one authorization epoch.
    pub const SLOT_DOMAIN: &'static str = "yougori/model-memory/boundaries/placement-slot/v1";

    /// The model the coordinator counts this placement's activations under: the execution
    /// identity on this runner, so two runners of one parent execution never share an
    /// activation, a generation or a lease.
    pub fn model_id(&self) -> ModelId {
        ModelId::new(
            DigestBuilder::new(Self::MODEL_DOMAIN)
                .digest(self.model.digest())
                .digest(&self.owner.device.machine)
                .digest(&self.owner.device.device)
                .u64(u64::from(self.owner.instance))
                .finish(),
        )
    }

    /// The P04 slot of this placement under authorization epoch `epoch` (S3.1: a slot's
    /// activations and leases bind to one epoch).
    pub fn slot_id(&self, epoch: AuthorizationEpoch) -> SlotId {
        SlotId::new(
            DigestBuilder::new(Self::SLOT_DOMAIN)
                .digest(&self.model_id().digest())
                .u64(epoch.get())
                .finish(),
        )
    }
}

/// The VM sandbox a runner's placements run in: the parent execution the coordinator
/// launched, and the runtime settings its authority allows (T09; the coordinator checks
/// them against the parent's grant).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeBinding {
    pub execution: ExecutionId,
    pub settings: RuntimeSettings,
}

/// What the flow may know of a runner's runtime: its parent execution and authority, and
/// its device budget.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RuntimeView {
    pub execution: ExecutionId,
    pub tenant: TenantId,
    pub category: ExecutionCategory,
    pub epoch: AuthorizationEpoch,
    pub priority: Priority,
    pub budget: DeviceBudget,
}

/// Direction of a transfer budget. Preparation reads into this host only; there is no
/// outbound variant, so a model transfer cannot become outbound authority (S3.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferDirection {
    Inbound,
}

/// Where a transferred extent lands (§3.5 step 2): the GPU allocation that holds it and
/// the ledger reservation behind that allocation, which the destination is carved from so
/// its memory is never counted twice.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct TransferDestination {
    pub allocation: GpuAllocationGeneration,
    pub reservation: ReservationId,
    /// GPU memory the reservation holds on the recipient device.
    pub capacity_bytes: u64,
}

/// The transfer budget of one preparation: exactly these objects, inbound, to one device,
/// up to their total length (§3.1 row 2; S3.7: explicit object, direction, recipient and
/// byte budget), and where they land: weights in their own holding, other state in the
/// activation's own memory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TransferBudget {
    objects: BTreeMap<ExtentRef, u64>,
    direction: TransferDirection,
    recipient: GpuDeviceKey,
    max_bytes: u64,
    destination: Option<TransferDestination>,
    destinations: BTreeMap<ExtentRef, TransferDestination>,
}

impl TransferBudget {
    /// A budget for exactly `objects` (each with its length in bytes); `None` if their
    /// total does not fit in 64 bits.
    pub fn inbound(objects: BTreeMap<ExtentRef, u64>, recipient: GpuDeviceKey) -> Option<Self> {
        let max_bytes = objects
            .values()
            .try_fold(0u64, |total, bytes| total.checked_add(*bytes))?;
        Some(Self {
            objects,
            direction: TransferDirection::Inbound,
            recipient,
            max_bytes,
            destination: None,
            destinations: BTreeMap::new(),
        })
    }

    /// The same budget, landing in `destination` wherever no extent has its own.
    pub fn with_destination(mut self, destination: TransferDestination) -> Self {
        self.destination = Some(destination);
        self
    }

    /// The same budget, with `extent` landing in `destination`, as weights land in their
    /// own holding; an extent the budget does not name is ignored.
    pub fn with_extent_destination(
        mut self,
        extent: ExtentRef,
        destination: TransferDestination,
    ) -> Self {
        if self.objects.contains_key(&extent) {
            self.destinations.insert(extent, destination);
        }
        self
    }

    pub fn direction(&self) -> TransferDirection {
        self.direction
    }

    pub fn recipient(&self) -> GpuDeviceKey {
        self.recipient
    }

    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    /// Where extents without their own destination land: the activation's own memory.
    pub fn destination(&self) -> Option<TransferDestination> {
        self.destination
    }

    /// Where `extent` lands: its own destination, otherwise the budget's.
    pub fn destination_of(&self, extent: &ExtentRef) -> Option<TransferDestination> {
        self.destinations.get(extent).copied().or(self.destination)
    }

    /// The extents with their own destination.
    pub fn destinations(&self) -> &BTreeMap<ExtentRef, TransferDestination> {
        &self.destinations
    }

    pub fn permits(&self, extent: &ExtentRef) -> bool {
        self.objects.contains_key(extent)
    }

    pub fn objects(&self) -> impl Iterator<Item = &ExtentRef> {
        self.objects.keys()
    }
}

/// Who asks for admission or a lease, and under which authority. Leases bind to the
/// parent execution and the authorization epoch (S3.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RequestAuthority {
    pub execution: ExecutionId,
    pub operation: OperationId,
    pub tenant: TenantId,
    pub epoch: AuthorizationEpoch,
}

/// One immutable extent a new activation reads (§3.6 step 1): the weights, rank layout
/// or adapter a node of the runner's declaration holds, by its state identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ActivationExtent {
    pub node: NodeId,
    pub identity: StateIdentity,
    pub device_bytes: u64,
    /// The runner holds it resident and usable already, so nothing makes it again.
    pub ready: bool,
    /// The catalog extents it is transferred from; empty when it is rebuilt or ready.
    pub transfers: Vec<ExtentRef>,
}

/// Whether an activation that cannot overlap the serving generation may pause serving to
/// reload (GPU-W05 line 110). Pausing is opt-in, per request or per placement; it is
/// never chosen silently.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(tag = "reload", rename_all = "snake_case")]
pub enum ReloadConsent {
    /// Refuse the activation rather than pause.
    #[default]
    Never,
    /// Drain the serving generation first: its requests keep their leases until they
    /// finish or `drain_within` has passed, bounded by the governor's policy.
    Pause { drain_within: Duration },
}

/// What a new activation serves and is checked for, besides its §2.7 demand: the
/// artifact as the catalog verified it, the extents it reads, the request shape its
/// readiness checks cover (§3.6 steps 1 and 4), its KV, and whether it may pause serving.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivationSpec {
    pub verified: VerifiedRepresentation,
    pub extents: Vec<ActivationExtent>,
    pub declared: SupportedShape,
    /// The KV its requests write and how the backend fills its pool.
    pub kv: KvSpec,
    pub reload: ReloadConsent,
    /// How long making it ready takes once it may load, for the estimate of a pause.
    pub reload_estimate: Duration,
}

/// One admission asked of the governor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionRequest {
    pub authority: RequestAuthority,
    pub placement: PlacementKey,
    pub priority: Priority,
    /// The new activation's §2.7 demand (T08); `None` when a compatible engine is ready
    /// and nothing new is activated.
    pub activation: Option<ActivationDemand>,
    /// What the new activation serves; present exactly when `activation` is.
    pub spec: Option<ActivationSpec>,
    /// Each extent to transfer with its length in bytes.
    pub transfer: BTreeMap<ExtentRef, u64>,
}

/// One ledger reservation the governor made, such as transfer staging. It is made only
/// in this module, from a reservation the ledger granted, and is neither `Clone` nor
/// `Copy`, so each grant stands for one live reservation until it is handed back.
#[derive(Debug, PartialEq, Eq)]
pub struct LedgerGrant {
    reservation: ReservationId,
    amounts: Amounts,
}

impl LedgerGrant {
    pub fn reservation(&self) -> ReservationId {
        self.reservation
    }

    /// Everything the reservation holds, each amount in its resource's unit.
    pub fn amounts(&self) -> &Amounts {
        &self.amounts
    }

    /// Pinned host RAM the grant holds.
    pub fn pinned_bytes(&self) -> u64 {
        self.amounts.get(STAGING)
    }

    /// Host RAM the grant holds; at least its pinned bytes.
    pub fn host_ram_bytes(&self) -> u64 {
        self.amounts.get(HOST_RAM)
    }
}

/// An activation that holds its generations and its GPU reservation in its slot but is
/// not yet published (GPU §3.6 steps 1–4). It is made only in this module, from the slot's
/// and the coordinator's grants, is neither `Clone` nor `Copy`, and is consumed by
/// publishing or abandoning.
#[derive(Debug, PartialEq, Eq)]
pub struct PendingActivation {
    placement: PlacementKey,
    epoch: AuthorizationEpoch,
    generations: ModelGenerations,
    reserved: GpuDemand,
    slot_placement: SlotPlacement,
    allocation: Option<GpuAllocationGeneration>,
    mode: TransitionMode,
}

impl PendingActivation {
    pub fn placement(&self) -> &PlacementKey {
        &self.placement
    }

    /// The activation generation the coordinator issued with the reservation.
    pub fn generation(&self) -> ModelActivationGeneration {
        self.generations.activation
    }

    /// Its activation and GPU allocation generations (S3.1).
    pub fn generations(&self) -> ModelGenerations {
        self.generations
    }

    /// The GPU memory the ledger granted for it, read back from the ledger's records:
    /// the weights it reads and its own memory.
    pub fn reserved(&self) -> GpuDemand {
        self.reserved
    }

    /// The authorization epoch its slot is bound to.
    pub fn epoch(&self) -> AuthorizationEpoch {
        self.epoch
    }

    /// The placement record in its slot.
    pub fn slot_placement(&self) -> SlotPlacement {
        self.slot_placement
    }

    /// The GPU allocation of its own memory on its device, if it reserved any anew.
    pub fn allocation(&self) -> Option<GpuAllocationGeneration> {
        self.allocation
    }

    /// How it replaces what serves: first, beside it, or after it drained.
    pub fn mode(&self) -> TransitionMode {
        self.mode
    }
}

/// Authority to serve one request on one published activation generation: the slot
/// router's serving lease, which is the coordinator's model-request lease (INT-03), with
/// the KV the request may write. Made only in this module; neither `Clone` nor `Copy`.
/// Enforcement points check its number with the coordinator.
#[derive(Debug, PartialEq, Eq)]
pub struct ExecutionLease {
    lease: Lease,
    placement: PlacementKey,
    generation: ModelActivationGeneration,
    epoch: AuthorizationEpoch,
    ticket: RequestTicket,
    shape: RequestShape,
    kv_bytes: u64,
    /// The session stays with its KV once the lease ends ([`ExecutionLease::keep_session`]).
    keep_session: bool,
}

impl ExecutionLease {
    pub fn id(&self) -> LeaseId {
        self.lease.id()
    }

    pub fn placement(&self) -> &PlacementKey {
        &self.placement
    }

    /// The activation generation the request keeps for its whole life (INT-03).
    pub fn generation(&self) -> ModelActivationGeneration {
        self.generation
    }

    /// The request the lease was issued for.
    pub fn operation(&self) -> &OperationId {
        self.lease.operation()
    }

    pub fn expires_at(&self) -> MonotonicTime {
        self.lease.expires_at()
    }

    /// The coordinator's lease as issued.
    pub fn lease(&self) -> &Lease {
        &self.lease
    }

    /// The slot router's ticket for the lease.
    pub fn ticket(&self) -> &RequestTicket {
        &self.ticket
    }

    /// The shape the request was admitted for.
    pub fn shape(&self) -> RequestShape {
        self.shape
    }

    /// The KV the request may write; the runner writes no more.
    pub fn kv_bytes(&self) -> u64 {
        self.kv_bytes
    }
}

/// Authority to compute ahead for exactly one assigned pending request on a generation
/// that is reserved but not published (GPU §3.6, line 601): the slot's execute-while-load
/// assignment under the coordinator's preparation-generation lease. It cannot serve or
/// publish a result: that needs an [`ExecutionLease`], which exists only for published
/// generations. Made only in this module; neither `Clone` nor `Copy`.
#[derive(Debug, PartialEq, Eq)]
pub struct PreparationLease {
    lease: Lease,
    placement: PlacementKey,
    generation: ModelActivationGeneration,
    epoch: AuthorizationEpoch,
    ticket: RequestTicket,
    kv_bytes: u64,
}

impl PreparationLease {
    pub fn id(&self) -> LeaseId {
        self.lease.id()
    }

    pub fn placement(&self) -> &PlacementKey {
        &self.placement
    }

    pub fn generation(&self) -> ModelActivationGeneration {
        self.generation
    }

    /// The one pending request this lease may compute for.
    pub fn assigned_operation(&self) -> &OperationId {
        self.lease.operation()
    }

    pub fn expires_at(&self) -> MonotonicTime {
        self.lease.expires_at()
    }

    /// The coordinator's lease as issued.
    pub fn lease(&self) -> &Lease {
        &self.lease
    }

    /// The slot's ticket for the assignment.
    pub fn ticket(&self) -> &RequestTicket {
        &self.ticket
    }

    /// The KV the assigned request may write while it computes ahead.
    pub fn kv_bytes(&self) -> u64 {
        self.kv_bytes
    }
}

/// What the governor admitted.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Admission {
    /// The new activation, holding its GPU reservation.
    pub activation: Option<PendingActivation>,
    /// Bounded pinned staging for the transfers (§3.5 step 2), charged to pinned RAM and
    /// host RAM alike, released after the last transfer's completion event.
    pub staging: Option<LedgerGrant>,
    pub transfer_budget: Option<TransferBudget>,
    /// The drained generation whose own memory passes to the activation (a reload): the
    /// runner frees its KV and contexts, then [`PlacementGovernor::hand_over`] reclaims it
    /// before the activation loads.
    pub handover: Option<ModelActivationGeneration>,
}

/// The first part of a request an admission does not match.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Shortfall {
    /// The activation is missing, short, on another device or for another placement,
    /// or was admitted although none was asked for.
    Activation,
    /// Transfers without staging, or staging not charged to host RAM in full.
    Staging,
    /// The budget does not name exactly the extents to transfer, inbound to the device.
    TransferBudget,
}

impl Admission {
    /// What `request` asked for must be covered: the activation's demand by a GPU
    /// reservation for its placement on its device, the transfers by a budget naming
    /// exactly their extents and by bounded staging, whose pinned bytes are host RAM too.
    pub fn covers(&self, request: &AdmissionRequest) -> Result<(), Shortfall> {
        let device = request.placement.owner.device;
        match (&request.activation, &self.activation) {
            (None, None) => {}
            (Some(demand), Some(pending)) => {
                let reserved = pending.reserved();
                if pending.placement != request.placement
                    || demand.device != device
                    || reserved.device != device
                    || reserved.memory_bytes < demand.device_bytes
                {
                    return Err(Shortfall::Activation);
                }
            }
            _ => return Err(Shortfall::Activation),
        }
        if !request.transfer.is_empty() {
            let budgeted = self.transfer_budget.as_ref().is_some_and(|budget| {
                budget.objects == request.transfer
                    && budget.recipient == device
                    && budget.direction == TransferDirection::Inbound
            });
            if !budgeted {
                return Err(Shortfall::TransferBudget);
            }
            let staged = self.staging.as_ref().is_some_and(|grant| {
                grant.pinned_bytes() > 0 && grant.host_ram_bytes() >= grant.pinned_bytes()
            });
            if !staged {
                return Err(Shortfall::Staging);
            }
        }
        Ok(())
    }

    /// GPU memory reserved for the activation.
    pub fn reserved_device_bytes(&self) -> u64 {
        self.activation
            .as_ref()
            .map_or(0, |pending| pending.reserved.memory_bytes)
    }
}

/// The kind of limit the ledger's refusal names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitKind {
    PhysicalCapacity,
    CapacityNotObserved,
    /// The host's latest usage observation is too old to know what is free.
    StaleHostObservation,
    TenantBudget,
    /// The runtime reservation the request is carved from (S3.2).
    ParentReservation,
    OwnerReturnHold,
}

/// Whether, and after what, a retry can make progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "outlook", rename_all = "snake_case")]
pub enum RetryOutlook {
    FitsAfterRelease { shortfall: u64 },
    ExceedsLimit { limit: u64 },
    AfterHostObservation,
    AfterHoldEnds,
}

/// The ledger's capacity refusal in a form the API, CLI and UI can carry: the limiting
/// resource, the limit, the amounts and whether a retry can progress (S10 line 179).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct CapacityRefusal {
    pub resource: ResourceKey,
    pub limit: LimitKind,
    pub requested: u64,
    pub available: u64,
    pub outlook: RetryOutlook,
    pub retry_can_progress: bool,
}

impl CapacityRefusal {
    pub fn from_ledger(error: &CapacityError) -> Self {
        let limiting = error.limiting();
        Self {
            resource: limiting.resource,
            limit: match limiting.limit {
                Limit::PhysicalCapacity => LimitKind::PhysicalCapacity,
                Limit::CapacityNotObserved => LimitKind::CapacityNotObserved,
                Limit::StaleHostObservation { .. } => LimitKind::StaleHostObservation,
                Limit::TenantBudget { .. } => LimitKind::TenantBudget,
                Limit::ParentReservation { .. } => LimitKind::ParentReservation,
                Limit::OwnerReturnHold { .. } => LimitKind::OwnerReturnHold,
            },
            requested: limiting.requested,
            available: limiting.available,
            outlook: match limiting.prospect {
                RetryProspect::FitsAfterRelease { shortfall } => {
                    RetryOutlook::FitsAfterRelease { shortfall }
                }
                RetryProspect::ExceedsLimit { limit } => RetryOutlook::ExceedsLimit { limit },
                RetryProspect::AfterHostObservation => RetryOutlook::AfterHostObservation,
                RetryProspect::AfterHoldEnds => RetryOutlook::AfterHoldEnds,
            },
            retry_can_progress: error.retry_can_progress(),
        }
    }
}

impl fmt::Display for CapacityRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} requested, {} available",
            self.resource, self.requested, self.available
        )
    }
}

/// A ledger error other than a capacity refusal, serialized as its message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerFault(pub LedgerError);

impl Serialize for LedgerFault {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&self.0)
    }
}

impl fmt::Display for LedgerFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Where a pause for reload stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum ReloadPhase {
    /// Old-generation requests still hold leases; they keep them until they finish or the
    /// drain deadline passes.
    Draining { remaining_leases: u32 },
    /// Every old lease ended: the runner frees the old generation's KV and contexts,
    /// whose memory passes to the new generation.
    HandingOver,
    /// The new generation loads its missing state.
    Loading,
}

/// A placement paused for a reload (GPU-W05 line 110), as GPU-W11's status shows it: why,
/// since when, until when old requests may run, where it stands and when serving should
/// resume.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReloadStatus {
    pub placement: PlacementKey,
    /// The generation that stopped admitting, until it is reclaimed.
    pub draining: ModelActivationGeneration,
    /// The generation that will serve once loaded.
    pub reloading: ModelActivationGeneration,
    /// Why the two generations could not be resident together.
    pub reason: PauseReason,
    pub since: MonotonicTime,
    /// The latest moment old-generation requests keep their leases.
    pub drain_deadline: MonotonicTime,
    /// Old-generation requests whose leases the drain deadline ended: they were stopped
    /// rather than finished.
    pub ended_leases: u32,
    pub phase: ReloadPhase,
    /// When serving should resume: the end of the drain, at the latest its deadline, plus
    /// the reload's planned time.
    pub eta: MonotonicTime,
}

/// How an activation ended without publishing (GPU-W05 acceptance: failed preparation
/// preserves the old serving state when transition capacity was reserved; when it was
/// not, this says so).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AbandonedActivation {
    pub placement: PlacementKey,
    pub generation: ModelActivationGeneration,
    pub mode: TransitionMode,
    /// Whether memory for both generations was reserved (an overlap), so the old one kept
    /// serving; `false` when the old one drained first or nothing served before.
    pub transition_capacity_reserved: bool,
    /// The generation serving now, if any: the old one, when it was preserved.
    pub serving: Option<ModelActivationGeneration>,
    /// When the old generation drained first: whether its content could serve again
    /// without reloading.
    pub predecessor_rollback: Option<RollbackOutlook>,
}

/// A governor operation that was refused or failed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "governor", rename_all = "snake_case")]
pub enum GovernorError {
    Ledger {
        fault: LedgerFault,
    },
    /// The coordinator refused a model activation step or a model-request lease.
    Activation {
        refusal: ModelRefusal,
    },
    /// The coordinator does not honour the lease now.
    Lease {
        refusal: LeaseRefusal,
    },
    /// The slot refused an activation step (§3.6).
    Placement {
        error: ActivationError,
    },
    /// The slot refused execute-while-load (line 601).
    Early {
        refusal: EarlyRefusal,
    },
    /// The slot's router refused to admit the request.
    Route {
        refusal: RouteRefusal,
    },
    /// The slot holds no such lease.
    Ticket {
        error: TicketError,
    },
    /// The slot refused to drain, park or reclaim a placement.
    Slot {
        error: SlotError,
    },
    /// The placement is paused for a reload; the request waits.
    PausedForReload {
        status: ReloadStatus,
    },
    /// The request's KV was not admitted.
    Kv {
        refusal: KvRefusal,
    },
    /// The generation was not checked for the request's shape (§3.6 step 4).
    Shape {
        refusal: ShapeRefusal,
    },
    /// The activation is not one the placement is reloading for.
    NoReload,
    /// A request assigned to the activation may still compute under its preparation
    /// lease: memory is never given up under a request that may still use it.
    PreparationInFlight {
        lease: LeaseId,
    },
    /// Memory is closed only as the runtime's own report or a stronger source saw it
    /// freed.
    ReleaseSourceTooWeak {
        source: SourceClass,
    },
    /// No runtime is attached for the runner.
    NoRuntime {
        owner: PlacementOwner,
    },
    /// The runtime's sandbox is not launched or holds no reservation.
    RuntimeUnavailable {
        execution: ExecutionId,
    },
    /// Activations and leases bind to the runner's parent execution (S3.1).
    OtherExecution {
        runtime: ExecutionId,
        requested: ExecutionId,
    },
    /// The request is another tenant's than the runtime's.
    OtherTenant,
    /// The presented authorization epoch is not the runtime's current one: it was
    /// revoked, and nothing bound to it is honoured again (S3.1).
    StaleAuthorization {
        presented: AuthorizationEpoch,
        current: AuthorizationEpoch,
    },
    /// A child reservation takes its parent's priority (CORE-03), so a request of another
    /// priority would be silently raised or lowered.
    PriorityMismatch {
        requested: Priority,
        runtime: Priority,
    },
    /// Leases for serving exist only on the generation the slot publishes.
    GenerationNotServing {
        requested: ModelActivationGeneration,
        serving: Option<ModelActivationGeneration>,
    },
    /// The residency to publish is not the pending activation's placement, device or
    /// current authority.
    ResidencyMismatch,
    /// The authority binding of a slot could not be formed.
    InvalidBinding {
        reason: String,
    },
    UnknownLease {
        lease: LeaseId,
    },
    Overflow {
        field: &'static str,
    },
}

impl fmt::Display for GovernorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ledger { fault } => fault.fmt(f),
            Self::Activation { refusal } => refusal.fmt(f),
            Self::Lease { refusal } => refusal.fmt(f),
            Self::Placement { error } => error.fmt(f),
            Self::Early { refusal } => refusal.fmt(f),
            Self::Route { refusal } => refusal.fmt(f),
            Self::Ticket { error } => error.fmt(f),
            Self::Slot { error } => error.fmt(f),
            Self::PausedForReload { status } => write!(
                f,
                "serving is paused while the model reloads; it should resume at {} ns on the \
                 monotonic clock",
                status.eta.as_nanos()
            ),
            Self::Kv { refusal } => refusal.fmt(f),
            Self::Shape { refusal } => refusal.fmt(f),
            Self::NoReload => f.write_str("the placement is not reloading for this activation"),
            Self::PreparationInFlight { lease } => write!(
                f,
                "the request assigned under lease {lease} may still compute on this activation"
            ),
            Self::ReleaseSourceTooWeak { source } => {
                write!(f, "a release observed by {source:?} does not close memory")
            }
            Self::NoRuntime { .. } => f.write_str("the runner has no attached runtime"),
            Self::RuntimeUnavailable { execution } => {
                write!(f, "the runtime of {execution} holds no reservation")
            }
            Self::OtherExecution { runtime, requested } => write!(
                f,
                "the runner belongs to {runtime}; the request runs under {requested}"
            ),
            Self::OtherTenant => f.write_str("the request is another tenant's"),
            Self::StaleAuthorization { presented, current } => write!(
                f,
                "authorization epoch {presented} is not current; the current epoch is {current}"
            ),
            Self::PriorityMismatch { requested, runtime } => write!(
                f,
                "the request asks for {requested:?} priority inside a {runtime:?} runtime"
            ),
            Self::GenerationNotServing { requested, .. } => {
                write!(f, "generation {requested} is not the serving generation")
            }
            Self::ResidencyMismatch => {
                f.write_str("the residency is not the pending activation's placement")
            }
            Self::InvalidBinding { reason } => write!(f, "invalid authority binding: {reason}"),
            Self::UnknownLease { lease } => write!(f, "unknown lease {lease}"),
            Self::Overflow { field } => write!(f, "{field} does not fit in 64 bits"),
        }
    }
}

impl From<LedgerError> for GovernorError {
    fn from(error: LedgerError) -> Self {
        Self::Ledger {
            fault: LedgerFault(error),
        }
    }
}

impl From<ActivationError> for GovernorError {
    fn from(error: ActivationError) -> Self {
        Self::Placement { error }
    }
}

impl From<KvRefusal> for GovernorError {
    fn from(refusal: KvRefusal) -> Self {
        Self::Kv { refusal }
    }
}

/// Why admission was refused. Nothing stays reserved after a refusal, except an
/// activation paused for its reload, which waits in its slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "admission", rename_all = "snake_case")]
pub enum AdmissionRefusal {
    /// The ledger refused the staging; this names the limiting resource and whether a
    /// retry helps.
    Capacity {
        refusal: CapacityRefusal,
    },
    Ledger {
        fault: LedgerFault,
    },
    /// The coordinator refused the activation, its GPU reservation included.
    Activation {
        refusal: ModelRefusal,
    },
    /// The slot refused the activation's first steps: a malformed activation, an
    /// unverified artifact, or a reservation the ledger or the coordinator refused.
    Placement {
        error: ActivationError,
    },
    /// The placement is paused for a reload: its old generation drains, and the request
    /// waits until the new one loads. A later admission continues the reload.
    PausedForReload {
        status: ReloadStatus,
    },
    /// The request's authority, tenant or priority does not match the runner's runtime.
    Runtime {
        error: GovernorError,
    },
    /// The demand names another device than the placement's.
    DeviceMismatch {
        placement: GpuDeviceKey,
        demand: GpuDeviceKey,
    },
    /// An activation's demand came without what it serves, or the other way round.
    IncompleteActivation,
    /// The governor's per-request transfer limit is lower than the missing bytes.
    TransferLimit {
        requested_bytes: u64,
        limit_bytes: u64,
    },
    /// Transfers need bounded staging, and the policy allows none.
    NoStaging,
    Overflow {
        field: &'static str,
    },
    /// The admission failed, and undoing its partial grants failed too.
    RollbackFailed {
        cause: Box<AdmissionRefusal>,
        faults: Vec<GovernorError>,
    },
}

impl fmt::Display for AdmissionRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capacity { refusal } => write!(f, "not enough capacity: {refusal}"),
            Self::Ledger { fault } => fault.fmt(f),
            Self::Activation { refusal } => refusal.fmt(f),
            Self::Placement { error } => error.fmt(f),
            Self::PausedForReload { status } => write!(
                f,
                "serving is paused while the model reloads; it should resume at {} ns on the \
                 monotonic clock",
                status.eta.as_nanos()
            ),
            Self::Runtime { error } => error.fmt(f),
            Self::DeviceMismatch { .. } => {
                f.write_str("the demand is for another device than the placement's")
            }
            Self::IncompleteActivation => {
                f.write_str("an activation needs both its demand and what it serves")
            }
            Self::TransferLimit {
                requested_bytes,
                limit_bytes,
            } => write!(
                f,
                "{requested_bytes} bytes to transfer exceed the limit of {limit_bytes}"
            ),
            Self::NoStaging => f.write_str("the policy allows no staging for transfers"),
            Self::Overflow { field } => write!(f, "{field} does not fit in 64 bits"),
            Self::RollbackFailed { cause, faults } => write!(
                f,
                "{cause}, and {} partial grants could not be undone",
                faults.len()
            ),
        }
    }
}

/// A refused publication or abandonment. The pending activation is handed back: it is
/// consumed only by a step that succeeded.
#[derive(Debug, PartialEq, Eq)]
pub struct PendingRefusal {
    pub pending: PendingActivation,
    pub error: GovernorError,
}

/// The placement governor boundary. Time comes from the coordination authority's clock.
pub trait PlacementGovernor {
    /// The runner's runtime: parent execution, authority and device budget.
    fn runtime(&self, owner: PlacementOwner) -> Result<RuntimeView, GovernorError>;

    /// Begins the activation in the placement's slot, whose coordinator's ledger reserves
    /// its memory, and reserves bounded staging for the transfers; either everything or
    /// nothing. When the activation cannot overlap the serving generation and consents to
    /// a pause, it waits in the slot while the old generation drains: the admission is
    /// refused with the pause's status until a later admission finds the drain complete,
    /// which receives the activation with the generation to hand over.
    fn admit(&mut self, request: &AdmissionRequest) -> Result<Admission, AdmissionRefusal>;

    /// Creation of the grant's workload has started (reserve before create).
    fn begin_create(&mut self, grant: &LedgerGrant) -> Result<(), GovernorError>;

    /// Returns a grant whose workload was never created, or whose release the
    /// device-owning runtime reported.
    fn release(&mut self, grant: LedgerGrant) -> Result<(), GovernorError>;

    /// Cancels a grant whose release nobody reported; its amounts keep counting until
    /// the host observes the release, so no capacity is freed early.
    fn abandon(&mut self, grant: LedgerGrant) -> Result<(), GovernorError>;

    /// The drained generation of a reload freed its KV and contexts, as `source` observed:
    /// it is reclaimed, its own memory passes to `pending`, and `pending` takes its memory
    /// for the extents it allocates (§3.6 steps 7 and 2).
    fn hand_over(
        &mut self,
        pending: &PendingActivation,
        source: SourceClass,
    ) -> Result<(), GovernorError>;

    /// Where each of `extents` lands in `pending`'s memory: weights in their own holding,
    /// other state in the activation's own memory.
    fn transfer_destinations(
        &self,
        pending: &PendingActivation,
        extents: &[ExtentRef],
    ) -> BTreeMap<ExtentRef, TransferDestination>;

    /// The state `identity` names is resident, verified and usable in the pending
    /// activation (§3.6 step 2). State that is not one of its immutable extents changes
    /// nothing.
    fn record_usable(
        &mut self,
        pending: &PendingActivation,
        identity: StateIdentity,
    ) -> Result<(), GovernorError>;

    /// Records the runner's validation and its readiness for the declared shape, then
    /// publishes the pending generation atomically with the residency it activates
    /// (§3.6 steps 3–5), ending any pause for it. A refusal hands the pending activation
    /// back.
    fn publish_activation(
        &mut self,
        pending: PendingActivation,
        residency: Residency,
    ) -> Result<ModelActivationGeneration, PendingRefusal>;

    /// Ends a pending activation without publishing it; its generation is never reused,
    /// and its GPU reservation counts until its release is confirmed. It is refused while
    /// a request assigned to it may still compute, and the pending activation comes back.
    /// The outcome says whether the old serving state was preserved.
    fn abandon_activation(
        &mut self,
        pending: PendingActivation,
    ) -> Result<AbandonedActivation, PendingRefusal>;

    /// Reclaims the placement that activated `generation`, once `source` observed its
    /// memory freed, and closes what nothing else holds (§3.6 step 7); `false` when
    /// nothing was left to close.
    fn confirm_released(
        &mut self,
        placement: &PlacementKey,
        generation: ModelActivationGeneration,
        source: SourceClass,
    ) -> Result<bool, GovernorError>;

    /// The authoritative residency record of a placement, the one advertisements are
    /// rechecked against (line 506): the serving generation's, or while serving is paused
    /// for a reload the draining generation's, whose state is resident until reclaimed.
    fn current_residency(&self, placement: &PlacementKey) -> Option<CurrentResidency>;

    /// A placement's pause for a reload, while it lasts.
    fn reload_status(&self, placement: &PlacementKey) -> Option<ReloadStatus>;

    /// A lease to serve one request of `shape` on `generation`, which must be the
    /// published one and checked for the shape (§3.6 step 4), with the request's KV
    /// admitted against the generation's pool.
    fn lease_execution(
        &mut self,
        authority: &RequestAuthority,
        placement: &PlacementKey,
        generation: ModelActivationGeneration,
        shape: RequestShape,
    ) -> Result<ExecutionLease, GovernorError>;

    /// The request's shape changes: its KV grows or shrinks to the new shape's, within
    /// what the generation was checked for and its pool can hold. A refusal leaves the
    /// lease as it was, so the request never writes past what is reserved.
    fn resize_execution_lease(
        &mut self,
        lease: &mut ExecutionLease,
        shape: RequestShape,
    ) -> Result<(), GovernorError>;

    /// `Ok` while the coordinator honours the lease and its request may publish a result:
    /// the enforcement point before serving (VM §6.3, GPU §3.6 line 601).
    fn check_execution_lease(&self, lease: &ExecutionLease) -> Result<(), GovernorError>;

    /// A lease to compute ahead on a pending generation for the one request in
    /// `authority`; no other request is assigned while it lives (line 601).
    fn lease_preparation(
        &mut self,
        authority: &RequestAuthority,
        pending: &PendingActivation,
    ) -> Result<PreparationLease, GovernorError>;

    /// The assigned request starts computing on the state `inputs` names; refused while
    /// an immutable extent among them is not usable.
    fn start_compute_ahead(
        &mut self,
        lease: &PreparationLease,
        inputs: &[StateIdentity],
    ) -> Result<(), GovernorError>;

    /// The assigned request finished computing on the state `inputs` names.
    fn finish_compute_ahead(
        &mut self,
        lease: &PreparationLease,
        inputs: &[StateIdentity],
    ) -> Result<(), GovernorError>;

    /// `Ok` while the coordinator honours the preparation lease.
    fn check_preparation_lease(&self, lease: &PreparationLease) -> Result<(), GovernorError>;

    fn release_execution_lease(&mut self, lease: ExecutionLease) -> Result<(), GovernorError>;

    fn release_preparation_lease(&mut self, lease: PreparationLease) -> Result<(), GovernorError>;

    /// Leases on a placement whose holders may still be acting.
    fn active_leases(&self, placement: &PlacementKey) -> usize;
}

/// The governor's own policy. Every field narrows or bounds; none adds capacity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GovernorPolicy {
    /// How long an execution lease lasts; it is never renewed past it.
    pub lease_duration: Duration,
    /// The bound within which a request stops after a cancellation or a revocation
    /// (CORE-04 lease terms; INT-02).
    pub cancel_within: Duration,
    /// Pinned staging per preparation is the smaller of this and the bytes to transfer
    /// (§3.5 step 2: bounded transient memory).
    pub staging_cap_bytes: u64,
    /// Refuses a preparation that would transfer more than this.
    pub max_transfer_bytes: Option<u64>,
    /// Room the §2.7 inequality keeps for GPU consumers outside managed allocations
    /// (line 491); T08 refuses zero.
    pub safety_reserve_bytes: u64,
    /// The longest any drain before a reload may last: old-generation requests keep their
    /// leases at most this long once serving pauses.
    pub max_drain: Duration,
}

/// How the governor reaches the CORE-03 ledger behind its coordinator's capacity port:
/// owned by the port, or the host's one ledger shared with the executor's reservations.
pub trait HostLedger<C: Clock>: CapacityPort {
    /// Runs `read` on the ledger.
    fn read_ledger<R>(&self, read: impl FnOnce(&Ledger<C>) -> R) -> R;

    /// Runs `write` on the ledger.
    fn write_ledger<R>(&mut self, write: impl FnOnce(&mut Ledger<C>) -> R) -> R;

    /// The open ledger reservation the coordinator's `key` names, as it stands now.
    fn reservation_record(&self, key: &ReservationKey) -> Option<ReservationRecord>;
}

impl<C: Clock> HostLedger<C> for LedgerCapacity<C> {
    fn read_ledger<R>(&self, read: impl FnOnce(&Ledger<C>) -> R) -> R {
        read(self.ledger())
    }

    fn write_ledger<R>(&mut self, write: impl FnOnce(&mut Ledger<C>) -> R) -> R {
        write(self.ledger_mut())
    }

    fn reservation_record(&self, key: &ReservationKey) -> Option<ReservationRecord> {
        self.record(key).cloned()
    }
}

impl<C: Clock> HostLedger<C> for LedgerCapacity<C, SharedLedger<C>> {
    fn read_ledger<R>(&self, read: impl FnOnce(&Ledger<C>) -> R) -> R {
        read(&self.ledger())
    }

    fn write_ledger<R>(&mut self, write: impl FnOnce(&mut Ledger<C>) -> R) -> R {
        write(&mut self.ledger())
    }

    fn reservation_record(&self, key: &ReservationKey) -> Option<ReservationRecord> {
        self.record(key)
    }
}

/// A pause for a reload in one slot.
#[derive(Debug)]
struct Reload {
    /// The activation, while it waits in the slot for the drain.
    pending: Option<PendingActivation>,
    predecessor: SlotPlacement,
    draining: ModelActivationGeneration,
    reloading: ModelActivationGeneration,
    reason: PauseReason,
    since: MonotonicTime,
    deadline: MonotonicTime,
    estimate: Duration,
    phase: ReloadPhase,
    /// When the last old lease ended, by its request finishing or at the deadline.
    drained_at: Option<MonotonicTime>,
    ended_leases: u32,
    /// The admission that began the reload, which resuming it continues (G03).
    request: AdmissionRequest,
    /// Once drained, the reload waits for its staging until then at the latest: the drain
    /// deadline plus the drain's bound again.
    resume_by: MonotonicTime,
}

/// What one generation of a slot holds besides its placement.
#[derive(Debug)]
struct Generation {
    placement: SlotPlacement,
    /// The operation of the activation that made it (S06).
    operation: OperationId,
    /// The placement that served when its activation began, which it replaces.
    predecessor: Option<SlotPlacement>,
    /// The extents it reads, by the state identity of the node holding them.
    extents: BTreeMap<StateIdentity, (ExtentKey, WeightPosition)>,
    /// The extents it found resident, marked usable once it holds them.
    ready: Vec<ExtentKey>,
    /// The catalog extents transferred into each extent.
    transfers: BTreeMap<ExtentRef, ExtentKey>,
    /// The shape its readiness checks cover.
    declared: SupportedShape,
    /// The residency it was published with.
    residency: Option<Residency>,
    kv: KvPool,
}

impl Generation {
    /// Whether `spec` asks for exactly this generation's activation: the same declared
    /// shape and the same immutable extents.
    fn serves(&self, spec: &ActivationSpec) -> bool {
        let extents: BTreeSet<StateIdentity> = spec
            .extents
            .iter()
            .filter(|extent| extent.device_bytes > 0)
            .map(|extent| extent.identity)
            .collect();
        self.declared == spec.declared && self.extents.keys().copied().eq(extents)
    }
}

/// One placement's P04 slot under one authorization epoch, with what the governor keeps
/// about the activations it ran there.
struct Slot<C: Clock> {
    slot: PlacementSlot<C>,
    ports: CoordinatorPlacement,
    generations: BTreeMap<ModelActivationGeneration, Generation>,
    /// The preparation lease of the activation in progress, until it is released.
    preparation: Option<LeaseId>,
    reload: Option<Reload>,
}

impl<C: Clock> Slot<C> {
    /// The slot and both ports over `coordinator`, for one slot operation.
    fn ports<'a, P: CapacityPort>(
        &'a mut self,
        coordinator: &'a mut Coordinator<C, P>,
    ) -> (&'a mut PlacementSlot<C>, CoordinatorPorts<'a, C, P>) {
        (&mut self.slot, self.ports.port(coordinator))
    }

    /// The positions of the state `inputs` names among the extents `generation` reads.
    fn positions(
        &self,
        generation: ModelActivationGeneration,
        inputs: &[StateIdentity],
    ) -> Vec<WeightPosition> {
        let Some(entry) = self.generations.get(&generation) else {
            return Vec::new();
        };
        let positions: BTreeSet<WeightPosition> = inputs
            .iter()
            .filter_map(|identity| entry.extents.get(identity))
            .map(|(_, position)| *position)
            .collect();
        positions.into_iter().collect()
    }

    /// The operation the parking, reclamation and retirement of `key` are recorded under
    /// (S06): that of the latest activation that began while it served, which replaced
    /// it, or else `own`, its own activation's.
    fn release_operation(&self, key: SlotPlacement, own: &OperationId) -> OperationId {
        self.generations
            .values()
            .rev()
            .find(|entry| entry.predecessor == Some(key))
            .map_or_else(|| own.clone(), |entry| entry.operation.clone())
    }

    /// The pause of this slot, as its status shows it at `now`: while old requests run,
    /// serving resumes at the latest the reload's planned time after the drain deadline;
    /// once they ended, that time after the drain, or now if the reload overran it.
    fn reload_status(&self, placement: PlacementKey, now: MonotonicTime) -> Option<ReloadStatus> {
        let reload = self.reload.as_ref()?;
        let eta = match (reload.phase, reload.drained_at) {
            (ReloadPhase::Draining { .. }, _) | (_, None) => {
                reload.deadline.max(now).saturating_add(reload.estimate)
            }
            (ReloadPhase::HandingOver | ReloadPhase::Loading, Some(drained)) => {
                drained.saturating_add(reload.estimate).max(now)
            }
        };
        Some(ReloadStatus {
            placement,
            draining: reload.draining,
            reloading: reload.reloading,
            reason: reload.reason,
            since: reload.since,
            drain_deadline: reload.deadline,
            ended_leases: reload.ended_leases,
            phase: reload.phase,
            eta,
        })
    }
}

/// The placement governor over P04's activation slots and the CORE-04 coordinator (T09),
/// and through it the CORE-03 ledger (T04): one capacity authority, which it never
/// shadows. `P` is the coordinator's capacity port over that ledger.
pub struct LedgerPolicyGovernor<C: Clock, P: CapacityPort = LedgerCapacity<C>> {
    coordinator: Coordinator<C, P>,
    clock: C,
    policy: GovernorPolicy,
    runtimes: BTreeMap<PlacementOwner, RuntimeBinding>,
    slots: BTreeMap<(PlacementKey, AuthorizationEpoch), Slot<C>>,
    /// Placements whose owner consented to pausing for a reload, with their drain bound.
    reload_consent: BTreeMap<PlacementKey, Duration>,
    /// The latest activation of each placement that ended without publishing.
    abandoned: BTreeMap<PlacementKey, AbandonedActivation>,
    /// The model lifecycle stream decisions are recorded on, if one is configured (S06).
    lifecycle: lifecycle::Lifecycle,
    /// Reloads a retried admission ended without resuming, until
    /// [`LedgerPolicyGovernor::resume_reloads`] reports them.
    ended_reloads: resume::EndedReloads,
}

const fn ledger_priority(priority: ReservationPriority) -> Priority {
    match priority {
        ReservationPriority::Background => Priority::Background,
        ReservationPriority::Foreground => Priority::Foreground,
    }
}

/// The one rank a runner's activation runs on.
const RANK: Rank = Rank::new(0);

/// The rank coordination a single-rank activation joins: its own, named by its model and
/// generation.
fn single_rank(model: ModelId, generation: ModelActivationGeneration) -> Digest {
    DigestBuilder::new("yougori/model-memory/boundaries/rank-coordination/v1")
        .digest(&model.digest())
        .u64(generation.get())
        .finish()
}

fn count(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

impl<C: Clock + Clone, P: HostLedger<C>> LedgerPolicyGovernor<C, P> {
    /// The governor over `coordinator`, whose clock `clock` reads too: the slots it opens
    /// keep time with it.
    pub fn new(coordinator: Coordinator<C, P>, clock: C, policy: GovernorPolicy) -> Self {
        Self {
            coordinator,
            clock,
            policy,
            runtimes: BTreeMap::new(),
            slots: BTreeMap::new(),
            reload_consent: BTreeMap::new(),
            abandoned: BTreeMap::new(),
            lifecycle: lifecycle::Lifecycle::default(),
            ended_reloads: resume::EndedReloads::default(),
        }
    }

    /// Records the VM sandbox a runner's placements run in. The coordinator launched it;
    /// the governor never reserves a runtime itself.
    pub fn attach_runtime(&mut self, owner: PlacementOwner, runtime: RuntimeBinding) {
        self.runtimes.insert(owner, runtime);
    }

    /// The placement's owner consents to pausing it for a reload when versions cannot
    /// overlap, draining old requests for at most `drain_within` (bounded by the policy).
    pub fn allow_reload(&mut self, placement: PlacementKey, drain_within: Duration) {
        self.reload_consent.insert(placement, drain_within);
    }

    pub fn coordinator(&self) -> &Coordinator<C, P> {
        &self.coordinator
    }

    /// The coordinator, for the lifecycle calls that are not the governor's, such as
    /// revocation.
    pub fn coordinator_mut(&mut self) -> &mut Coordinator<C, P> {
        &mut self.coordinator
    }

    /// Runs `read` on the one capacity authority.
    pub fn read_ledger<R>(&self, read: impl FnOnce(&Ledger<C>) -> R) -> R {
        self.coordinator.capacity().read_ledger(read)
    }

    pub fn policy(&self) -> &GovernorPolicy {
        &self.policy
    }

    /// The P04 slot `placement` has under `epoch`, if an activation opened it.
    pub fn slot(
        &self,
        placement: &PlacementKey,
        epoch: AuthorizationEpoch,
    ) -> Option<&PlacementSlot<C>> {
        self.slots.get(&(*placement, epoch)).map(|slot| &slot.slot)
    }

    /// The coordinator ports state of `placement`'s slot under `epoch`: the weights it
    /// holds and what the coordinator granted.
    pub fn slot_ports(
        &self,
        placement: &PlacementKey,
        epoch: AuthorizationEpoch,
    ) -> Option<&CoordinatorPlacement> {
        self.slots.get(&(*placement, epoch)).map(|slot| &slot.ports)
    }

    /// The latest activation of `placement` that ended without publishing.
    pub fn last_abandoned(&self, placement: &PlacementKey) -> Option<&AbandonedActivation> {
        self.abandoned.get(placement)
    }

    /// The KV of `generation` of `placement` committed now and admitted to leases.
    pub fn kv_usage(
        &self,
        placement: &PlacementKey,
        epoch: AuthorizationEpoch,
        generation: ModelActivationGeneration,
    ) -> Option<(u64, u64)> {
        let entry = self
            .slots
            .get(&(*placement, epoch))?
            .generations
            .get(&generation)?;
        Some((entry.kv.committed_bytes(), entry.kv.leased_bytes()))
    }

    fn binding(&self, owner: PlacementOwner) -> Result<&RuntimeBinding, GovernorError> {
        self.runtimes
            .get(&owner)
            .ok_or(GovernorError::NoRuntime { owner })
    }

    fn sandbox(&self, binding: &RuntimeBinding) -> Result<&SandboxLifecycle, GovernorError> {
        self.coordinator.sandbox(&binding.execution).ok_or_else(|| {
            GovernorError::RuntimeUnavailable {
                execution: binding.execution.clone(),
            }
        })
    }

    /// The ledger record of the runtime's sandbox reservation.
    fn sandbox_reservation(
        &self,
        binding: &RuntimeBinding,
    ) -> Result<ReservationRecord, GovernorError> {
        self.sandbox(binding)?
            .reservation()
            .and_then(|key| self.coordinator.capacity().reservation_record(&key))
            .ok_or_else(|| GovernorError::RuntimeUnavailable {
                execution: binding.execution.clone(),
            })
    }

    /// The runtime's current authorization epoch.
    fn current_epoch(&self, owner: PlacementOwner) -> Option<AuthorizationEpoch> {
        let binding = self.runtimes.get(&owner)?;
        self.coordinator
            .sandbox(&binding.execution)
            .map(|sandbox| sandbox.generations().authorization)
    }

    /// The request runs under the runner's parent execution, as its tenant, with the
    /// current authorization epoch (S3.1).
    fn check_authority(
        &self,
        authority: &RequestAuthority,
        owner: PlacementOwner,
    ) -> Result<RuntimeBinding, GovernorError> {
        let binding = self.binding(owner)?;
        if authority.execution != binding.execution {
            return Err(GovernorError::OtherExecution {
                runtime: binding.execution.clone(),
                requested: authority.execution.clone(),
            });
        }
        let sandbox = self.sandbox(binding)?;
        if *sandbox.tenant() != authority.tenant {
            return Err(GovernorError::OtherTenant);
        }
        let current = sandbox.generations().authorization;
        if authority.epoch != current {
            return Err(GovernorError::StaleAuthorization {
                presented: authority.epoch,
                current,
            });
        }
        Ok(binding.clone())
    }

    /// The state of a model activation of a placement, as the coordinator sees it.
    fn activation_state(
        &self,
        placement: &PlacementKey,
        generation: ModelActivationGeneration,
    ) -> Option<crate::foundation::coordination::ActivationState> {
        let binding = self.runtimes.get(&placement.owner)?;
        self.coordinator
            .model_activations(&binding.execution, placement.model_id())?
            .activation(generation)
            .map(|activation| activation.state())
    }

    /// What the ledger granted on `device` for the memory one activation holds: the VRAM
    /// of every open ledger reservation behind its holdings on that device, the weights it
    /// reads and its own memory, and behind the holdings a drained predecessor promised
    /// it, which no other request can take (GPU §3.6: a drain-first handover).
    fn granted_for(
        &self,
        execution: &ExecutionId,
        model: ModelId,
        generation: ModelActivationGeneration,
        device: GpuDeviceKey,
    ) -> u64 {
        let Some(activations) = self.coordinator.model_activations(execution, model) else {
            return 0;
        };
        let Some(activation) = activations.activation(generation) else {
            return 0;
        };
        let promised = activations.holdings().iter().filter(|holding| {
            holding
                .promised_to()
                .is_some_and(|(successor, _)| successor == generation)
        });
        let keys: BTreeSet<ReservationKey> = activation
            .holdings()
            .iter()
            .filter_map(|id| activations.holding(*id))
            .chain(promised)
            .filter(|holding| {
                matches!(holding.memory(), HoldingMemory::Gpu { device: on, .. } if on == device)
            })
            .flat_map(|holding| holding.reservations().iter().copied())
            .collect();
        keys.iter()
            .filter_map(|key| self.coordinator.capacity().reservation_record(key))
            .fold(0u64, |total, record| {
                total.saturating_add(record.granted().get(vram_key(device)))
            })
    }

    /// Where memory of `holding` lands: its allocation and the ledger reservation behind
    /// it on `device`.
    fn destination_of_holding(
        &self,
        execution: &ExecutionId,
        model: ModelId,
        holding: HoldingId,
        device: GpuDeviceKey,
    ) -> Option<TransferDestination> {
        let HoldingId::Gpu { allocation } = holding else {
            return None;
        };
        let entry = self
            .coordinator
            .model_activations(execution, model)?
            .holding(holding)?;
        entry
            .reservations()
            .iter()
            .filter_map(|key| self.coordinator.capacity().reservation_record(key))
            .map(|record| TransferDestination {
                allocation,
                reservation: record.id(),
                capacity_bytes: record.granted().get(vram_key(device)),
            })
            .find(|destination| destination.capacity_bytes > 0)
    }

    /// Where `pending`'s own memory lands on its device: its own allocation and the ledger
    /// reservation behind it, once that memory is reserved, as after a reload's handover.
    fn own_destination(&self, pending: &PendingActivation) -> Option<TransferDestination> {
        let placement = pending.placement;
        let binding = self.runtimes.get(&placement.owner)?;
        let allocation = pending
            .allocation
            .or_else(|| self.own_allocation((placement, pending.epoch), pending.generation()))?;
        self.destination_of_holding(
            &binding.execution,
            placement.model_id(),
            HoldingId::Gpu { allocation },
            placement.owner.device,
        )
    }

    /// Where each of `extents` that is part of `pending`'s weights lands: the holding of
    /// the weights it is transferred into.
    fn weights_destinations(
        &self,
        pending: &PendingActivation,
        extents: &[ExtentRef],
    ) -> BTreeMap<ExtentRef, TransferDestination> {
        let placement = pending.placement;
        let (Some(binding), Some(slot)) = (
            self.runtimes.get(&placement.owner),
            self.slots.get(&(placement, pending.epoch)),
        ) else {
            return BTreeMap::new();
        };
        let Some(entry) = slot.generations.get(&pending.generation()) else {
            return BTreeMap::new();
        };
        extents
            .iter()
            .filter_map(|extent| {
                let holding = entry
                    .transfers
                    .get(extent)
                    .and_then(|key| slot.ports.weights_holding(key))?;
                self.destination_of_holding(
                    &binding.execution,
                    placement.model_id(),
                    holding,
                    placement.owner.device,
                )
                .map(|destination| (*extent, destination))
            })
            .collect()
    }

    /// `budget` landing where `pending` holds memory for it: weights in their own holding,
    /// everything else in the activation's own memory.
    fn land(&self, pending: &PendingActivation, budget: TransferBudget) -> TransferBudget {
        let extents: Vec<ExtentRef> = budget.objects().copied().collect();
        let mut budget = match self.own_destination(pending) {
            Some(own) => budget.with_destination(own),
            None => budget,
        };
        for (extent, destination) in self.weights_destinations(pending, &extents) {
            budget = budget.with_extent_destination(extent, destination);
        }
        budget
    }

    /// The settings a placement's activations run with: the runtime's, verifying exactly
    /// the catalog objects the artifact was read from when a catalog holds it.
    fn settings_for(
        binding: &RuntimeBinding,
        verified: &VerifiedRepresentation,
    ) -> RuntimeSettings {
        let mut settings = binding.settings.clone();
        let artifacts = verified.verified_artifacts();
        if !artifacts.is_empty() {
            settings.artifact_verification = ArtifactVerification::Verified { artifacts };
        }
        settings
    }

    /// Opens the placement's slot for `epoch` unless it is open.
    fn open_slot(
        &mut self,
        placement: PlacementKey,
        epoch: AuthorizationEpoch,
        binding: &RuntimeBinding,
        tenant: TenantId,
        settings: RuntimeSettings,
    ) -> Result<(), GovernorError> {
        if self.slots.contains_key(&(placement, epoch)) {
            return Ok(());
        }
        let authority = AuthorityBinding::new(
            binding.execution.clone(),
            binding.settings.execution_category,
            Some(epoch),
        )
        .map_err(|error| GovernorError::InvalidBinding {
            reason: error.to_string(),
        })?;
        let slot = PlacementSlot::new(
            SlotSpec {
                slot: placement.slot_id(epoch),
                tenant,
                authority,
            },
            self.clock.clone(),
        );
        let ports = CoordinatorPlacement::new(CoordinatorBinding {
            execution: binding.execution.clone(),
            model: placement.model_id(),
            settings,
            cancel_within: self.policy.cancel_within,
            release_source: SourceClass::GuestReport,
        });
        self.slots.insert(
            (placement, epoch),
            Slot {
                slot,
                ports,
                generations: BTreeMap::new(),
                preparation: None,
                reload: None,
            },
        );
        Ok(())
    }

    /// The drain a reload of `placement` may take: the request's or the placement's
    /// consent, bounded by the policy; `None` when neither consents.
    fn reload_bound(&self, placement: &PlacementKey, spec: &ActivationSpec) -> Option<Duration> {
        let requested = match spec.reload {
            ReloadConsent::Pause { drain_within } => Some(drain_within),
            ReloadConsent::Never => self.reload_consent.get(placement).copied(),
        };
        requested.map(|drain| drain.min(self.policy.max_drain))
    }

    /// §3.6 steps 1 and 2 in the placement's slot: reserves the T08 demand as the steady
    /// state, then acquires or allocates every extent and marks the ready ones usable.
    /// When the activation drains the serving generation first, extents it does not share
    /// wait for the handover.
    fn begin_activation(
        &mut self,
        request: &AdmissionRequest,
        binding: &RuntimeBinding,
        tenant: TenantId,
        demand: &ActivationDemand,
        spec: &ActivationSpec,
        may_pause: bool,
    ) -> Result<(PendingActivation, Option<(SlotPlacement, PauseRecord)>), AdmissionRefusal> {
        let placement = request.placement;
        let device = placement.owner.device;
        let epoch = request.authority.epoch;
        let artifact = spec.verified.artifact();
        let mut extents = BTreeMap::new();
        let mut components = Vec::new();
        let mut transfers = BTreeMap::new();
        for extent in spec.extents.iter().filter(|extent| extent.device_bytes > 0) {
            let key = ExtentKey {
                content: ContentKey::from_digest(extent.identity.digest()),
                device,
            };
            let position = WeightPosition::new(RANK, Component::Layer(extent.node.get()));
            components.push(ExtentSpec {
                position,
                extent: key,
                bytes: extent.device_bytes,
            });
            extents.insert(extent.identity, (key, position));
            for transfer in &extent.transfers {
                transfers.insert(*transfer, key);
            }
        }
        let ready: Vec<ExtentKey> = spec
            .extents
            .iter()
            .filter(|extent| extent.ready)
            .filter_map(|extent| extents.get(&extent.identity).map(|(key, _)| *key))
            .collect();
        let activation = SlotActivation {
            operation: request.authority.operation.clone(),
            identity: ActivationIdentity {
                execution: placement.model,
                artifact,
                adapters: BTreeMap::new(),
            },
            placement: PlacementChoice::New {
                process: ProcessInstance::new(u64::from(placement.owner.instance)),
            },
            artifact: ArtifactValidity::Verified { artifact },
            layout: BTreeMap::from([(RANK, device)]),
            components,
            steady: ResourceDemand {
                vram_bytes: BTreeMap::from([(device, demand.device_bytes)]),
                host_ram_bytes: 0,
                pinned_host_bytes: 0,
            },
            transition_peak: ResourceDemand::default(),
            declared_shape: spec.declared,
            preference: if may_pause {
                TransitionPreference::OverlapOrPause
            } else {
                TransitionPreference::OverlapOnly
            },
        };
        let runtime = |error| AdmissionRefusal::Runtime { error };
        let settings = Self::settings_for(binding, &spec.verified);
        self.open_slot(placement, epoch, binding, tenant, settings)
            .map_err(runtime)?;
        let Self {
            coordinator,
            slots,
            lifecycle,
            ..
        } = self;
        let site = (placement, epoch);
        let slot = slots
            .get_mut(&site)
            .ok_or(AdmissionRefusal::IncompleteActivation)?;
        let (placements, mut port) = slot.ports(coordinator);
        let started = lifecycle
            .begin(site, placements, &activation, &mut port)
            .map_err(|error| AdmissionRefusal::Placement { error })?;
        let marked = lifecycle.step(site, placements, |placements| {
            let progress = placements.prepare_extents(&mut port)?;
            if !progress.waiting_for_other_holders.is_empty() {
                return Err(ActivationError::ExtentsNotUsable {
                    waiting: progress.waiting_for_other_holders,
                });
            }
            ready
                .iter()
                .try_for_each(|key| match placements.record_extent_usable(*key) {
                    Ok(()) | Err(ActivationError::UnknownExtent { .. }) => Ok(()),
                    Err(error) => Err(error),
                })
        });
        if let Err(error) = marked {
            let _cancelled = lifecycle.end(site, placements, |placements| {
                placements.cancel_activation(&mut port)
            });
            slot.generations.insert(
                started.generation,
                Generation {
                    placement: started.placement,
                    operation: activation.operation.clone(),
                    predecessor: started.predecessor,
                    extents: BTreeMap::new(),
                    ready: Vec::new(),
                    transfers: BTreeMap::new(),
                    declared: spec.declared,
                    residency: None,
                    kv: KvPool::new(spec.kv),
                },
            );
            let refusal = AdmissionRefusal::Placement { error };
            let closed =
                self.confirm_released(&placement, started.generation, SourceClass::GuestReport);
            return Err(match closed {
                Ok(_) => refusal,
                Err(fault) => AdmissionRefusal::RollbackFailed {
                    cause: Box::new(refusal),
                    faults: vec![fault],
                },
            });
        }
        slot.generations.insert(
            started.generation,
            Generation {
                placement: started.placement,
                operation: activation.operation.clone(),
                predecessor: started.predecessor,
                extents,
                ready,
                transfers,
                declared: spec.declared,
                residency: None,
                kv: KvPool::new(spec.kv),
            },
        );
        let handle = slot.ports.current().cloned();
        let generations = handle
            .as_ref()
            .map(|handle| handle.generations)
            .filter(|generations| generations.activation == started.generation)
            .ok_or(AdmissionRefusal::IncompleteActivation)?;
        let allocation = handle.and_then(|handle| handle.allocated.get(&device).copied());
        let memory_bytes = self.granted_for(
            &binding.execution,
            placement.model_id(),
            started.generation,
            device,
        );
        let pause = match (started.predecessor, started.pause) {
            (Some(predecessor), Some(pause)) if started.mode == TransitionMode::DrainFirst => {
                Some((predecessor, pause))
            }
            _ => None,
        };
        Ok((
            PendingActivation {
                placement,
                epoch,
                generations,
                reserved: GpuDemand {
                    device,
                    memory_bytes,
                },
                slot_placement: started.placement,
                allocation,
                mode: started.mode,
            },
            pause,
        ))
    }

    /// Parks `pending`, which `request` began, in its slot while its predecessor drains,
    /// for at most `drain`, with the reload's planned time from `request`. A predecessor
    /// the governor never activated hands `pending` back.
    fn start_reload(
        &mut self,
        request: &AdmissionRequest,
        pending: PendingActivation,
        predecessor: SlotPlacement,
        reason: PauseReason,
        since: MonotonicTime,
        drain: Duration,
    ) -> Result<(), PendingActivation> {
        let estimate = request
            .spec
            .as_ref()
            .map_or(Duration::ZERO, |spec| spec.reload_estimate);
        let key = (pending.placement, pending.epoch);
        let Some(slot) = self.slots.get_mut(&key) else {
            return Err(pending);
        };
        let Some(draining) = slot
            .generations
            .iter()
            .filter(|(_, entry)| entry.placement == predecessor)
            .map(|(generation, _)| *generation)
            .max()
        else {
            return Err(pending);
        };
        let deadline = since.saturating_add(drain);
        slot.reload = Some(Reload {
            reloading: pending.generation(),
            pending: Some(pending),
            predecessor,
            draining,
            reason,
            since,
            deadline,
            estimate,
            phase: ReloadPhase::Draining {
                remaining_leases: 0,
            },
            drained_at: None,
            ended_leases: 0,
            request: request.clone(),
            resume_by: deadline.saturating_add(drain),
        });
        Ok(())
    }

    /// Drives a pause for a reload: old-generation leases drain until their requests
    /// finish or the deadline ends them, and once none remains the old generation's memory
    /// may be handed over. Returns the pause's status.
    fn advance_reload(
        &mut self,
        placement: PlacementKey,
        epoch: AuthorizationEpoch,
    ) -> Result<ReloadStatus, AdmissionRefusal> {
        let now = self.clock.now();
        let Self {
            coordinator, slots, ..
        } = self;
        let slot = slots
            .get_mut(&(placement, epoch))
            .ok_or(AdmissionRefusal::IncompleteActivation)?;
        let (predecessor, deadline, phase) = slot
            .reload
            .as_ref()
            .map(|reload| (reload.predecessor, reload.deadline, reload.phase))
            .ok_or(AdmissionRefusal::IncompleteActivation)?;
        if let ReloadPhase::Draining { .. } = phase {
            let slot_error = |error| AdmissionRefusal::Runtime {
                error: GovernorError::Slot { error },
            };
            let (placements, mut port) = slot.ports(coordinator);
            let mut drain = placements
                .drain_status(predecessor, &port)
                .map_err(slot_error)?;
            let mut ended = 0;
            if !drain.is_drained() && now >= deadline {
                ended = placements
                    .end_leases(predecessor, &mut port)
                    .map_err(slot_error)?
                    .len();
                drain = placements
                    .drain_status(predecessor, &port)
                    .map_err(slot_error)?;
            }
            if let Some(reload) = slot.reload.as_mut() {
                reload.ended_leases = reload.ended_leases.saturating_add(count(ended));
                if drain.is_drained() {
                    reload.phase = ReloadPhase::HandingOver;
                    reload.drained_at = Some(now);
                } else {
                    reload.phase = ReloadPhase::Draining {
                        remaining_leases: count(drain.remaining_leases),
                    };
                }
            }
        }
        slot.reload_status(placement, now)
            .ok_or(AdmissionRefusal::IncompleteActivation)
    }

    /// The reload's waiting activation, once its predecessor drained, with the generation
    /// whose memory it takes; `None` while old requests run or once another admission
    /// took it.
    fn take_reload(
        &mut self,
        placement: PlacementKey,
        epoch: AuthorizationEpoch,
    ) -> Option<(PendingActivation, ModelActivationGeneration)> {
        let reload = self.slots.get_mut(&(placement, epoch))?.reload.as_mut()?;
        if reload.phase != ReloadPhase::HandingOver {
            return None;
        }
        let pending = reload.pending.take()?;
        Some((pending, reload.draining))
    }

    fn reserve_staging(
        &mut self,
        request: &AdmissionRequest,
        execution: &ExecutionId,
        parent: ReservationId,
        priority: Priority,
        bytes: u64,
    ) -> Result<LedgerGrant, AdmissionRefusal> {
        let provenance = Provenance {
            requester: Requester::ModelPlacement,
            execution: execution.clone(),
            operation: request.authority.operation.clone(),
            tenant: request.authority.tenant.clone(),
            purpose: CostPurpose::Transfer,
            retry_number: 0,
        };
        // Pinned pages are host RAM: the staging is charged to both (§2.7, T08, P02).
        let demand = Amounts::new().with(STAGING, bytes).with(HOST_RAM, bytes);
        let request = ReservationRequest::new(provenance, priority, demand.clone()).within(parent);
        self.coordinator
            .capacity_mut()
            .write_ledger(|ledger| match ledger.reserve(request) {
                Ok(LedgerAdmission::Granted(reservation)) => Ok(LedgerGrant {
                    reservation,
                    amounts: demand,
                }),
                Ok(LedgerAdmission::Queued {
                    ticket,
                    waiting_for,
                    ..
                }) => {
                    let refusal = AdmissionRefusal::Capacity {
                        refusal: CapacityRefusal::from_ledger(&waiting_for),
                    };
                    match ledger.cancel_queued(ticket) {
                        Ok(_) => Err(refusal),
                        Err(error) => Err(AdmissionRefusal::RollbackFailed {
                            cause: Box::new(refusal),
                            faults: vec![error.into()],
                        }),
                    }
                }
                Err(LedgerError::Capacity(error)) => Err(AdmissionRefusal::Capacity {
                    refusal: CapacityRefusal::from_ledger(&error),
                }),
                Err(error) => Err(AdmissionRefusal::Ledger {
                    fault: LedgerFault(error),
                }),
            })
    }

    /// Undoes a partial admission. Nothing was handed to the runtime yet, so it created
    /// nothing for the activation, and its own report closes the GPU reservation.
    fn roll_back(&mut self, admission: Admission, cause: AdmissionRefusal) -> AdmissionRefusal {
        let mut faults = Vec::new();
        if let Some(grant) = admission.staging {
            if let Err(error) = self.abandon(grant) {
                faults.push(error);
            }
        }
        if let Some(pending) = admission.activation {
            let (placement, generation) = (pending.placement, pending.generation());
            let closed = self
                .abandon_activation(pending)
                .map_err(|refused| refused.error)
                .and_then(|_| {
                    self.confirm_released(&placement, generation, SourceClass::GuestReport)
                });
            if let Err(error) = closed {
                faults.push(error);
            }
        }
        if faults.is_empty() {
            cause
        } else {
            AdmissionRefusal::RollbackFailed {
                cause: Box::new(cause),
                faults,
            }
        }
    }

    /// Carves one KV increment of `bytes` from `parent`, a reservation of the generation's
    /// own memory, in use at once: the backend maps it now.
    fn carve_kv(
        &mut self,
        placement: &PlacementKey,
        operation: &OperationId,
        parent: ReservationId,
        bytes: u64,
    ) -> Result<ReservationId, KvRefusal> {
        let binding = self
            .runtimes
            .get(&placement.owner)
            .cloned()
            .ok_or(KvRefusal::NoPool)?;
        let (tenant, priority) = {
            let sandbox = self.sandbox(&binding).map_err(|_| KvRefusal::NoPool)?;
            (
                sandbox.tenant().clone(),
                ledger_priority(sandbox.priority()),
            )
        };
        let provenance = Provenance {
            requester: Requester::ModelPlacement,
            execution: binding.execution.clone(),
            operation: operation.clone(),
            tenant,
            purpose: CostPurpose::Compute,
            retry_number: 0,
        };
        let request = ReservationRequest::new(
            provenance,
            priority,
            Amounts::new().with(vram_key(placement.owner.device), bytes),
        )
        .within(parent);
        self.coordinator
            .capacity_mut()
            .write_ledger(|ledger| match ledger.reserve(request) {
                Ok(LedgerAdmission::Granted(reservation)) => {
                    match ledger.begin_create(reservation) {
                        Ok(_) => Ok(reservation),
                        Err(_) => {
                            let _cancelled = ledger.cancel(reservation);
                            Err(KvRefusal::NoPool)
                        }
                    }
                }
                Ok(LedgerAdmission::Queued {
                    ticket,
                    waiting_for,
                    ..
                }) => {
                    let _withdrawn = ledger.cancel_queued(ticket);
                    Err(KvRefusal::Ledger {
                        refusal: CapacityRefusal::from_ledger(&waiting_for),
                    })
                }
                Err(LedgerError::Capacity(error)) => Err(KvRefusal::Ledger {
                    refusal: CapacityRefusal::from_ledger(&error),
                }),
                Err(_) => Err(KvRefusal::NoPool),
            })
    }

    /// Hands KV increments back: the backend unmapped them, as its own report observed.
    fn release_kv(&mut self, increments: Vec<(ReservationId, u64)>) {
        if increments.is_empty() {
            return;
        }
        self.coordinator.capacity_mut().write_ledger(|ledger| {
            for (reservation, _) in increments {
                if let Ok(ReleaseOutcome::Pending) = ledger.cancel(reservation) {
                    let _confirmed = ledger.confirm_release(reservation, SourceClass::GuestReport);
                }
            }
        });
    }

    /// Lets `lease` hold `total` bytes of KV in `generation`'s pool, growing the pool first
    /// when the backend grows its KV: each increment is carved from a reservation of the
    /// generation's own memory. A refusal admits nothing and leaves nothing carved.
    fn admit_kv(
        &mut self,
        key: (PlacementKey, AuthorizationEpoch),
        generation: ModelActivationGeneration,
        lease: LeaseId,
        operation: &OperationId,
        total: u64,
    ) -> Result<(), KvRefusal> {
        let now = self.clock.now();
        let plan = self
            .slots
            .get_mut(&key)
            .and_then(|slot| slot.generations.get_mut(&generation))
            .ok_or(KvRefusal::NoPool)?
            .kv
            .plan(lease, operation, total, now)?;
        let mut carved = Vec::new();
        if let KvPlan::Grow { increments } = plan {
            let parents = self.own_reservations(key, generation);
            if parents.is_empty() {
                self.leave_kv_wait(key, generation, operation);
                return Err(KvRefusal::NoPool);
            }
            for increment in increments {
                let mut refusal = KvRefusal::NoPool;
                let mut reservation = None;
                for parent in &parents {
                    match self.carve_kv(&key.0, operation, *parent, increment) {
                        Ok(granted) => {
                            reservation = Some(granted);
                            break;
                        }
                        Err(refused) => refusal = refused,
                    }
                }
                match reservation {
                    Some(granted) => carved.push((granted, increment)),
                    None => {
                        self.release_kv(carved);
                        self.leave_kv_wait(key, generation, operation);
                        return Err(refusal);
                    }
                }
            }
        }
        match self
            .slots
            .get_mut(&key)
            .and_then(|slot| slot.generations.get_mut(&generation))
        {
            Some(entry) => {
                for (reservation, increment) in carved {
                    entry.kv.grew(reservation, increment);
                }
                entry.kv.admit(lease, operation, total);
                Ok(())
            }
            None => {
                self.release_kv(carved);
                Err(KvRefusal::NoPool)
            }
        }
    }

    /// The own GPU allocation a generation's coordinator activation reserved on its
    /// device: its GPU holding that is not weights.
    fn own_allocation(
        &self,
        key: (PlacementKey, AuthorizationEpoch),
        generation: ModelActivationGeneration,
    ) -> Option<GpuAllocationGeneration> {
        let (placement, _) = key;
        let binding = self.runtimes.get(&placement.owner)?;
        let activations = self
            .coordinator
            .model_activations(&binding.execution, placement.model_id())?;
        activations
            .activation(generation)?
            .holdings()
            .iter()
            .filter_map(|id| activations.holding(*id))
            .filter(|holding| !holding.holds_weights())
            .find_map(|holding| match (holding.id(), holding.memory()) {
                (HoldingId::Gpu { allocation }, HoldingMemory::Gpu { device, .. })
                    if device == placement.owner.device =>
                {
                    Some(allocation)
                }
                _ => None,
            })
    }

    /// The ledger reservations behind a generation's own GPU memory on its device that
    /// hold VRAM there: its own first, then any taken over from a drained predecessor.
    fn own_reservations(
        &self,
        key: (PlacementKey, AuthorizationEpoch),
        generation: ModelActivationGeneration,
    ) -> Vec<ReservationId> {
        let (placement, _) = key;
        let device = placement.owner.device;
        let (Some(binding), Some(allocation)) = (
            self.runtimes.get(&placement.owner),
            self.own_allocation(key, generation),
        ) else {
            return Vec::new();
        };
        self.coordinator
            .model_activations(&binding.execution, placement.model_id())
            .and_then(|activations| activations.holding(HoldingId::Gpu { allocation }))
            .map(|holding| {
                holding
                    .reservations()
                    .iter()
                    .filter_map(|key| self.coordinator.capacity().reservation_record(key))
                    .filter(|record| record.granted().get(vram_key(device)) > 0)
                    .map(|record| record.id())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The KV a lease of `generation` releases.
    fn release_lease_kv(
        &mut self,
        key: (PlacementKey, AuthorizationEpoch),
        generation: ModelActivationGeneration,
        lease: LeaseId,
    ) {
        if let Some(entry) = self
            .slots
            .get_mut(&key)
            .and_then(|slot| slot.generations.get_mut(&generation))
        {
            entry.kv.release(lease);
        }
    }

    /// Records in the lease's slot that the assigned request starts, or with `finish`
    /// finished, computing on the immutable extents among `inputs`; a part already at
    /// that step is left as it is.
    fn compute_ahead(
        &mut self,
        lease: &PreparationLease,
        inputs: &[StateIdentity],
        finish: bool,
    ) -> Result<(), GovernorError> {
        let slot = self
            .slots
            .get_mut(&(lease.placement, lease.epoch))
            .ok_or(GovernorError::UnknownLease { lease: lease.id() })?;
        let request = &lease.ticket.request;
        for position in slot.positions(lease.generation, inputs) {
            let step = if finish {
                slot.slot.finish_early_compute(request, position)
            } else {
                slot.slot.start_early_compute(request, position)
            };
            match step {
                Ok(())
                | Err(EarlyRefusal::AlreadyStarted { .. })
                | Err(EarlyRefusal::AlreadyFinished { .. }) => {}
                Err(refusal) => return Err(GovernorError::Early { refusal }),
            }
        }
        Ok(())
    }

    fn finish_ticket(
        &mut self,
        placement: &PlacementKey,
        epoch: AuthorizationEpoch,
        ticket: &RequestTicket,
    ) -> Result<(), GovernorError> {
        let Self {
            coordinator, slots, ..
        } = self;
        let slot = slots
            .get_mut(&(*placement, epoch))
            .ok_or(GovernorError::UnknownLease {
                lease: ticket.lease,
            })?;
        let (placements, mut port) = slot.ports(coordinator);
        placements
            .finish(ticket, &mut port)
            .map_err(|error| GovernorError::Ticket { error })
    }

    /// When a lease taken now ends: its term is the policy's lease duration.
    fn lease_terms_end(&self) -> MonotonicTime {
        self.clock.now().saturating_add(self.policy.lease_duration)
    }
}

impl<C: Clock> LedgerPolicyGovernor<C, LedgerCapacity<C>> {
    /// The one capacity authority.
    pub fn ledger(&self) -> &Ledger<C> {
        self.coordinator.capacity().ledger()
    }
}

impl<C: Clock + Clone, P: HostLedger<C>> PlacementGovernor for LedgerPolicyGovernor<C, P> {
    fn runtime(&self, owner: PlacementOwner) -> Result<RuntimeView, GovernorError> {
        let binding = self.binding(owner)?;
        let sandbox = self.sandbox(binding)?;
        let record = self.sandbox_reservation(binding)?;
        Ok(RuntimeView {
            execution: binding.execution.clone(),
            tenant: sandbox.tenant().clone(),
            category: binding.settings.execution_category,
            epoch: sandbox.generations().authorization,
            priority: ledger_priority(sandbox.priority()),
            budget: DeviceBudget {
                device: owner.device,
                usable_bytes: record.granted().get(vram_key(owner.device)),
                safety_reserve_bytes: self.policy.safety_reserve_bytes,
            },
        })
    }

    fn admit(&mut self, request: &AdmissionRequest) -> Result<Admission, AdmissionRefusal> {
        let transfer_bytes = request
            .transfer
            .values()
            .try_fold(0u64, |total, bytes| total.checked_add(*bytes))
            .ok_or(AdmissionRefusal::Overflow {
                field: "transfer bytes",
            })?;
        if let Some(limit_bytes) = self.policy.max_transfer_bytes {
            if transfer_bytes > limit_bytes {
                return Err(AdmissionRefusal::TransferLimit {
                    requested_bytes: transfer_bytes,
                    limit_bytes,
                });
            }
        }
        let staging_bytes = transfer_bytes.min(self.policy.staging_cap_bytes);
        if transfer_bytes > 0 && staging_bytes == 0 {
            return Err(AdmissionRefusal::NoStaging);
        }
        let owner = request.placement.owner;
        let runtime = |error| AdmissionRefusal::Runtime { error };
        let binding = self
            .check_authority(&request.authority, owner)
            .map_err(runtime)?;
        let (priority, parent, tenant) = {
            let sandbox = self.sandbox(&binding).map_err(runtime)?;
            let priority = ledger_priority(sandbox.priority());
            let tenant = sandbox.tenant().clone();
            let parent = self.sandbox_reservation(&binding).map_err(runtime)?.id();
            (priority, parent, tenant)
        };
        if request.priority != priority {
            return Err(runtime(GovernorError::PriorityMismatch {
                requested: request.priority,
                runtime: priority,
            }));
        }
        if let Some(demand) = &request.activation {
            if demand.device != owner.device {
                return Err(AdmissionRefusal::DeviceMismatch {
                    placement: owner.device,
                    demand: demand.device,
                });
            }
        }
        let budget = if transfer_bytes > 0 {
            Some(
                TransferBudget::inbound(request.transfer.clone(), owner.device).ok_or(
                    AdmissionRefusal::Overflow {
                        field: "transfer bytes",
                    },
                )?,
            )
        } else {
            None
        };
        let mut admission = Admission::default();
        let key = (request.placement, request.authority.epoch);
        // A waiting reload whose generation is no longer current ends here rather than
        // continue under this admission (G03).
        self.end_stale_reload(key);
        let reloading = self
            .slots
            .get(&key)
            .and_then(|slot| slot.reload.as_ref())
            .map(|reload| reload.reloading);
        let stage = |governor: &mut Self| {
            if transfer_bytes == 0 {
                return Ok(None);
            }
            governor
                .reserve_staging(request, &binding.execution, parent, priority, staging_bytes)
                .map(Some)
        };
        match (&request.activation, &request.spec, reloading) {
            // While serving pauses for a reload, only the reload's own activation continues
            // it, once the old generation drained; every other admission waits with the
            // pause's status. Staging comes first, so a refusal leaves the reload waiting.
            (Some(_), Some(spec), Some(reloading)) => {
                let continues = self
                    .slots
                    .get(&key)
                    .and_then(|slot| slot.generations.get(&reloading))
                    .is_some_and(|entry| entry.serves(spec));
                let status = self.advance_reload(key.0, key.1)?;
                let parked = self
                    .slots
                    .get(&key)
                    .and_then(|slot| slot.reload.as_ref())
                    .is_some_and(|reload| reload.pending.is_some());
                if !continues || status.phase != ReloadPhase::HandingOver || !parked {
                    return Err(AdmissionRefusal::PausedForReload { status });
                }
                admission.staging = stage(self)?;
                let Some((pending, drained)) = self.take_reload(key.0, key.1) else {
                    let refusal = AdmissionRefusal::PausedForReload { status };
                    return Err(self.roll_back(admission, refusal));
                };
                admission.activation = Some(pending);
                admission.handover = Some(drained);
            }
            (_, _, Some(_)) => {
                let status = self.advance_reload(key.0, key.1)?;
                return Err(AdmissionRefusal::PausedForReload { status });
            }
            (None, None, None) => {
                admission.staging = stage(self)?;
            }
            (Some(demand), Some(spec), None) => {
                let bound = self.reload_bound(&request.placement, spec);
                let (pending, pause) = self.begin_activation(
                    request,
                    &binding,
                    tenant,
                    demand,
                    spec,
                    bound.is_some(),
                )?;
                match (pause, bound) {
                    (Some((predecessor, record)), Some(drain)) => {
                        // Serving pauses: the activation waits in its slot until the old
                        // generation drained, and continues under this admission at once
                        // if no old request runs.
                        if let Err(pending) = self.start_reload(
                            request,
                            pending,
                            predecessor,
                            record.reason,
                            record.started_at,
                            drain,
                        ) {
                            admission.activation = Some(pending);
                            let refusal = AdmissionRefusal::IncompleteActivation;
                            return Err(self.roll_back(admission, refusal));
                        }
                        let status = self.advance_reload(key.0, key.1)?;
                        if status.phase != ReloadPhase::HandingOver {
                            return Err(AdmissionRefusal::PausedForReload { status });
                        }
                        admission.staging = stage(self)?;
                        let Some((pending, drained)) = self.take_reload(key.0, key.1) else {
                            let refusal = AdmissionRefusal::PausedForReload { status };
                            return Err(self.roll_back(admission, refusal));
                        };
                        admission.activation = Some(pending);
                        admission.handover = Some(drained);
                    }
                    _ => {
                        admission.activation = Some(pending);
                        match stage(self) {
                            Ok(staging) => admission.staging = staging,
                            Err(refusal) => return Err(self.roll_back(admission, refusal)),
                        }
                    }
                }
            }
            _ => return Err(AdmissionRefusal::IncompleteActivation),
        }
        admission.transfer_budget = budget.map(|budget| match &admission.activation {
            Some(pending) => self.land(pending, budget),
            None => budget,
        });
        Ok(admission)
    }

    fn begin_create(&mut self, grant: &LedgerGrant) -> Result<(), GovernorError> {
        Ok(self
            .coordinator
            .capacity_mut()
            .write_ledger(|ledger| ledger.begin_create(grant.reservation))?)
    }

    fn release(&mut self, grant: LedgerGrant) -> Result<(), GovernorError> {
        self.coordinator.capacity_mut().write_ledger(|ledger| {
            match ledger.cancel(grant.reservation)? {
                ReleaseOutcome::Released { .. } | ReleaseOutcome::AlreadyClosed => Ok(()),
                ReleaseOutcome::Pending => {
                    ledger.confirm_release(grant.reservation, SourceClass::GuestReport)?;
                    Ok(())
                }
            }
        })
    }

    fn abandon(&mut self, grant: LedgerGrant) -> Result<(), GovernorError> {
        self.coordinator
            .capacity_mut()
            .write_ledger(|ledger| ledger.cancel(grant.reservation))?;
        Ok(())
    }

    fn hand_over(
        &mut self,
        pending: &PendingActivation,
        source: SourceClass,
    ) -> Result<(), GovernorError> {
        let key = (pending.placement, pending.epoch);
        let draining = self
            .slots
            .get(&key)
            .and_then(|slot| slot.reload.as_ref())
            .filter(|reload| {
                reload.reloading == pending.generation() && reload.phase == ReloadPhase::HandingOver
            })
            .map(|reload| reload.draining)
            .ok_or(GovernorError::NoReload)?;
        self.confirm_released(&pending.placement, draining, source)?;
        let Self {
            coordinator,
            slots,
            lifecycle,
            ..
        } = self;
        let slot = slots.get_mut(&key).ok_or(GovernorError::NoReload)?;
        let ready = slot
            .generations
            .get(&pending.generation())
            .map(|entry| entry.ready.clone())
            .unwrap_or_default();
        let (placements, mut port) = slot.ports(coordinator);
        lifecycle.step(key, placements, |placements| {
            let progress = placements.prepare_extents(&mut port)?;
            if !progress.waiting_for_predecessor.is_empty()
                || !progress.waiting_for_other_holders.is_empty()
            {
                return Err(ActivationError::ExtentsNotUsable {
                    waiting: progress
                        .waiting_for_predecessor
                        .into_iter()
                        .chain(progress.waiting_for_other_holders)
                        .collect(),
                });
            }
            ready
                .into_iter()
                .try_for_each(|extent| match placements.record_extent_usable(extent) {
                    Ok(()) | Err(ActivationError::UnknownExtent { .. }) => Ok(()),
                    Err(error) => Err(error),
                })
        })?;
        if let Some(reload) = slot.reload.as_mut() {
            reload.phase = ReloadPhase::Loading;
        }
        Ok(())
    }

    fn transfer_destinations(
        &self,
        pending: &PendingActivation,
        extents: &[ExtentRef],
    ) -> BTreeMap<ExtentRef, TransferDestination> {
        let own = self.own_destination(pending);
        let weights = self.weights_destinations(pending, extents);
        extents
            .iter()
            .filter_map(|extent| {
                weights
                    .get(extent)
                    .copied()
                    .or(own)
                    .map(|destination| (*extent, destination))
            })
            .collect()
    }

    fn record_usable(
        &mut self,
        pending: &PendingActivation,
        identity: StateIdentity,
    ) -> Result<(), GovernorError> {
        let slot = self
            .slots
            .get_mut(&(pending.placement, pending.epoch))
            .ok_or(GovernorError::Placement {
                error: ActivationError::NoActivation,
            })?;
        let Some((key, _)) = slot
            .generations
            .get(&pending.generation())
            .and_then(|entry| entry.extents.get(&identity))
            .copied()
        else {
            return Ok(());
        };
        Ok(slot.slot.record_extent_usable(key)?)
    }

    fn publish_activation(
        &mut self,
        pending: PendingActivation,
        residency: Residency,
    ) -> Result<ModelActivationGeneration, PendingRefusal> {
        let placement = pending.placement;
        let generation = pending.generation();
        let checked = self.binding(placement.owner).cloned().and_then(|binding| {
            let current = self.sandbox(&binding)?.generations().authorization;
            let expected = AuthorityBinding::new(
                binding.execution.clone(),
                binding.settings.execution_category,
                Some(current),
            )
            .map_err(|_| GovernorError::ResidencyMismatch)?;
            if residency.execution != placement.model
                || residency.device != placement.owner.device
                || residency.authority != expected
                || pending.epoch != current
            {
                return Err(GovernorError::ResidencyMismatch);
            }
            Ok(binding)
        });
        if let Err(error) = checked {
            return Err(PendingRefusal { pending, error });
        }
        let Self {
            coordinator,
            slots,
            lifecycle,
            ..
        } = self;
        let site = (placement, pending.epoch);
        let Some(slot) = slots.get_mut(&site) else {
            return Err(PendingRefusal {
                pending,
                error: GovernorError::Placement {
                    error: ActivationError::NoActivation,
                },
            });
        };
        let declared = slot
            .generations
            .get(&generation)
            .map(|entry| entry.declared);
        let (placements, mut port) = slot.ports(coordinator);
        let in_progress = placements
            .activation()
            .is_some_and(|activation| activation.generation == generation);
        let published = match (in_progress, declared) {
            (true, Some(declared)) => lifecycle
                .step(site, placements, |placements| {
                    placements
                        .record_runtime_initialized()
                        .and_then(|()| placements.materialize())
                        .and_then(|()| placements.begin_activating())
                        .and_then(|()| {
                            placements.record_validation(
                                &ValidationReport {
                                    generation,
                                    rank: RANK,
                                    weights_verified: true,
                                    buffers_ready: true,
                                    graphs_compatible: true,
                                    coordination: single_rank(placement.model_id(), generation),
                                },
                                &mut port,
                            )
                        })
                        .and_then(|()| {
                            placements.record_readiness(
                                generation,
                                RANK,
                                &ReadinessReport::Ready {
                                    supported: declared,
                                },
                                &mut port,
                            )
                        })
                })
                .and_then(|()| lifecycle.publish(site, placements, &mut port)),
            _ => Err(ActivationError::NoActivation),
        };
        match published {
            Ok(report) if report.generation == generation => {
                if let Some(entry) = slot.generations.get_mut(&generation) {
                    entry.residency = Some(residency);
                }
                if slot
                    .reload
                    .as_ref()
                    .is_some_and(|reload| reload.reloading == generation)
                {
                    slot.reload = None;
                }
                Ok(generation)
            }
            Ok(report) => Err(PendingRefusal {
                pending,
                error: GovernorError::GenerationNotServing {
                    requested: generation,
                    serving: Some(report.generation),
                },
            }),
            Err(error) => Err(PendingRefusal {
                pending,
                error: GovernorError::Placement { error },
            }),
        }
    }

    fn abandon_activation(
        &mut self,
        pending: PendingActivation,
    ) -> Result<AbandonedActivation, PendingRefusal> {
        let placement = pending.placement;
        let generation = pending.generation();
        let key = (placement, pending.epoch);
        let mut freed = Vec::new();
        let outcome = {
            let Self {
                coordinator,
                slots,
                lifecycle,
                ..
            } = self;
            let Some(slot) = slots.get_mut(&key) else {
                return Ok(AbandonedActivation {
                    placement,
                    generation,
                    mode: pending.mode,
                    transition_capacity_reserved: pending.mode == TransitionMode::Overlap,
                    serving: None,
                    predecessor_rollback: None,
                });
            };
            if let Some(lease) = slot.preparation {
                if coordinator.check_lease(lease).is_ok() {
                    return Err(PendingRefusal {
                        pending,
                        error: GovernorError::PreparationInFlight { lease },
                    });
                }
            }
            let (placements, mut port) = slot.ports(coordinator);
            let in_progress = placements
                .activation()
                .is_some_and(|activation| activation.generation == generation);
            let predecessor_rollback = if in_progress {
                match lifecycle.end(key, placements, |placements| {
                    placements.cancel_activation(&mut port)
                }) {
                    Ok(report) => report.predecessor_rollback,
                    Err(error) => {
                        return Err(PendingRefusal {
                            pending,
                            error: GovernorError::Placement { error },
                        })
                    }
                }
            } else {
                // The slot ended the activation itself, as when a rank's check failed.
                None
            };
            if slot
                .reload
                .as_ref()
                .is_some_and(|reload| reload.reloading == generation)
            {
                slot.reload = None;
            }
            if let Some(entry) = slot.generations.get_mut(&generation) {
                freed = entry.kv.take_increments();
            }
            AbandonedActivation {
                placement,
                generation,
                mode: pending.mode,
                transition_capacity_reserved: pending.mode == TransitionMode::Overlap,
                serving: slot.slot.published().map(|content| content.generation),
                predecessor_rollback: (pending.mode == TransitionMode::DrainFirst)
                    .then_some(predecessor_rollback)
                    .flatten(),
            }
        };
        self.release_kv(freed);
        self.abandoned.insert(placement, outcome.clone());
        Ok(outcome)
    }

    fn confirm_released(
        &mut self,
        placement: &PlacementKey,
        generation: ModelActivationGeneration,
        source: SourceClass,
    ) -> Result<bool, GovernorError> {
        if !source.satisfies(SourceClass::GuestReport) {
            return Err(GovernorError::ReleaseSourceTooWeak { source });
        }
        let mut freed = Vec::new();
        let reclaimed = {
            let Self {
                coordinator,
                slots,
                lifecycle,
                ..
            } = self;
            let Some((site, slot)) = slots
                .iter_mut()
                .filter(|((key, _), _)| key == placement)
                .find(|(_, slot)| slot.generations.contains_key(&generation))
            else {
                return Ok(false);
            };
            let site = *site;
            let Some((key, operation)) = slot.generations.get(&generation).map(|entry| {
                (
                    entry.placement,
                    slot.release_operation(entry.placement, &entry.operation),
                )
            }) else {
                return Ok(false);
            };
            let Some(view) = slot.slot.placement(key) else {
                return Ok(false);
            };
            let slot_error = |error| GovernorError::Slot { error };
            let (placements, mut port) = slot.ports(coordinator);
            match view.state.kind() {
                StateKind::Draining => {
                    let drained = placements.drain_status(key, &port).map_err(slot_error)?;
                    if !drained.is_drained() {
                        return Err(slot_error(SlotError::LeasesHeld {
                            placement: key,
                            leases: drained.remaining_leases,
                        }));
                    }
                    lifecycle
                        .park(site, placements, key, &operation)
                        .map_err(slot_error)?;
                }
                StateKind::Materialized | StateKind::Parked | StateKind::Failed => {}
                state => {
                    return Err(slot_error(SlotError::NotReclaimable {
                        placement: key,
                        state,
                    }))
                }
            }
            let report = lifecycle
                .reclaim(site, placements, key, &mut port, &operation)
                .map_err(slot_error)?;
            let _retired = lifecycle.retire(site, &mut slot.slot, key, &operation);
            for entry in slot
                .generations
                .values_mut()
                .filter(|entry| entry.placement == key)
            {
                freed.extend(entry.kv.take_increments());
            }
            report.released_reservation.is_some() || !report.freed.is_empty()
        };
        self.release_kv(freed);
        Ok(reclaimed)
    }

    fn current_residency(&self, placement: &PlacementKey) -> Option<CurrentResidency> {
        let epoch = self.current_epoch(placement.owner)?;
        let slot = self.slots.get(&(*placement, epoch))?;
        let generation = match &slot.reload {
            // Serving is paused, but the draining generation's state stays resident until
            // it is reclaimed.
            Some(reload) => {
                let state = self.activation_state(placement, reload.draining)?;
                if state.is_retired() && reload.pending.is_none() {
                    return None;
                }
                reload.draining
            }
            None => {
                let generation = slot.slot.published()?.generation;
                let binding = self.runtimes.get(&placement.owner)?;
                let serving = self
                    .coordinator
                    .model_activations(&binding.execution, placement.model_id())?
                    .serving()
                    .map(|activation| activation.generations().activation);
                if serving != Some(generation) {
                    return None;
                }
                generation
            }
        };
        Some(CurrentResidency {
            residency: slot.generations.get(&generation)?.residency.clone()?,
            generation,
        })
    }

    fn reload_status(&self, placement: &PlacementKey) -> Option<ReloadStatus> {
        let epoch = self.current_epoch(placement.owner)?;
        self.slots
            .get(&(*placement, epoch))?
            .reload_status(*placement, self.clock.now())
    }

    fn lease_execution(
        &mut self,
        authority: &RequestAuthority,
        placement: &PlacementKey,
        generation: ModelActivationGeneration,
        shape: RequestShape,
    ) -> Result<ExecutionLease, GovernorError> {
        let binding = self.check_authority(authority, placement.owner)?;
        let epoch = authority.epoch;
        let key = (*placement, epoch);
        let now = self.clock.now();
        if let Some(status) = self
            .slots
            .get(&key)
            .and_then(|slot| slot.reload_status(*placement, now))
        {
            return Err(GovernorError::PausedForReload { status });
        }
        let expires_at = self.lease_terms_end();
        let (ticket, lease, kv_spec) = {
            let Self {
                coordinator, slots, ..
            } = self;
            let Some(slot) = slots.get_mut(&key) else {
                return Err(GovernorError::GenerationNotServing {
                    requested: generation,
                    serving: None,
                });
            };
            let serving = slot.slot.published().map(|content| content.generation);
            if serving != Some(generation) {
                return Err(GovernorError::GenerationNotServing {
                    requested: generation,
                    serving,
                });
            }
            let (placements, mut port) = slot.ports(coordinator);
            let ticket = placements
                .admit(
                    &SlotAdmission {
                        request: authority.operation.clone(),
                        execution: binding.execution.clone(),
                        epoch,
                        shape,
                        adapter: None,
                        lease_expires_at: expires_at,
                    },
                    &mut port,
                )
                .map_err(|refusal| GovernorError::Route { refusal })?;
            let lease = coordinator
                .lease_record(ticket.lease)
                .map(|record| record.lease().clone());
            let kv_spec = slot
                .generations
                .get(&generation)
                .map(|entry| entry.kv.spec());
            (ticket, lease, kv_spec)
        };
        let admitted = match (lease, kv_spec) {
            (Some(lease), Some(kv)) if ticket.generation == generation => {
                match kv_bytes(&shape, kv.bytes_per_token) {
                    Some(bytes) => self
                        .admit_kv(key, generation, ticket.lease, &authority.operation, bytes)
                        .map(|()| (lease, bytes))
                        .map_err(GovernorError::from),
                    None => Err(GovernorError::Kv {
                        refusal: KvRefusal::Overflow,
                    }),
                }
            }
            (Some(_), None) => Err(GovernorError::Kv {
                refusal: KvRefusal::NoPool,
            }),
            _ => Err(GovernorError::GenerationNotServing {
                requested: generation,
                serving: Some(ticket.generation),
            }),
        };
        match admitted {
            Ok((lease, kv_bytes)) => Ok(ExecutionLease {
                lease,
                placement: *placement,
                generation,
                epoch,
                ticket,
                shape,
                kv_bytes,
                keep_session: false,
            }),
            Err(error) => {
                self.finish_ticket(placement, epoch, &ticket)?;
                Err(error)
            }
        }
    }

    fn resize_execution_lease(
        &mut self,
        lease: &mut ExecutionLease,
        shape: RequestShape,
    ) -> Result<(), GovernorError> {
        self.coordinator
            .check_lease(lease.id())
            .map_err(|refusal| GovernorError::Lease { refusal })?;
        let key = (lease.placement, lease.epoch);
        let (declared, spec): (SupportedShape, KvSpec) = self
            .slots
            .get(&key)
            .and_then(|slot| slot.generations.get(&lease.generation))
            .map(|entry| (entry.declared, entry.kv.spec()))
            .ok_or(GovernorError::Kv {
                refusal: KvRefusal::NoPool,
            })?;
        declared
            .check(&shape)
            .map_err(|refusal| GovernorError::Shape { refusal })?;
        let total = kv_bytes(&shape, spec.bytes_per_token).ok_or(GovernorError::Kv {
            refusal: KvRefusal::Overflow,
        })?;
        let operation = lease.operation().clone();
        self.admit_kv(key, lease.generation, lease.id(), &operation, total)?;
        lease.kv_bytes = total;
        lease.shape = shape;
        Ok(())
    }

    fn check_execution_lease(&self, lease: &ExecutionLease) -> Result<(), GovernorError> {
        self.coordinator
            .check_result_publication(lease.id())
            .map(|_| ())
            .map_err(|refusal| GovernorError::Lease { refusal })
    }

    fn lease_preparation(
        &mut self,
        authority: &RequestAuthority,
        pending: &PendingActivation,
    ) -> Result<PreparationLease, GovernorError> {
        let binding = self.check_authority(authority, pending.placement.owner)?;
        let expires_at = self.lease_terms_end();
        let key = (pending.placement, pending.epoch);
        let (ticket, lease, declared, kv) = {
            let Self {
                coordinator, slots, ..
            } = self;
            let slot = slots.get_mut(&key).ok_or(GovernorError::Placement {
                error: ActivationError::NoActivation,
            })?;
            let entry =
                slot.generations
                    .get(&pending.generation())
                    .ok_or(GovernorError::Placement {
                        error: ActivationError::NoActivation,
                    })?;
            let required: BTreeSet<WeightPosition> = entry
                .extents
                .values()
                .map(|(_, position)| *position)
                .collect();
            let (declared, kv) = (entry.declared, entry.kv.spec());
            let (placements, mut port) = slot.ports(coordinator);
            let ticket = placements
                .assign_early_request(
                    &AssignedRequest {
                        request: authority.operation.clone(),
                        execution: binding.execution.clone(),
                        epoch: authority.epoch,
                        required,
                        lease_expires_at: expires_at,
                    },
                    &mut port,
                )
                .map_err(|refusal| GovernorError::Early { refusal })?;
            slot.preparation = Some(ticket.lease);
            let lease = coordinator
                .lease_record(ticket.lease)
                .map(|record| record.lease().clone());
            (ticket, lease, declared, kv)
        };
        let shape = RequestShape {
            context_tokens: declared.max_context_tokens,
            batch_sequences: declared.max_batch_sequences,
        };
        let admitted = match lease {
            Some(lease) => match kv_bytes(&shape, kv.bytes_per_token) {
                Some(bytes) => self
                    .admit_kv(
                        key,
                        pending.generation(),
                        ticket.lease,
                        &authority.operation,
                        bytes,
                    )
                    .map(|()| (lease, bytes))
                    .map_err(GovernorError::from),
                None => Err(GovernorError::Kv {
                    refusal: KvRefusal::Overflow,
                }),
            },
            None => Err(GovernorError::UnknownLease {
                lease: ticket.lease,
            }),
        };
        match admitted {
            Ok((lease, kv_bytes)) => Ok(PreparationLease {
                lease,
                placement: pending.placement,
                generation: ticket.generation,
                epoch: pending.epoch,
                ticket,
                kv_bytes,
            }),
            Err(error) => {
                self.finish_ticket(&pending.placement, pending.epoch, &ticket)?;
                if let Some(slot) = self.slots.get_mut(&key) {
                    slot.preparation = None;
                }
                Err(error)
            }
        }
    }

    fn start_compute_ahead(
        &mut self,
        lease: &PreparationLease,
        inputs: &[StateIdentity],
    ) -> Result<(), GovernorError> {
        self.compute_ahead(lease, inputs, false)
    }

    fn finish_compute_ahead(
        &mut self,
        lease: &PreparationLease,
        inputs: &[StateIdentity],
    ) -> Result<(), GovernorError> {
        self.compute_ahead(lease, inputs, true)
    }

    fn check_preparation_lease(&self, lease: &PreparationLease) -> Result<(), GovernorError> {
        self.coordinator
            .check_lease(lease.id())
            .map(|_| ())
            .map_err(|refusal| GovernorError::Lease { refusal })
    }

    fn release_execution_lease(&mut self, lease: ExecutionLease) -> Result<(), GovernorError> {
        let finished = self.finish_ticket(&lease.placement, lease.epoch, &lease.ticket);
        // A drain deadline already ended the lease (GPU-W05 line 110): its request was
        // told to stop, and releasing it now changes nothing.
        let ended = matches!(
            finished,
            Err(GovernorError::Ticket {
                error: TicketError::UnknownTicket
            })
        ) && self
            .coordinator
            .lease_record(lease.id())
            .is_some_and(|record| matches!(record.state(), LeaseState::Released { .. }));
        if !ended {
            finished?;
        }
        self.keep_session_kv(&lease);
        self.release_lease_kv((lease.placement, lease.epoch), lease.generation, lease.id());
        Ok(())
    }

    fn release_preparation_lease(&mut self, lease: PreparationLease) -> Result<(), GovernorError> {
        self.finish_ticket(&lease.placement, lease.epoch, &lease.ticket)?;
        let key = (lease.placement, lease.epoch);
        self.release_lease_kv(key, lease.generation, lease.id());
        if let Some(slot) = self.slots.get_mut(&key) {
            if slot.preparation == Some(lease.id()) {
                slot.preparation = None;
            }
        }
        Ok(())
    }

    fn active_leases(&self, placement: &PlacementKey) -> usize {
        let Some(binding) = self.runtimes.get(&placement.owner) else {
            return 0;
        };
        let model = placement.model_id();
        let now = self.coordinator.now();
        self.coordinator
            .leases()
            .filter(|record| {
                record.lease().parent() == &binding.execution
                    && record
                        .lease()
                        .model()
                        .is_some_and(|bound| bound.model == model)
                    && record.may_be_in_use(now)
            })
            .count()
    }
}
