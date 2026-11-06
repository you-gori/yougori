//! The activation protocol of §3.6 (lines 587–597):
//!
//! 1. resolve exact identity and reserve steady state plus transition peak;
//! 2. allocate or acquire immutable extents and initialize runtime state;
//! 3. validate weights, buffers, graphs and rank coordination;
//! 4. run readiness checks for the declared request shape;
//! 5. publish the new activation generation to the router atomically;
//! 6. drain requests holding old-generation leases;
//! 7. reclaim old resources only after process references and GPU completion events
//!    permit it.
//!
//! Versions overlap only when the reservation for both fits. Otherwise, if the caller
//! accepts it, the old generation drains first (steps 6–7 before step 2's allocation)
//! and the slot reports a real pause until step 5. Steps 6 and 7 act on the old
//! placement through [`PlacementSlot::drain_status`], [`PlacementSlot::park`] and
//! [`PlacementSlot::reclaim`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::barrier::{BarrierError, RankBarrier, ReadinessReport, ValidationReport};
use super::extents::{Acquired, ExtentSpec};
use super::fields::{ArtifactValidity, ProcessLiveness, SupportedShape};
use super::keys::{
    Component, ExtentKey, PlacementKey, ProcessInstance, Rank, ReservationId, WeightPosition,
};
use super::ports::{
    CoordinationRefusal, LeaseKind, PlacementPorts, ReservationRefusal, ReservationRequest,
    ResourceDemand,
};
use super::reclaim::ReclaimGate;
use super::router::{
    ActivationContent, GenerationEntry, HeldLease, PauseOutcome, PauseReason, PauseRecord,
};
use super::slot::{unique_extents, HeldReservation, Placement, PlacementSlot, RollbackOutlook};
use super::state::{Failure, FailureReason, IllegalTransition, PlacementState, StateKind};
use crate::foundation::ids::{
    Clock, ContentKey, GpuAllocationGeneration, GpuDeviceKey, ModelActivationGeneration,
    MonotonicTime, OperationId,
};
use crate::model_memory::identity::{AdapterIdentity, ArtifactIdentity, ExecutionIdentity};

/// The seven steps of §3.6, numbered as the plan numbers them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolStep {
    ResolveAndReserve,
    AcquireAndInitialize,
    Validate,
    CheckReadiness,
    Publish,
    DrainOld,
    ReclaimOld,
}

impl ProtocolStep {
    /// The step's number in the plan's list (lines 589–595).
    pub const fn number(self) -> u8 {
        match self {
            Self::ResolveAndReserve => 1,
            Self::AcquireAndInitialize => 2,
            Self::Validate => 3,
            Self::CheckReadiness => 4,
            Self::Publish => 5,
            Self::DrainOld => 6,
            Self::ReclaimOld => 7,
        }
    }
}

impl fmt::Display for ProtocolStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "step {}", self.number())
    }
}

/// Whether the caller accepts a real pause when versions cannot overlap (line 597).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionPreference {
    /// Refuse the activation rather than pause serving.
    OverlapOnly,
    /// Overlap when capacity allows; otherwise drain first and report the pause.
    OverlapOrPause,
}

/// How an activation replaces what serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionMode {
    /// Nothing was serving.
    Initial,
    /// Old and new generations are resident together; the old one serves until the new
    /// one is published.
    Overlap,
    /// Capacity permits one resident generation: the old one drains and is reclaimed
    /// before the new one allocates, and serving pauses until publication.
    DrainFirst,
}

/// Which placement an activation uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "choice", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum PlacementChoice {
    /// A new placement in the runtime process `process`.
    New { process: ProcessInstance },
    /// A resting placement (materialized or parked) with exactly the same content, such
    /// as a rollback or a wake; it gets a new activation generation.
    Reuse { placement: PlacementKey },
}

crate::foundation::strict_serde::strict_tag!(PlacementChoice, "choice");

/// The exact identities an activation serves (§3.6 step 1), built by the identity
/// layers (T07) from typed specs; no name or size stands in for them (§3.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ActivationIdentity {
    pub execution: ExecutionIdentity,
    pub artifact: ArtifactIdentity,
    /// The identity of each applied adapter, by its `Component::Adapter` index; an
    /// adapter update is a new identity (line 599).
    pub adapters: BTreeMap<u32, AdapterIdentity>,
}

/// Everything step 1 needs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ActivationRequest {
    pub operation: OperationId,
    pub identity: ActivationIdentity,
    pub placement: PlacementChoice,
    /// The artifact's validity as the catalog reports it; it must be verified as the
    /// resolved artifact.
    pub artifact: ArtifactValidity,
    /// Ranks 0..n and the device each runs on.
    pub layout: BTreeMap<Rank, GpuDeviceKey>,
    pub components: Vec<ExtentSpec>,
    /// Steady-state demand; it must cover every extent of the content.
    pub steady: ResourceDemand,
    pub transition_peak: ResourceDemand,
    /// The request shape readiness checks must cover; the only shape published.
    pub declared_shape: SupportedShape,
    pub preference: TransitionPreference,
}

/// A malformed activation request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum RequestProblem {
    NoRanks,
    /// Ranks must be numbered 0..n.
    RanksNotContiguous,
    NoComponents,
    RankNotInLayout {
        position: WeightPosition,
    },
    /// The extent is not on the device its rank runs on.
    DeviceMismatch {
        position: WeightPosition,
    },
    DuplicatePosition {
        position: WeightPosition,
    },
    EmptyExtent {
        position: WeightPosition,
    },
    /// One extent appears with two sizes, here or against a resident copy.
    ExtentSizeMismatch {
        extent: ExtentKey,
    },
    RankWithoutComponents {
        rank: Rank,
    },
    EmptyDeclaredShape,
    NoSteadyDemand,
    /// A reused placement's held steady-state reservation does not cover the
    /// requested steady state; reclaim it first so step 1 reserves anew.
    SteadyExceedsHeldReservation,
    /// The steady-state reservation would not cover the content's extents.
    UnderReserved {
        device: GpuDeviceKey,
        extent_bytes: u64,
        reserved_bytes: u64,
    },
    /// An adapter component has no adapter identity.
    AdapterWithoutIdentity {
        index: u32,
    },
    /// An adapter identity names no adapter component.
    IdentityWithoutAdapter {
        index: u32,
    },
}

crate::foundation::strict_serde::strict_tag!(RequestProblem, "problem");

/// Why an activation step was refused. Unless the variant is [`Self::Failed`], nothing
/// changed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ActivationError {
    /// One activation at a time per slot.
    ActivationInProgress {
        generation: ModelActivationGeneration,
    },
    NoActivation,
    InvalidRequest {
        problem: RequestProblem,
    },
    /// An adapter identity already names other weights for this execution (line 599:
    /// an adapter update receives its own identity).
    AdapterIdentityReused {
        adapter: AdapterIdentity,
        index: u32,
    },
    ArtifactNotVerified,
    UnknownPlacement {
        placement: PlacementKey,
    },
    /// Only a materialized or parked placement is reused.
    ReuseNotResting {
        placement: PlacementKey,
        state: StateKind,
    },
    /// A reused placement must have exactly the requested content.
    ReuseMismatch {
        placement: PlacementKey,
    },
    ProcessNotAlive {
        placement: PlacementKey,
    },
    /// The reservation was refused. `mode` is the transition that was attempted last.
    Reservation {
        refusal: ReservationRefusal,
        mode: TransitionMode,
    },
    /// The reservation port granted less than was asked; the grant was released.
    ReservationIncomplete,
    /// The serving placement holds no steady reservation to hand over.
    PredecessorUnreserved,
    PlacementsExhausted,
    Coordination {
        refusal: CoordinationRefusal,
    },
    /// The new generation is not newer than one already published.
    StaleGeneration {
        generation: ModelActivationGeneration,
    },
    /// A step was attempted before the step it depends on.
    OutOfOrder {
        attempted: ProtocolStep,
        missing: ProtocolStep,
    },
    /// Publication waits for every rank (line 599).
    BarrierIncomplete {
        missing: ProtocolStep,
        waiting: Vec<Rank>,
    },
    Barrier {
        error: BarrierError,
    },
    UnknownExtent {
        extent: ExtentKey,
    },
    ExtentsNotUsable {
        waiting: Vec<ExtentKey>,
    },
    RuntimeNotInitialized,
    Transition {
        transition: IllegalTransition,
    },
    /// An extent step 1 counted as acquired was freed before step 2 acquired it; the
    /// reservation does not cover allocating it again, so cancel and begin anew.
    PlannedExtentGone {
        extent: ExtentKey,
    },
    /// The step failed the activation; the report says what happened.
    Failed {
        report: AbortReport,
    },
}

impl fmt::Display for ActivationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ActivationInProgress { generation } => {
                write!(
                    f,
                    "activation of generation {generation} is still in progress"
                )
            }
            Self::NoActivation => f.write_str("no activation is in progress"),
            Self::InvalidRequest { problem } => {
                write!(f, "invalid activation request: {problem:?}")
            }
            Self::AdapterIdentityReused { adapter, .. } => write!(
                f,
                "adapter identity {adapter} already names other content; an adapter update \
                 needs its own identity"
            ),
            Self::ArtifactNotVerified => f.write_str("the artifact is not verified"),
            Self::UnknownPlacement { placement } => write!(f, "placement {placement} is unknown"),
            Self::ReuseNotResting { placement, state } => write!(
                f,
                "placement {placement} is {state}; only a materialized or parked placement is \
                 reused"
            ),
            Self::ReuseMismatch { placement } => {
                write!(f, "placement {placement} holds different content")
            }
            Self::ProcessNotAlive { placement } => {
                write!(f, "placement {placement} has no live process")
            }
            Self::Reservation { refusal, .. } => refusal.fmt(f),
            Self::ReservationIncomplete => f.write_str("the reservation was incomplete"),
            Self::PredecessorUnreserved => {
                f.write_str("the serving placement holds no reservation to hand over")
            }
            Self::PlacementsExhausted => f.write_str("the slot has used every placement number"),
            Self::Coordination { refusal } => refusal.fmt(f),
            Self::StaleGeneration { generation } => write!(
                f,
                "generation {generation} is not newer than the generations already published"
            ),
            Self::OutOfOrder { attempted, missing } => {
                write!(f, "{attempted} cannot run before {missing} is complete")
            }
            Self::BarrierIncomplete { missing, waiting } => write!(
                f,
                "{} rank(s) have not completed {missing}; one ready rank is not enough",
                waiting.len()
            ),
            Self::Barrier { error } => error.fmt(f),
            Self::UnknownExtent { extent } => {
                write!(
                    f,
                    "extent {} is not part of this activation",
                    extent.content
                )
            }
            Self::ExtentsNotUsable { waiting } => {
                write!(f, "{} extent(s) are not usable yet", waiting.len())
            }
            Self::RuntimeNotInitialized => f.write_str("runtime state is not initialized"),
            Self::Transition { transition } => transition.fmt(f),
            Self::PlannedExtentGone { extent } => write!(
                f,
                "extent {} was freed before this activation acquired it; begin it anew",
                extent.content
            ),
            Self::Failed { report } => match &report.failure {
                Some(failure) => failure.fmt(f),
                None => write!(f, "the activation ended: {}", report.reason),
            },
        }
    }
}

impl std::error::Error for ActivationError {}

impl From<IllegalTransition> for ActivationError {
    fn from(transition: IllegalTransition) -> Self {
        Self::Transition { transition }
    }
}

/// What step 1 started.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationStarted {
    pub generation: ModelActivationGeneration,
    pub placement: PlacementKey,
    pub mode: TransitionMode,
    /// The placement being replaced, if one was serving.
    pub predecessor: Option<PlacementKey>,
    /// The pause that began, when the old generation drains first.
    pub pause: Option<PauseRecord>,
}

/// Progress of step 2.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtentProgress {
    /// Resident extents now also held by this placement.
    pub acquired: Vec<ExtentKey>,
    /// Newly allocated extents with their allocation generations; they become usable
    /// once populated and verified.
    pub allocated: Vec<(ExtentKey, GpuAllocationGeneration)>,
    /// Extents that wait for the old placement's reclamation (drain first).
    pub waiting_for_predecessor: Vec<ExtentKey>,
    /// Extents another placement holds but never made usable; they are neither shared
    /// nor allocated again until that placement is reclaimed.
    pub waiting_for_other_holders: Vec<ExtentKey>,
    /// Held extents not yet usable.
    pub not_yet_usable: Vec<ExtentKey>,
}

/// What step 5 published.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishReport {
    pub generation: ModelActivationGeneration,
    pub placement: PlacementKey,
    /// The generation that stopped admitting at this switch, if one was published.
    pub previous: Option<ModelActivationGeneration>,
    pub mode: TransitionMode,
    pub predecessor: Option<PlacementKey>,
    /// The ended pause, when the old generation drained first.
    pub pause: Option<PauseRecord>,
    /// Whether the replaced content could still serve without reloading.
    pub predecessor_rollback: Option<RollbackOutlook>,
}

/// How an activation ended without publishing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbortReport {
    pub placement: PlacementKey,
    pub generation: ModelActivationGeneration,
    pub reason: FailureReason,
    /// The failure record, when the placement was in a transient state that fails.
    pub failure: Option<Failure>,
    /// The placement's state afterwards.
    pub state: StateKind,
    /// The ended pause, when the old generation had drained first.
    pub pause: Option<PauseRecord>,
    pub predecessor: Option<PlacementKey>,
    pub predecessor_rollback: Option<RollbackOutlook>,
}

/// A view of the activation in progress.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationView {
    pub operation: OperationId,
    pub generation: ModelActivationGeneration,
    pub placement: PlacementKey,
    pub mode: TransitionMode,
    pub predecessor: Option<PlacementKey>,
    pub runtime_initialized: bool,
    pub waiting_ranks: Vec<Rank>,
    pub started_at: MonotonicTime,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Activation {
    pub(super) operation: OperationId,
    pub(super) generation: ModelActivationGeneration,
    pub(super) placement: PlacementKey,
    pub(super) mode: TransitionMode,
    pub(super) predecessor: Option<PlacementKey>,
    pub(super) components: BTreeMap<WeightPosition, ExtentSpec>,
    pub(super) barrier: RankBarrier,
    pub(super) transition_peak: Option<ReservationId>,
    /// Resident extents step 1 told the reservation authority this activation acquires;
    /// its reservation does not cover allocating them again.
    pub(super) planned_acquire: BTreeSet<ExtentKey>,
    pub(super) runtime_initialized: bool,
    pub(super) started_at: MonotonicTime,
}

/// Checks the request's structure and returns its content by position.
fn check_request(
    request: &ActivationRequest,
) -> Result<BTreeMap<WeightPosition, ExtentSpec>, RequestProblem> {
    if request.layout.is_empty() {
        return Err(RequestProblem::NoRanks);
    }
    if request
        .layout
        .keys()
        .zip(0u64..)
        .any(|(rank, expected)| rank.get() != expected)
    {
        return Err(RequestProblem::RanksNotContiguous);
    }
    if request.components.is_empty() {
        return Err(RequestProblem::NoComponents);
    }
    let mut components = BTreeMap::new();
    let mut sizes: BTreeMap<ExtentKey, u64> = BTreeMap::new();
    for spec in &request.components {
        let position = spec.position;
        let device = request
            .layout
            .get(&position.rank)
            .ok_or(RequestProblem::RankNotInLayout { position })?;
        if spec.extent.device != *device {
            return Err(RequestProblem::DeviceMismatch { position });
        }
        if spec.bytes == 0 {
            return Err(RequestProblem::EmptyExtent { position });
        }
        if let Some(bytes) = sizes.insert(spec.extent, spec.bytes) {
            if bytes != spec.bytes {
                return Err(RequestProblem::ExtentSizeMismatch {
                    extent: spec.extent,
                });
            }
        }
        if components.insert(position, *spec).is_some() {
            return Err(RequestProblem::DuplicatePosition { position });
        }
    }
    if let Some(rank) = request.layout.keys().find(|rank| {
        !components
            .keys()
            .any(|position: &WeightPosition| position.rank == **rank)
    }) {
        return Err(RequestProblem::RankWithoutComponents { rank: *rank });
    }
    if request.declared_shape.max_context_tokens == 0
        || request.declared_shape.max_batch_sequences == 0
    {
        return Err(RequestProblem::EmptyDeclaredShape);
    }
    Ok(components)
}

/// The weights of each adapter component, by adapter index, across ranks.
fn adapter_contents(
    components: &BTreeMap<WeightPosition, ExtentSpec>,
) -> BTreeMap<u32, BTreeSet<ContentKey>> {
    let mut weights: BTreeMap<u32, BTreeSet<ContentKey>> = BTreeMap::new();
    for (position, spec) in components {
        if let Component::Adapter(index) = position.component {
            weights
                .entry(index)
                .or_default()
                .insert(spec.extent.content);
        }
    }
    weights
}

/// Checks that `steady` covers every extent of the content on its device.
fn check_steady(
    steady: &ResourceDemand,
    components: &BTreeMap<WeightPosition, ExtentSpec>,
) -> Result<(), RequestProblem> {
    if steady.is_empty() {
        return Err(RequestProblem::NoSteadyDemand);
    }
    let mut per_device: BTreeMap<GpuDeviceKey, u64> = BTreeMap::new();
    for (extent, bytes) in unique_extents(components.values()) {
        let total = per_device.entry(extent.device).or_insert(0);
        *total = total.saturating_add(bytes);
    }
    for (device, extent_bytes) in per_device {
        let reserved_bytes = steady.vram_bytes_on(&device);
        if extent_bytes > reserved_bytes {
            return Err(RequestProblem::UnderReserved {
                device,
                extent_bytes,
                reserved_bytes,
            });
        }
    }
    Ok(())
}

impl<C: Clock> PlacementSlot<C> {
    /// The activation in progress, if any.
    pub fn activation(&self) -> Option<ActivationView> {
        self.activation.as_ref().map(|activation| ActivationView {
            operation: activation.operation.clone(),
            generation: activation.generation,
            placement: activation.placement,
            mode: activation.mode,
            predecessor: activation.predecessor,
            runtime_initialized: activation.runtime_initialized,
            waiting_ranks: activation.barrier.waiting_for(),
            started_at: activation.started_at,
        })
    }

    /// Step 1: resolves exact identities, allocates the new activation generation and
    /// reserves steady state plus transition peak before anything is created. Overlap is
    /// chosen only when the reservation fits beside the serving generation; otherwise,
    /// if the caller accepts a pause, the old generation starts draining at once and its
    /// reservation passes to the new one.
    pub fn begin_activation(
        &mut self,
        request: &ActivationRequest,
        ports: &mut dyn PlacementPorts,
    ) -> Result<ActivationStarted, ActivationError> {
        if let Some(activation) = &self.activation {
            return Err(ActivationError::ActivationInProgress {
                generation: activation.generation,
            });
        }
        let invalid = |problem| ActivationError::InvalidRequest { problem };
        let components = check_request(request).map_err(invalid)?;
        for spec in components.values() {
            if let Some(resident) = self.extents.get(&spec.extent) {
                if resident.bytes != spec.bytes {
                    return Err(invalid(RequestProblem::ExtentSizeMismatch {
                        extent: spec.extent,
                    }));
                }
            }
        }

        let identity = &request.identity;
        let adapter_weights = adapter_contents(&components);
        if let Some(index) = adapter_weights
            .keys()
            .find(|index| !identity.adapters.contains_key(index))
        {
            return Err(invalid(RequestProblem::AdapterWithoutIdentity {
                index: *index,
            }));
        }
        if let Some(index) = identity
            .adapters
            .keys()
            .find(|index| !adapter_weights.contains_key(index))
        {
            return Err(invalid(RequestProblem::IdentityWithoutAdapter {
                index: *index,
            }));
        }
        // One adapter identity names one set of weights for one execution: an update
        // with other weights needs its own identity (line 599).
        let mut bindings: BTreeMap<(ExecutionIdentity, AdapterIdentity), BTreeSet<ContentKey>> =
            BTreeMap::new();
        for (index, adapter) in &identity.adapters {
            let weights = adapter_weights.get(index).cloned().unwrap_or_default();
            let key = (identity.execution, *adapter);
            let bound = self
                .adapter_contents
                .get(&key)
                .or_else(|| bindings.get(&key));
            if bound.is_some_and(|bound| *bound != weights) {
                return Err(ActivationError::AdapterIdentityReused {
                    adapter: *adapter,
                    index: *index,
                });
            }
            bindings.insert(key, weights);
        }
        if !request.artifact.is_verified_as(&identity.artifact) {
            return Err(ActivationError::ArtifactNotVerified);
        }

        let (reuse, new_process) = match request.placement {
            PlacementChoice::New { process } => (None, Some(process)),
            PlacementChoice::Reuse { placement } => (Some(placement), None),
        };
        let needs_steady = match reuse {
            None => true,
            Some(key) => {
                let placement = self
                    .placements
                    .get(&key)
                    .ok_or(ActivationError::UnknownPlacement { placement: key })?;
                let state = placement.state.kind();
                if !matches!(state, StateKind::Materialized | StateKind::Parked) {
                    return Err(ActivationError::ReuseNotResting {
                        placement: key,
                        state,
                    });
                }
                if placement.execution != identity.execution
                    || placement.artifact_identity != identity.artifact
                    || placement.adapters != identity.adapters
                    || placement.components != components
                    || placement.layout != request.layout
                {
                    return Err(ActivationError::ReuseMismatch { placement: key });
                }
                if !placement
                    .artifact
                    .is_verified_as(&placement.artifact_identity)
                {
                    return Err(ActivationError::ArtifactNotVerified);
                }
                if !placement.process.is_alive() {
                    return Err(ActivationError::ProcessNotAlive { placement: key });
                }
                match &placement.steady {
                    Some(held) if !held.demand.covers(&request.steady) => {
                        return Err(invalid(RequestProblem::SteadyExceedsHeldReservation));
                    }
                    Some(_) => false,
                    None => true,
                }
            }
        };
        if needs_steady {
            check_steady(&request.steady, &components).map_err(invalid)?;
        }

        // Everything that can fail without side effects is checked before the
        // reservation, so a refusal after it never leaves a grant behind.
        let predecessor = self
            .router
            .published()
            .and_then(|generation| self.router.entry(generation))
            .map(|entry| entry.placement);
        let predecessor_draining = match predecessor {
            Some(key) => Some(
                self.placements
                    .get(&key)
                    .ok_or(ActivationError::UnknownPlacement { placement: key })?
                    .state
                    .next(StateKind::Draining)?,
            ),
            None => None,
        };
        let predecessor_steady = predecessor
            .and_then(|key| self.placements.get(&key))
            .and_then(|placement| placement.steady.as_ref())
            .map(|steady| steady.id);
        let preparing = PlacementState::Absent.next(StateKind::Preparing)?;
        let new_key = PlacementKey::new(self.next_placement);
        let following = self
            .next_placement
            .checked_add(1)
            .ok_or(ActivationError::PlacementsExhausted)?;

        let within = if needs_steady {
            None
        } else {
            reuse
                .and_then(|key| self.placements.get(&key))
                .and_then(|placement| placement.steady.as_ref())
                .map(|steady| steady.id)
        };
        let shares = if needs_steady {
            self.acquirable_shares(&components, reuse)
        } else {
            BTreeMap::new()
        };
        let reservation = ReservationRequest {
            slot: self.spec.slot,
            execution: self.spec.owner().clone(),
            operation: request.operation.clone(),
            steady: if needs_steady {
                request.steady.clone()
            } else {
                ResourceDemand::default()
            },
            transition_peak: request.transition_peak.clone(),
            within,
            acquire: shares
                .iter()
                .map(|(holder, share)| (*holder, share.vram_bytes.clone()))
                .collect(),
            extents: unique_extents(components.values()),
        };
        let refused = |mode| move |refusal| ActivationError::Reservation { refusal, mode };
        let (grant, mode, pause_refusal, acquired_from) = match predecessor {
            None => (
                ports
                    .reservations()
                    .reserve(&reservation)
                    .map_err(refused(TransitionMode::Initial))?,
                TransitionMode::Initial,
                None,
                None,
            ),
            Some(_) => match ports.reservations().reserve(&reservation) {
                Ok(grant) => (grant, TransitionMode::Overlap, None, None),
                // Only a capacity refusal can be met by draining first; any other refusal
                // stands.
                Err(ReservationRefusal::Capacity { refusal })
                    if request.preference == TransitionPreference::OverlapOrPause =>
                {
                    let steady =
                        predecessor_steady.ok_or(ActivationError::PredecessorUnreserved)?;
                    // The predecessor's memory passes to its successor whole, so none of
                    // it is acquired.
                    let mut successor = reservation.clone();
                    successor.acquire.remove(&steady);
                    let grant = ports
                        .reservations()
                        .reserve_successor(steady, &successor)
                        .map_err(refused(TransitionMode::DrainFirst))?;
                    (
                        grant,
                        TransitionMode::DrainFirst,
                        Some(refusal),
                        Some(steady),
                    )
                }
                Err(refusal) => {
                    return Err(ActivationError::Reservation {
                        refusal,
                        mode: TransitionMode::Overlap,
                    })
                }
            },
        };
        let planned_acquire: BTreeSet<ExtentKey> = shares
            .into_iter()
            .filter(|(holder, _)| Some(*holder) != acquired_from)
            .flat_map(|(_, share)| share.extents)
            .collect();
        let release_grant = |ports: &mut dyn PlacementPorts| {
            for id in [grant.steady, grant.transition_peak].into_iter().flatten() {
                ports.reservations().release(id);
            }
        };
        // The generation comes after the reservation: an authority that issues
        // generations only with a reservation hands it out here.
        let generation = match ports
            .coordination()
            .next_activation_generation(&self.spec.slot)
        {
            Ok(generation) => generation,
            Err(refusal) => {
                release_grant(ports);
                return Err(ActivationError::Coordination { refusal });
            }
        };
        let incomplete = (!reservation.steady.is_empty() && grant.steady.is_none())
            || (!reservation.transition_peak.is_empty() && grant.transition_peak.is_none());
        let refusal = if incomplete {
            Some(ActivationError::ReservationIncomplete)
        } else if !self.router.is_newer(generation) {
            Some(ActivationError::StaleGeneration { generation })
        } else {
            None
        };
        if let Some(refusal) = refusal {
            release_grant(ports);
            ports
                .coordination()
                .abandon_generation(&self.spec.slot, generation);
            return Err(refusal);
        }

        // From here on nothing fails.
        let now = self.now();
        self.adapter_contents.extend(bindings);
        let steady = grant.steady.map(|id| HeldReservation {
            id,
            demand: request.steady.clone(),
        });
        let key = match reuse {
            Some(key) => {
                if let (Some(placement), Some(steady)) = (self.placements.get_mut(&key), steady) {
                    placement.steady = Some(steady);
                }
                key
            }
            None => {
                self.next_placement = following;
                self.placements.insert(
                    new_key,
                    Placement {
                        state: preparing,
                        execution: identity.execution,
                        artifact_identity: identity.artifact,
                        adapters: identity.adapters.clone(),
                        artifact: request.artifact,
                        process: match new_process {
                            Some(instance) => ProcessLiveness::Alive { instance },
                            None => ProcessLiveness::NoProcess,
                        },
                        layout: request.layout.clone(),
                        components: components.clone(),
                        steady,
                        gate: ReclaimGate::default(),
                    },
                );
                new_key
            }
        };
        if let (Some(refusal), Some(old), Some(draining)) =
            (pause_refusal, predecessor, predecessor_draining)
        {
            self.router.unpublish();
            if let Some(placement) = self.placements.get_mut(&old) {
                placement.state = draining;
            }
            self.pause = Some(PauseRecord {
                reason: PauseReason::SingleGenerationCapacity { refusal },
                started_at: now,
                ended_at: None,
                outcome: None,
            });
        }
        self.activation = Some(Activation {
            operation: request.operation.clone(),
            generation,
            placement: key,
            mode,
            predecessor,
            barrier: RankBarrier::new(
                generation,
                request.layout.keys().copied().collect(),
                request.declared_shape,
            ),
            components,
            transition_peak: grant.transition_peak,
            planned_acquire,
            runtime_initialized: false,
            started_at: now,
        });
        Ok(ActivationStarted {
            generation,
            placement: key,
            mode,
            predecessor,
            pause: self.pause,
        })
    }

    /// Step 2: acquires every extent already resident and allocates the rest. When the
    /// old generation drains first, allocation waits until its placement is reclaimed;
    /// acquiring shared extents does not wait, so they are kept rather than freed.
    pub fn prepare_extents(
        &mut self,
        ports: &mut dyn PlacementPorts,
    ) -> Result<ExtentProgress, ActivationError> {
        let activation = self
            .activation
            .as_ref()
            .ok_or(ActivationError::NoActivation)?;
        let key = activation.placement;
        let placement = self
            .placements
            .get(&key)
            .ok_or(ActivationError::UnknownPlacement { placement: key })?;
        if !matches!(
            placement.state.kind(),
            StateKind::Preparing | StateKind::Parked | StateKind::Materialized
        ) {
            return Err(ActivationError::Transition {
                transition: IllegalTransition {
                    from: placement.state.kind(),
                    to: StateKind::Materialized,
                },
            });
        }
        if !placement
            .artifact
            .is_verified_as(&placement.artifact_identity)
        {
            return Err(ActivationError::ArtifactNotVerified);
        }
        let capacity_ready = activation.mode != TransitionMode::DrainFirst
            || activation.predecessor.is_none_or(|old| {
                self.placements
                    .get(&old)
                    .is_none_or(|placement| placement.steady.is_none())
            });
        let unique = unique_extents(activation.components.values());

        if let Some(extent) = activation
            .planned_acquire
            .iter()
            .find(|extent| !self.extents.holds(key, extent) && self.extents.get(extent).is_none())
        {
            return Err(ActivationError::PlannedExtentGone { extent: *extent });
        }

        let mut progress = ExtentProgress::default();
        let mut missing = Vec::new();
        for (extent, bytes) in &unique {
            if self.extents.holds(key, extent) {
                continue;
            }
            match self.extents.acquire(extent, key) {
                Acquired::Shared => progress.acquired.push(*extent),
                Acquired::NotUsable => progress.waiting_for_other_holders.push(*extent),
                Acquired::NotResident => missing.push((*extent, *bytes)),
            }
        }
        if capacity_ready {
            for (extent, bytes) in missing {
                let allocation = ports
                    .coordination()
                    .extent_allocation(&self.spec.slot, &extent)
                    .map_err(|refusal| ActivationError::Coordination { refusal })?;
                self.extents
                    .insert_allocated(extent, bytes, allocation, key);
                progress.allocated.push((extent, allocation));
            }
        } else {
            progress.waiting_for_predecessor =
                missing.into_iter().map(|(extent, _)| extent).collect();
        }
        progress.not_yet_usable = unique
            .keys()
            .filter(|extent| self.extents.holds(key, extent) && !self.extents.is_usable(extent))
            .copied()
            .collect();
        Ok(progress)
    }

    /// Step 2: an allocated extent was populated and verified, so computation may use
    /// it (§2.6 "usable").
    pub fn record_extent_usable(&mut self, extent: ExtentKey) -> Result<(), ActivationError> {
        let activation = self
            .activation
            .as_ref()
            .ok_or(ActivationError::NoActivation)?;
        if !activation
            .components
            .values()
            .any(|spec| spec.extent == extent)
            || !self.extents.holds(activation.placement, &extent)
        {
            return Err(ActivationError::UnknownExtent { extent });
        }
        self.extents.mark_usable(&extent);
        Ok(())
    }

    /// Step 2: an extent could not be made usable; the activation fails.
    pub fn record_extent_failed(
        &mut self,
        extent: ExtentKey,
        ports: &mut dyn PlacementPorts,
    ) -> Result<AbortReport, ActivationError> {
        let activation = self
            .activation
            .take()
            .ok_or(ActivationError::NoActivation)?;
        if !activation
            .components
            .values()
            .any(|spec| spec.extent == extent)
        {
            self.activation = Some(activation);
            return Err(ActivationError::UnknownExtent { extent });
        }
        Ok(self.abort(activation, FailureReason::ExtentFailed { extent }, ports))
    }

    /// Step 2: the runtime state the generation needs is initialized.
    pub fn record_runtime_initialized(&mut self) -> Result<(), ActivationError> {
        let activation = self
            .activation
            .as_mut()
            .ok_or(ActivationError::NoActivation)?;
        let key = activation.placement;
        let placement = self
            .placements
            .get(&key)
            .ok_or(ActivationError::UnknownPlacement { placement: key })?;
        if !placement.process.is_alive() {
            return Err(ActivationError::ProcessNotAlive { placement: key });
        }
        activation.runtime_initialized = true;
        Ok(())
    }

    /// Step 2: runtime state could not be initialized; the activation fails.
    pub fn record_runtime_failed(
        &mut self,
        ports: &mut dyn PlacementPorts,
    ) -> Result<AbortReport, ActivationError> {
        let activation = self
            .activation
            .take()
            .ok_or(ActivationError::NoActivation)?;
        Ok(self.abort(
            activation,
            FailureReason::RuntimeInitializationFailed,
            ports,
        ))
    }

    /// Completes step 2: preparing (or parked) → materialized once every extent is held
    /// and usable and runtime state is initialized.
    pub fn materialize(&mut self) -> Result<(), ActivationError> {
        let activation = self
            .activation
            .as_ref()
            .ok_or(ActivationError::NoActivation)?;
        let key = activation.placement;
        let placement = self
            .placements
            .get(&key)
            .ok_or(ActivationError::UnknownPlacement { placement: key })?;
        if !placement
            .artifact
            .is_verified_as(&placement.artifact_identity)
        {
            return Err(ActivationError::ArtifactNotVerified);
        }
        let waiting = self.waiting_extents(activation);
        if !waiting.is_empty() {
            return Err(ActivationError::ExtentsNotUsable { waiting });
        }
        if !activation.runtime_initialized {
            return Err(ActivationError::RuntimeNotInitialized);
        }
        if !placement.process.is_alive() {
            return Err(ActivationError::ProcessNotAlive { placement: key });
        }
        if placement.state.kind() == StateKind::Materialized {
            return Ok(());
        }
        let next = placement.state.next(StateKind::Materialized)?;
        if let Some(placement) = self.placements.get_mut(&key) {
            placement.state = next;
        }
        Ok(())
    }

    /// Begins steps 3–4: materialized → activating.
    pub fn begin_activating(&mut self) -> Result<(), ActivationError> {
        let activation = self
            .activation
            .as_ref()
            .ok_or(ActivationError::NoActivation)?;
        let key = activation.placement;
        let placement = self
            .placements
            .get(&key)
            .ok_or(ActivationError::UnknownPlacement { placement: key })?;
        if matches!(
            placement.state.kind(),
            StateKind::Preparing | StateKind::Parked
        ) {
            return Err(ActivationError::OutOfOrder {
                attempted: ProtocolStep::Validate,
                missing: ProtocolStep::AcquireAndInitialize,
            });
        }
        let next = placement.state.next(StateKind::Activating)?;
        if let Some(placement) = self.placements.get_mut(&key) {
            placement.state = next;
        }
        Ok(())
    }

    /// Step 3 for one rank. A failed check fails the activation.
    pub fn record_validation(
        &mut self,
        report: &ValidationReport,
        ports: &mut dyn PlacementPorts,
    ) -> Result<(), ActivationError> {
        self.record_rank_step(ProtocolStep::Validate, ports, |barrier| {
            barrier.record_validation(report)
        })
    }

    /// Step 4 for one rank. A failed check, or readiness for less than the declared
    /// shape, fails the activation.
    pub fn record_readiness(
        &mut self,
        generation: ModelActivationGeneration,
        rank: Rank,
        report: &ReadinessReport,
        ports: &mut dyn PlacementPorts,
    ) -> Result<(), ActivationError> {
        self.record_rank_step(ProtocolStep::CheckReadiness, ports, |barrier| {
            barrier.record_readiness(generation, rank, report)
        })
    }

    fn record_rank_step(
        &mut self,
        step: ProtocolStep,
        ports: &mut dyn PlacementPorts,
        record: impl FnOnce(&mut RankBarrier) -> Result<(), BarrierError>,
    ) -> Result<(), ActivationError> {
        let activation = self
            .activation
            .as_mut()
            .ok_or(ActivationError::NoActivation)?;
        let state = self
            .placements
            .get(&activation.placement)
            .map(|placement| placement.state.kind());
        if state != Some(StateKind::Activating) {
            return Err(ActivationError::OutOfOrder {
                attempted: step,
                missing: ProtocolStep::AcquireAndInitialize,
            });
        }
        match record(&mut activation.barrier) {
            Ok(()) => Ok(()),
            Err(BarrierError::Failed(reason)) => {
                let report = match self.activation.take() {
                    Some(activation) => self.abort(activation, reason, ports),
                    None => return Err(ActivationError::NoActivation),
                };
                Err(ActivationError::Failed { report })
            }
            Err(error) => Err(ActivationError::Barrier { error }),
        }
    }

    /// Step 5: publishes the new generation to the router in one step. New requests get
    /// it from now on; requests admitted earlier keep the generation they hold, which
    /// stops admitting and drains (step 6). The transition peak is released; the
    /// predecessor keeps its resources until it is reclaimed (step 7).
    pub fn publish(
        &mut self,
        ports: &mut dyn PlacementPorts,
    ) -> Result<PublishReport, ActivationError> {
        let now = self.now();
        let activation = self
            .activation
            .as_ref()
            .ok_or(ActivationError::NoActivation)?;
        let key = activation.placement;
        let placement = self
            .placements
            .get(&key)
            .ok_or(ActivationError::UnknownPlacement { placement: key })?;
        if placement.state.kind() != StateKind::Activating {
            return Err(ActivationError::OutOfOrder {
                attempted: ProtocolStep::Publish,
                missing: ProtocolStep::Validate,
            });
        }
        if !activation.barrier.all_validated() {
            return Err(ActivationError::BarrierIncomplete {
                missing: ProtocolStep::Validate,
                waiting: activation.barrier.waiting_for(),
            });
        }
        if !activation.barrier.is_complete() {
            return Err(ActivationError::BarrierIncomplete {
                missing: ProtocolStep::CheckReadiness,
                waiting: activation.barrier.waiting_for(),
            });
        }
        if !placement
            .artifact
            .is_verified_as(&placement.artifact_identity)
        {
            return Err(ActivationError::ArtifactNotVerified);
        }
        if !placement.process.is_alive() {
            return Err(ActivationError::ProcessNotAlive { placement: key });
        }
        let waiting = self.waiting_extents(activation);
        if !waiting.is_empty() {
            return Err(ActivationError::ExtentsNotUsable { waiting });
        }
        let generation = activation.generation;
        if !self.router.is_newer(generation) {
            return Err(ActivationError::StaleGeneration { generation });
        }
        let serving = placement.state.next(StateKind::Serving)?;
        let predecessor_draining = match (activation.mode, activation.predecessor) {
            (TransitionMode::Overlap, Some(old)) => match self.placements.get(&old) {
                Some(old_placement) if old_placement.state.kind() == StateKind::Serving => {
                    Some((old, old_placement.state.next(StateKind::Draining)?))
                }
                _ => None,
            },
            _ => None,
        };
        let content = ActivationContent {
            generation,
            execution: placement.execution,
            artifact: placement.artifact_identity,
            adapters: placement.adapters.clone(),
            components: activation
                .components
                .iter()
                .map(|(position, spec)| (*position, spec.extent))
                .collect(),
        };
        let mut leases = BTreeMap::new();
        if let Some(early) = self
            .early
            .as_ref()
            .filter(|early| early.generation == generation && !early.ended)
        {
            leases.insert(
                early.request.clone(),
                HeldLease {
                    kind: LeaseKind::Preparation,
                    lease: early.lease,
                },
            );
        }
        let entry = GenerationEntry {
            placement: key,
            content,
            supported: activation.barrier.declared(),
            published_at: now,
            leases,
        };
        let mode = activation.mode;
        let predecessor = activation.predecessor;
        let transition_peak = activation.transition_peak;
        ports
            .coordination()
            .publish_generation(&self.spec.slot, generation)
            .map_err(|refusal| ActivationError::Coordination { refusal })?;

        // From here on nothing fails.
        let previous = self.router.publish(entry);
        if let Some(placement) = self.placements.get_mut(&key) {
            placement.state = serving;
        }
        if let Some((old, draining)) = predecessor_draining {
            if let Some(placement) = self.placements.get_mut(&old) {
                placement.state = draining;
            }
        }
        if let Some(early) = self
            .early
            .as_mut()
            .filter(|early| early.generation == generation && !early.ended)
        {
            early.lease_in_router = true;
        }
        if let Some(peak) = transition_peak {
            ports.reservations().release(peak);
        }
        let pause = self.pause.take().map(|mut pause| {
            pause.ended_at = Some(now);
            pause.outcome = Some(PauseOutcome::Resumed { generation });
            pause
        });
        self.activation = None;
        let predecessor_rollback = predecessor.and_then(|old| self.rollback_outlook(old).ok());
        Ok(PublishReport {
            generation,
            placement: key,
            previous,
            mode,
            predecessor,
            pause,
            predecessor_rollback,
        })
    }

    /// Cancels the activation in progress. A preparing placement fails with reason
    /// cancelled; an activating one drains (activating → draining) and can then be
    /// parked and reused; a materialized or parked one stays as it is.
    pub fn cancel_activation(
        &mut self,
        ports: &mut dyn PlacementPorts,
    ) -> Result<AbortReport, ActivationError> {
        let activation = self
            .activation
            .take()
            .ok_or(ActivationError::NoActivation)?;
        Ok(self.abort(activation, FailureReason::Cancelled, ports))
    }

    /// Ends an activation without publishing: releases the transition peak and the
    /// preparation lease and ends a pause. The serving generation of an overlap is not
    /// touched, so a failed preparation preserves the old serving state.
    pub(super) fn abort_activation(
        &mut self,
        reason: FailureReason,
        ports: &mut dyn PlacementPorts,
    ) -> AbortOutcome {
        match self.activation.take() {
            Some(activation) => AbortOutcome {
                failure: self.abort(activation, reason, ports).failure,
            },
            None => AbortOutcome { failure: None },
        }
    }

    fn abort(
        &mut self,
        activation: Activation,
        reason: FailureReason,
        ports: &mut dyn PlacementPorts,
    ) -> AbortReport {
        let now = self.now();
        let key = activation.placement;
        let mut failure = None;
        let mut state = StateKind::Absent;
        if let Some(placement) = self.placements.get_mut(&key) {
            match (placement.state.kind(), reason) {
                (StateKind::Activating, FailureReason::Cancelled) => {
                    if let Ok(draining) = placement.state.next(StateKind::Draining) {
                        placement.state = draining;
                    }
                }
                (StateKind::Preparing | StateKind::Activating, _) => {
                    failure = placement.state.fail(reason, now).ok();
                }
                _ => {}
            }
            state = placement.state.kind();
        }
        if let Some(peak) = activation.transition_peak {
            ports.reservations().release(peak);
        }
        if let Some(early) = self
            .early
            .as_mut()
            .filter(|early| early.generation == activation.generation && !early.ended)
        {
            ports.coordination().release_lease(early.lease);
            early.ended = true;
        }
        ports
            .coordination()
            .abandon_generation(&self.spec.slot, activation.generation);
        let pause = self.pause.take().map(|mut pause| {
            pause.ended_at = Some(now);
            pause.outcome = Some(PauseOutcome::ActivationFailed);
            pause
        });
        if let Some(failure) = failure {
            self.last_failure = Some((key, failure));
        }
        let predecessor_rollback = activation
            .predecessor
            .and_then(|old| self.rollback_outlook(old).ok());
        AbortReport {
            placement: key,
            generation: activation.generation,
            reason,
            failure,
            state,
            pause,
            predecessor: activation.predecessor,
            predecessor_rollback,
        }
    }

    /// The resident, usable extents of `components` other placements hold, by the steady
    /// reservation of one holder each: what step 2 will acquire rather than allocate.
    fn acquirable_shares(
        &self,
        components: &BTreeMap<WeightPosition, ExtentSpec>,
        reuse: Option<PlacementKey>,
    ) -> BTreeMap<ReservationId, Share> {
        let mut shares: BTreeMap<ReservationId, Share> = BTreeMap::new();
        for (extent, bytes) in unique_extents(components.values()) {
            let Some(resident) = self.extents.get(&extent).filter(|resident| resident.usable)
            else {
                continue;
            };
            if reuse.is_some_and(|key| resident.holders.contains(&key)) {
                continue;
            }
            let holder = resident.holders.iter().find_map(|holder| {
                self.placements
                    .get(holder)
                    .and_then(|placement| placement.steady.as_ref())
                    .map(|steady| steady.id)
            });
            if let Some(holder) = holder {
                let share = shares.entry(holder).or_default();
                let covered = share.vram_bytes.entry(extent.device).or_insert(0);
                *covered = covered.saturating_add(bytes);
                share.extents.insert(extent);
            }
        }
        shares
    }

    /// Extents of the activation that are not held and usable.
    fn waiting_extents(&self, activation: &Activation) -> Vec<ExtentKey> {
        unique_extents(activation.components.values())
            .into_keys()
            .filter(|extent| {
                !(self.extents.holds(activation.placement, extent)
                    && self.extents.is_usable(extent))
            })
            .collect()
    }
}

/// Resident extents of one other placement an activation will acquire.
#[derive(Default)]
struct Share {
    vram_bytes: BTreeMap<GpuDeviceKey, u64>,
    extents: BTreeSet<ExtentKey>,
}

/// The failure an internal abort recorded, if any.
pub(super) struct AbortOutcome {
    pub(super) failure: Option<Failure>,
}
