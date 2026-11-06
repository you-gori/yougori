//! The GPU §1 flow over the five boundaries (lines 272–295):
//!
//! 1. exact model and request;
//! 2. plan dependencies (T06 request graph) from the catalog and the runners' rechecked
//!    residencies, then reserve capacity through the placement governor: the activation's
//!    §2.7 demand comes from T08, the catalog verifies the artifact it serves, and the
//!    ledger, through the placement's P04 slot and the coordinator, grants it;
//! 3. if a compatible engine is ready, take an execution lease (T09) and serve;
//! 4. otherwise transfer or reconstruct only the missing state, verify it, publish
//!    dependency events, mark each immutable extent usable in the slot, and activate a
//!    compatible generation, computing ahead for the request while later state loads only
//!    under a preparation-generation lease, which ends before the request is served. When
//!    the new generation cannot be resident beside the serving one and the request or its
//!    placement consents, serving pauses for a reload (GPU-W05 line 110): the request is
//!    refused with the pause's status until the old generation drained, then the runner
//!    frees the old KV and contexts, their memory passes to the new generation, and the
//!    state they held is made again;
//! 5. lease, serve, release leases and keep valuable state (T08).
//!
//! The three paths of §1 fall out of the plan: ready nodes are skipped (use what is
//! ready), only missing nodes are transferred or reconstructed (materialize only what is
//! missing), and transfers run in the background while the flow reconstructs (overlap the
//! rest). Compatibility, the runner's parent execution and the security partition are
//! checked before admission (§3.9, S3.1, S3.6). Ready state comes only from residencies
//! that passed the T07 recheck against the coordinator's record and are bound to the
//! request's parent execution and epoch (line 506, S3.1). A failure releases everything
//! still held; state made for an activation that never published is discarded, because
//! the activation's GPU reservation goes with it.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use serde::Serialize;

use super::abi::CheckedRunner;
use super::api::{ApiAdapter, Intent};
use super::catalog::{ArtifactCatalog, CatalogRefusal, ExtentRef, VerifiedRepresentation};
use super::declaration::{
    ComputeGroup, DependencyNode, ExecutionDependencies, Materialization, NodeId,
    SecurityPartition, StateIdentity, StateRef,
};
use super::demand::{activation_demand, ActivationDemand, DemandError, DeviceBudget};
use super::executor::{
    ExtentCompletion, OrderRefusal, OrderedExtent, TransferExecutor, TransferFailure,
    TransferOrder, TransferRefusal, TransferTicket,
};
use super::governor::{
    ActivationExtent, ActivationSpec, AdmissionRefusal, AdmissionRequest, ExecutionLease,
    GovernorError, LedgerGrant, PendingActivation, PendingRefusal, PlacementGovernor, PlacementKey,
    PlacementOwner, PreparationLease, RequestAuthority, Shortfall, TransferBudget,
};
use super::kv::{KvLayout, KvSpec};
use super::planning::{plan_dependencies, DependencyPlan, PlanFault, RecheckedState};
use super::preparation::PreparationToken;
use super::retention::{retain_session, served_session, SessionRetention};
use super::runner::{
    ActivationOrder, Compatibility, ComputeAssignment, DependencyEvent, Incompatibility,
    RequestPayload, ResidentState, RunnerAdapter, RunnerRefusal, ServeOrder,
};
use crate::foundation::coordination::ModelRefusal;
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{
    AuthorizationEpoch, Clock, ContentKey, ExecutionCategory, ExecutionId,
    ModelActivationGeneration, MonotonicTime, OperationId, TenantId, TrustScope,
};
use crate::model_memory::graph::node::NodeKind;
use crate::model_memory::identity::{
    check_grant, AdvertisementPurpose, AdvertisementRefusal, AdvertisementRequest,
    ArtifactIdentity, AuthorityBinding, CurrentResidency, ExecutionIdentity, GrantNeed, GrantedUse,
    RecheckedResidency, Residency, ScopedGrant,
};
use crate::model_memory::math::overlap::{
    finish_times, ideal_finish_seconds, no_stall, GroupTiming, NoStall, OverlapError,
};
use crate::model_memory::placement::{
    CoordinationRefusal, EarlyRefusal, RequestShape, SupportedShape,
};
use crate::model_memory::residency::eviction::CopyTier;

/// The authority context of one request: its parent execution, operation, tenant,
/// authorization epoch (S3.1), security partition (S3.6) and the scoped grants it holds
/// for resident state (S3.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestContext {
    pub execution: ExecutionId,
    pub operation: OperationId,
    pub tenant: TenantId,
    pub epoch: AuthorizationEpoch,
    pub partition: SecurityPartition,
    pub grants: Vec<ScopedGrant>,
}

/// One exact request (GPU §1 step 1).
#[derive(Clone, Debug)]
pub struct ExactRequest {
    pub context: RequestContext,
    pub intent: Intent,
    pub payload: RequestPayload,
}

/// The five boundaries one request runs over. Only ABI-checked runners can be listed.
pub struct Boundaries<'b> {
    pub catalog: &'b dyn ArtifactCatalog,
    pub governor: &'b mut dyn PlacementGovernor,
    pub executor: &'b mut dyn TransferExecutor,
    pub runners: Vec<CheckedRunner<'b>>,
    pub api: &'b mut dyn ApiAdapter,
}

/// One step of the flow, as the nodes of the §1 diagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum FlowPhase {
    Requested,
    Planned {
        ready_nodes: u32,
        missing_nodes: u32,
        not_needed_nodes: u32,
    },
    Reserved,
    ReadyEngine,
    MissingState,
    PreparationLeased,
    /// Another request is assigned to the pending generation, or its memory waits for a
    /// drain-first handover, so nothing is computed ahead and nothing weaker is used
    /// (line 601).
    ComputeAheadRefused,
    TransferStarted,
    ExtentVerified,
    DependencyPublished,
    ComputedAhead {
        group: u32,
    },
    /// Every transfer chain completed, so staging was recycled (§3.5 step 8).
    StagingReleased,
    /// A reload's old generation drained and the runner freed its KV and contexts, whose
    /// memory passed to the new generation (GPU-W05 line 110).
    HandedOver {
        drained: ModelActivationGeneration,
    },
    /// The new generation was abandoned without publishing. With transition capacity
    /// reserved the old generation kept serving; without it, nothing serves until another
    /// activation succeeds (GPU-W05 acceptance).
    ActivationAbandoned {
        transition_capacity_reserved: bool,
        old_generation_serving: bool,
    },
    Activated,
    LeaseAcquired,
    PreparationReleased,
    Served,
    LeaseReleased,
    StateRetained {
        kept_nodes: u32,
        session: SessionRetention,
    },
}

/// One progress event (GPU §3.10 fields the flow knows). It carries no handle, lease,
/// grant or payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FlowEvent {
    pub operation: OperationId,
    /// Starts at 1 for each request and rises by one per event.
    pub sequence: u64,
    pub at: MonotonicTime,
    pub phase: FlowPhase,
    pub generation: Option<ModelActivationGeneration>,
    pub resource: Option<NodeId>,
    pub completed_bytes: u64,
    pub total_bytes: u64,
    pub committed_usable_bytes: u64,
}

/// Why a request was refused or failed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "flow_error", rename_all = "snake_case")]
pub enum FlowError {
    /// No admitted runner is compatible, in the request's parent execution and inside
    /// the partition.
    NoCompatibleRunner {
        reasons: Vec<(PlacementOwner, Incompatibility)>,
    },
    Plan {
        fault: PlanFault,
    },
    /// An identity could not be formed, such as an authority binding.
    Identity {
        reason: String,
    },
    /// T08 refused the activation's demand model-side.
    Demand {
        error: DemandError,
    },
    Admission {
        refusal: AdmissionRefusal,
    },
    /// The governor's admission does not cover what was asked.
    AdmissionShort {
        shortfall: Shortfall,
    },
    Catalog {
        refusal: CatalogRefusal,
    },
    Order {
        refusal: OrderRefusal,
    },
    MissingTransferBudget,
    TransferRefused {
        refusal: TransferRefusal,
    },
    Transfer {
        failure: TransferFailure,
    },
    /// The executor delivered something other than the ordered extent.
    ExecutorSwitchedModel {
        requested: ExtentRef,
        delivered: ExtentRef,
    },
    /// The executor's verified content key is not the ordered one.
    DigestMismatch {
        extent: ExtentRef,
        expected: ContentKey,
        delivered: ContentKey,
    },
    /// The bytes came from a source that is never a read source (Appendix A.3).
    NotAReadSource {
        extent: ExtentRef,
    },
    TransferBudgetExceeded {
        budget_bytes: u64,
        read_bytes: u64,
    },
    Runner {
        refusal: RunnerRefusal,
    },
    Governor {
        error: GovernorError,
    },
    /// The generation published or served is not the one prepared or leased.
    GenerationChanged {
        expected: ModelActivationGeneration,
        actual: ModelActivationGeneration,
    },
    /// These missing nodes depend on state that never becomes usable.
    Unsatisfiable {
        remaining: Vec<NodeId>,
    },
    Overlap {
        reason: String,
    },
    Overflow {
        field: &'static str,
    },
    /// The request failed, and releasing what it held failed too.
    RollbackIncomplete {
        cause: Box<FlowError>,
        errors: Vec<GovernorError>,
    },
}

impl fmt::Display for FlowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCompatibleRunner { reasons } => write!(
                f,
                "no runner can serve this exact model ({} considered)",
                reasons.len()
            ),
            Self::Plan { fault } => fault.fmt(f),
            Self::Identity { reason } => write!(f, "identity: {reason}"),
            Self::Demand { error } => error.fmt(f),
            Self::Admission { refusal } => refusal.fmt(f),
            Self::AdmissionShort { .. } => {
                f.write_str("the admission does not cover the model's demand")
            }
            Self::Catalog { refusal } => refusal.fmt(f),
            Self::Order { refusal } => refusal.fmt(f),
            Self::MissingTransferBudget => f.write_str("no transfer budget was admitted"),
            Self::TransferRefused { refusal } => refusal.fmt(f),
            Self::Transfer { failure } => failure.fmt(f),
            Self::ExecutorSwitchedModel { .. } => {
                f.write_str("the transfer delivered something other than the ordered model")
            }
            Self::DigestMismatch { .. } => {
                f.write_str("the transferred state does not match its identity")
            }
            Self::NotAReadSource { .. } => {
                f.write_str("the transfer read from a source that is never a read source")
            }
            Self::TransferBudgetExceeded { .. } => {
                f.write_str("the transfer read more than its budget")
            }
            Self::Runner { refusal } => refusal.fmt(f),
            Self::Governor { error } => error.fmt(f),
            Self::GenerationChanged { expected, actual } => {
                write!(
                    f,
                    "generation {actual} is not the expected generation {expected}"
                )
            }
            Self::Unsatisfiable { remaining } => {
                write!(
                    f,
                    "{} required states can never become usable",
                    remaining.len()
                )
            }
            Self::Overlap { reason } => write!(f, "overlap model: {reason}"),
            Self::Overflow { field } => write!(f, "{field} does not fit in 64 bits"),
            Self::RollbackIncomplete { cause, errors } => write!(
                f,
                "{cause}; {} reservations or leases could not be released",
                errors.len()
            ),
        }
    }
}

impl std::error::Error for FlowError {}

impl From<GovernorError> for FlowError {
    fn from(error: GovernorError) -> Self {
        Self::Governor { error }
    }
}

impl From<RunnerRefusal> for FlowError {
    fn from(refusal: RunnerRefusal) -> Self {
        Self::Runner { refusal }
    }
}

impl From<PlanFault> for FlowError {
    fn from(fault: PlanFault) -> Self {
        Self::Plan { fault }
    }
}

/// Which §1 path served the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServePath {
    /// A compatible engine was ready: nothing was transferred, reconstructed or
    /// activated.
    Ready,
    /// Missing state was materialized and a new generation activated.
    Materialized,
}

/// Why a runner's residency contributed no ready state (line 506, S3.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HintRefusal {
    /// Coordination holds no serving record of the advertised residency.
    NoRecord { model: ExecutionIdentity },
    /// The T07 recheck refused the advertisement.
    Recheck {
        model: ExecutionIdentity,
        refusal: AdvertisementRefusal,
    },
    /// The residency is bound to another parent execution or authorization epoch, and
    /// nothing bound to an older epoch is honoured again (S3.1).
    OtherAuthority { model: ExecutionIdentity },
}

/// The §2.6 execute-while-load recurrence over the measured times each compute group's
/// inputs became usable, relative to the request: `f_i = max(a_i, f_(i-1)) + t_i`. With
/// compute ahead allowed this is what happened; without it, what it would have achieved.
#[derive(Clone, Debug, PartialEq)]
pub struct OverlapReport {
    pub group_usable_at_seconds: Vec<f64>,
    pub group_compute_seconds: Vec<f64>,
    pub group_finish_seconds: Vec<f64>,
    /// `a_1 + sum t_i`: the finish had loading never stalled computation.
    pub ideal_finish_seconds: f64,
    pub no_stall: NoStall,
}

/// A served request.
#[derive(Clone, Debug, PartialEq)]
pub struct ServeReceipt {
    pub operation: OperationId,
    pub path: ServePath,
    pub placement: PlacementKey,
    pub generation: ModelActivationGeneration,
    pub transferred: Vec<NodeId>,
    pub reconstructed: Vec<NodeId>,
    /// Missing nodes consumed only by ready state, so never materialized.
    pub not_needed: Vec<NodeId>,
    /// Why residencies of the chosen runner contributed no ready state.
    pub hint_refusals: Vec<HintRefusal>,
    pub computed_ahead_groups: u32,
    /// Why nothing was computed ahead although the caller and the backend allowed it.
    pub compute_ahead_refusal: Option<GovernorError>,
    /// GPU memory the ledger granted the new activation; zero on the ready path.
    pub reserved_device_bytes: u64,
    /// When the request graph's schedule expected the first token.
    pub planned_first_token_at: MonotonicTime,
    /// Scheduled work the plan overlapped (§1 path 3).
    pub planned_overlap: Duration,
    /// When the runner produced the first token.
    pub first_token_at: MonotonicTime,
    pub overlap: Option<OverlapReport>,
    pub session: SessionRetention,
    /// The drained generation whose memory a reload's new generation took, if serving
    /// paused for one (GPU-W05 line 110).
    pub handed_over: Option<ModelActivationGeneration>,
}

/// Runs one exact request through the flow. Every event goes to the API adapter as it
/// happens; a refusal or failure goes to it too, after everything held is released.
pub fn serve(
    clock: &dyn Clock,
    boundaries: &mut Boundaries<'_>,
    request: &ExactRequest,
) -> Result<ServeReceipt, FlowError> {
    let Boundaries {
        catalog,
        governor,
        executor,
        runners,
        api,
    } = boundaries;
    let context = &request.context;
    let mut run = Run {
        clock,
        catalog: *catalog,
        governor: &mut **governor,
        executor: &mut **executor,
        api: &mut **api,
        request,
        authority: RequestAuthority {
            execution: context.execution.clone(),
            operation: context.operation.clone(),
            tenant: context.tenant.clone(),
            epoch: context.epoch,
        },
        started_at: clock.now(),
        sequence: 0,
    };
    let result = run.execute(runners);
    if let Err(error) = &result {
        run.api.refusal(&context.operation, error);
    }
    result
}

/// What one event says besides its phase.
#[derive(Default)]
struct Note {
    generation: Option<ModelActivationGeneration>,
    resource: Option<NodeId>,
    completed_bytes: u64,
    total_bytes: u64,
    committed_usable_bytes: u64,
}

impl Note {
    fn generation(generation: ModelActivationGeneration) -> Self {
        Self {
            generation: Some(generation),
            ..Self::default()
        }
    }
}

/// A residency that passed every check, with what the runner holds under it.
struct Accepted {
    rechecked: RecheckedResidency,
    resident: BTreeSet<StateIdentity>,
    ready_for: SupportedShape,
}

/// The runner chosen for a request and its plan.
struct Prepared {
    index: usize,
    placement: PlacementKey,
    scope: TrustScope,
    authority: AuthorityBinding,
    budget: DeviceBudget,
    dependencies: ExecutionDependencies,
    plan: DependencyPlan,
    ready: Option<ModelActivationGeneration>,
    hint_refusals: Vec<HintRefusal>,
    execute_while_load: bool,
    kv_write_back: Option<CopyTier>,
    /// The KV layout the runner declares for the model and shape.
    kv_layout: Option<KvLayout>,
    missing_device_bytes: u64,
    ordered: Vec<OrderedExtent>,
}

impl Prepared {
    fn node(&self, id: NodeId) -> Option<&DependencyNode> {
        self.dependencies.node(id)
    }

    /// A ready engine wins; otherwise the runner with the least missing state; the first
    /// listed wins a tie.
    fn better_than(&self, other: &Prepared) -> bool {
        match (self.ready.is_some(), other.ready.is_some()) {
            (true, false) => true,
            (false, true) => false,
            _ => self.missing_device_bytes < other.missing_device_bytes,
        }
    }
}

/// Everything a request holds while it runs; released on failure.
#[derive(Default)]
struct Held {
    staging: Option<LedgerGrant>,
    budget: Option<TransferBudget>,
    pending: Option<PendingActivation>,
    preparation: Option<PreparationLease>,
    execution: Option<ExecutionLease>,
    ticket: Option<TransferTicket>,
    /// State made usable in the runner for the pending activation; it goes with the
    /// activation's GPU reservation if the activation never publishes.
    materialized: Vec<StateIdentity>,
    /// A generation the runner validated that is not published yet.
    activated: Option<ModelActivationGeneration>,
    /// The runner holds KV for the request's session.
    session_started: bool,
    reserved_device_bytes: u64,
    /// A reload's drained generation, until the runner frees its KV and contexts.
    handover: Option<ModelActivationGeneration>,
    /// The drained generation whose memory passed to the pending activation.
    handed_over: Option<ModelActivationGeneration>,
}

/// What the materialization did, carried into the receipt.
#[derive(Default)]
struct Progress {
    transferred: Vec<NodeId>,
    reconstructed: Vec<NodeId>,
    computed_ahead: u32,
    compute_ahead_refusal: Option<GovernorError>,
    overlap: Option<OverlapReport>,
}

struct Run<'r> {
    clock: &'r dyn Clock,
    catalog: &'r dyn ArtifactCatalog,
    governor: &'r mut dyn PlacementGovernor,
    executor: &'r mut dyn TransferExecutor,
    api: &'r mut dyn ApiAdapter,
    request: &'r ExactRequest,
    authority: RequestAuthority,
    started_at: MonotonicTime,
    sequence: u64,
}

impl Run<'_> {
    fn emit(&mut self, phase: FlowPhase, note: Note) {
        self.sequence = self.sequence.saturating_add(1);
        let event = FlowEvent {
            operation: self.request.context.operation.clone(),
            sequence: self.sequence,
            at: self.clock.now(),
            phase,
            generation: note.generation,
            resource: note.resource,
            completed_bytes: note.completed_bytes,
            total_bytes: note.total_bytes,
            committed_usable_bytes: note.committed_usable_bytes,
        };
        self.api.progress(&event);
    }

    fn intent(&self) -> &Intent {
        &self.request.intent
    }

    fn execute(&mut self, runners: &mut [CheckedRunner<'_>]) -> Result<ServeReceipt, FlowError> {
        self.emit(FlowPhase::Requested, Note::default());
        let mut prepared = self.select(runners)?;
        prepared.ordered = self.order_extents(&prepared)?;
        let transfer_bytes = prepared
            .ordered
            .iter()
            .try_fold(0u64, |total, ordered| {
                total.checked_add(ordered.length_bytes)
            })
            .ok_or(FlowError::Overflow {
                field: "transfer bytes",
            })?;
        self.emit(
            FlowPhase::Planned {
                ready_nodes: count(prepared.plan.ready.len()),
                missing_nodes: count(prepared.plan.missing.len()),
                not_needed_nodes: count(prepared.plan.not_needed.len()),
            },
            Note {
                total_bytes: transfer_bytes,
                ..Note::default()
            },
        );

        let (activation, spec) = match prepared.ready {
            Some(_) => (None, None),
            None => {
                let held: Vec<NodeId> = prepared
                    .dependencies
                    .nodes
                    .iter()
                    .map(|node| node.id)
                    .filter(|id| {
                        prepared.plan.ready.contains(id) || prepared.plan.missing.contains(id)
                    })
                    .collect();
                let demand = activation_demand(
                    &prepared.dependencies,
                    &held,
                    prepared.scope,
                    &prepared.budget,
                    self.clock.now(),
                )
                .map_err(|error| FlowError::Demand { error })?;
                let spec = self.activation_spec(&prepared, &held, &demand)?;
                (Some(demand), Some(spec))
            }
        };
        let admission_request = AdmissionRequest {
            authority: self.authority.clone(),
            placement: prepared.placement,
            priority: self.intent().priority,
            activation,
            spec,
            transfer: prepared
                .ordered
                .iter()
                .map(|ordered| (ordered.extent, ordered.length_bytes))
                .collect(),
        };
        let admission = self
            .governor
            .admit(&admission_request)
            .map_err(|refusal| FlowError::Admission { refusal })?;
        let covered = admission.covers(&admission_request);
        let reserved_device_bytes = admission.reserved_device_bytes();
        let mut held = Held {
            staging: admission.staging,
            budget: admission.transfer_budget,
            pending: admission.activation,
            reserved_device_bytes,
            handover: admission.handover,
            ..Held::default()
        };
        let placement = prepared.placement;
        let Some(checked) = runners.get_mut(prepared.index) else {
            let error = FlowError::NoCompatibleRunner {
                reasons: Vec::new(),
            };
            return Err(self.roll_back(held, placement, None, error));
        };
        let runner = checked.runner_mut();
        if let Err(shortfall) = covered {
            let error = FlowError::AdmissionShort { shortfall };
            return Err(self.roll_back(held, placement, Some(runner), error));
        }
        self.emit(
            FlowPhase::Reserved,
            Note {
                total_bytes: reserved_device_bytes,
                ..Note::default()
            },
        );
        if let Some(grant) = &held.staging {
            if let Err(error) = self.governor.begin_create(grant) {
                return Err(self.roll_back(held, placement, Some(runner), error.into()));
            }
        }
        if let Some(drained) = held.handover {
            if let Err(error) = self.hand_over(runner, &mut prepared, &mut held, drained) {
                return Err(self.roll_back(held, placement, Some(runner), error));
            }
        }
        let result = match prepared.ready {
            Some(generation) => {
                self.emit(FlowPhase::ReadyEngine, Note::generation(generation));
                self.finish(
                    runner,
                    &prepared,
                    &mut held,
                    generation,
                    Progress::default(),
                )
            }
            None => self.materialize(runner, &prepared, &mut held),
        };
        match result {
            Ok(receipt) => Ok(receipt),
            Err(error) => Err(self.roll_back(held, placement, Some(runner), error)),
        }
    }

    /// The runner's runtime, compatibility and the security partition first (S3.1,
    /// §3.9, S3.6), then the plan over rechecked ready state.
    fn select(&self, runners: &[CheckedRunner<'_>]) -> Result<Prepared, FlowError> {
        let intent = self.intent();
        let context = &self.request.context;
        let mut reasons = Vec::new();
        let mut best: Option<Prepared> = None;
        for (index, checked) in runners.iter().enumerate() {
            let runner = checked.runner();
            let profile = runner.profile();
            let refuse = |reasons: &mut Vec<_>, reason| reasons.push((profile.owner, reason));
            if !context.partition.allows(&profile.scope) {
                refuse(&mut reasons, Incompatibility::OutsidePartition);
                continue;
            }
            let runtime = match self.governor.runtime(profile.owner) {
                Ok(runtime) => runtime,
                Err(_) => {
                    refuse(&mut reasons, Incompatibility::NoRuntime);
                    continue;
                }
            };
            if runtime.execution != context.execution {
                refuse(&mut reasons, Incompatibility::OtherExecution);
                continue;
            }
            if runtime.category != profile.category {
                refuse(&mut reasons, Incompatibility::CategoryMismatch);
                continue;
            }
            if let Compatibility::Incompatible { reason } =
                runner.compatibility(&intent.model, &intent.shape)
            {
                refuse(&mut reasons, reason);
                continue;
            }
            let dependencies = runner.dependencies(&intent.model, &intent.shape)?;
            if let Some(reason) = declaration_problem(&dependencies, &context.partition) {
                refuse(&mut reasons, reason);
                continue;
            }
            let placement = PlacementKey {
                owner: profile.owner,
                model: intent.model,
            };
            let authority = self.authority_binding(profile.category)?;
            let (accepted, hint_refusals) =
                self.recheck(runner, profile.owner, &authority, self.clock.now());
            let ready_state: Vec<RecheckedState> = accepted
                .iter()
                .flat_map(|accepted| {
                    RecheckedState::from_rechecked(&accepted.rechecked, &accepted.resident)
                })
                .collect();
            let plan = plan_dependencies(
                &intent.model,
                &dependencies,
                profile.scope,
                &context.partition,
                &ready_state,
                self.clock,
            )?;
            let ready = accepted
                .iter()
                .find(|accepted| {
                    accepted.rechecked.residency.execution == intent.model
                        && accepted.ready_for.check(&intent.shape).is_ok()
                })
                .map(|accepted| accepted.rechecked.generation)
                .filter(|_| plan.missing.is_empty());
            let missing_device_bytes = plan
                .missing
                .iter()
                .filter_map(|id| dependencies.node(*id))
                .try_fold(0u64, |total, node| total.checked_add(node.device_bytes))
                .ok_or(FlowError::Overflow {
                    field: "missing device bytes",
                })?;
            let candidate = Prepared {
                index,
                placement,
                scope: profile.scope,
                authority,
                budget: runtime.budget,
                ready,
                hint_refusals,
                dependencies,
                plan,
                execute_while_load: profile.execute_while_load,
                kv_write_back: profile.kv_write_back,
                kv_layout: runner.kv_layout(&intent.model, &intent.shape),
                missing_device_bytes,
                ordered: Vec::new(),
            };
            best = match best {
                Some(current) if !candidate.better_than(&current) => Some(current),
                _ => Some(candidate),
            };
        }
        best.ok_or(FlowError::NoCompatibleRunner { reasons })
    }

    /// The authority an activation for this request binds to (S3.1).
    fn authority_binding(
        &self,
        category: ExecutionCategory,
    ) -> Result<AuthorityBinding, FlowError> {
        let context = &self.request.context;
        AuthorityBinding::new(context.execution.clone(), category, Some(context.epoch)).map_err(
            |error| FlowError::Identity {
                reason: error.to_string(),
            },
        )
    }

    /// Every residency of a runner is a hint (line 506): it is rechecked by T07 against
    /// the coordinator's record with the request's scoped grant, and must be bound to the
    /// request's authority (S3.1). Only accepted residencies contribute ready state.
    fn recheck(
        &self,
        runner: &dyn RunnerAdapter,
        owner: PlacementOwner,
        authority: &AuthorityBinding,
        now: MonotonicTime,
    ) -> (Vec<Accepted>, Vec<HintRefusal>) {
        let context = &self.request.context;
        let mut accepted = Vec::new();
        let mut refusals = Vec::new();
        for ResidentState {
            advertisement,
            resident,
            ready_for,
        } in runner.residencies(now)
        {
            let model = advertisement.residency.execution;
            let placement = PlacementKey { owner, model };
            let Some(current) = self.governor.current_residency(&placement) else {
                refusals.push(HintRefusal::NoRecord { model });
                continue;
            };
            let request = AdvertisementRequest {
                requester: context.tenant.clone(),
                required: model,
                purpose: AdvertisementPurpose::Serve,
            };
            let grant = serving_grant(&context.grants, &current, &context.tenant, now);
            match advertisement.recheck(&current, &request, grant, self.clock) {
                Err(refusal) => refusals.push(HintRefusal::Recheck { model, refusal }),
                Ok(rechecked) if rechecked.residency.authority != *authority => {
                    refusals.push(HintRefusal::OtherAuthority { model });
                }
                Ok(rechecked) => accepted.push(Accepted {
                    rechecked,
                    resident,
                    ready_for,
                }),
            }
        }
        (accepted, refusals)
    }

    /// What a new activation serves: the artifact as the catalog verifies it under the
    /// request's partition, the immutable extents among the nodes it holds, each ready or
    /// still to be made, and the request's shape as the one its readiness checks cover.
    fn activation_spec(
        &self,
        prepared: &Prepared,
        held: &[NodeId],
        demand: &ActivationDemand,
    ) -> Result<ActivationSpec, FlowError> {
        let verified = self
            .catalog
            .representation(
                &prepared.dependencies.artifact,
                &self.request.context.partition,
            )
            .map_err(|refusal| FlowError::Catalog { refusal })?;
        let extents = held
            .iter()
            .filter_map(|id| prepared.node(*id))
            .filter(|node| immutable(node.kind))
            .map(|node| ActivationExtent {
                node: node.id,
                identity: node.identity,
                device_bytes: node.device_bytes,
                ready: prepared.plan.ready.contains(&node.id),
                transfers: match &node.materialization {
                    Materialization::Transfer { extents }
                        if prepared.plan.missing.contains(&node.id) =>
                    {
                        extents.clone()
                    }
                    _ => Vec::new(),
                },
            })
            .collect();
        let shape = self.intent().shape;
        let declared = SupportedShape {
            max_context_tokens: shape.context_tokens,
            max_batch_sequences: shape.batch_sequences,
        };
        let pool_bytes = demand.peak.kv_bytes;
        // After a drain, everything but the resident immutable extents is made again.
        let reload_estimate = held
            .iter()
            .filter_map(|id| prepared.node(*id))
            .filter(|node| !(immutable(node.kind) && prepared.plan.ready.contains(&node.id)))
            .fold(Duration::ZERO, |total, node| {
                total.saturating_add(node.estimate)
            });
        Ok(ActivationSpec {
            verified,
            extents,
            declared,
            kv: match prepared.kv_layout {
                Some(layout) => KvSpec::with_layout(layout, pool_bytes),
                None => KvSpec::bounded_by_pool(pool_bytes, &declared),
            },
            reload: self.intent().policy.reload,
            reload_estimate,
        })
    }

    /// A reload's handover (GPU-W05 line 110): the old generation drained, so the runner
    /// frees its KV and contexts, their memory passes to the pending activation, and the
    /// state they held is missing now and made again. The transfers land where the
    /// activation holds memory for them now.
    fn hand_over(
        &mut self,
        runner: &mut dyn RunnerAdapter,
        prepared: &mut Prepared,
        held: &mut Held,
        drained: ModelActivationGeneration,
    ) -> Result<(), FlowError> {
        let freed = runner.release_generation(&prepared.placement, drained)?;
        held.handover = None;
        let pending = held.pending.as_ref().ok_or(FlowError::AdmissionShort {
            shortfall: Shortfall::Activation,
        })?;
        self.governor.hand_over(pending, SourceClass::GuestReport)?;
        held.handed_over = Some(drained);
        let generation = pending.generation();
        if let Some(budget) = held.budget.take() {
            let extents: Vec<ExtentRef> = budget.objects().copied().collect();
            let destinations = self.governor.transfer_destinations(pending, &extents);
            held.budget = Some(
                destinations
                    .into_iter()
                    .fold(budget, |budget, (extent, destination)| {
                        budget.with_extent_destination(extent, destination)
                    }),
            );
        }
        let freed: BTreeSet<StateIdentity> = freed.into_iter().collect();
        let gone: Vec<NodeId> = prepared
            .plan
            .ready
            .iter()
            .copied()
            .filter(|id| {
                prepared
                    .node(*id)
                    .is_some_and(|node| freed.contains(&node.identity))
            })
            .collect();
        let mut missing_device_bytes = prepared.missing_device_bytes;
        for id in &gone {
            let node = prepared.node(*id).ok_or(FlowError::Unsatisfiable {
                remaining: vec![*id],
            })?;
            // Only reconstructed state can be made again: nothing was ordered for it.
            if node.materialization != Materialization::Reconstruct {
                return Err(FlowError::Unsatisfiable { remaining: gone });
            }
            missing_device_bytes =
                missing_device_bytes
                    .checked_add(node.device_bytes)
                    .ok_or(FlowError::Overflow {
                        field: "missing device bytes",
                    })?;
        }
        prepared.plan.ready.retain(|id| !gone.contains(id));
        prepared.plan.missing.extend(gone);
        prepared.missing_device_bytes = missing_device_bytes;
        self.emit(
            FlowPhase::HandedOver { drained },
            Note::generation(generation),
        );
        Ok(())
    }

    /// Marks state the pending activation holds as usable in its slot.
    fn mark_usable(&mut self, held: &Held, identity: StateIdentity) -> Result<(), FlowError> {
        if let Some(pending) = held.pending.as_ref() {
            self.governor.record_usable(pending, identity)?;
        }
        Ok(())
    }

    /// The verified identity and length of every missing extent, from the catalog under
    /// the request's partition.
    fn order_extents(&self, prepared: &Prepared) -> Result<Vec<OrderedExtent>, FlowError> {
        let partition = &self.request.context.partition;
        let mut representations: BTreeMap<ArtifactIdentity, VerifiedRepresentation> =
            BTreeMap::new();
        let mut ordered = Vec::new();
        for id in &prepared.plan.missing {
            let Some(node) = prepared.node(*id) else {
                continue;
            };
            let Materialization::Transfer { extents } = &node.materialization else {
                continue;
            };
            for extent in extents {
                let representation = match representations.entry(extent.artifact) {
                    Entry::Occupied(entry) => entry.into_mut(),
                    Entry::Vacant(entry) => entry.insert(
                        self.catalog
                            .representation(&extent.artifact, partition)
                            .map_err(|refusal| FlowError::Catalog { refusal })?,
                    ),
                };
                let descriptor =
                    representation
                        .extent(extent.extent)
                        .ok_or(FlowError::Catalog {
                            refusal: CatalogRefusal::UnknownExtent { extent: *extent },
                        })?;
                ordered.push(OrderedExtent {
                    extent: *extent,
                    digest: descriptor.digest,
                    length_bytes: descriptor.length_bytes,
                    stored: descriptor.stored,
                });
            }
        }
        Ok(ordered)
    }

    /// GPU §1 step 4: transfer or reconstruct only the missing state, verify it, publish
    /// dependency events, compute ahead only under a preparation lease, then activate.
    fn materialize(
        &mut self,
        runner: &mut dyn RunnerAdapter,
        prepared: &Prepared,
        held: &mut Held,
    ) -> Result<ServeReceipt, FlowError> {
        self.emit(FlowPhase::MissingState, Note::default());
        let context = &self.request.context;
        let placement = prepared.placement;
        let token = PreparationToken::issue(
            context.execution.clone(),
            context.operation.clone(),
            context.tenant.clone(),
            context.epoch,
            placement,
        );
        let pending_generation = held
            .pending
            .as_ref()
            .map(PendingActivation::generation)
            .ok_or(FlowError::AdmissionShort {
                shortfall: Shortfall::Activation,
            })?;
        let mut progress = Progress::default();
        if prepared.execute_while_load
            && self.intent().policy.execute_while_load
            && !prepared.dependencies.compute.is_empty()
        {
            let Some(pending) = held.pending.as_ref() else {
                return Err(FlowError::AdmissionShort {
                    shortfall: Shortfall::Activation,
                });
            };
            match self.governor.lease_preparation(&self.authority, pending) {
                Ok(lease) => {
                    held.preparation = Some(lease);
                    self.emit(
                        FlowPhase::PreparationLeased,
                        Note::generation(pending_generation),
                    );
                }
                Err(
                    error @ (GovernorError::Activation {
                        refusal:
                            ModelRefusal::PreparationAssigned { .. }
                            | ModelRefusal::HandoverPending { .. },
                    }
                    | GovernorError::Early {
                        refusal:
                            EarlyRefusal::AlreadyAssigned { .. }
                            | EarlyRefusal::UnrelatedTraffic { .. }
                            | EarlyRefusal::PreviousRequestPending { .. }
                            | EarlyRefusal::LeaseRefused {
                                refusal:
                                    CoordinationRefusal::PreparationAssigned
                                    | CoordinationRefusal::HandoverPending { .. },
                            },
                    }),
                ) => {
                    progress.compute_ahead_refusal = Some(error);
                    self.emit(
                        FlowPhase::ComputeAheadRefused,
                        Note::generation(pending_generation),
                    );
                }
                Err(error) => return Err(error.into()),
            }
        }

        let order = if prepared.ordered.is_empty() {
            None
        } else {
            let budget = held
                .budget
                .as_ref()
                .ok_or(FlowError::MissingTransferBudget)?;
            let order = TransferOrder::new(&token, budget, prepared.ordered.clone())
                .map_err(|refusal| FlowError::Order { refusal })?;
            let ticket = self
                .executor
                .submit(&order)
                .map_err(|refusal| FlowError::TransferRefused { refusal })?;
            held.ticket = Some(ticket);
            self.emit(
                FlowPhase::TransferStarted,
                Note {
                    total_bytes: order.total_bytes(),
                    ..Note::default()
                },
            );
            Some((order, ticket))
        };

        let mut usable: BTreeSet<NodeId> = prepared.plan.ready.iter().copied().collect();
        let mut remaining = prepared.plan.missing.clone();
        let mut usable_at: BTreeMap<NodeId, MonotonicTime> = BTreeMap::new();
        let mut read_bytes = 0u64;
        let mut committed_bytes = 0u64;
        while !remaining.is_empty() {
            let position = next_node(&remaining, &usable, prepared)?;
            let id = remaining.remove(position);
            let node = prepared.node(id).ok_or(FlowError::Unsatisfiable {
                remaining: vec![id],
            })?;
            match &node.materialization {
                Materialization::Reconstruct => {
                    held.materialized.push(node.identity);
                    runner.reconstruct(node, &token)?;
                    self.mark_usable(held, node.identity)?;
                    progress.reconstructed.push(id);
                }
                Materialization::Transfer { extents } => {
                    let (order, ticket) = order.as_ref().ok_or(FlowError::MissingTransferBudget)?;
                    for extent in extents {
                        let completion = self
                            .executor
                            .await_extent(*ticket, extent)
                            .map_err(|failure| FlowError::Transfer { failure })?;
                        check_completion(order, extent, &completion)?;
                        read_bytes = read_bytes.checked_add(completion.bytes_read).ok_or(
                            FlowError::Overflow {
                                field: "bytes read",
                            },
                        )?;
                        if read_bytes > order.budget_bytes() {
                            return Err(FlowError::TransferBudgetExceeded {
                                budget_bytes: order.budget_bytes(),
                                read_bytes,
                            });
                        }
                        self.emit(
                            FlowPhase::ExtentVerified,
                            Note {
                                resource: Some(id),
                                completed_bytes: read_bytes,
                                total_bytes: order.total_bytes(),
                                ..Note::default()
                            },
                        );
                    }
                    held.materialized.push(node.identity);
                    runner.dependency_usable(
                        &DependencyEvent {
                            placement,
                            node: id,
                            kind: node.kind,
                            identity: node.identity,
                            device_bytes: node.device_bytes,
                        },
                        &token,
                    )?;
                    self.mark_usable(held, node.identity)?;
                    progress.transferred.push(id);
                }
            }
            usable.insert(id);
            usable_at.insert(id, self.clock.now());
            committed_bytes =
                committed_bytes
                    .checked_add(node.device_bytes)
                    .ok_or(FlowError::Overflow {
                        field: "committed bytes",
                    })?;
            self.emit(
                FlowPhase::DependencyPublished,
                Note {
                    resource: Some(id),
                    committed_usable_bytes: committed_bytes,
                    total_bytes: prepared.missing_device_bytes,
                    ..Note::default()
                },
            );
            if let Some(lease) = held.preparation.as_ref() {
                while !remaining.is_empty() {
                    let Some(group) =
                        group_at(&prepared.dependencies.compute, progress.computed_ahead)
                    else {
                        break;
                    };
                    if !group.requires.iter().all(|input| usable.contains(input)) {
                        break;
                    }
                    self.governor.check_preparation_lease(lease)?;
                    let inputs: Vec<StateIdentity> = group
                        .requires
                        .iter()
                        .filter_map(|input| prepared.node(*input))
                        .map(|node| node.identity)
                        .collect();
                    self.governor.start_compute_ahead(lease, &inputs)?;
                    held.session_started = true;
                    runner.compute_ahead(&ComputeAssignment {
                        lease,
                        group: progress.computed_ahead,
                        payload: &self.request.payload,
                    })?;
                    self.governor.finish_compute_ahead(lease, &inputs)?;
                    self.emit(
                        FlowPhase::ComputedAhead {
                            group: progress.computed_ahead,
                        },
                        Note::generation(pending_generation),
                    );
                    progress.computed_ahead = progress.computed_ahead.saturating_add(1);
                }
            }
        }
        held.ticket = None;
        if let Some(grant) = held.staging.take() {
            self.governor.release(grant)?;
            self.emit(FlowPhase::StagingReleased, Note::default());
        }

        let residency = Residency {
            execution: placement.model,
            artifact: prepared.dependencies.artifact,
            owner: context.tenant.clone(),
            scope: prepared.scope,
            device: placement.owner.device,
            authority: prepared.authority.clone(),
        };
        let shape = self.intent().shape;
        runner.activate(
            &ActivationOrder {
                placement,
                generation: pending_generation,
                declared: SupportedShape {
                    max_context_tokens: shape.context_tokens,
                    max_batch_sequences: shape.batch_sequences,
                },
                residency: residency.clone(),
            },
            &token,
        )?;
        held.activated = Some(pending_generation);
        let pending = held.pending.take().ok_or(FlowError::AdmissionShort {
            shortfall: Shortfall::Activation,
        })?;
        let generation = match self.governor.publish_activation(pending, residency) {
            Ok(generation) => generation,
            Err(PendingRefusal { pending, error }) => {
                held.pending = Some(pending);
                return Err(error.into());
            }
        };
        held.activated = None;
        held.materialized.clear();
        self.emit(FlowPhase::Activated, Note::generation(generation));
        if generation != pending_generation {
            return Err(FlowError::GenerationChanged {
                expected: pending_generation,
                actual: generation,
            });
        }
        progress.overlap = self.overlap_report(&prepared.dependencies.compute, &usable_at)?;
        self.finish(runner, prepared, held, generation, progress)
    }

    /// GPU §1 step 5: lease, serve, release the lease and keep valuable state. The
    /// preparation lease ends first: the slot admits one lease per request, and what was
    /// computed ahead is published only through the serving lease's check.
    fn finish(
        &mut self,
        runner: &mut dyn RunnerAdapter,
        prepared: &Prepared,
        held: &mut Held,
        generation: ModelActivationGeneration,
        progress: Progress,
    ) -> Result<ServeReceipt, FlowError> {
        let placement = prepared.placement;
        if let Some(preparation) = held.preparation.take() {
            self.governor.release_preparation_lease(preparation)?;
            self.emit(FlowPhase::PreparationReleased, Note::generation(generation));
        }
        let lease = self.governor.lease_execution(
            &self.authority,
            &placement,
            generation,
            self.intent().shape,
        )?;
        let lease = held.execution.insert(lease);
        self.emit(FlowPhase::LeaseAcquired, Note::generation(generation));
        self.governor.check_execution_lease(lease)?;
        held.session_started = true;
        let shape: RequestShape = self.intent().shape;
        let outcome = runner.serve(&ServeOrder {
            lease,
            shape,
            payload: &self.request.payload,
            computed_ahead_groups: progress.computed_ahead,
        })?;
        if outcome.generation != generation {
            return Err(FlowError::GenerationChanged {
                expected: generation,
                actual: outcome.generation,
            });
        }
        self.emit(FlowPhase::Served, Note::generation(generation));
        let operation = self.request.context.operation.clone();
        let session = retain_session(
            prepared.dependencies.session_device_bytes,
            served_session(&operation, generation),
            self.intent().policy.resume_session,
            prepared.kv_write_back,
        );
        if let Some(mut lease) = held.execution.take() {
            // A session that stays keeps its KV past the lease, so it is never trimmed.
            if !matches!(session, SessionRetention::Released { .. }) {
                lease.keep_session();
            }
            self.governor.release_execution_lease(lease)?;
            self.emit(FlowPhase::LeaseReleased, Note::generation(generation));
        }
        held.session_started = false;
        if let SessionRetention::Released { action } = &session {
            runner.release_session(&operation, action)?;
        }
        let kept_nodes = prepared.plan.ready.len() + prepared.plan.missing.len();
        self.emit(
            FlowPhase::StateRetained {
                kept_nodes: count(kept_nodes),
                session,
            },
            Note::generation(generation),
        );
        Ok(ServeReceipt {
            operation,
            path: if prepared.ready.is_some() {
                ServePath::Ready
            } else {
                ServePath::Materialized
            },
            placement,
            generation,
            transferred: progress.transferred,
            reconstructed: progress.reconstructed,
            not_needed: prepared.plan.not_needed.clone(),
            hint_refusals: prepared.hint_refusals.clone(),
            computed_ahead_groups: progress.computed_ahead,
            compute_ahead_refusal: progress.compute_ahead_refusal,
            reserved_device_bytes: held.reserved_device_bytes,
            planned_first_token_at: prepared.plan.planned_first_token_at,
            planned_overlap: prepared.plan.planned_overlap(),
            first_token_at: outcome.first_token_at,
            overlap: progress.overlap,
            session,
            handed_over: held.handed_over,
        })
    }

    fn overlap_report(
        &self,
        groups: &[ComputeGroup],
        usable_at: &BTreeMap<NodeId, MonotonicTime>,
    ) -> Result<Option<OverlapReport>, FlowError> {
        if groups.is_empty() {
            return Ok(None);
        }
        let timings: Vec<GroupTiming> = groups
            .iter()
            .map(|group| GroupTiming {
                usable_at_seconds: group
                    .requires
                    .iter()
                    .filter_map(|input| usable_at.get(input))
                    .map(|at| at.saturating_duration_since(self.started_at).as_secs_f64())
                    .fold(0.0, f64::max),
                compute_seconds: group.compute.as_secs_f64(),
            })
            .collect();
        let overlap = |error: OverlapError| FlowError::Overlap {
            reason: error.to_string(),
        };
        Ok(Some(OverlapReport {
            group_finish_seconds: finish_times(&timings).map_err(overlap)?,
            ideal_finish_seconds: ideal_finish_seconds(&timings).map_err(overlap)?,
            no_stall: no_stall(&timings).map_err(overlap)?,
            group_usable_at_seconds: timings.iter().map(|t| t.usable_at_seconds).collect(),
            group_compute_seconds: timings.iter().map(|t| t.compute_seconds).collect(),
        }))
    }

    /// Releases everything a failed request still holds. Transfers stop at a safe
    /// boundary and their staging is recycled. State made for an activation that never
    /// published is discarded with it: once the runner confirms, its own report closes
    /// the activation's GPU reservation; otherwise the reservation keeps counting until
    /// the host observes the release.
    fn roll_back(
        &mut self,
        held: Held,
        placement: PlacementKey,
        runner: Option<&mut dyn RunnerAdapter>,
        cause: FlowError,
    ) -> FlowError {
        let mut errors = Vec::new();
        let mut record = |result: Result<(), GovernorError>| {
            if let Err(error) = result {
                errors.push(error);
            }
        };
        if let Some(ticket) = held.ticket {
            self.executor.cancel(ticket);
        }
        if let Some(lease) = held.execution {
            record(self.governor.release_execution_lease(lease));
        }
        if let Some(lease) = held.preparation {
            record(self.governor.release_preparation_lease(lease));
        }
        let mut discard: Vec<StateRef> = held
            .materialized
            .iter()
            .map(|identity| StateRef::Node {
                identity: *identity,
            })
            .collect();
        if held.session_started {
            discard.push(StateRef::Session {
                operation: self.request.context.operation.clone(),
            });
        }
        let mut runner = runner;
        let discarded = match runner.as_deref_mut() {
            Some(runner) => {
                let dropped = discard.is_empty() || runner.drop_state(&discard).is_ok();
                let forgotten = held.activated.is_none_or(|generation| {
                    runner.discard_activation(&placement, generation).is_ok()
                });
                dropped && forgotten
            }
            None => discard.is_empty() && held.activated.is_none(),
        };
        if let Some(pending) = held.pending {
            let generation = pending.generation();
            match self.governor.abandon_activation(pending) {
                Ok(abandoned) => {
                    self.emit(
                        FlowPhase::ActivationAbandoned {
                            transition_capacity_reserved: abandoned.transition_capacity_reserved,
                            old_generation_serving: abandoned.serving.is_some(),
                        },
                        Note::generation(generation),
                    );
                    if discarded {
                        record(
                            self.governor
                                .confirm_released(&placement, generation, SourceClass::GuestReport)
                                .map(|_| ()),
                        );
                    }
                }
                Err(refused) => record(Err(refused.error)),
            }
        }
        // A reload that failed before its handover leaves the old generation drained and
        // serving nothing: the runner frees it, then its memory is reclaimed. A runner that
        // cannot free it leaves it counted.
        if let (Some(drained), Some(runner)) = (held.handover, runner) {
            if runner.release_generation(&placement, drained).is_ok() {
                record(
                    self.governor
                        .confirm_released(&placement, drained, SourceClass::GuestReport)
                        .map(|_| ()),
                );
            }
        }
        if let Some(grant) = held.staging {
            record(self.governor.release(grant));
        }
        if errors.is_empty() {
            cause
        } else {
            FlowError::RollbackIncomplete {
                cause: Box::new(cause),
                errors,
            }
        }
    }
}

/// A grant that authorizes serving from `current` for `tenant`, if the request holds
/// one; otherwise any grant for its artifact, so the recheck names what is wrong.
fn serving_grant<'g>(
    grants: &'g [ScopedGrant],
    current: &CurrentResidency,
    tenant: &TenantId,
    now: MonotonicTime,
) -> Option<&'g ScopedGrant> {
    let need = GrantNeed {
        owner: &current.residency.owner,
        grantee: tenant,
        artifact: &current.residency.artifact,
        scope: &current.residency.scope,
        granted_use: GrantedUse::Serve,
    };
    grants
        .iter()
        .find(|grant| check_grant(Some(grant), &need, now).is_ok())
        .or_else(|| {
            grants
                .iter()
                .find(|grant| grant.artifact == current.residency.artifact)
        })
}

/// The next missing node to make usable: a reconstruction whose dependencies are usable
/// runs while transfers continue in the background; otherwise wait for the first
/// transfer whose dependencies are usable.
fn next_node(
    remaining: &[NodeId],
    usable: &BTreeSet<NodeId>,
    prepared: &Prepared,
) -> Result<usize, FlowError> {
    let startable = |id: &NodeId| {
        prepared
            .node(*id)
            .is_some_and(|node| node.depends_on.iter().all(|input| usable.contains(input)))
    };
    let reconstruct = remaining.iter().position(|id| {
        startable(id)
            && prepared
                .node(*id)
                .is_some_and(|node| node.materialization == Materialization::Reconstruct)
    });
    reconstruct
        .or_else(|| remaining.iter().position(startable))
        .ok_or_else(|| FlowError::Unsatisfiable {
            remaining: remaining.to_vec(),
        })
}

/// A completion must be the ordered extent with the ordered content key, read from a
/// read source.
fn check_completion(
    order: &TransferOrder,
    requested: &ExtentRef,
    completion: &ExtentCompletion,
) -> Result<(), FlowError> {
    if completion.extent != *requested {
        return Err(FlowError::ExecutorSwitchedModel {
            requested: *requested,
            delivered: completion.extent,
        });
    }
    let expected = order.expected(requested).ok_or(FlowError::Transfer {
        failure: TransferFailure::NotOrdered { extent: *requested },
    })?;
    if completion.verified_digest != expected.digest {
        return Err(FlowError::DigestMismatch {
            extent: *requested,
            expected: expected.digest,
            delivered: completion.verified_digest,
        });
    }
    if !completion.source.is_read_source() {
        return Err(FlowError::NotAReadSource { extent: *requested });
    }
    Ok(())
}

/// The first inconsistency or partition violation in a runner's declaration.
fn declaration_problem(
    dependencies: &ExecutionDependencies,
    partition: &SecurityPartition,
) -> Option<Incompatibility> {
    if let Some(node) = dependencies
        .nodes
        .iter()
        .find(|node| !partition.allows(&node.scope))
    {
        return Some(Incompatibility::DependencyOutsidePartition { node: node.id });
    }
    dependencies
        .compute
        .iter()
        .flat_map(|group| group.requires.iter())
        .find(|input| !dependencies.nodes.iter().any(|node| node.id == **input))
        .map(|input| Incompatibility::UndeclaredComputeInput { node: *input })
}

/// Whether a node of `kind` is an immutable extent an activation reads: weights, a rank
/// layout or an adapter (§3.6 step 1).
fn immutable(kind: NodeKind) -> bool {
    matches!(
        kind,
        NodeKind::ArtifactExtent | NodeKind::RankLayout | NodeKind::Adapter
    )
}

fn group_at(groups: &[ComputeGroup], index: u32) -> Option<&ComputeGroup> {
    usize::try_from(index)
        .ok()
        .and_then(|index| groups.get(index))
}

fn count(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}
