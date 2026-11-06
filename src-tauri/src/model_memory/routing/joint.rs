//! GPU §4.6, joint routing and placement (lines 707–720): "sending a request to
//! compatible ready state may be cheaper than moving that state to the request."
//!
//! For every authorized eligible endpoint the router estimates `finish_at_node`
//! ([`super::estimate`]) and ranks endpoints by a score that adds the uncertainty, a
//! stale-report penalty, egress spend, donor impact and the interference of a peer
//! source. Session stickiness is the cost of moving the session's KV state, by a
//! mechanism the destination backend actually supports; data locality is the cost of
//! moving the request's input. User placement restrictions exclude endpoints outright.
//!
//! Only endpoints for the exact requested model are compared: a [`RequestedModel`] is one
//! logical model with an explicit set of execution identities, and nothing else is ever
//! substituted, however fast or capable. Resident state is used only through
//! [`ResidentAdvertisement::recheck`]; local artifacts only under a scoped grant
//! ([`check_grant`]). Token reconstruction ([`check_recompute`]) and raw KV transfer
//! ([`check_kv_reuse`]) are separate mechanisms with separate checks and costs, never
//! interchangeable. A hysteresis threshold keeps a flow on its endpoint unless another
//! wins by a clear margin.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::foundation::ids::{
    Clock, Digest, DigestBuilder, ExecutionCategory, GpuDeviceKey, MonotonicTime, OperationId,
    TenantId, TrustScope,
};
use crate::model_memory::identity::{
    check_grant, check_kv_reuse, AdvertisementPurpose, AdvertisementRefusal, AdvertisementRequest,
    ArtifactIdentity, CurrentResidency, ExecutionIdentity, ExecutionSpec, GrantNeed, GrantRefusal,
    GrantedUse, KvReuseRefusal, KvScopeComponent, KvScopeKey, KvScopeSpec, LogicalModelIdentity,
    RecheckedResidency, ResidentAdvertisement, ScopeEnforcement, ScopedGrant, SessionIdentity,
};
use crate::model_memory::math::bounds::{
    transfer_lower_bound, BandwidthBasis, BandwidthRating, BoundsError, ResourceTable,
    TransferDemand,
};
use crate::model_memory::math::recompute::{
    check_recompute, KvRecompute, KvRequirement, RecomputeRefusal,
};
use crate::model_memory::math::{non_negative, InputError};

use super::error::RoutingError;
use super::estimate::{
    finish_at_node, stale_penalty, FinishComponents, FinishEstimate, SecondsEstimate, StalePenalty,
    StaleRefusal, StalenessPolicy,
};
use super::numbers::{approx_f64, count_u64};

/// Domain of [`FlowKey`] digests.
pub const FLOW_KEY_DOMAIN: &str = "yougori/routing/flow/v1";

/// The exact model a request asks for (§4.6, line 716): one logical model identity and
/// the execution identities the caller explicitly accepts for it (§3.2 items 2–3). An
/// endpoint serving any other execution identity is never compared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestedModel {
    logical: LogicalModelIdentity,
    executions: BTreeSet<ExecutionIdentity>,
}

impl RequestedModel {
    /// Exactly one execution of one logical model.
    pub fn exact(spec: &ExecutionSpec) -> Result<Self, RoutingError> {
        Self::with_executions(spec.logical, std::slice::from_ref(spec))
    }

    /// Several executions of the same logical model, such as a single-GPU replica and a
    /// temporary pipeline (§4.8). Every spec must name `logical`; a spec of another
    /// logical model is refused, since accepting it would substitute a model.
    pub fn with_executions(
        logical: LogicalModelIdentity,
        specs: &[ExecutionSpec],
    ) -> Result<Self, RoutingError> {
        if specs.is_empty() {
            return Err(InputError::Empty {
                field: "RequestedModel.executions",
            }
            .into());
        }
        let mut executions = BTreeSet::new();
        for spec in specs {
            if spec.logical != logical {
                return Err(RoutingError::MixedLogicalModels);
            }
            executions.insert(spec.identity()?);
        }
        Ok(Self {
            logical,
            executions,
        })
    }

    pub fn logical(&self) -> LogicalModelIdentity {
        self.logical
    }

    pub fn executions(&self) -> &BTreeSet<ExecutionIdentity> {
        &self.executions
    }

    /// Whether `execution` is one the caller accepted.
    pub fn accepts(&self, execution: &ExecutionIdentity) -> bool {
        self.executions.contains(execution)
    }
}

/// What the hysteresis remembers a choice for: one session, or one tenant's stream of
/// requests for one requested model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FlowKey(Digest);

impl FlowKey {
    /// The flow of one session.
    pub fn session(session: &SessionIdentity) -> Self {
        Self(
            DigestBuilder::new(FLOW_KEY_DOMAIN)
                .str("session")
                .digest(session.digest())
                .finish(),
        )
    }

    /// The flow of one tenant's requests for one requested model.
    pub fn model(tenant: &TenantId, model: &RequestedModel) -> Self {
        let mut builder = DigestBuilder::new(FLOW_KEY_DOMAIN)
            .str("model")
            .str(tenant.as_str())
            .digest(model.logical.digest())
            .u64(count_u64(model.executions.len()));
        for execution in &model.executions {
            builder = builder.digest(execution.digest());
        }
        Self(builder.finish())
    }

    pub fn digest(&self) -> Digest {
        self.0
    }
}

/// A session's resident KV state and what restoring it elsewhere needs (§4.6 "session
/// stickiness"; §2.8 KV recompute versus transfer).
#[derive(Clone, Debug, PartialEq)]
pub struct SessionState {
    /// The device whose memory holds the session's KV.
    pub home: GpuDeviceKey,
    /// The reuse scope of the stored KV (FAST-03).
    pub scope: KvScopeSpec,
    /// The exact state, its prefix inputs and the current epoch (§2.8).
    pub requirement: KvRequirement,
    pub kv_bytes: u64,
    pub context_tokens: u64,
}

/// Input data the request needs, and where it is (§4.6 "data locality").
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct InputData {
    pub machine: Digest,
    pub bytes: u64,
}

/// The user's placement restrictions (§4.6). An endpoint outside them is never compared.
#[derive(Clone, Debug, PartialEq)]
pub struct PlacementRestrictions {
    /// Machines the user excludes, even when authorized.
    pub excluded_machines: BTreeSet<Digest>,
    /// The exact runtime categories the request accepts; no other category is
    /// substituted (S3.5).
    pub categories: BTreeSet<ExecutionCategory>,
    /// The most egress spend this request may cause, in USD.
    pub max_egress_usd: Option<f64>,
}

/// One request to route (§4.6).
#[derive(Clone, Debug, PartialEq)]
pub struct RoutingRequest {
    pub request: OperationId,
    pub requester: TenantId,
    pub model: RequestedModel,
    pub flow: FlowKey,
    /// Machines already authorized for this tenant ("two already-authorized machines",
    /// line 718). No other machine is compared.
    pub authorized_machines: BTreeSet<Digest>,
    pub restrictions: PlacementRestrictions,
    pub session: Option<SessionState>,
    pub input: Option<InputData>,
}

/// A resident-state claim and what is needed to recheck it (§3.2, line 506).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResidentClaim {
    pub advertisement: ResidentAdvertisement,
    /// The authoritative record, from the coordinator rather than the advertisement.
    pub current: CurrentResidency,
    pub grant: Option<ScopedGrant>,
}

/// Where a cold endpoint gets the exact state from.
#[derive(Clone, Debug, PartialEq)]
pub enum PreparationSource {
    /// A peer's resident copy, transferred to this endpoint's scope under a transfer
    /// grant.
    PeerResident {
        claim: ResidentClaim,
        /// Bytes the transfer moves into this endpoint.
        bytes: u64,
        /// Delay the transfer causes the peer's own work, in seconds of the declared
        /// objective per byte (§4.6 "donor impact").
        interference_seconds_per_byte: f64,
    },
    /// A verified artifact copy on the endpoint's machine, used under a storage grant.
    LocalArtifact {
        artifact: ArtifactIdentity,
        owner: TenantId,
        grant: Option<ScopedGrant>,
    },
}

/// How long making the state ready takes, with what it moves, so the estimate can be
/// checked against the GPU §2.2 lower bound.
#[derive(Clone, Debug)]
pub struct Preparation {
    pub critical_path: SecondsEstimate,
    /// Measured usable directional bandwidth of every resource the preparation crosses.
    pub resources: ResourceTable,
    pub demands: Vec<TransferDemand>,
    /// Minimum duration of the parts that move no bytes, such as engine start.
    pub minimum_seconds: f64,
}

/// What an endpoint holds for the request.
#[derive(Clone, Debug)]
pub enum EndpointState {
    /// The execution is resident and serving.
    Ready(ResidentClaim),
    /// Nothing usable is resident; `execution` would be prepared from `source`.
    Cold {
        execution: ExecutionIdentity,
        source: PreparationSource,
        preparation: Preparation,
    },
}

/// Token reconstruction at the destination: the prefix tokens move and the KV is
/// recomputed there (the mechanism ServerlessLLM migrates with).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TokenReconstructionSupport {
    /// The recomputation offered, with its queue and compute time (§2.8).
    pub recompute: KvRecompute,
    /// Bytes of the prefix tokens sent from the session's home.
    pub token_bytes: u64,
    /// Measured link from the session's home.
    pub link: BandwidthRating,
}

/// Raw KV transfer: the KV bytes move as they are and are installed under the
/// destination's reuse scope.
#[derive(Clone, Debug, PartialEq)]
pub struct RawKvTransferSupport {
    /// The scope the destination would install the KV under; it must equal the stored
    /// scope exactly (FAST-03).
    pub destination_scope: KvScopeSpec,
    pub enforcement: ScopeEnforcement,
    /// Measured link from the session's home.
    pub link: BandwidthRating,
    pub setup_seconds: f64,
}

/// The session-move mechanisms the destination backend supports (line 720: "Reproduce
/// the migration mechanism actually supported by the chosen backend").
#[derive(Clone, Debug, Default, PartialEq)]
pub struct MigrationSupport {
    pub token_reconstruction: Option<TokenReconstructionSupport>,
    pub raw_kv_transfer: Option<RawKvTransferSupport>,
}

/// One endpoint as last reported (§4.6).
#[derive(Clone, Debug)]
pub struct EndpointReport {
    pub device: GpuDeviceKey,
    /// The trust scope the endpoint executes in; its category is the runtime category.
    pub scope: TrustScope,
    /// When the queue and compute figures were observed, on the router's clock.
    pub observed_at: MonotonicTime,
    pub queue: SecondsEstimate,
    pub request_compute: SecondsEstimate,
    pub client_network_tail: SecondsEstimate,
    pub state: EndpointState,
    pub migration: MigrationSupport,
    /// Measured link from the request's input data, when the data is on another machine.
    pub input_link: Option<BandwidthRating>,
    /// Price of each byte moved into this endpoint's site; zero when unmetered.
    pub egress_usd_per_byte: f64,
    /// Delay serving here causes the machine owner's or donor's own work, in seconds of
    /// the declared objective (§4.6 "donor impact").
    pub donor_impact_seconds: f64,
}

/// Which way a session's KV state moves (line 720). The two are never interchangeable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MigrationMechanism {
    TokenReconstruction,
    RawKvTransfer,
}

/// A chosen session move, priced for its own mechanism only.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MigrationPlan {
    TokenReconstruction {
        /// Token transfer plus the recomputation's queue and compute.
        completion_seconds: f64,
        tokens: u64,
        token_bytes: u64,
    },
    RawKvTransfer {
        /// Setup plus the KV bytes over the measured link.
        completion_seconds: f64,
        kv_bytes: u64,
        scope: KvScopeKey,
    },
}

/// Why a migration plan cannot be carried out as asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationRefusal {
    /// The plan was priced for one mechanism; another may not carry it out (line 720).
    MechanismMismatch {
        planned: MigrationMechanism,
        offered: MigrationMechanism,
    },
}

impl fmt::Display for MigrationRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MechanismMismatch { planned, offered } => write!(
                f,
                "the session move was planned as {planned:?} and cannot be carried out as {offered:?}"
            ),
        }
    }
}

impl std::error::Error for MigrationRefusal {}

impl MigrationPlan {
    pub fn mechanism(&self) -> MigrationMechanism {
        match self {
            Self::TokenReconstruction { .. } => MigrationMechanism::TokenReconstruction,
            Self::RawKvTransfer { .. } => MigrationMechanism::RawKvTransfer,
        }
    }

    pub fn completion_seconds(&self) -> f64 {
        match self {
            Self::TokenReconstruction {
                completion_seconds, ..
            }
            | Self::RawKvTransfer {
                completion_seconds, ..
            } => *completion_seconds,
        }
    }

    /// Refuses to carry the plan out with any mechanism but the one it was priced for.
    pub fn check_execution(&self, offered: MigrationMechanism) -> Result<(), MigrationRefusal> {
        if self.mechanism() == offered {
            Ok(())
        } else {
            Err(MigrationRefusal::MechanismMismatch {
                planned: self.mechanism(),
                offered,
            })
        }
    }
}

/// Why one mechanism cannot move the session to an endpoint.
#[derive(Clone, Debug, PartialEq)]
pub enum MechanismUnavailable {
    /// The destination backend does not support it.
    NotSupported,
    /// §2.8: the prefix is not held, the recomputation is not authorized under the
    /// current epoch, or it would produce another state.
    Recompute(RecomputeRefusal),
    /// FAST-03: the destination scope differs or is not enforced.
    KvScope(KvReuseRefusal),
    /// The link figure is not a measured directional bandwidth.
    UnmeasuredLink { basis: BandwidthBasis },
}

/// What authorizes serving at an endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteAuthority {
    /// The resident advertisement passed its recheck.
    Ready(RecheckedResidency),
    /// The state is prepared from a peer whose advertisement passed a transfer recheck.
    PreparedFromPeer(RecheckedResidency),
    /// The state is prepared from a local artifact under a grant valid until then.
    PreparedFromLocalArtifact { grant_valid_until: MonotonicTime },
}

/// Why an endpoint was not compared.
#[derive(Clone, Debug, PartialEq)]
pub enum Ineligible {
    /// The machine is not among the tenant's authorized machines.
    MachineNotAuthorized,
    /// The user excluded the machine.
    ExcludedByUser,
    /// The runtime category is not one the request accepts.
    CategoryNotAccepted {
        category: ExecutionCategory,
    },
    StaleReport(StaleRefusal),
    /// The endpoint serves or would prepare another execution: never substituted.
    NotRequestedModel {
        offered: ExecutionIdentity,
    },
    /// The endpoint's device or scope differs from its resident record.
    ReportDisagreesWithResidency,
    /// The resident advertisement failed its recheck (line 506).
    Advertisement(AdvertisementRefusal),
    /// The peer source's advertisement failed its transfer recheck.
    SourceAdvertisement(AdvertisementRefusal),
    /// No scoped grant covers using the local artifact here.
    LocalArtifactGrant(GrantRefusal),
    /// The session's KV cannot be moved here by any supported mechanism; required
    /// context is never dropped.
    SessionUnreachable {
        token_reconstruction: MechanismUnavailable,
        raw_kv_transfer: MechanismUnavailable,
    },
    /// The input data is on another machine and no measured link reaches this endpoint.
    NoMeasuredInputLink,
    /// The preparation estimate beats the GPU §2.2 lower bound for its bytes.
    BelowPhysicalBound {
        claimed_seconds: f64,
        lower_bound_seconds: f64,
    },
    /// The egress spend exceeds the user's limit.
    EgressBudgetExceeded {
        cost_usd: f64,
        budget_usd: f64,
    },
    /// The report itself is invalid.
    Invalid(RoutingError),
}

impl From<RoutingError> for Ineligible {
    fn from(error: RoutingError) -> Self {
        Self::Invalid(error)
    }
}

impl From<InputError> for Ineligible {
    fn from(error: InputError) -> Self {
        Self::Invalid(error.into())
    }
}

/// An endpoint left out, and why.
#[derive(Clone, Debug, PartialEq)]
pub struct IneligibleEndpoint {
    pub device: GpuDeviceKey,
    pub reason: Ineligible,
}

/// One compared endpoint with its estimate and score.
#[derive(Clone, Debug, PartialEq)]
pub struct RouteOption {
    pub device: GpuDeviceKey,
    pub authority: RouteAuthority,
    /// The session move this option needs, if the session lives elsewhere.
    pub migration: Option<MigrationPlan>,
    pub finish: FinishEstimate,
    pub stale: StalePenalty,
    pub egress_bytes: u64,
    pub egress_usd: f64,
    /// Donor impact of serving here plus the interference of a peer source.
    pub donor_impact_seconds: f64,
    /// `expected + risk × spread + stale penalty + egress × value of time + donor impact`.
    pub score_seconds: f64,
}

/// How endpoint estimates become a score, and when a flow changes endpoint (§4.6).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RoutingPolicy {
    /// Seconds of score per second of finish uncertainty.
    pub risk_weight: f64,
    /// Seconds of score per USD of egress.
    pub seconds_per_usd: f64,
    pub staleness: StalenessPolicy,
    pub hysteresis: HysteresisPolicy,
}

/// A flow moves to another endpoint only when that endpoint's score is lower by at least
/// `max(min_gain_seconds, min_gain_fraction × current score)` (§4.6 "Keep a hysteresis
/// threshold to prevent oscillation").
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HysteresisPolicy {
    pub min_gain_seconds: f64,
    pub min_gain_fraction: f64,
}

impl HysteresisPolicy {
    /// The gain a move from a flow's endpoint with `current_score_seconds` must reach.
    pub fn threshold_seconds(&self, current_score_seconds: f64) -> f64 {
        self.min_gain_seconds
            .max(self.min_gain_fraction * current_score_seconds)
    }
}

impl RoutingPolicy {
    fn check(&self) -> Result<(), InputError> {
        non_negative("risk_weight", self.risk_weight)?;
        non_negative("seconds_per_usd", self.seconds_per_usd)?;
        non_negative("min_gain_seconds", self.hysteresis.min_gain_seconds)?;
        non_negative("min_gain_fraction", self.hysteresis.min_gain_fraction)?;
        Ok(())
    }
}

/// The routing outcome.
#[derive(Clone, Debug, PartialEq)]
pub struct RouteDecision {
    pub chosen: RouteOption,
    /// The lowest-score endpoint; it differs from the chosen one only when the
    /// hysteresis kept the flow where it was.
    pub best: GpuDeviceKey,
    pub kept_by_hysteresis: bool,
    /// Every compared option, by ascending score.
    pub options: Vec<RouteOption>,
    pub ineligible: Vec<IneligibleEndpoint>,
}

/// Why nothing was chosen.
#[derive(Clone, Debug, PartialEq)]
pub enum RouteRefusal {
    /// No authorized endpoint for the exact requested model is eligible; no other model
    /// is offered instead.
    NoEligibleEndpoint {
        ineligible: Vec<IneligibleEndpoint>,
    },
    Invalid(RoutingError),
}

impl From<RoutingError> for RouteRefusal {
    fn from(error: RoutingError) -> Self {
        Self::Invalid(error)
    }
}

impl fmt::Display for RouteRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoEligibleEndpoint { ineligible } => write!(
                f,
                "no authorized endpoint for the exact requested model is eligible ({} refused); \
                 no other model is substituted",
                ineligible.len()
            ),
            Self::Invalid(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for RouteRefusal {}

/// The §4.6 router with per-flow hysteresis.
#[derive(Clone, Debug)]
pub struct JointRouter {
    policy: RoutingPolicy,
    current: BTreeMap<FlowKey, GpuDeviceKey>,
}

fn usable(rating: &BandwidthRating) -> Result<f64, BandwidthBasis> {
    rating
        .usable_bytes_per_second()
        .map_err(|unusable| unusable.basis)
}

impl JointRouter {
    /// Refuses a negative or non-finite policy figure.
    pub fn new(policy: RoutingPolicy) -> Result<Self, RoutingError> {
        policy.check()?;
        Ok(Self {
            policy,
            current: BTreeMap::new(),
        })
    }

    pub fn policy(&self) -> &RoutingPolicy {
        &self.policy
    }

    /// The endpoint a flow is currently routed to.
    pub fn current(&self, flow: &FlowKey) -> Option<&GpuDeviceKey> {
        self.current.get(flow)
    }

    /// Forgets a flow, as when its session ends.
    pub fn forget(&mut self, flow: &FlowKey) {
        self.current.remove(flow);
    }

    /// Scores every endpoint without changing any flow: options by ascending score, and
    /// the endpoints left out with their reasons.
    pub fn evaluate(
        &self,
        request: &RoutingRequest,
        endpoints: &[EndpointReport],
        clock: &dyn Clock,
    ) -> Result<(Vec<RouteOption>, Vec<IneligibleEndpoint>), RoutingError> {
        for (index, endpoint) in endpoints.iter().enumerate() {
            if endpoints
                .iter()
                .take(index)
                .any(|other| other.device == endpoint.device)
            {
                return Err(InputError::Duplicate {
                    field: "endpoints",
                    name: endpoint.device.device.to_hex(),
                }
                .into());
            }
        }
        if let Some(budget) = request.restrictions.max_egress_usd {
            non_negative("max_egress_usd", budget)?;
        }
        let now = clock.now();
        let mut options = Vec::new();
        let mut ineligible = Vec::new();
        for endpoint in endpoints {
            match self.option_for(request, endpoint, clock, now) {
                Ok(option) => options.push(option),
                Err(reason) => ineligible.push(IneligibleEndpoint {
                    device: endpoint.device,
                    reason,
                }),
            }
        }
        options.sort_by(|left, right| {
            left.score_seconds
                .total_cmp(&right.score_seconds)
                .then_with(|| left.device.cmp(&right.device))
        });
        Ok((options, ineligible))
    }

    /// Chooses an endpoint for `request` and remembers it for the request's flow. The
    /// flow stays on its endpoint unless another clears the hysteresis threshold or the
    /// current one is no longer eligible.
    pub fn route(
        &mut self,
        request: &RoutingRequest,
        endpoints: &[EndpointReport],
        clock: &dyn Clock,
    ) -> Result<RouteDecision, RouteRefusal> {
        let (options, ineligible) = self.evaluate(request, endpoints, clock)?;
        let Some(best) = options.first().cloned() else {
            return Err(RouteRefusal::NoEligibleEndpoint { ineligible });
        };
        let held = self
            .current
            .get(&request.flow)
            .and_then(|device| options.iter().find(|option| option.device == *device));
        let (chosen, kept_by_hysteresis) = match held {
            Some(current) if current.device != best.device => {
                let gain = current.score_seconds - best.score_seconds;
                if gain
                    < self
                        .policy
                        .hysteresis
                        .threshold_seconds(current.score_seconds)
                {
                    (current.clone(), true)
                } else {
                    (best.clone(), false)
                }
            }
            _ => (best.clone(), false),
        };
        self.current.insert(request.flow, chosen.device);
        Ok(RouteDecision {
            chosen,
            best: best.device,
            kept_by_hysteresis,
            options,
            ineligible,
        })
    }

    fn option_for(
        &self,
        request: &RoutingRequest,
        endpoint: &EndpointReport,
        clock: &dyn Clock,
        now: MonotonicTime,
    ) -> Result<RouteOption, Ineligible> {
        let machine = endpoint.device.machine;
        if !request.authorized_machines.contains(&machine) {
            return Err(Ineligible::MachineNotAuthorized);
        }
        if request.restrictions.excluded_machines.contains(&machine) {
            return Err(Ineligible::ExcludedByUser);
        }
        if !request
            .restrictions
            .categories
            .contains(&endpoint.scope.category)
        {
            return Err(Ineligible::CategoryNotAccepted {
                category: endpoint.scope.category,
            });
        }
        let egress_usd_per_byte =
            non_negative("egress_usd_per_byte", endpoint.egress_usd_per_byte)?;
        let mut donor_impact_seconds =
            non_negative("donor_impact_seconds", endpoint.donor_impact_seconds)?;
        let stale = stale_penalty(&self.policy.staleness, endpoint.observed_at, now)
            .map_err(Ineligible::StaleReport)?;

        let mut egress_bytes = 0u64;
        let (authority, execution, preparation) = match &endpoint.state {
            EndpointState::Ready(claim) => {
                let execution = claim.advertisement.residency.execution;
                if !request.model.accepts(&execution) {
                    return Err(Ineligible::NotRequestedModel { offered: execution });
                }
                if claim.advertisement.residency.device != endpoint.device
                    || claim.advertisement.residency.scope != endpoint.scope
                {
                    return Err(Ineligible::ReportDisagreesWithResidency);
                }
                let rechecked = claim
                    .advertisement
                    .recheck(
                        &claim.current,
                        &AdvertisementRequest {
                            requester: request.requester.clone(),
                            required: execution,
                            purpose: AdvertisementPurpose::Serve,
                        },
                        claim.grant.as_ref(),
                        clock,
                    )
                    .map_err(Ineligible::Advertisement)?;
                (
                    RouteAuthority::Ready(rechecked),
                    execution,
                    SecondsEstimate::ZERO,
                )
            }
            EndpointState::Cold {
                execution,
                source,
                preparation,
            } => {
                if !request.model.accepts(execution) {
                    return Err(Ineligible::NotRequestedModel {
                        offered: *execution,
                    });
                }
                let authority = match source {
                    PreparationSource::PeerResident {
                        claim,
                        bytes,
                        interference_seconds_per_byte,
                    } => {
                        let rechecked = claim
                            .advertisement
                            .recheck(
                                &claim.current,
                                &AdvertisementRequest {
                                    requester: request.requester.clone(),
                                    required: *execution,
                                    purpose: AdvertisementPurpose::Transfer {
                                        recipient: endpoint.scope,
                                    },
                                },
                                claim.grant.as_ref(),
                                clock,
                            )
                            .map_err(Ineligible::SourceAdvertisement)?;
                        egress_bytes = egress_bytes.saturating_add(*bytes);
                        donor_impact_seconds += approx_f64(*bytes)
                            * non_negative(
                                "interference_seconds_per_byte",
                                *interference_seconds_per_byte,
                            )?;
                        RouteAuthority::PreparedFromPeer(rechecked)
                    }
                    PreparationSource::LocalArtifact {
                        artifact,
                        owner,
                        grant,
                    } => {
                        let need = GrantNeed {
                            owner,
                            grantee: &request.requester,
                            artifact,
                            scope: &endpoint.scope,
                            granted_use: GrantedUse::ShareImmutableStorage,
                        };
                        let grant_valid_until = check_grant(grant.as_ref(), &need, now)
                            .map_err(Ineligible::LocalArtifactGrant)?;
                        RouteAuthority::PreparedFromLocalArtifact { grant_valid_until }
                    }
                };
                let bound = transfer_lower_bound(
                    &preparation.resources,
                    &preparation.demands,
                    preparation.minimum_seconds,
                )
                .map_err(|error| Ineligible::Invalid(error.into()))?;
                if let Err(BoundsError::BelowLowerBound {
                    claimed_seconds,
                    lower_bound_seconds,
                }) = bound.check_claim(preparation.critical_path.expected_seconds())
                {
                    return Err(Ineligible::BelowPhysicalBound {
                        claimed_seconds,
                        lower_bound_seconds,
                    });
                }
                (authority, *execution, preparation.critical_path)
            }
        };

        let (path, migration, session_bytes) =
            self.session_path(request, endpoint, &execution, preparation)?;
        egress_bytes = egress_bytes.saturating_add(session_bytes);

        let path = match &request.input {
            Some(input) if input.machine != machine => {
                let link = endpoint
                    .input_link
                    .as_ref()
                    .ok_or(Ineligible::NoMeasuredInputLink)?;
                let bytes_per_second = usable(link).map_err(|_| Ineligible::NoMeasuredInputLink)?;
                egress_bytes = egress_bytes.saturating_add(input.bytes);
                path.alongside(SecondsEstimate::exact(
                    approx_f64(input.bytes) / bytes_per_second,
                )?)
            }
            _ => path,
        };

        let egress_usd = approx_f64(egress_bytes) * egress_usd_per_byte;
        if let Some(budget_usd) = request.restrictions.max_egress_usd {
            if egress_usd > budget_usd {
                return Err(Ineligible::EgressBudgetExceeded {
                    cost_usd: egress_usd,
                    budget_usd,
                });
            }
        }
        let finish = finish_at_node(FinishComponents {
            queue: endpoint.queue.widened(stale.added_uncertainty_seconds)?,
            state_preparation_critical_path: path,
            request_compute: endpoint.request_compute,
            client_network_tail: endpoint.client_network_tail,
        });
        let score_seconds = finish.finish.risk_adjusted_seconds(self.policy.risk_weight)
            + stale.penalty_seconds
            + egress_usd * self.policy.seconds_per_usd
            + donor_impact_seconds;
        Ok(RouteOption {
            device: endpoint.device,
            authority,
            migration,
            finish,
            stale,
            egress_bytes,
            egress_usd,
            donor_impact_seconds,
            score_seconds,
        })
    }

    /// The preparation path including the session move, if the session lives elsewhere.
    /// Token reconstruction needs the model, so it follows the preparation; raw KV
    /// transfer runs alongside it. Each supported mechanism is priced on its own and the
    /// faster valid one is used.
    fn session_path(
        &self,
        request: &RoutingRequest,
        endpoint: &EndpointReport,
        execution: &ExecutionIdentity,
        preparation: SecondsEstimate,
    ) -> Result<(SecondsEstimate, Option<MigrationPlan>, u64), Ineligible> {
        let Some(session) = &request.session else {
            return Ok((preparation, None, 0));
        };
        if session.home == endpoint.device {
            return Ok((preparation, None, 0));
        }
        if let Some(support) = &endpoint.migration.token_reconstruction {
            non_negative("KvRecompute.queue_seconds", support.recompute.queue_seconds)?;
            non_negative(
                "KvRecompute.compute_seconds",
                support.recompute.compute_seconds,
            )?;
        }
        if let Some(support) = &endpoint.migration.raw_kv_transfer {
            non_negative("RawKvTransferSupport.setup_seconds", support.setup_seconds)?;
        }
        let token = match &endpoint.migration.token_reconstruction {
            None => Err(MechanismUnavailable::NotSupported),
            Some(support) => token_reconstruction(session, support),
        };
        let raw = match &endpoint.migration.raw_kv_transfer {
            None => Err(MechanismUnavailable::NotSupported),
            Some(support) => raw_kv_transfer(session, support, execution),
        };
        let mut candidates = Vec::new();
        if let Ok((plan, bytes)) = &token {
            let path = preparation.then(SecondsEstimate::exact(plan.completion_seconds())?);
            candidates.push((path, *plan, *bytes));
        }
        if let Ok((plan, bytes)) = &raw {
            let path = preparation.alongside(SecondsEstimate::exact(plan.completion_seconds())?);
            candidates.push((path, *plan, *bytes));
        }
        let best = candidates.into_iter().min_by(|left, right| {
            left.0
                .risk_adjusted_seconds(self.policy.risk_weight)
                .total_cmp(&right.0.risk_adjusted_seconds(self.policy.risk_weight))
                .then_with(|| left.1.mechanism().cmp(&right.1.mechanism()))
        });
        match best {
            Some((path, plan, bytes)) => Ok((path, Some(plan), bytes)),
            None => Err(Ineligible::SessionUnreachable {
                token_reconstruction: token.err().unwrap_or(MechanismUnavailable::NotSupported),
                raw_kv_transfer: raw.err().unwrap_or(MechanismUnavailable::NotSupported),
            }),
        }
    }
}

/// Prices token reconstruction: allowed only under the §2.8 recompute rule; costs the
/// token transfer plus the recomputation's queue and compute.
fn token_reconstruction(
    session: &SessionState,
    support: &TokenReconstructionSupport,
) -> Result<(MigrationPlan, u64), MechanismUnavailable> {
    check_recompute(&session.requirement, &support.recompute)
        .map_err(MechanismUnavailable::Recompute)?;
    let bytes_per_second =
        usable(&support.link).map_err(|basis| MechanismUnavailable::UnmeasuredLink { basis })?;
    let completion_seconds = approx_f64(support.token_bytes) / bytes_per_second
        + support.recompute.queue_seconds
        + support.recompute.compute_seconds;
    Ok((
        MigrationPlan::TokenReconstruction {
            completion_seconds,
            tokens: session.context_tokens,
            token_bytes: support.token_bytes,
        },
        support.token_bytes,
    ))
}

/// Prices raw KV transfer: allowed only into an identical, enforced reuse scope on the
/// same execution; costs setup plus the KV bytes over the measured link.
fn raw_kv_transfer(
    session: &SessionState,
    support: &RawKvTransferSupport,
    execution: &ExecutionIdentity,
) -> Result<(MigrationPlan, u64), MechanismUnavailable> {
    if support.destination_scope.model != *execution {
        return Err(MechanismUnavailable::KvScope(
            KvReuseRefusal::ScopeMismatch {
                components: vec![KvScopeComponent::Model],
            },
        ));
    }
    let scope = check_kv_reuse(
        &session.scope,
        &support.destination_scope,
        &support.enforcement,
    )
    .map_err(MechanismUnavailable::KvScope)?;
    let bytes_per_second =
        usable(&support.link).map_err(|basis| MechanismUnavailable::UnmeasuredLink { basis })?;
    let completion_seconds =
        support.setup_seconds + approx_f64(session.kv_bytes) / bytes_per_second;
    Ok((
        MigrationPlan::RawKvTransfer {
            completion_seconds,
            kv_bytes: session.kv_bytes,
            scope,
        },
        session.kv_bytes,
    ))
}
