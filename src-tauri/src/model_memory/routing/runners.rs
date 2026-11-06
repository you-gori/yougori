//! The §4.6 prototype: simulated runners (line 718, "Prototype locally first with two
//! simulated runners").
//!
//! Each runner serves one request at a time, may start cold and load its state, and has
//! a backlog of work already admitted. Requests arrive in order; a policy picks a runner
//! from what the runners report at arrival, and the simulator then plays the request out
//! with the trial's seeded variation of load and compute times. Three policies are
//! compared:
//!
//! - [`SimPolicy::Joint`]: the §4.6 router ([`JointRouter`]) over endpoint reports built
//!   from the runners' state, with real advertisement rechecks and grants.
//! - [`SimPolicy::RouteToReady`]: the ordinary workflow, sticky to ready state: a
//!   session stays home, other requests go to the ready runner that frees first.
//! - [`SimPolicy::LocalityStartup`]: a reimplementation of the mechanism ServerlessLLM
//!   describes: a request goes to a runner with a free slot, choosing the shortest
//!   estimated startup (zero when ready, else the remaining load); when no slot is free
//!   it waits for the runner whose slot opens first; a session moves off a busy home by
//!   token reconstruction, the migration ServerlessLLM uses.
//!
//! Nothing here runs a model or touches a GPU; the results are fake-substrate evidence.

use std::collections::BTreeSet;

use crate::foundation::ids::{
    Clock, Digest, GpuDeviceKey, ManualClock, MonotonicTime, TenantId, TrustScope,
};
use crate::foundation::report::{
    CacheTier, ColdProvenance, ModelAtArrival, PrefillMode, StartState, StartTemperature,
};
use crate::model_memory::bench::rng::SeededRng;
use crate::model_memory::identity::{ExecutionIdentity, ScopeEnforcement};
use crate::model_memory::math::bounds::{BandwidthRating, ResourceTable, TransferDemand};
use crate::model_memory::math::recompute::KvRecompute;
use crate::model_memory::math::{non_negative, positive, InputError};

use super::error::RoutingError;
use super::estimate::SecondsEstimate;
use super::evidence::DemandLoad;
use super::joint::{
    EndpointReport, EndpointState, FlowKey, JointRouter, MigrationMechanism, MigrationPlan,
    MigrationSupport, PlacementRestrictions, Preparation, PreparationSource, RawKvTransferSupport,
    RequestedModel, ResidentClaim, RouteRefusal, RoutingPolicy, RoutingRequest, SessionState,
    TokenReconstructionSupport,
};
use super::numbers::{approx_f64, floor_u64};

/// One simulated runner (§4.6, line 718).
#[derive(Clone, Debug)]
pub struct RunnerSpec {
    pub device: GpuDeviceKey,
    pub scope: TrustScope,
    pub ready_at_start: bool,
    /// The resident claim the runner reports once it is ready.
    pub resident: ResidentClaim,
    /// Where a cold runner prepares the state from.
    pub source: PreparationSource,
    /// What a full load crosses, for the GPU §2.2 bound check.
    pub resources: ResourceTable,
    pub demands: Vec<TransferDemand>,
    /// Engine start and other byte-free parts of a load.
    pub minimum_seconds: f64,
    /// Nominal full load time; the trial varies it.
    pub load_seconds: f64,
    /// Spread reported on a load, as a fraction of its remaining time.
    pub load_uncertainty_fraction: f64,
    /// Bytes a load reads from local storage.
    pub artifact_bytes: u64,
    /// Work already admitted at time zero.
    pub backlog_seconds: f64,
    pub prefill_tokens_per_second: f64,
    pub decode_tokens_per_second: f64,
    /// Spread reported on compute and queue, as a fraction of their expected time.
    pub compute_uncertainty_fraction: f64,
    pub client_tail_seconds: f64,
    pub supports_token_reconstruction: bool,
    pub accepts_raw_kv: bool,
    pub egress_usd_per_byte: f64,
    pub donor_impact_seconds: f64,
}

/// The simulated fleet and the tenant's fixed request context.
#[derive(Clone, Debug)]
pub struct Fleet {
    pub runners: Vec<RunnerSpec>,
    pub requester: TenantId,
    pub model: RequestedModel,
    /// The execution every runner serves once ready.
    pub execution: ExecutionIdentity,
    pub authorized_machines: BTreeSet<Digest>,
    pub restrictions: PlacementRestrictions,
    /// The session the trace continues, if any, at its initial home.
    pub session: Option<SimSession>,
    /// Measured link between runners for session moves.
    pub session_link: BandwidthRating,
    pub raw_kv_setup_seconds: f64,
    pub kv_enforcement: ScopeEnforcement,
}

/// A session the trace continues (§4.6 "session stickiness").
#[derive(Clone, Debug, PartialEq)]
pub struct SimSession {
    /// Index of the runner holding the session's KV at time zero.
    pub home: usize,
    pub state: SessionState,
    /// Bytes per token sent for token reconstruction.
    pub token_bytes_per_token: u64,
}

/// One request of a trace.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TraceRequest {
    pub arrival_seconds: f64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// Continues the fleet's session.
    pub continues_session: bool,
}

/// The policy that picks a runner.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SimPolicy {
    /// The §4.6 joint router (the candidate).
    Joint(RoutingPolicy),
    /// Sticky to ready state (the ordinary workflow).
    RouteToReady,
    /// ServerlessLLM-style startup-time selection (the strongest compatible baseline).
    LocalityStartup,
}

/// One trial's seeded variation, shared by every policy so trials are paired.
#[derive(Clone, Debug, PartialEq)]
pub struct TrialConditions {
    pub trial: u32,
    /// Per runner: actual load time over nominal.
    pub load_factor: Vec<f64>,
    /// Per runner: actual compute time over nominal.
    pub compute_factor: Vec<f64>,
}

impl TrialConditions {
    /// Draws each runner's factors uniformly within `spread_ppm` either side of one.
    pub fn draw(
        trial: u32,
        runners: usize,
        seed: u64,
        spread_ppm: u32,
    ) -> Result<Self, RoutingError> {
        if spread_ppm >= 1_000_000 {
            return Err(InputError::OutOfRange {
                field: "spread_ppm",
            }
            .into());
        }
        let mut rng = SeededRng::new(seed ^ u64::from(trial).wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let spread = u64::from(spread_ppm);
        let factor = |rng: &mut SeededRng| {
            let parts = 1_000_000u64
                .saturating_sub(spread)
                .saturating_add(rng.below(spread.saturating_mul(2).saturating_add(1)));
            approx_f64(parts) / 1_000_000.0
        };
        let load_factor = (0..runners).map(|_| factor(&mut rng)).collect();
        let compute_factor = (0..runners).map(|_| factor(&mut rng)).collect();
        Ok(Self {
            trial,
            load_factor,
            compute_factor,
        })
    }
}

/// How a request was served.
#[derive(Clone, Debug, PartialEq)]
pub struct ServedRequest {
    pub index: usize,
    pub runner: usize,
    pub arrival_seconds: f64,
    pub demand_load: Option<DemandLoad>,
    pub service_start_seconds: f64,
    /// Client-side, tail included.
    pub first_token_seconds: f64,
    /// Client-side, tail included.
    pub completion_seconds: f64,
    pub state: StartState,
    pub migration: Option<MigrationMechanism>,
    pub transferred_bytes: u64,
    pub storage_read_bytes: u64,
}

impl ServedRequest {
    /// Arrival to completion, as the client sees it.
    pub fn latency_seconds(&self) -> f64 {
        self.completion_seconds - self.arrival_seconds
    }
}

#[derive(Clone, Copy, Debug)]
struct RunnerState {
    ready_at: Option<f64>,
    free_at: f64,
}

fn check_runner(spec: &RunnerSpec) -> Result<(), InputError> {
    non_negative("minimum_seconds", spec.minimum_seconds)?;
    non_negative("load_seconds", spec.load_seconds)?;
    non_negative("load_uncertainty_fraction", spec.load_uncertainty_fraction)?;
    non_negative("backlog_seconds", spec.backlog_seconds)?;
    positive("prefill_tokens_per_second", spec.prefill_tokens_per_second)?;
    positive("decode_tokens_per_second", spec.decode_tokens_per_second)?;
    non_negative(
        "compute_uncertainty_fraction",
        spec.compute_uncertainty_fraction,
    )?;
    non_negative("client_tail_seconds", spec.client_tail_seconds)?;
    non_negative("egress_usd_per_byte", spec.egress_usd_per_byte)?;
    non_negative("donor_impact_seconds", spec.donor_impact_seconds)?;
    Ok(())
}

impl Fleet {
    fn check(
        &self,
        trace: &[TraceRequest],
        conditions: &TrialConditions,
    ) -> Result<(), RoutingError> {
        if self.runners.is_empty() {
            return Err(InputError::Empty { field: "runners" }.into());
        }
        for runner in &self.runners {
            check_runner(runner)?;
        }
        for factors in [&conditions.load_factor, &conditions.compute_factor] {
            if factors.len() != self.runners.len() {
                return Err(InputError::LengthMismatch {
                    field: "TrialConditions",
                    expected: self.runners.len(),
                    actual: factors.len(),
                }
                .into());
            }
        }
        non_negative("raw_kv_setup_seconds", self.raw_kv_setup_seconds)?;
        if let Some(session) = &self.session {
            if session.home >= self.runners.len() {
                return Err(InputError::OutOfRange {
                    field: "SimSession.home",
                }
                .into());
            }
        }
        let mut previous = 0.0;
        for request in trace {
            let arrival = non_negative("arrival_seconds", request.arrival_seconds)?;
            if arrival < previous {
                return Err(InputError::OutOfRange {
                    field: "arrival_seconds",
                }
                .into());
            }
            previous = arrival;
            if request.continues_session && self.session.is_none() {
                return Err(InputError::OutOfRange {
                    field: "continues_session",
                }
                .into());
            }
        }
        Ok(())
    }

    fn session_support(&self, spec: &RunnerSpec, session: &SimSession) -> MigrationSupport {
        let state = &session.state;
        MigrationSupport {
            token_reconstruction: spec.supports_token_reconstruction.then(|| {
                TokenReconstructionSupport {
                    recompute: KvRecompute {
                        held_prefix: Some(state.requirement.prefix_identity),
                        produces_state: state.requirement.state_identity,
                        authorized_epoch: Some(state.requirement.current_epoch),
                        queue_seconds: 0.0,
                        compute_seconds: approx_f64(state.context_tokens)
                            / spec.prefill_tokens_per_second,
                    },
                    token_bytes: state
                        .context_tokens
                        .saturating_mul(session.token_bytes_per_token),
                    link: self.session_link,
                }
            }),
            raw_kv_transfer: spec.accepts_raw_kv.then(|| RawKvTransferSupport {
                destination_scope: state.scope.clone(),
                enforcement: self.kv_enforcement.clone(),
                link: self.session_link,
                setup_seconds: self.raw_kv_setup_seconds,
            }),
        }
    }

    /// The report runner `spec` gives at `now`.
    fn report(
        &self,
        spec: &RunnerSpec,
        state: &RunnerState,
        now: f64,
        observed_at: MonotonicTime,
        request: &TraceRequest,
        session: Option<&SimSession>,
    ) -> Result<EndpointReport, RoutingError> {
        let (endpoint_state, remaining) = match state.ready_at {
            Some(ready_at) if ready_at <= now => (EndpointState::Ready(spec.resident.clone()), 0.0),
            other => {
                let remaining = other.map_or(spec.load_seconds, |ready_at| ready_at - now);
                let fraction = if spec.load_seconds > 0.0 {
                    (remaining / spec.load_seconds).min(1.0)
                } else {
                    0.0
                };
                let demands = spec
                    .demands
                    .iter()
                    .map(|demand| TransferDemand {
                        bytes: floor_u64(approx_f64(demand.bytes) * fraction),
                        resources: demand.resources.clone(),
                    })
                    .collect();
                let preparation = Preparation {
                    critical_path: SecondsEstimate::new(
                        remaining,
                        remaining * spec.load_uncertainty_fraction,
                    )?,
                    resources: spec.resources.clone(),
                    demands,
                    minimum_seconds: spec.minimum_seconds * fraction,
                };
                (
                    EndpointState::Cold {
                        execution: self.execution,
                        source: spec.source.clone(),
                        preparation,
                    },
                    remaining,
                )
            }
        };
        let queue = (state.free_at - (now + remaining)).max(0.0);
        let compute = compute_seconds(spec, request);
        Ok(EndpointReport {
            device: spec.device,
            scope: spec.scope,
            observed_at,
            queue: SecondsEstimate::new(queue, queue * spec.compute_uncertainty_fraction)?,
            request_compute: SecondsEstimate::new(
                compute,
                compute * spec.compute_uncertainty_fraction,
            )?,
            client_network_tail: SecondsEstimate::exact(spec.client_tail_seconds)?,
            state: endpoint_state,
            migration: session.map_or_else(MigrationSupport::default, |session| {
                self.session_support(spec, session)
            }),
            input_link: None,
            egress_usd_per_byte: spec.egress_usd_per_byte,
            donor_impact_seconds: spec.donor_impact_seconds,
        })
    }
}

fn compute_seconds(spec: &RunnerSpec, request: &TraceRequest) -> f64 {
    approx_f64(request.input_tokens) / spec.prefill_tokens_per_second
        + approx_f64(request.output_tokens) / spec.decode_tokens_per_second
}

fn unknown_runner() -> RoutingError {
    RoutingError::Input(InputError::OutOfRange { field: "runner" })
}

fn is_ready(state: &RunnerState, now: f64) -> bool {
    state.ready_at.is_some_and(|ready_at| ready_at <= now)
}

/// Runs `trace` on `fleet` under `policy` with the trial's variation. Every policy run
/// with the same conditions sees the same load and compute times.
pub fn simulate(
    fleet: &Fleet,
    trace: &[TraceRequest],
    policy: &SimPolicy,
    conditions: &TrialConditions,
) -> Result<Vec<ServedRequest>, RoutingError> {
    fleet.check(trace, conditions)?;
    let mut states: Vec<RunnerState> = fleet
        .runners
        .iter()
        .map(|spec| RunnerState {
            ready_at: spec.ready_at_start.then_some(0.0),
            free_at: spec.backlog_seconds,
        })
        .collect();
    let mut session = fleet.session.clone();
    let clock = ManualClock::new(MonotonicTime::ZERO);
    let mut router = match policy {
        SimPolicy::Joint(routing) => Some(JointRouter::new(*routing)?),
        _ => None,
    };
    let mut served = Vec::with_capacity(trace.len());
    for (index, request) in trace.iter().enumerate() {
        let now = request.arrival_seconds;
        let now_time = super::evidence::trial_time("arrival_seconds", now)?;
        clock.advance_to(now_time);
        let active_session = if request.continues_session {
            session.as_ref()
        } else {
            None
        };
        let (runner, migration) = match (policy, router.as_mut()) {
            (SimPolicy::Joint(_), Some(router)) => {
                let routing_request = RoutingRequest {
                    request: crate::foundation::ids::OperationId::new(format!("op-route-{index}"))?,
                    requester: fleet.requester.clone(),
                    model: fleet.model.clone(),
                    flow: FlowKey::model(&fleet.requester, &fleet.model),
                    authorized_machines: fleet.authorized_machines.clone(),
                    restrictions: fleet.restrictions.clone(),
                    session: active_session.map(|session| session.state.clone()),
                    input: None,
                };
                let reports = fleet
                    .runners
                    .iter()
                    .zip(&states)
                    .map(|(spec, state)| {
                        fleet.report(spec, state, now, clock.now(), request, active_session)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let decision =
                    router
                        .route(&routing_request, &reports, &clock)
                        .map_err(|refusal| match refusal {
                            RouteRefusal::Invalid(error) => error,
                            RouteRefusal::NoEligibleEndpoint { .. } => {
                                RoutingError::Input(InputError::Empty {
                                    field: "eligible endpoints",
                                })
                            }
                        })?;
                let runner = fleet
                    .runners
                    .iter()
                    .position(|spec| spec.device == decision.chosen.device)
                    .ok_or(RoutingError::Input(InputError::Unknown {
                        field: "chosen device",
                        name: decision.chosen.device.device.to_hex(),
                    }))?;
                (runner, decision.chosen.migration)
            }
            (SimPolicy::RouteToReady, _) => {
                (route_to_ready(fleet, &states, now, active_session), None)
            }
            _ => locality_startup(fleet, &states, now, active_session),
        };
        served.push(play(
            fleet,
            &mut states,
            index,
            runner,
            migration,
            request,
            active_session,
            conditions,
        )?);
        if let (Some(session), true) = (session.as_mut(), request.continues_session) {
            session.home = runner;
            session.state.home = fleet.runners.get(runner).ok_or_else(unknown_runner)?.device;
        }
    }
    Ok(served)
}

/// The ordinary workflow: a session stays home; otherwise the ready runner that frees
/// first, else the runner that will be ready first, else the fastest cold load.
fn route_to_ready(
    fleet: &Fleet,
    states: &[RunnerState],
    now: f64,
    session: Option<&SimSession>,
) -> usize {
    if let Some(session) = session {
        return session.home;
    }
    let runners = || fleet.runners.iter().zip(states).enumerate();
    let ready = runners()
        .filter(|(_, (_, state))| is_ready(state, now))
        .min_by(|(_, (_, left)), (_, (_, right))| left.free_at.total_cmp(&right.free_at));
    if let Some((runner, _)) = ready {
        return runner;
    }
    let loading = runners()
        .filter_map(|(runner, (_, state))| state.ready_at.map(|ready_at| (runner, ready_at)))
        .min_by(|left, right| left.1.total_cmp(&right.1));
    if let Some((runner, _)) = loading {
        return runner;
    }
    runners()
        .min_by(|(_, (left, _)), (_, (right, _))| left.load_seconds.total_cmp(&right.load_seconds))
        .map_or(0, |(runner, _)| runner)
}

/// ServerlessLLM-style selection: among runners with a free slot, the shortest startup
/// (zero when ready, the remaining load when loading, the full load when cold); with no
/// free slot, the runner whose slot opens first. A session leaves a busy home only for a
/// free runner that supports token reconstruction.
fn locality_startup(
    fleet: &Fleet,
    states: &[RunnerState],
    now: f64,
    session: Option<&SimSession>,
) -> (usize, Option<MigrationPlan>) {
    let startup = |spec: &RunnerSpec, state: &RunnerState| match state.ready_at {
        Some(ready_at) => (ready_at - now).max(0.0),
        None => spec.load_seconds,
    };
    let free = |state: &RunnerState| state.free_at <= now;
    let runners = || fleet.runners.iter().zip(states).enumerate();
    if let Some(session) = session {
        if states.get(session.home).is_some_and(|state| free(state)) {
            return (session.home, None);
        }
        let target = runners()
            .filter(|(runner, (spec, state))| {
                *runner != session.home && free(state) && spec.supports_token_reconstruction
            })
            .min_by(|(_, (left_spec, left)), (_, (right_spec, right))| {
                startup(left_spec, left).total_cmp(&startup(right_spec, right))
            });
        return match target {
            Some((runner, (spec, _))) => {
                let state = &session.state;
                let token_bytes = state
                    .context_tokens
                    .saturating_mul(session.token_bytes_per_token);
                let link_seconds = fleet
                    .session_link
                    .usable_bytes_per_second()
                    .map_or(f64::INFINITY, |rate| approx_f64(token_bytes) / rate);
                (
                    runner,
                    Some(MigrationPlan::TokenReconstruction {
                        completion_seconds: link_seconds
                            + approx_f64(state.context_tokens) / spec.prefill_tokens_per_second,
                        tokens: state.context_tokens,
                        token_bytes,
                    }),
                )
            }
            None => (session.home, None),
        };
    }
    let best_free = runners().filter(|(_, (_, state))| free(state)).min_by(
        |(_, (left_spec, left)), (_, (right_spec, right))| {
            startup(left_spec, left).total_cmp(&startup(right_spec, right))
        },
    );
    if let Some((runner, _)) = best_free {
        return (runner, None);
    }
    // No free slot: the runner whose slot opens first, as a shared queue would dispatch.
    let available = |spec: &RunnerSpec, state: &RunnerState| {
        state
            .free_at
            .max(state.ready_at.unwrap_or(now + spec.load_seconds))
    };
    let earliest = runners()
        .min_by(|(_, (left_spec, left)), (_, (right_spec, right))| {
            available(left_spec, left).total_cmp(&available(right_spec, right))
        })
        .map_or(0, |(runner, _)| runner);
    (earliest, None)
}

/// Plays one request out on `runner` with the trial's actual times.
#[allow(clippy::too_many_arguments)]
fn play(
    fleet: &Fleet,
    states: &mut [RunnerState],
    index: usize,
    runner: usize,
    migration: Option<MigrationPlan>,
    request: &TraceRequest,
    session: Option<&SimSession>,
    conditions: &TrialConditions,
) -> Result<ServedRequest, RoutingError> {
    let spec = fleet.runners.get(runner).ok_or_else(unknown_runner)?;
    let now = request.arrival_seconds;
    let compute_factor = conditions
        .compute_factor
        .get(runner)
        .copied()
        .ok_or_else(unknown_runner)?;
    let load_factor = conditions
        .load_factor
        .get(runner)
        .copied()
        .ok_or_else(unknown_runner)?;
    let state = states.get_mut(runner).ok_or_else(unknown_runner)?;
    let was_ready = is_ready(state, now);
    let mut storage_read_bytes = 0;
    let ready_at = match state.ready_at {
        Some(ready_at) => ready_at,
        None => {
            let ready_at = now + spec.load_seconds * load_factor;
            state.ready_at = Some(ready_at);
            storage_read_bytes = spec.artifact_bytes;
            ready_at
        }
    };
    let demand_load = (!was_ready).then_some(DemandLoad {
        started_seconds: now,
        completed_seconds: ready_at,
    });
    let mut start = now.max(state.free_at).max(ready_at);
    let mut reconstruction_seconds = 0.0;
    let mut transferred_bytes = 0;
    if let (Some(plan), Some(session)) = (migration, session) {
        match plan {
            MigrationPlan::TokenReconstruction { token_bytes, .. } => {
                let link = fleet.session_link.usable_bytes_per_second().map_err(|_| {
                    InputError::NotPositive {
                        field: "session_link",
                    }
                })?;
                start = start.max(now + approx_f64(token_bytes) / link);
                reconstruction_seconds = approx_f64(session.state.context_tokens)
                    / spec.prefill_tokens_per_second
                    * compute_factor;
                transferred_bytes = token_bytes;
            }
            MigrationPlan::RawKvTransfer { kv_bytes, .. } => {
                let link = fleet.session_link.usable_bytes_per_second().map_err(|_| {
                    InputError::NotPositive {
                        field: "session_link",
                    }
                })?;
                start = start.max(now + fleet.raw_kv_setup_seconds + approx_f64(kv_bytes) / link);
                transferred_bytes = kv_bytes;
            }
        }
    }
    let prefill =
        approx_f64(request.input_tokens) / spec.prefill_tokens_per_second * compute_factor;
    let decode = approx_f64(request.output_tokens) / spec.decode_tokens_per_second * compute_factor;
    let first_token = start + reconstruction_seconds + prefill;
    let completion = first_token + decode;
    state.free_at = completion;
    let (cache_tier, prefill_mode) = match (session, migration) {
        (Some(_), None) => (CacheTier::GpuMemory, PrefillMode::WarmPrefix),
        (Some(_), Some(MigrationPlan::RawKvTransfer { .. })) => {
            (CacheTier::Peer, PrefillMode::WarmPrefix)
        }
        _ => (CacheTier::NoReusableState, PrefillMode::Fresh),
    };
    let start_state = if was_ready {
        StartState {
            temperature: StartTemperature::Hot,
            model_at_arrival: ModelAtArrival::ReadyToServe,
            cache_tier,
            prefill: prefill_mode,
            cold_provenance: ColdProvenance::NotCold,
        }
    } else {
        StartState {
            temperature: StartTemperature::Warm,
            model_at_arrival: ModelAtArrival::NotLoaded,
            cache_tier: if cache_tier == CacheTier::NoReusableState {
                CacheTier::LocalDisk
            } else {
                cache_tier
            },
            prefill: prefill_mode,
            cold_provenance: ColdProvenance::NotCold,
        }
    };
    Ok(ServedRequest {
        index,
        runner,
        arrival_seconds: now,
        demand_load,
        service_start_seconds: start,
        first_token_seconds: first_token + spec.client_tail_seconds,
        completion_seconds: completion + spec.client_tail_seconds,
        state: start_state,
        migration: migration.map(|plan| plan.mechanism()),
        transferred_bytes,
        storage_read_bytes,
    })
}
