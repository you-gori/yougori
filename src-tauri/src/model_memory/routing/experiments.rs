//! The runnable §4.6–§4.8 experiments on the fake substrate (GPU §4, line 661: "a
//! runnable prototype, traces, a matched baseline, an interference result and a
//! decision").
//!
//! Each experiment runs its regimes for [`TRIALS_PER_REGIME`] seeded trials per policy,
//! records every simulated request as a fake-substrate CORE-08 record, compares the
//! candidate with the ordinary workflow and the strongest compatible baseline in a
//! [`ComparisonReport`], and ends with a §4.17 [`ClaimRecord`] whose result is computed
//! from those comparisons. The fake substrate caps every result at inconclusive.

use std::collections::BTreeSet;

use crate::foundation::ids::{ModelActivationGeneration, MonotonicTime, OperationId, ResourceId};
use crate::foundation::report::{
    Baseline, CacheTier, ColdProvenance, ComparisonReport, FixtureFamily, Label, ModelAtArrival,
    PrefillMode, Quantile, RunRecord, StartState, StartTemperature, StateComparison,
};
use crate::foundation::transfer::Endpoint;
use crate::model_memory::identity::GrantedUse;
use crate::model_memory::math::bounds::{BandwidthRating, ResourceTable, TransferDemand};
use crate::model_memory::math::InputError;

use super::claims::{regime_outcome, ClaimRecord, ClaimText, Experiment, PriorWork, RegimeOutcome};
use super::distributed::{
    serve_window, DistributedError, DonorRoute, LoadingWindow, ModelShape, PipelineLink,
    PipelinePlan, PipelineStage, ReplicaService, ServingUnit, WindowRequest, WindowServed,
    WindowStrategy,
};
use super::error::RoutingError;
use super::estimate::StalenessPolicy;
use super::evidence::{
    fake_comparison, fake_side, DemandLoad, FakeRunSetup, SimulatedAttempt, TRIALS_PER_REGIME,
};
use super::fixtures::{device, named, FleetAuthority, SyntheticFleet};
use super::joint::{HysteresisPolicy, PlacementRestrictions, PreparationSource, RoutingPolicy};
use super::numbers::count_u64;
use super::replication::{
    choose_schedule, plan_schedule, GatedPath, LinkSpec, NodeId, ReplicationError, ReplicationNode,
    ReplicationProblem, Schedule, ScheduleObjective, ScheduleRefusal, ScheduleShape, TargetSpec,
    Topology, Transport, TransportKind,
};
use super::runners::{
    simulate, Fleet, RunnerSpec, SimPolicy, SimSession, TraceRequest, TrialConditions,
};

/// A candidate within this fraction of the strongest baseline ties with it.
pub const TIE_TOLERANCE: f64 = 0.05;

/// Seeded variation of every simulated load and compute time: 5% either side.
pub const TRIAL_SPREAD_PPM: u32 = 50_000;

/// One regime's comparison and outcome.
#[derive(Clone, Debug, PartialEq)]
pub struct RegimeReport {
    pub regime: &'static str,
    pub report: ComparisonReport,
    pub outcome: RegimeOutcome,
}

/// An experiment's regimes and its claim record.
#[derive(Clone, Debug, PartialEq)]
pub struct ExperimentReport {
    pub claim: ClaimRecord,
    pub regimes: Vec<RegimeReport>,
}

fn label(value: &str) -> Result<Label, RoutingError> {
    Ok(Label::new(value)?)
}

/// The far future on the simulation clock, for advertisements and grants that do not
/// expire during an experiment.
fn far_future() -> MonotonicTime {
    MonotonicTime::from_nanos(u64::MAX / 2)
}

// §4.6 fleet: a 14 GB model read at the §2.2 illustration's 7 GB/s (a 2 s bound) plus
// 0.8 s of engine start.
const MODEL_BYTES: u64 = 14_000_000_000;
const NVME_BYTES_PER_SECOND: f64 = 7.0e9;
const ENGINE_START_SECONDS: f64 = 0.8;
const LOAD_SECONDS: f64 = 2.8;
const LAN_BYTES_PER_SECOND: f64 = 1.25e9;

/// A §4.6 runner on `machine`: ready or cold, with `backlog_seconds` of admitted work,
/// prefill at 8,000 tokens/s and decode at 40 tokens/s.
pub fn routing_runner(
    synthetic: &SyntheticFleet,
    authority: &FleetAuthority,
    machine: &str,
    ready_at_start: bool,
    backlog_seconds: f64,
) -> Result<RunnerSpec, RoutingError> {
    let gpu = device(machine, "gpu0");
    let scope = synthetic.scope(machine);
    let nvme = ResourceId::new(format!("{machine}-nvme-read"))?;
    let mut resources = ResourceTable::new();
    resources.add(
        nvme.clone(),
        BandwidthRating::measured_directional(NVME_BYTES_PER_SECOND)?,
    )?;
    Ok(RunnerSpec {
        device: gpu,
        scope,
        ready_at_start,
        resident: synthetic.resident_claim(
            authority,
            gpu,
            scope,
            synthetic.single_execution()?,
            ModelActivationGeneration::FIRST,
            far_future(),
        )?,
        source: PreparationSource::LocalArtifact {
            artifact: synthetic.artifact,
            owner: synthetic.tenant.clone(),
            grant: Some(synthetic.grant(
                authority,
                scope,
                &[GrantedUse::ShareImmutableStorage],
                far_future(),
            )?),
        },
        resources,
        demands: vec![TransferDemand {
            bytes: MODEL_BYTES,
            resources: vec![nvme],
        }],
        minimum_seconds: ENGINE_START_SECONDS,
        load_seconds: LOAD_SECONDS,
        load_uncertainty_fraction: 0.1,
        artifact_bytes: MODEL_BYTES,
        backlog_seconds,
        prefill_tokens_per_second: 8_000.0,
        decode_tokens_per_second: 40.0,
        compute_uncertainty_fraction: 0.1,
        client_tail_seconds: 0.02,
        supports_token_reconstruction: true,
        accepts_raw_kv: true,
        egress_usd_per_byte: 0.0,
        donor_impact_seconds: 0.0,
    })
}

/// A fleet of `runners` for the synthetic tenant, every machine authorized.
pub fn routing_fleet(
    synthetic: &SyntheticFleet,
    authority: &FleetAuthority,
    runners: Vec<RunnerSpec>,
    session: Option<SimSession>,
) -> Result<Fleet, RoutingError> {
    Ok(Fleet {
        authorized_machines: runners.iter().map(|runner| runner.device.machine).collect(),
        runners,
        requester: synthetic.tenant.clone(),
        model: synthetic.requested_single()?,
        execution: synthetic.single_execution()?,
        restrictions: PlacementRestrictions {
            excluded_machines: BTreeSet::new(),
            categories: BTreeSet::from([synthetic.category]),
            max_egress_usd: None,
        },
        session,
        session_link: BandwidthRating::measured_directional(LAN_BYTES_PER_SECOND)?,
        raw_kv_setup_seconds: 0.05,
        kv_enforcement: authority.kv_enforcement.clone(),
    })
}

/// The candidate's routing policy: one second of score per second of spread, reports
/// penalized 0.1 s per second of age and unused after 5 s, and a flow moves only for a
/// gain of at least 0.25 s and 5%.
pub fn routing_policy() -> Result<RoutingPolicy, RoutingError> {
    Ok(RoutingPolicy {
        risk_weight: 1.0,
        seconds_per_usd: 0.0,
        staleness: StalenessPolicy::new(0.1, 0.1, 5.0)?,
        hysteresis: HysteresisPolicy {
            min_gain_seconds: 0.25,
            min_gain_fraction: 0.05,
        },
    })
}

fn request(arrival_seconds: f64, continues_session: bool) -> TraceRequest {
    TraceRequest {
        arrival_seconds,
        input_tokens: 1_000,
        output_tokens: 60,
        continues_session,
    }
}

/// The §4.6 regimes: name, fleet, trace and fixture family.
pub fn routing_regimes(
    synthetic: &SyntheticFleet,
    authority: &FleetAuthority,
) -> Result<Vec<(&'static str, Fleet, Vec<TraceRequest>, FixtureFamily)>, RoutingError> {
    let overloaded = routing_fleet(
        synthetic,
        authority,
        vec![
            routing_runner(synthetic, authority, "host-a", true, 8.0)?,
            routing_runner(synthetic, authority, "host-b", false, 0.0)?,
        ],
        None,
    )?;
    let briefly_busy = routing_fleet(
        synthetic,
        authority,
        vec![
            routing_runner(synthetic, authority, "host-a", true, 0.6)?,
            routing_runner(synthetic, authority, "host-b", false, 0.0)?,
        ],
        None,
    )?;
    let home = routing_runner(synthetic, authority, "host-a", true, 6.0)?;
    let session = SimSession {
        home: 0,
        state: synthetic.session(home.device, 131_072, 131_072)?,
        token_bytes_per_token: 4,
    };
    let long_context = routing_fleet(
        synthetic,
        authority,
        vec![
            home,
            routing_runner(synthetic, authority, "host-b", true, 0.0)?,
        ],
        Some(session),
    )?;
    Ok(vec![
        (
            "overloaded-ready-vs-idle-cold",
            overloaded,
            (0..6)
                .map(|index| request(0.5 * f64::from(index), false))
                .collect(),
            FixtureFamily::Prose,
        ),
        (
            "briefly-busy-ready-vs-idle-cold",
            briefly_busy,
            vec![
                request(0.0, false),
                request(4.0, false),
                request(8.0, false),
            ],
            FixtureFamily::Prose,
        ),
        (
            "long-context-session-on-busy-home",
            long_context,
            vec![request(0.0, true), request(20.0, true)],
            FixtureFamily::LongContext,
        ),
    ])
}

/// Runs one §4.6 regime under the three policies and compares them.
pub fn run_routing_regime(
    regime: &'static str,
    fleet: &Fleet,
    trace: &[TraceRequest],
    family: FixtureFamily,
    seed: u64,
) -> Result<RegimeReport, RoutingError> {
    let setup = FakeRunSetup {
        experiment: label("gpu-4-6-joint-routing")?,
        trace: label(regime)?,
        family,
        max_output_tokens: trace
            .iter()
            .map(|request| request.output_tokens)
            .max()
            .unwrap_or(0),
        concurrent_requests: 1,
    };
    let policies = [
        ("joint-router", SimPolicy::Joint(routing_policy()?)),
        ("route-to-ready", SimPolicy::RouteToReady),
        ("locality-startup", SimPolicy::LocalityStartup),
    ];
    let mut records: [Vec<RunRecord>; 3] = [Vec::new(), Vec::new(), Vec::new()];
    for trial in 0..TRIALS_PER_REGIME {
        let conditions = TrialConditions::draw(trial, fleet.runners.len(), seed, TRIAL_SPREAD_PPM)?;
        for ((name, policy), side) in policies.iter().zip(records.iter_mut()) {
            let policy_label = label(name)?;
            for served in simulate(fleet, trace, policy, &conditions)? {
                let attempt = SimulatedAttempt {
                    operation: OperationId::new(format!("op-{name}-t{trial}-r{}", served.index))?,
                    trial,
                    input_tokens: trace
                        .get(served.index)
                        .map_or(0, |request| request.input_tokens),
                    arrival_seconds: served.arrival_seconds,
                    demand_load: served.demand_load,
                    service_start_seconds: served.service_start_seconds,
                    first_token_seconds: served.first_token_seconds,
                    completion_seconds: served.completion_seconds,
                    state: served.state,
                    transferred_bytes: served.transferred_bytes,
                    storage_read_bytes: served.storage_read_bytes,
                };
                side.push(setup.record(&policy_label, &attempt)?);
            }
        }
    }
    let [joint, ready, startup] = records;
    let report = fake_comparison(
        "joint-routing",
        StateComparison::HotDispatch,
        seed,
        fake_side("joint-router", &joint, StartTemperature::Hot, Quantile::P95)?,
        Baseline::Measured {
            sides: vec![fake_side(
                "route-to-ready",
                &ready,
                StartTemperature::Hot,
                Quantile::P95,
            )?],
        },
        Baseline::Measured {
            sides: vec![fake_side(
                "locality-startup",
                &startup,
                StartTemperature::Hot,
                Quantile::P95,
            )?],
        },
    )?;
    let outcome = regime_outcome(regime, &report, TIE_TOLERANCE)?;
    Ok(RegimeReport {
        regime,
        report,
        outcome,
    })
}

/// The §4.6 claim text (§4.17 items 1–4).
pub const JOINT_ROUTING_CLAIM: ClaimText = ClaimText {
    contribution: "A router for one exact requested model that ranks only authorized endpoints by \
        finish_at_node (queue, state preparation critical path, request compute and client tail) \
        with uncertainty and a stale-report penalty, prices a session move only by a mechanism the \
        destination backend supports, adds data locality, egress and donor impact, honours user \
        placement restrictions and keeps a hysteresis threshold.",
    closest_prior_work: PriorWork {
        name: "ServerlessLLM",
        reference: "https://www.usenix.org/conference/osdi24/presentation/fu",
        formulation: "Serverless LLM inference: start each model on the server where it starts \
            fastest, given where its checkpoints are stored.",
        algorithm: "Locality-aware server selection by estimated loading time from the fastest \
            storage tier, and live migration of running inference.",
        implementation: "The ServerlessLLM prototype (OSDI 2024); its migration sends tokens and \
            recomputes the KV cache at the destination.",
    },
    difference_tested: "The estimate adds the request's own queue, compute and client tail with \
        uncertainty, a stale-report penalty and hysteresis, and prices a session move per \
        supported mechanism, token reconstruction or raw KV transfer, never interchangeably.",
    assumptions: &[
        "Endpoint reports younger than the maximum age bound the real queue and compute time.",
        "Preparation estimates respect the GPU §2.2 lower bound for the bytes they move.",
        "Advertisements, authority records and grants are current when rechecked.",
        "Equal requests need equal compute on equal endpoints unless reported otherwise.",
    ],
    smallest_counterexample: "A report 1 s old from an idle endpoint hides a burst admitted \
        since; the router sends the request there and it finishes later than at the ready \
        endpoint (test the_stale_report_counterexample_breaks_the_assumption).",
    strongest_baseline: "ServerlessLLM-style startup-time selection with token-reconstruction \
        migration, reimplemented on the same simulated runners; the ordinary workflow routes to \
        ready state.",
};

/// Runs every §4.6 regime and builds its claim record. The seed fixes every trial.
/// The fleet's grants are checked through `authority`'s catalog.
pub fn joint_routing_experiment(
    seed: u64,
    authority: &FleetAuthority,
) -> Result<ExperimentReport, RoutingError> {
    let synthetic = SyntheticFleet::new()?;
    let mut regimes = Vec::new();
    for (index, (regime, fleet, trace, family)) in routing_regimes(&synthetic, authority)?
        .into_iter()
        .enumerate()
    {
        regimes.push(run_routing_regime(
            regime,
            &fleet,
            &trace,
            family,
            seed.wrapping_add(count_u64(index)),
        )?);
    }
    let claim = ClaimRecord::new(
        Experiment::JointRoutingAndPlacement,
        JOINT_ROUTING_CLAIM,
        regimes
            .iter()
            .map(|regime| regime.outcome.clone())
            .collect(),
        vec!["evaluation on two already-authorized machines (line 718)"],
        None,
    )?;
    Ok(ExperimentReport { claim, regimes })
}

// §4.7: a 10 GB object in 0.5 GB chunks over 10 GbE (1.25 GB/s per NIC direction).
const OBJECT_BYTES: u64 = 10_000_000_000;
const CHUNK_BYTES: u64 = 500_000_000;
const ORIGIN_BYTES_PER_SECOND: f64 = 100_000_000.0;
const STAGING_BYTES_PER_STREAM: u64 = 256 << 20;
const TARGET_PREFILL_SECONDS: f64 = 0.125;
const TARGET_DECODE_SECONDS: f64 = 1.5;

/// One §4.7 regime: the topology, the problem and the ordinary workflow's origin
/// topology, before any trial variation.
#[derive(Clone, Debug)]
pub struct ReplicationRegime {
    pub name: &'static str,
    pub topology: Topology,
    pub problem: ReplicationProblem,
    pub origin_topology: Topology,
    pub origin_problem: ReplicationProblem,
}

fn node_id(name: &str) -> Result<NodeId, RoutingError> {
    Ok(NodeId::new(name)?)
}

/// A full mesh over NICs: `name-tx` and `name-rx` per node at the listed transmit and
/// receive rates times `factor`, and one transport of `kind` spanning every node.
pub fn mesh_topology(
    nodes: &[(&str, f64, f64)],
    kind: TransportKind,
    setup_seconds: f64,
    factor: f64,
) -> Result<Topology, RoutingError> {
    let mut table = ResourceTable::new();
    let mut members = Vec::with_capacity(nodes.len());
    for (name, transmit, receive) in nodes {
        table.add(
            ResourceId::new(format!("{name}-tx"))?,
            BandwidthRating::measured_directional(transmit * factor)?,
        )?;
        table.add(
            ResourceId::new(format!("{name}-rx"))?,
            BandwidthRating::measured_directional(receive * factor)?,
        )?;
        members.push(ReplicationNode {
            id: node_id(name)?,
            endpoint: Endpoint::PeerHost {
                host: named(&format!("host:{name}")),
            },
            free_staging_bytes: 8 << 30,
            serving_impact_seconds_per_byte: 0.0,
        });
    }
    let mut links = Vec::new();
    for (from, _, _) in nodes {
        for (to, _, _) in nodes {
            if from != to {
                links.push(LinkSpec {
                    from: node_id(from)?,
                    to: node_id(to)?,
                    resources: vec![
                        ResourceId::new(format!("{from}-tx"))?,
                        ResourceId::new(format!("{to}-rx"))?,
                    ],
                });
            }
        }
    }
    Ok(Topology {
        transports: vec![Transport {
            kind,
            setup_seconds,
            resources: table,
            spans: members.iter().map(|node| node.id.clone()).collect(),
        }],
        nodes: members,
        links,
    })
}

fn targets(names: &[&str]) -> Result<Vec<TargetSpec>, RoutingError> {
    names
        .iter()
        .map(|name| {
            Ok(TargetSpec {
                node: node_id(name)?,
                priority_weight: 1.0,
            })
        })
        .collect()
}

/// The ordinary workflow: every target downloads the object from the origin over one
/// shared internet link (A.9: each member downloads from Hugging Face itself).
fn origin_regime(
    target_names: &[&str],
    object_bytes: u64,
    chunk_bytes: u64,
    factor: f64,
) -> Result<(Topology, ReplicationProblem), RoutingError> {
    let mut nodes = vec![("origin", ORIGIN_BYTES_PER_SECOND, ORIGIN_BYTES_PER_SECOND)];
    nodes.extend(
        target_names
            .iter()
            .map(|name| (*name, LAN_BYTES_PER_SECOND, LAN_BYTES_PER_SECOND)),
    );
    let topology = mesh_topology(&nodes, TransportKind::DirectHandle, 0.3, factor)?;
    let problem = ReplicationProblem {
        object_bytes,
        chunk_bytes,
        round_overhead_seconds: 0.0,
        staging_bytes_per_stream: 0,
        sources: vec![node_id("origin")?],
        targets: targets(target_names)?,
        objective: ScheduleObjective::Makespan,
    };
    Ok((topology, problem))
}

type RegimeShape = (
    &'static str,
    Vec<(&'static str, f64, f64)>,
    Vec<&'static str>,
    Vec<&'static str>,
    u64,
    u64,
    f64,
);

/// The §4.7 regimes with every measured rate multiplied by `factor`: a symmetric LAN, a
/// donor with four times the transmit rate, one unsplittable 1.25 GB extent for seven
/// targets with 0.1 s rounds, and three independent donors.
pub fn replication_regimes(factor: f64) -> Result<Vec<ReplicationRegime>, RoutingError> {
    let lan = LAN_BYTES_PER_SECOND;
    let three = ["t1", "t2", "t3"];
    let seven = ["t1", "t2", "t3", "t4", "t5", "t6", "t7"];
    let with_targets = |head: Vec<(&'static str, f64, f64)>, names: &[&'static str]| {
        let mut nodes = head;
        nodes.extend(names.iter().map(|name| (*name, lan, lan)));
        nodes
    };
    let shapes: Vec<RegimeShape> = vec![
        (
            "symmetric-lan",
            with_targets(vec![("d", lan, lan)], &three),
            vec!["d"],
            three.to_vec(),
            OBJECT_BYTES,
            CHUNK_BYTES,
            0.0,
        ),
        (
            "fat-donor",
            with_targets(vec![("d", 4.0 * lan, lan)], &three),
            vec!["d"],
            three.to_vec(),
            OBJECT_BYTES,
            CHUNK_BYTES,
            0.0,
        ),
        (
            "single-extent-many-targets",
            with_targets(vec![("d", lan, lan)], &seven),
            vec!["d"],
            seven.to_vec(),
            1_250_000_000,
            1_250_000_000,
            0.1,
        ),
        (
            "independent-sources",
            with_targets(
                vec![("d1", lan, lan), ("d2", lan, lan), ("d3", lan, lan)],
                &three,
            ),
            vec!["d1", "d2", "d3"],
            three.to_vec(),
            OBJECT_BYTES,
            CHUNK_BYTES,
            0.0,
        ),
    ];
    let mut regimes = Vec::with_capacity(shapes.len());
    for (name, nodes, sources, target_names, object_bytes, chunk_bytes, overhead) in shapes {
        let topology = mesh_topology(&nodes, TransportKind::EstablishedCommunicator, 0.02, factor)?;
        let (origin_topology, origin_problem) =
            origin_regime(&target_names, object_bytes, chunk_bytes, factor)?;
        regimes.push(ReplicationRegime {
            name,
            topology,
            problem: ReplicationProblem {
                object_bytes,
                chunk_bytes,
                round_overhead_seconds: overhead,
                staging_bytes_per_stream: STAGING_BYTES_PER_STREAM,
                sources: sources
                    .iter()
                    .map(|source| node_id(source))
                    .collect::<Result<_, _>>()?,
                targets: targets(&target_names)?,
                objective: ScheduleObjective::Makespan,
            },
            origin_topology,
            origin_problem,
        });
    }
    Ok(regimes)
}

fn trial_factor(seed: u64, trial: u32) -> Result<f64, RoutingError> {
    Ok(TrialConditions::draw(trial, 1, seed, TRIAL_SPREAD_PPM)?
        .load_factor
        .first()
        .copied()
        .unwrap_or(1.0))
}

fn cold_target_state() -> StartState {
    StartState {
        temperature: StartTemperature::Cold,
        model_at_arrival: ModelAtArrival::NotLoaded,
        cache_tier: CacheTier::NoReusableState,
        prefill: PrefillMode::Fresh,
        cold_provenance: ColdProvenance::FirstUseOfArtifact,
    }
}

/// Each target's first request arrives as replication starts, waits for its replica and
/// then runs 1,000 prompt tokens and 60 output tokens.
fn replication_attempts(
    policy: &str,
    trial: u32,
    schedule: &Schedule,
    object_bytes: u64,
) -> Result<Vec<SimulatedAttempt>, RoutingError> {
    schedule
        .ready_seconds
        .iter()
        .map(|(target, ready)| {
            Ok(SimulatedAttempt {
                operation: OperationId::new(format!("op-{policy}-t{trial}-{target}"))?,
                trial,
                input_tokens: 1_000,
                arrival_seconds: 0.0,
                demand_load: Some(DemandLoad {
                    started_seconds: 0.0,
                    completed_seconds: *ready,
                }),
                service_start_seconds: *ready,
                first_token_seconds: ready + TARGET_PREFILL_SECONDS,
                completion_seconds: ready + TARGET_PREFILL_SECONDS + TARGET_DECODE_SECONDS,
                state: cold_target_state(),
                transferred_bytes: object_bytes,
                storage_read_bytes: 0,
            })
        })
        .collect()
}

fn schedule_error(refusal: ScheduleRefusal) -> RoutingError {
    match refusal {
        ScheduleRefusal::Invalid(error) => error,
        _ => RoutingError::Input(InputError::OutOfRange {
            field: "baseline schedule",
        }),
    }
}

fn replication_error(error: ReplicationError) -> RoutingError {
    match error {
        ReplicationError::Invalid(error) => error,
        ReplicationError::NoFeasibleSchedule { .. } => RoutingError::Input(InputError::Empty {
            field: "feasible schedules",
        }),
    }
}

/// Runs §4.7 regime `index`: the topology-aware choice against a fixed pipelined chain
/// from the first donor and against the origin download.
pub fn run_replication_regime(index: usize, seed: u64) -> Result<RegimeReport, RoutingError> {
    let mut records: [Vec<RunRecord>; 3] = [Vec::new(), Vec::new(), Vec::new()];
    let mut regime_name = "";
    for trial in 0..TRIALS_PER_REGIME {
        let regimes = replication_regimes(trial_factor(seed, trial)?)?;
        let regime = regimes
            .get(index)
            .ok_or(RoutingError::Input(InputError::OutOfRange {
                field: "regime",
            }))?;
        regime_name = regime.name;
        let chosen = choose_schedule(&regime.topology, &regime.problem)
            .map_err(replication_error)?
            .chosen;
        let root = regime
            .problem
            .sources
            .first()
            .ok_or(RoutingError::Input(InputError::Empty { field: "sources" }))?;
        let chain = plan_schedule(
            &regime.topology,
            &regime.problem,
            ScheduleShape::Chain,
            Some(root),
            0,
        )
        .map_err(schedule_error)?;
        let origin_root = regime
            .origin_problem
            .sources
            .first()
            .ok_or(RoutingError::Input(InputError::Empty { field: "sources" }))?;
        let origin = plan_schedule(
            &regime.origin_topology,
            &regime.origin_problem,
            ScheduleShape::Star,
            Some(origin_root),
            0,
        )
        .map_err(schedule_error)?;
        let setup = FakeRunSetup {
            experiment: label("gpu-4-7-topology-replication")?,
            trace: label(regime.name)?,
            family: FixtureFamily::Prose,
            max_output_tokens: 60,
            concurrent_requests: u32::try_from(regime.problem.targets.len()).unwrap_or(u32::MAX),
        };
        for ((policy, schedule), side) in [
            ("topology-aware", &chosen),
            ("fixed-chain", &chain),
            ("origin-download", &origin),
        ]
        .into_iter()
        .zip(records.iter_mut())
        {
            let policy_label = label(policy)?;
            for attempt in
                replication_attempts(policy, trial, schedule, regime.problem.object_bytes)?
            {
                side.push(setup.record(&policy_label, &attempt)?);
            }
        }
    }
    let [chosen, chain, origin] = records;
    let report = fake_comparison(
        "topology-aware-replication",
        StateComparison::ColdLoad,
        seed,
        fake_side(
            "topology-aware",
            &chosen,
            StartTemperature::Cold,
            Quantile::P95,
        )?,
        Baseline::Measured {
            sides: vec![fake_side(
                "origin-download",
                &origin,
                StartTemperature::Cold,
                Quantile::P95,
            )?],
        },
        Baseline::Measured {
            sides: vec![fake_side(
                "fixed-chain",
                &chain,
                StartTemperature::Cold,
                Quantile::P95,
            )?],
        },
    )?;
    let outcome = regime_outcome(regime_name, &report, TIE_TOLERANCE)?;
    Ok(RegimeReport {
        regime: regime_name,
        report,
        outcome,
    })
}

/// The §4.7 claim text (§4.17 items 1–4).
pub const REPLICATION_CLAIM: ClaimText = ClaimText {
    contribution: "Replication that plans star, chain, binomial tree and multiple independent \
        sources over the measured topology, with startup and transport setup, links and cuts \
        shared by concurrent streams counted once, donor HBM pressure and serving impact and \
        target readiness order, picks the best feasible schedule, and recovers failed nodes by \
        bounded re-planning.",
    closest_prior_work: PriorWork {
        name: "FlashBoot",
        reference: "https://arxiv.org/abs/2608.08482",
        formulation: "Fast model start-up across GPU nodes from a large immutable arena on \
            compatible rack-scale hardware, as the plan describes it (line 728).",
        algorithm: "An arena-based transfer path on compatible hardware; its findings are \
            hardware-specific evidence, not a laptop forecast.",
        implementation: "The plan records its code availability as future work, so its \
            reproducibility is assessed before any dependency.",
    },
    difference_tested: "A choice among schedule shapes on commodity measured links, with donor \
        load, communicator reuse and failure recovery as inputs, instead of one fixed path.",
    assumptions: &[
        "Measured directional bandwidth holds under concurrent streams, and every shared link \
         and cut is declared.",
        "Chunks arrive in order, and chunks delivered before a failure stay verified.",
        "Each sender's free staging memory and per-stream staging need are known.",
        "Round overhead and transport setup are constant within a schedule.",
    ],
    smallest_counterexample: "Two targets behind an undeclared shared switch uplink: the plan \
        treats their streams as independent and predicts a star faster than the uplink allows \
        (test the_undeclared_shared_uplink_breaks_the_assumption).",
    strongest_baseline: "A fixed pipelined chain from the first donor, as an NCCL-style \
        broadcast runs; the ordinary workflow downloads every target from the origin over one \
        shared internet link.",
};

/// Runs every §4.7 regime and builds its claim record.
pub fn replication_experiment(seed: u64) -> Result<ExperimentReport, RoutingError> {
    let count = replication_regimes(1.0)?.len();
    let mut regimes = Vec::with_capacity(count);
    for index in 0..count {
        regimes.push(run_replication_regime(
            index,
            seed.wrapping_add(count_u64(index)),
        )?);
    }
    let claim = ClaimRecord::new(
        Experiment::TopologyAwareReplication,
        REPLICATION_CLAIM,
        regimes
            .iter()
            .map(|regime| regime.outcome.clone())
            .collect(),
        GatedPath::ALL.iter().map(|path| path.reason()).collect(),
        None,
    )?;
    Ok(ExperimentReport { claim, regimes })
}

// §4.8: a 32-layer model with hidden size 4,096 in BF16 split over two nodes; each half
// prefills 2,048 tokens in 0.1 s and decodes a token in 10 ms.
const STAGE_PREFILL_SECONDS_PER_TOKEN: f64 = 0.1 / 2048.0;
const STAGE_DECODE_SECONDS: f64 = 0.010;

/// The §4.8 model shape: 32 layers, hidden size 4,096, BF16 activations (8,192 bytes per
/// token per boundary) and 4,096 KV bytes per token per layer.
pub fn window_shape() -> ModelShape {
    ModelShape {
        layers: 32,
        hidden_size: 4096,
        activation_bytes_per_element: 2,
        kv_bytes_per_token_per_layer: 4096,
    }
}

fn distributed_error(error: DistributedError) -> RoutingError {
    match error {
        DistributedError::Input(error) => RoutingError::Input(error),
        _ => RoutingError::Input(InputError::OutOfRange {
            field: "pipeline plan",
        }),
    }
}

/// Two stages of 16 layers on nodes `a` and `b`, joined by a link of `bytes_per_second`
/// and `latency_seconds` each way, with compute scaled by `compute_factor`.
pub fn two_stage_plan(
    bytes_per_second: f64,
    latency_seconds: f64,
    compute_factor: f64,
) -> Result<PipelinePlan, RoutingError> {
    let stage = |name: &str, first_layer: u32| -> Result<PipelineStage, RoutingError> {
        Ok(PipelineStage {
            node: node_id(name)?,
            first_layer,
            layer_count: 16,
            prefill_seconds_per_token: STAGE_PREFILL_SECONDS_PER_TOKEN * compute_factor,
            decode_step_seconds: STAGE_DECODE_SECONDS * compute_factor,
            free_kv_bytes: 4 << 30,
        })
    };
    let link = PipelineLink {
        bandwidth: BandwidthRating::measured_directional(bytes_per_second)?,
        latency_seconds,
    };
    PipelinePlan::new(
        window_shape(),
        vec![stage("a", 0)?, stage("b", 16)?],
        vec![link],
        link,
        4,
    )
    .map_err(distributed_error)
}

/// One §4.8 regime before trial variation.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct WindowRegime {
    pub name: &'static str,
    pub link_bytes_per_second: f64,
    pub link_latency_seconds: f64,
    pub pipeline_ready_seconds: f64,
    pub replicas_ready_seconds: f64,
    pub donor_backlog_seconds: f64,
    pub arrivals: &'static [f64],
    pub prompt_tokens: u64,
    pub output_tokens: u64,
}

/// The §4.8 regimes: a fast LAN with an overloaded donor, a 50 Mb/s link with long
/// prompts, and an idle donor.
pub const WINDOW_REGIMES: [WindowRegime; 3] = [
    WindowRegime {
        name: "fast-lan-overloaded-donor",
        link_bytes_per_second: 1.25e9,
        link_latency_seconds: 0.0002,
        pipeline_ready_seconds: 5.0,
        replicas_ready_seconds: 15.0,
        donor_backlog_seconds: 30.0,
        arrivals: &[0.0, 1.0, 2.0, 3.0, 4.0, 5.0],
        prompt_tokens: 2048,
        output_tokens: 128,
    },
    WindowRegime {
        name: "slow-lan-long-prompts",
        link_bytes_per_second: 6.25e6,
        link_latency_seconds: 0.005,
        pipeline_ready_seconds: 3.0,
        replicas_ready_seconds: 6.0,
        donor_backlog_seconds: 20.0,
        arrivals: &[0.0, 1.0, 2.0],
        prompt_tokens: 8192,
        output_tokens: 128,
    },
    WindowRegime {
        name: "idle-donor",
        link_bytes_per_second: 1.25e9,
        link_latency_seconds: 0.0002,
        pipeline_ready_seconds: 5.0,
        replicas_ready_seconds: 15.0,
        donor_backlog_seconds: 0.0,
        arrivals: &[0.0, 1.0, 2.0, 3.0, 4.0, 5.0],
        prompt_tokens: 2048,
        output_tokens: 128,
    },
];

/// The regime's pipeline, window and requests with compute scaled by `compute_factor` and
/// the link by `link_factor`.
pub fn window_for(
    synthetic: &SyntheticFleet,
    regime: &WindowRegime,
    compute_factor: f64,
    link_factor: f64,
) -> Result<(PipelinePlan, LoadingWindow, Vec<WindowRequest>), RoutingError> {
    let plan = two_stage_plan(
        regime.link_bytes_per_second * link_factor,
        regime.link_latency_seconds,
        compute_factor,
    )?;
    let service = ReplicaService {
        prefill_seconds_per_token: 2.0 * STAGE_PREFILL_SECONDS_PER_TOKEN * compute_factor,
        decode_step_seconds: 2.0 * STAGE_DECODE_SECONDS * compute_factor,
    };
    let window = LoadingWindow {
        pipeline_ready_seconds: regime.pipeline_ready_seconds,
        replicas_ready_seconds: regime.replicas_ready_seconds,
        replica_nodes: 2,
        replica_service: service,
        donor: Some(DonorRoute {
            backlog_seconds: regime.donor_backlog_seconds,
            service,
            network_tail_seconds: 0.01,
        }),
        client_tail_seconds: 0.02,
        microbatches: 4,
        pipeline_execution: synthetic.pipeline_execution()?,
        replica_execution: synthetic.single_execution()?,
        pipeline_generation: ModelActivationGeneration::new(1),
        replica_generation: ModelActivationGeneration::new(2),
    };
    let requests = regime
        .arrivals
        .iter()
        .map(|arrival| WindowRequest {
            arrival_seconds: *arrival,
            prompt_tokens: regime.prompt_tokens,
            output_tokens: regime.output_tokens,
        })
        .collect();
    Ok((plan, window, requests))
}

fn window_attempt(
    policy: &str,
    trial: u32,
    window: &LoadingWindow,
    request: &WindowRequest,
    served: &WindowServed,
) -> Result<SimulatedAttempt, RoutingError> {
    let ready_at = match served.unit {
        ServingUnit::Pipeline => Some(window.pipeline_ready_seconds),
        ServingUnit::Replica(_) => Some(window.replicas_ready_seconds),
        ServingUnit::Donor => None,
    };
    let waited = ready_at.filter(|ready| served.arrival_seconds < *ready);
    let state = match waited {
        Some(_) => StartState {
            temperature: StartTemperature::Warm,
            model_at_arrival: ModelAtArrival::NotLoaded,
            cache_tier: CacheTier::LocalDisk,
            prefill: PrefillMode::Fresh,
            cold_provenance: ColdProvenance::NotCold,
        },
        None => StartState {
            temperature: StartTemperature::Hot,
            model_at_arrival: ModelAtArrival::ReadyToServe,
            cache_tier: CacheTier::NoReusableState,
            prefill: PrefillMode::Fresh,
            cold_provenance: ColdProvenance::NotCold,
        },
    };
    Ok(SimulatedAttempt {
        operation: OperationId::new(format!("op-{policy}-t{trial}-r{}", served.index))?,
        trial,
        input_tokens: request.prompt_tokens,
        arrival_seconds: served.arrival_seconds,
        demand_load: waited.map(|ready| DemandLoad {
            started_seconds: served.arrival_seconds,
            completed_seconds: ready,
        }),
        service_start_seconds: served.start_seconds,
        first_token_seconds: served.first_token_seconds,
        completion_seconds: served.completion_seconds,
        state,
        transferred_bytes: served.activation_bytes,
        storage_read_bytes: 0,
    })
}

/// Runs one §4.8 regime: the temporary pipeline against waiting for replicas and routing
/// to the donor.
pub fn run_window_regime(regime: &WindowRegime, seed: u64) -> Result<RegimeReport, RoutingError> {
    let synthetic = SyntheticFleet::new()?;
    let model = synthetic.requested_single_or_pipeline()?;
    let setup = FakeRunSetup {
        experiment: label("gpu-4-8-temporary-distributed")?,
        trace: label(regime.name)?,
        family: FixtureFamily::Prose,
        max_output_tokens: regime.output_tokens,
        concurrent_requests: u32::try_from(regime.arrivals.len()).unwrap_or(u32::MAX),
    };
    let strategies = [
        ("temporary-pipeline", WindowStrategy::TemporaryPipeline),
        ("wait-for-replicas", WindowStrategy::WaitForReplicas),
        ("route-to-donor", WindowStrategy::RouteToDonor),
    ];
    let mut records: [Vec<RunRecord>; 3] = [Vec::new(), Vec::new(), Vec::new()];
    for trial in 0..TRIALS_PER_REGIME {
        let conditions = TrialConditions::draw(trial, 2, seed, TRIAL_SPREAD_PPM)?;
        let compute_factor = conditions.compute_factor.first().copied().unwrap_or(1.0);
        let link_factor = conditions.load_factor.first().copied().unwrap_or(1.0);
        let (plan, window, requests) = window_for(&synthetic, regime, compute_factor, link_factor)?;
        for ((name, strategy), side) in strategies.iter().zip(records.iter_mut()) {
            let policy_label = label(name)?;
            let served = serve_window(
                &plan,
                &window,
                &requests,
                *strategy,
                &model,
                synthetic.epoch,
            )
            .map_err(distributed_error)?;
            for (request, entry) in requests.iter().zip(&served) {
                side.push(setup.record(
                    &policy_label,
                    &window_attempt(name, trial, &window, request, entry)?,
                )?);
            }
        }
    }
    let [pipeline, wait, donor] = records;
    let report = fake_comparison(
        "temporary-distributed-execution",
        StateComparison::WarmLoad,
        seed,
        fake_side(
            "temporary-pipeline",
            &pipeline,
            StartTemperature::Warm,
            Quantile::P95,
        )?,
        Baseline::Measured {
            sides: vec![fake_side(
                "wait-for-replicas",
                &wait,
                StartTemperature::Warm,
                Quantile::P95,
            )?],
        },
        Baseline::Measured {
            sides: vec![fake_side(
                "route-to-donor",
                &donor,
                StartTemperature::Warm,
                Quantile::P95,
            )?],
        },
    )?;
    let outcome = regime_outcome(regime.name, &report, TIE_TOLERANCE)?;
    Ok(RegimeReport {
        regime: regime.name,
        report,
        outcome,
    })
}

/// The §4.8 claim text (§4.17 items 1–4).
pub const DISTRIBUTED_CLAIM: ClaimText = ClaimText {
    contribution: "Serving from complementary layers on several nodes while full replicas load, \
        with per-boundary activation traffic, link latency, microbatch fill and temporary KV \
        placement modelled, and plan epochs so every request finishes on the plan it was admitted \
        to while new requests move to the replicas.",
    closest_prior_work: PriorWork {
        name: "λScale",
        reference: "https://arxiv.org/abs/2502.09922",
        formulation: "Fast scaling of serverless LLM inference: serve on nodes that hold only \
            part of the model while its weights are still being distributed.",
        algorithm: "Execute-while-load across nodes during scale-out, with model multicast over \
            fast interconnects.",
        implementation: "Evaluated with RDMA networking; the plan warns that RDMA results do not \
            imply commodity-network wins (line 738).",
    },
    difference_tested: "A commodity-LAN cost model with an epoch-coordinated transition to \
        replicas, compared with both waiting for full replicas and routing to the donor.",
    assumptions: &[
        "Each stage boundary carries hidden size × activation bytes per token.",
        "Link latency and measured bandwidth hold for the whole window.",
        "Stage compute times add, and are known for prefill and decode.",
        "The temporary KV of every in-flight request fits each stage.",
    ],
    smallest_counterexample: "On a 50 Mb/s link with 8,192-token prompts the pipeline's \
        prefill outlasts the 3 s wait for replicas (regime slow-lan-long-prompts).",
    strongest_baseline: "In each regime, the better of waiting for full replicas (the ordinary \
        workflow) and routing to the donor.",
};

/// Runs every §4.8 regime and builds its claim record.
pub fn distributed_experiment(seed: u64) -> Result<ExperimentReport, RoutingError> {
    let mut regimes = Vec::with_capacity(WINDOW_REGIMES.len());
    for (index, regime) in WINDOW_REGIMES.iter().enumerate() {
        regimes.push(run_window_regime(
            regime,
            seed.wrapping_add(count_u64(index)),
        )?);
    }
    let claim = ClaimRecord::new(
        Experiment::TemporaryDistributedExecution,
        DISTRIBUTED_CLAIM,
        regimes
            .iter()
            .map(|regime| regime.outcome.clone())
            .collect(),
        vec![GatedPath::RdmaFabric.reason()],
        None,
    )?;
    Ok(ExperimentReport { claim, regimes })
}
