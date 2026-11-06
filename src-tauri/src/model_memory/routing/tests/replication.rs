//! §4.7 topology-aware replication on hand-worked topologies: schedule times, the choice
//! from measured topology and donor load, communicator reuse, readiness order, bounded
//! failure recovery and gated paths.

use crate::foundation::ids::ResourceId;
use crate::foundation::transfer::Endpoint;
use crate::model_memory::math::bounds::{
    BandwidthBasis, BandwidthRating, BoundsError, ResourceTable,
};

use super::super::experiments::{mesh_topology, replication_regimes};
use super::super::replication::*;
use super::support::*;

const LAN: f64 = 1.25e9;

fn node(name: &str) -> NodeId {
    NodeId::new(name).unwrap()
}

fn targets(names: &[&str]) -> Vec<TargetSpec> {
    names
        .iter()
        .map(|name| TargetSpec {
            node: node(name),
            priority_weight: 1.0,
        })
        .collect()
}

/// Donor `d` (and `d2`) and targets t1–t3 on 10 GbE, one communicator with no setup.
fn lan() -> Topology {
    mesh_topology(
        &[
            ("d", LAN, LAN),
            ("d2", LAN, LAN),
            ("t1", LAN, LAN),
            ("t2", LAN, LAN),
            ("t3", LAN, LAN),
        ],
        TransportKind::EstablishedCommunicator,
        0.0,
        1.0,
    )
    .unwrap()
}

/// 10 GB in 0.5 GB chunks from `sources` to t1–t3.
fn problem(sources: &[&str]) -> ReplicationProblem {
    ReplicationProblem {
        object_bytes: 10_000_000_000,
        chunk_bytes: 500_000_000,
        round_overhead_seconds: 0.0,
        staging_bytes_per_stream: 256 << 20,
        sources: sources.iter().map(|name| node(name)).collect(),
        targets: targets(&["t1", "t2", "t3"]),
        objective: ScheduleObjective::Makespan,
    }
}

fn plan(topology: &Topology, problem: &ReplicationProblem, shape: ScheduleShape) -> Schedule {
    plan_schedule(topology, problem, shape, problem.sources.first(), 0).unwrap()
}

#[test]
fn star_chain_and_binomial_times_on_a_symmetric_lan() {
    let topology = lan();
    let problem = problem(&["d"]);
    // Star: the donor's 1.25 GB/s carries three chunks per round, 1.2 s × 20 rounds.
    let star = plan(&topology, &problem, ScheduleShape::Star);
    assert_close(star.makespan_seconds, 24.0);
    assert_eq!(star.rounds.len(), 20);
    // Chain: 0.4 s rounds, 20 chunks + 2 hops of fill; t1, t2, t3 at 8.0, 8.4, 8.8 s.
    let chain = plan(&topology, &problem, ScheduleShape::Chain);
    assert_eq!(chain.rounds.len(), 22);
    assert_close(chain.ready_seconds[&node("t1")], 8.0);
    assert_close(chain.ready_seconds[&node("t2")], 8.4);
    assert_close(chain.ready_seconds[&node("t3")], 8.8);
    assert_eq!(
        chain.readiness_order(),
        vec![node("t1"), node("t2"), node("t3")]
    );
    // Binomial tree: d→t1 in 8 s, then d→t2 and t1→t3 together in 8 s.
    let tree = plan(&topology, &problem, ScheduleShape::BinomialTree);
    assert_close(tree.ready_seconds[&node("t1")], 8.0);
    assert_close(tree.ready_seconds[&node("t2")], 16.0);
    assert_close(tree.ready_seconds[&node("t3")], 16.0);
    assert_eq!(tree.sent_bytes[&node("t1")], 10_000_000_000);
}

#[test]
fn multiple_sources_share_each_donor_link_across_targets_once() {
    let topology = lan();
    let problem = problem(&["d", "d2"]);
    // Each target alone would take 8 s at its 1.25 GB/s receive side, but each donor
    // sends 15 GB across the three targets: 12 s on its transmit side, for every target.
    let multi = plan(&topology, &problem, ScheduleShape::MultiSource);
    assert_eq!(multi.sent_bytes[&node("d")], 15_000_000_000);
    assert_eq!(multi.sent_bytes[&node("d2")], 15_000_000_000);
    for target in ["t1", "t2", "t3"] {
        assert_close(multi.ready_seconds[&node(target)], 12.0);
    }
    assert_eq!(
        plan_schedule(
            &topology,
            &self::problem(&["d"]),
            ScheduleShape::MultiSource,
            None,
            0
        ),
        Err(ScheduleRefusal::NeedsSeveralSources)
    );
}

#[test]
fn the_schedule_is_chosen_from_measured_topology_never_a_mandatory_chain() {
    let regimes = replication_regimes(1.0).unwrap();
    let chosen: Vec<(ScheduleShape, f64)> = regimes
        .iter()
        .map(|regime| {
            let schedule = choose_schedule(&regime.topology, &regime.problem)
                .unwrap()
                .chosen;
            (schedule.shape, schedule.makespan_seconds)
        })
        .collect();
    // Symmetric LAN: the chain (8.8 s + 0.02 s setup).
    assert_eq!(chosen[0].0, ScheduleShape::Chain);
    assert_close(chosen[0].1, 8.82);
    // A donor with four times the transmit rate: a star, bound by each target's 0.4 s
    // receive per chunk (8.0 s), beats the chain's 8.82 s.
    assert_eq!(chosen[1].0, ScheduleShape::Star);
    assert_close(chosen[1].1, 8.02);
    // One unsplittable 1.25 GB extent for seven targets with 0.1 s rounds: three
    // binomial rounds of 1.1 s (3.32 s) against a 7.12 s star and a 7.72 s chain.
    assert_eq!(chosen[2].0, ScheduleShape::BinomialTree);
    assert_close(chosen[2].1, 3.32);
    let star = plan(
        &regimes[2].topology,
        &regimes[2].problem,
        ScheduleShape::Star,
    );
    assert_close(star.makespan_seconds, 7.12);
    let chain = plan(
        &regimes[2].topology,
        &regimes[2].problem,
        ScheduleShape::Chain,
    );
    assert_close(chain.makespan_seconds, 7.72);
    // Three independent donors: multiple sources. The §2.5 planner holds each source's
    // fair share for its whole queue, so the source with 7 of 20 chunks sets 8.4 s.
    assert_eq!(chosen[3].0, ScheduleShape::MultiSource);
    assert_close(chosen[3].1, 8.42);
}

#[test]
fn donor_hbm_pressure_refuses_a_star_and_the_choice_falls_back() {
    let regimes = replication_regimes(1.0).unwrap();
    let mut topology = regimes[1].topology.clone();
    for member in &mut topology.nodes {
        if member.id == node("d") {
            member.free_staging_bytes = 2 * (256 << 20);
        }
    }
    let problem = regimes[1].problem.clone();
    assert_eq!(
        plan_schedule(
            &topology,
            &problem,
            ScheduleShape::Star,
            Some(&node("d")),
            0
        ),
        Err(ScheduleRefusal::DonorHbmPressure {
            node: node("d"),
            needed_bytes: 3 * (256 << 20),
            available_bytes: 2 * (256 << 20),
        })
    );
    let choice = choose_schedule(&topology, &problem).unwrap();
    assert_eq!(choice.chosen.shape, ScheduleShape::Chain);
    assert!(choice.evaluated.iter().any(|candidate| matches!(
        candidate.outcome,
        Err(ScheduleRefusal::DonorHbmPressure { .. })
    )));
}

#[test]
fn donor_serving_impact_steers_the_choice() {
    let regimes = replication_regimes(1.0).unwrap();
    let mut topology = regimes[1].topology.clone();
    for member in &mut topology.nodes {
        if member.id == node("d") {
            member.serving_impact_seconds_per_byte = 1e-10;
        }
    }
    let problem = regimes[1].problem.clone();
    // The star sends 30 GB from the donor (3 s of impact), the chain 10 GB (1 s).
    let star = plan(&topology, &problem, ScheduleShape::Star);
    assert_close(star.donor_impact_seconds, 3.0);
    assert_close(star.objective_seconds, 8.02 + 3.0);
    let choice = choose_schedule(&topology, &problem).unwrap();
    assert_eq!(choice.chosen.shape, ScheduleShape::Chain);
    assert_close(choice.chosen.objective_seconds, 8.82 + 1.0);
}

fn transport(kind: TransportKind, setup_seconds: f64, factor: f64, spans: &[&str]) -> Transport {
    let mut source = mesh_topology(
        &[
            ("d", LAN, LAN),
            ("d2", LAN, LAN),
            ("t1", LAN, LAN),
            ("t2", LAN, LAN),
            ("t3", LAN, LAN),
        ],
        kind,
        setup_seconds,
        factor,
    )
    .unwrap();
    let mut transport = source.transports.remove(0);
    transport.spans = spans.iter().map(|name| node(name)).collect();
    transport
}

#[test]
fn an_established_communicator_is_reused_when_it_wins_and_direct_handles_when_fresh_setup_dominates(
) {
    let everyone = ["d", "d2", "t1", "t2", "t3"];
    let mut topology = lan();
    topology.transports = vec![
        transport(TransportKind::EstablishedCommunicator, 0.02, 1.0, &everyone),
        transport(TransportKind::FreshCommunicator, 6.0, 1.0, &[]),
        transport(TransportKind::DirectHandle, 0.3, 1.0, &[]),
    ];
    let problem = problem(&["d"]);
    let chosen = choose_schedule(&topology, &problem).unwrap().chosen;
    assert_eq!(chosen.transport, TransportKind::EstablishedCommunicator);
    assert_close(chosen.makespan_seconds, 8.82);

    // A communicator over d and t1 only cannot carry t2 and t3; fresh setup (6 s) loses
    // to direct handles opened hop by hop (3 × 0.3 s): 9.7 s against 14.8 s.
    topology.transports[0] = transport(
        TransportKind::EstablishedCommunicator,
        0.02,
        1.0,
        &["d", "t1"],
    );
    let choice = choose_schedule(&topology, &problem).unwrap();
    assert_eq!(choice.chosen.transport, TransportKind::DirectHandle);
    assert_close(choice.chosen.makespan_seconds, 9.7);
    assert!(choice.evaluated.iter().any(|candidate| matches!(
        &candidate.outcome,
        Err(ScheduleRefusal::CommunicatorDoesNotSpan { node: missing }) if *missing == node("t2")
    )));
    let fresh = plan_schedule(
        &topology,
        &problem,
        ScheduleShape::Chain,
        Some(&node("d")),
        1,
    )
    .unwrap();
    assert_close(fresh.makespan_seconds, 14.8);

    // When direct handles measure 0.5 GB/s per NIC, a 2 s fresh communicator wins:
    // 10.8 s against 22 one-second rounds plus three hop setups, 22.9 s.
    topology.transports = vec![
        transport(TransportKind::FreshCommunicator, 2.0, 1.0, &[]),
        transport(TransportKind::DirectHandle, 0.3, 0.4, &[]),
    ];
    let chosen = choose_schedule(&topology, &problem).unwrap().chosen;
    assert_eq!(chosen.transport, TransportKind::FreshCommunicator);
    assert_close(chosen.makespan_seconds, 10.8);
    let direct = plan_schedule(
        &topology,
        &problem,
        ScheduleShape::Chain,
        Some(&node("d")),
        1,
    )
    .unwrap();
    assert_close(direct.makespan_seconds, 22.9);
}

#[test]
fn targets_become_ready_in_priority_order() {
    let topology = lan();
    let mut problem = problem(&["d"]);
    problem.targets[2].priority_weight = 3.0;
    problem.objective = ScheduleObjective::WeightedReadiness;
    let chain = plan(&topology, &problem, ScheduleShape::Chain);
    assert_eq!(
        chain.readiness_order(),
        vec![node("t3"), node("t1"), node("t2")]
    );
    // 3 × 8.0 + 8.4 + 8.8.
    assert_close(chain.objective_seconds, 41.2);
    let tree = plan(&topology, &problem, ScheduleShape::BinomialTree);
    assert_eq!(tree.readiness_order()[0], node("t3"));
}

#[test]
fn a_failed_node_is_recovered_by_bounded_re_planning() {
    let topology = lan();
    let problem = problem(&["d"]);
    let failures = [
        NodeFailure {
            node: node("t1"),
            at_seconds: 4.1,
        },
        NodeFailure {
            node: node("t2"),
            at_seconds: 7.0,
        },
    ];
    let policy = RecoveryPolicy {
        detection_seconds: 1.0,
        max_replans: 2,
    };
    // t1 fails at 4.1 s with 10 chunks; t2 holds 9 and t3 8. At 5.1 s a chain d→t2→t3
    // re-plans the 12 chunks t3 lacks (5.2 s). t2 fails at 7.0 s, when t3 holds 11; at
    // 8.0 s the 9 missing chunks take 3.6 s: t3 is ready at 11.6 s.
    let outcome = replicate_with_failures(&topology, &problem, &failures, policy).unwrap();
    assert_eq!(outcome.replans, 2);
    assert_eq!(
        outcome.failed,
        [node("t1"), node("t2")].into_iter().collect()
    );
    assert_eq!(outcome.ready_seconds.len(), 1);
    assert_close(outcome.ready_seconds[&node("t3")], 11.6);
    let (start, first_replan) = &outcome.schedules[1];
    assert_close(*start, 5.1);
    assert_eq!(first_replan.shape, ScheduleShape::Chain);
    assert_close(first_replan.makespan_seconds, 5.2);
    // The bound is enforced.
    assert_eq!(
        replicate_with_failures(
            &topology,
            &problem,
            &failures,
            RecoveryPolicy {
                detection_seconds: 1.0,
                max_replans: 1
            }
        ),
        Err(RecoveryRefusal::RecoveryExhausted { max_replans: 1 })
    );
    // With no complete copy left there is nothing to recover from.
    assert_eq!(
        replicate_with_failures(
            &topology,
            &problem,
            &[NodeFailure {
                node: node("d"),
                at_seconds: 1.0
            }],
            policy
        ),
        Err(RecoveryRefusal::NoSurvivingSource)
    );
    // A failure of a node the schedule does not use changes nothing.
    let untouched = replicate_with_failures(
        &topology,
        &problem,
        &[NodeFailure {
            node: node("d2"),
            at_seconds: 1.0,
        }],
        policy,
    )
    .unwrap();
    assert_eq!(untouched.replans, 0);
    assert_close(untouched.ready_seconds[&node("t3")], 8.8);
}

#[test]
fn flashboot_rdma_paid_hardware_and_driver_changes_stay_gated() {
    for path in GatedPath::ALL {
        assert_eq!(plan_gated(path), Err(ScheduleRefusal::Gated(path)));
        assert!(!path.reason().is_empty());
    }
}

#[test]
fn advertised_and_aggregate_bandwidth_never_enter_a_schedule() {
    let mut table = ResourceTable::new();
    let nic = ResourceId::new("d-tx").unwrap();
    assert_eq!(
        table.add(nic.clone(), BandwidthRating::advertised(1.25e9).unwrap()),
        Err(BoundsError::UnusableBandwidth {
            resource: nic.clone(),
            basis: BandwidthBasis::Advertised
        })
    );
    assert!(table
        .add(
            nic,
            BandwidthRating::aggregate_bidirectional(2.5e9).unwrap()
        )
        .is_err());
}

#[test]
fn the_undeclared_shared_uplink_breaks_the_assumption() {
    // §4.7 claim record: t1 and t2 sit behind one 1.25 GB/s switch uplink. Declared, a
    // star needs 16 s; left out of the topology, the plan predicts 8 s, which the uplink
    // cannot deliver.
    let mut declared = mesh_topology(
        &[("d", 4.0 * LAN, LAN), ("t1", LAN, LAN), ("t2", LAN, LAN)],
        TransportKind::EstablishedCommunicator,
        0.0,
        1.0,
    )
    .unwrap();
    let undeclared = declared.clone();
    let uplink = ResourceId::new("rack-uplink").unwrap();
    declared.transports[0]
        .resources
        .add(
            uplink.clone(),
            BandwidthRating::measured_directional(LAN).unwrap(),
        )
        .unwrap();
    for link in &mut declared.links {
        if link.from == node("d") {
            link.resources.push(uplink.clone());
        }
    }
    let mut problem = problem(&["d"]);
    problem.targets = targets(&["t1", "t2"]);
    let real = plan(&declared, &problem, ScheduleShape::Star);
    let believed = plan(&undeclared, &problem, ScheduleShape::Star);
    assert_close(real.makespan_seconds, 16.0);
    assert_close(believed.makespan_seconds, 8.0);
}

#[test]
fn each_peer_pair_is_one_leg_with_its_own_envelope() {
    let topology = lan();
    let chain = plan(&topology, &problem(&["d"]), ScheduleShape::Chain);
    assert_eq!(chain.legs.len(), 3);
    assert!(chain
        .legs
        .iter()
        .all(|leg| leg.bytes == 10_000_000_000 && leg.needs_peer_envelope));
    let mut local = topology;
    for member in &mut local.nodes {
        member.endpoint = Endpoint::HostCatalog;
    }
    let local_chain = plan(&local, &problem(&["d"]), ScheduleShape::Chain);
    assert!(local_chain.legs.iter().all(|leg| !leg.needs_peer_envelope));
}
