//! GPU §2.3: finish(v) = duration(v) + max(finish(u) for u in predecessors(v)) for a
//! fixed schedule, resource-conflict ordering edges, capacity, and the first-token
//! objective.

use std::time::Duration;

use super::super::dag::{GraphBuilder, Policy, RequestGraph};
use super::super::node::{DemandProfile, DemandSegment, DurationEstimate, NodeKind, ResourceUnit};
use super::super::schedule::{evaluate_fixed, Capacities, EvaluatedSchedule};
use super::super::{NodeId, ScheduleError};
use super::support::{
    example, example_graph, example_with_ext1, first_token, id, ms, node, pcie_capacity, resource,
    GB_PER_SECOND, PCIE,
};

fn times(schedule: &EvaluatedSchedule, name: &str) -> (u64, u64) {
    let scheduled = schedule.node(&id(name)).unwrap();
    (
        scheduled.start.as_millis() as u64,
        scheduled.finish.as_millis() as u64,
    )
}

fn edge(from: &str, to: &str) -> (NodeId, NodeId) {
    (id(from), id(to))
}

#[test]
fn the_recurrence_matches_the_hand_worked_example() {
    let schedule = evaluate_fixed(&example_graph(false), &Capacities::new(), &[]).unwrap();
    let expected = [
        ("tok", (0, 5)),
        ("ext1", (0, 40)),
        ("ext2", (0, 30)),
        ("init", (0, 20)),
        ("layout", (40, 50)),
        ("adapter", (30, 45)),
        ("prefill", (50, 75)),
        ("respond", (75, 78)),
    ];
    for (name, start_finish) in expected {
        assert_eq!(times(&schedule, name), start_finish, "{name}");
    }
    assert_eq!(schedule.first_token(), ms(78));
    assert_eq!(schedule.makespan(), ms(78));
    assert_eq!(schedule.serial_work(), ms(148));
    assert_eq!(schedule.overlap(), ms(70));
    assert_eq!(schedule.work_spent(), 0);
    assert_eq!(
        schedule.runs_concurrently(&id("tok"), &id("ext2")),
        Some(true)
    );
    assert_eq!(
        schedule.runs_concurrently(&id("layout"), &id("prefill")),
        Some(false)
    );
    assert_eq!(schedule.runs_concurrently(&id("tok"), &id("ghost")), None);
}

#[test]
fn the_uncertainty_interval_propagates_through_the_same_schedule() {
    let ext1 = DurationEstimate::new(ms(30), ms(40), ms(60)).unwrap();
    let graph = example_with_ext1(false, ext1).build(Policy::new()).unwrap();
    let schedule = evaluate_fixed(&graph, &Capacities::new(), &[]).unwrap();
    // low: layout 10 + max(30, 20) = 40, prefill 25 + max(5, 40, 45) = 70, respond 73.
    // high: layout 10 + max(60, 20) = 70, prefill 25 + max(5, 70, 45) = 95, respond 98.
    assert_eq!(schedule.first_token(), ms(78));
    assert_eq!(schedule.first_token_interval(), (ms(73), ms(98)));
    let layout = schedule.node(&id("layout")).unwrap();
    assert_eq!(
        (layout.finish_low, layout.finish, layout.finish_high),
        (ms(40), ms(50), ms(70))
    );
    for scheduled in schedule.nodes() {
        assert!(
            scheduled.finish_low <= scheduled.finish && scheduled.finish <= scheduled.finish_high
        );
    }
}

#[test]
fn contending_nodes_without_a_conflict_edge_exceed_capacity() {
    assert_eq!(
        evaluate_fixed(&example_graph(true), &pcie_capacity(), &[]).unwrap_err(),
        ScheduleError::CapacityExceeded {
            resource: resource(PCIE),
            at: Duration::ZERO,
            demand: 40 * GB_PER_SECOND,
            capacity: 25 * GB_PER_SECOND,
        }
    );
}

#[test]
fn a_resource_conflict_edge_delays_the_right_node() {
    let graph = example_graph(true);
    let unconstrained = evaluate_fixed(&example_graph(false), &Capacities::new(), &[]).unwrap();

    let ext1_first = evaluate_fixed(&graph, &pcie_capacity(), &[edge("ext1", "ext2")]).unwrap();
    // ext2 waits for ext1 to finish; only ext2 and what consumes it move.
    assert_eq!(times(&ext1_first, "ext2"), (40, 70));
    assert_eq!(times(&ext1_first, "adapter"), (70, 85));
    assert_eq!(times(&ext1_first, "prefill"), (85, 110));
    assert_eq!(ext1_first.first_token(), ms(113));
    for unmoved in ["tok", "ext1", "init", "layout"] {
        assert_eq!(
            times(&ext1_first, unmoved),
            times(&unconstrained, unmoved),
            "{unmoved}"
        );
    }
    assert_eq!(ext1_first.conflict_edges(), &[edge("ext1", "ext2")]);

    let ext2_first = evaluate_fixed(&graph, &pcie_capacity(), &[edge("ext2", "ext1")]).unwrap();
    assert_eq!(times(&ext2_first, "ext1"), (30, 70));
    assert_eq!(times(&ext2_first, "layout"), (70, 80));
    assert_eq!(times(&ext2_first, "prefill"), (80, 105));
    assert_eq!(ext2_first.first_token(), ms(108));
    for unmoved in ["tok", "ext2", "init", "adapter"] {
        assert_eq!(
            times(&ext2_first, unmoved),
            times(&unconstrained, unmoved),
            "{unmoved}"
        );
    }
}

#[test]
fn conflict_edges_must_join_contending_nodes_without_a_cycle() {
    let graph = example_graph(true);
    assert_eq!(
        evaluate_fixed(&graph, &pcie_capacity(), &[edge("tok", "init")]).unwrap_err(),
        ScheduleError::NotAConflict {
            from: id("tok"),
            to: id("init")
        }
    );
    assert_eq!(
        evaluate_fixed(
            &graph,
            &pcie_capacity(),
            &[edge("ext1", "ext2"), edge("ext2", "ext1")]
        )
        .unwrap_err(),
        ScheduleError::ConflictEdgeCycle {
            nodes: vec![id("ext1"), id("ext2")]
        }
    );
    assert_eq!(
        evaluate_fixed(&graph, &pcie_capacity(), &[edge("ext1", "ghost")]).unwrap_err(),
        ScheduleError::UnknownNode { node: id("ghost") }
    );
}

#[test]
fn capacities_are_declared_once_in_one_unit() {
    let pcie = resource(PCIE);
    assert_eq!(
        Capacities::new()
            .with(pcie.clone(), ResourceUnit::Bytes, 0)
            .unwrap_err(),
        ScheduleError::ZeroCapacity {
            resource: pcie.clone()
        }
    );
    assert_eq!(
        pcie_capacity()
            .with(pcie.clone(), ResourceUnit::BytesPerSecond, 1)
            .unwrap_err(),
        ScheduleError::DuplicateResource {
            resource: pcie.clone()
        }
    );
    assert_eq!(
        pcie_capacity().get(&pcie),
        Some((ResourceUnit::BytesPerSecond, 25 * GB_PER_SECOND))
    );
    let graph = example_graph(true);
    assert_eq!(
        evaluate_fixed(&graph, &Capacities::new(), &[]).unwrap_err(),
        ScheduleError::UnknownResource {
            node: id("ext1"),
            resource: pcie.clone()
        }
    );
    let in_bytes = Capacities::new()
        .with(pcie.clone(), ResourceUnit::Bytes, 100 * GB_PER_SECOND)
        .unwrap();
    assert_eq!(
        evaluate_fixed(&graph, &in_bytes, &[]).unwrap_err(),
        ScheduleError::UnitMismatch {
            node: id("ext1"),
            resource: pcie.clone(),
            declared: ResourceUnit::Bytes,
            demanded: ResourceUnit::BytesPerSecond
        }
    );
    let narrow = Capacities::new()
        .with(
            pcie.clone(),
            ResourceUnit::BytesPerSecond,
            10 * GB_PER_SECOND,
        )
        .unwrap();
    assert_eq!(
        evaluate_fixed(&graph, &narrow, &[]).unwrap_err(),
        ScheduleError::NodeExceedsCapacity {
            node: id("ext1"),
            resource: pcie,
            demand: 20 * GB_PER_SECOND,
            capacity: 10 * GB_PER_SECOND
        }
    );
}

const VRAM_GB: u64 = 1_000_000_000;

/// `held` weights retain VRAM from their start until the request ends; `staging` needs a
/// transient buffer while it runs.
fn held_and_staging(held_gb: u64, staging_gb: u64) -> RequestGraph {
    let vram = || resource("gpu0.vram");
    let held = node("held", NodeKind::ArtifactExtent, 4).with_demand(DemandProfile::new(vec![
        DemandSegment::retained(
            vram(),
            ResourceUnit::Bytes,
            held_gb * VRAM_GB,
            Duration::ZERO,
        )
        .unwrap(),
    ]));
    let staging = node("staging", NodeKind::KvBlock, 4).with_demand(DemandProfile::new(vec![
        DemandSegment::transient(
            vram(),
            ResourceUnit::Bytes,
            staging_gb * VRAM_GB,
            ms(0),
            ms(4),
        )
        .unwrap(),
    ]));
    GraphBuilder::new()
        .node(held)
        .node(staging)
        .node(node("prefill", NodeKind::Compute, 2))
        .node(first_token("respond", 1))
        .edge(&id("held"), &id("prefill"))
        .edge(&id("staging"), &id("prefill"))
        .edge(&id("prefill"), &id("respond"))
        .build(Policy::new())
        .unwrap()
}

fn vram_capacity(gb: u64) -> Capacities {
    Capacities::new()
        .with(resource("gpu0.vram"), ResourceUnit::Bytes, gb * VRAM_GB)
        .unwrap()
}

#[test]
fn memory_held_until_the_request_ends_stays_counted_after_its_node_finishes() {
    let graph = held_and_staging(6, 5);
    assert!(matches!(
        evaluate_fixed(&graph, &vram_capacity(10), &[]).unwrap_err(),
        ScheduleError::CapacityExceeded { at, demand, .. } if at == Duration::ZERO && demand == 11 * VRAM_GB
    ));
    // Staging after the held weights still overlaps their allocation.
    assert!(matches!(
        evaluate_fixed(&graph, &vram_capacity(10), &[edge("held", "staging")]).unwrap_err(),
        ScheduleError::CapacityExceeded { at, .. } if at == ms(4)
    ));
    // Staging first releases its buffer before the weights arrive.
    let staged_first =
        evaluate_fixed(&graph, &vram_capacity(10), &[edge("staging", "held")]).unwrap();
    assert_eq!(times(&staged_first, "held"), (4, 8));
    assert_eq!(staged_first.first_token(), ms(11));

    // Held demand alone above capacity is refused in every order.
    let two_held = GraphBuilder::new()
        .node(
            node("a", NodeKind::ArtifactExtent, 1).with_demand(DemandProfile::new(vec![
                DemandSegment::retained(
                    resource("gpu0.vram"),
                    ResourceUnit::Bytes,
                    6 * VRAM_GB,
                    ms(1),
                )
                .unwrap(),
            ])),
        )
        .node(
            node("b", NodeKind::ArtifactExtent, 1).with_demand(DemandProfile::new(vec![
                DemandSegment::retained(
                    resource("gpu0.vram"),
                    ResourceUnit::Bytes,
                    5 * VRAM_GB,
                    ms(0),
                )
                .unwrap(),
            ])),
        )
        .node(node("prefill", NodeKind::Compute, 2))
        .node(first_token("respond", 1))
        .edge(&id("a"), &id("prefill"))
        .edge(&id("b"), &id("prefill"))
        .edge(&id("prefill"), &id("respond"))
        .build(Policy::new())
        .unwrap();
    assert_eq!(
        evaluate_fixed(&two_held, &vram_capacity(10), &[]).unwrap_err(),
        ScheduleError::RetainedDemandExceedsCapacity {
            resource: resource("gpu0.vram"),
            demand: 11 * VRAM_GB,
            capacity: 10 * VRAM_GB
        }
    );
}

#[test]
fn the_first_token_objective_ignores_work_off_its_path() {
    let with_later_work = example(false)
        .node(node("decode-graph", NodeKind::GraphCapture, 50))
        .node(node("later", NodeKind::NetworkResponse, 4))
        .edge(&id("init"), &id("decode-graph"))
        .edge(&id("decode-graph"), &id("later"))
        .edge(&id("respond"), &id("later"))
        .build(Policy::new())
        .unwrap();
    let schedule = evaluate_fixed(&with_later_work, &Capacities::new(), &[]).unwrap();
    assert_eq!(schedule.first_token(), ms(78));
    assert_eq!(times(&schedule, "decode-graph"), (20, 70));
    assert_eq!(times(&schedule, "later"), (78, 82));
    assert_eq!(schedule.makespan(), ms(82));
}
