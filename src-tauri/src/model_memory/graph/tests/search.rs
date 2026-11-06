//! GPU §2.3: a bounded heuristic in production, an exhaustive oracle offline, and their
//! comparison on small seeded graphs. The heuristic never beats the oracle; its ratio is
//! reported.

use super::super::dag::{GraphBuilder, Policy, RequestGraph};
use super::super::heuristic::{self, WorkBound};
use super::super::node::{DemandProfile, DemandSegment, NodeKind, ResourceUnit};
use super::super::oracle::{self, compare, ORACLE_MAX_NODES};
use super::super::schedule::{evaluate_fixed, Capacities};
use super::super::{NodeId, ScheduleError};
use super::support::{
    example, example_graph, first_token, id, ms, node, on_pcie, pcie_capacity, random_case,
    resource, SeededRng, Shape, GB_PER_SECOND,
};

const ORACLE_STEPS: u64 = 20_000_000;

#[test]
fn the_heuristic_follows_the_critical_path_and_the_oracle_finds_the_optimum() {
    let graph = example_graph(true);
    let bound = WorkBound::for_graph(&graph);
    let fast = heuristic::schedule(&graph, &pcie_capacity(), bound).unwrap();
    // ext1 has the longer remaining path (78 ms against 73 ms), so it goes first.
    assert_eq!(fast.conflict_edges(), &[(id("ext1"), id("ext2"))]);
    assert_eq!(fast.first_token(), ms(113));
    assert!(fast.work_spent() > 0 && fast.work_spent() <= bound.max_units());

    // Waiting on ext2's adapter path costs more: one of the two must end at 70 ms, and
    // only ext1 ending there leaves 70 + 10 + 25 + 3 = 108 ms.
    let best = oracle::oracle(&graph, &pcie_capacity(), ORACLE_STEPS).unwrap();
    assert_eq!(best.first_token(), ms(108));
    assert_eq!(best.node(&id("ext1")).unwrap().start, ms(30));

    let comparison = compare(&graph, &pcie_capacity(), bound, ORACLE_STEPS).unwrap();
    assert_eq!(comparison.heuristic_first_token, Some(ms(113)));
    assert_eq!(comparison.oracle_first_token, ms(108));
    let ratio = comparison.ratio().unwrap();
    assert!((ratio - 113.0 / 108.0).abs() < 1e-12);
    println!("hand-worked example: heuristic/oracle first-token ratio {ratio:.4}");
}

#[test]
fn both_searches_reproduce_under_plain_evaluation() {
    let graph = example_graph(true);
    for schedule in [
        heuristic::schedule(&graph, &pcie_capacity(), WorkBound::for_graph(&graph)).unwrap(),
        oracle::oracle(&graph, &pcie_capacity(), ORACLE_STEPS).unwrap(),
    ] {
        let replay = evaluate_fixed(&graph, &pcie_capacity(), schedule.conflict_edges()).unwrap();
        assert_eq!(replay.nodes(), schedule.nodes());
        assert_eq!(replay.first_token(), schedule.first_token());
    }
}

#[test]
fn the_heuristic_never_beats_the_oracle_on_seeded_graphs() {
    // Transient demand up to 80% of a capacity makes pairs contend often, and without
    // demand held to the end of the request every order stays feasible.
    let mut rng = SeededRng::new(0x7006);
    let (mut ratios, mut optimal, mut conflicts) = (Vec::new(), 0usize, 0usize);
    for _ in 0..150 {
        let shape = Shape {
            nodes: rng.between(6, 9),
            max_transient_percent: 80,
            retained: false,
        };
        let (graph, capacities) = random_case(&mut rng, shape);
        let bound = WorkBound::for_graph(&graph);
        conflicts += heuristic::schedule(&graph, &capacities, bound)
            .unwrap()
            .conflict_edges()
            .len();
        let comparison = compare(&graph, &capacities, bound, ORACLE_STEPS).unwrap();
        let heuristic = comparison.heuristic_first_token.unwrap();
        assert!(comparison.oracle_first_token <= heuristic);
        let ratio = comparison.ratio().unwrap();
        assert!(ratio >= 1.0);
        optimal += usize::from(heuristic == comparison.oracle_first_token);
        ratios.push(ratio);
    }
    let worst = ratios.iter().copied().fold(1.0, f64::max);
    let mean = ratios.iter().sum::<f64>() / ratios.len() as f64;
    println!(
        "heuristic vs oracle on {} seeded graphs of 6-9 nodes ({conflicts} conflict edges): \
         optimal in {optimal}, mean first-token ratio {mean:.4}, worst {worst:.4}",
        ratios.len()
    );
    assert!(conflicts >= ratios.len() / 3);
    assert!(
        optimal < ratios.len(),
        "the comparison should exercise suboptimal cases"
    );
}

#[test]
fn under_tight_capacity_a_heuristic_schedule_implies_an_oracle_schedule() {
    let mut rng = SeededRng::new(0x7106);
    let (mut both, mut neither, mut only_oracle) = (0, 0, 0);
    for _ in 0..80 {
        let shape = Shape {
            nodes: rng.between(5, 8),
            max_transient_percent: 100,
            retained: true,
        };
        let (graph, capacities) = random_case(&mut rng, shape);
        let bound = WorkBound::for_graph(&graph);
        let fast = heuristic::schedule(&graph, &capacities, bound);
        let best = oracle::oracle(&graph, &capacities, ORACLE_STEPS);
        match (fast, best) {
            (Ok(fast), Ok(best)) => {
                assert!(best.first_token() <= fast.first_token());
                assert!(fast.work_spent() <= bound.max_units());
                both += 1;
            }
            (Err(ScheduleError::NoFeasiblePlacement { .. }), Ok(_)) => only_oracle += 1,
            (Err(fast), Err(best)) => {
                assert!(
                    matches!(best, ScheduleError::NoFeasibleSchedule) || fast == best,
                    "{fast:?} / {best:?}"
                );
                neither += 1;
            }
            (Ok(_), Err(best)) => {
                panic!("the heuristic found a schedule the oracle missed: {best:?}")
            }
            (Err(fast), Ok(_)) => panic!("unexpected heuristic failure: {fast:?}"),
        }
    }
    println!("tight capacity: both {both}, oracle only {only_oracle}, neither {neither}");
    // The critical-path rule alone left 7 of these to the oracle; the retry solves all 7.
    assert_eq!((both, only_oracle, neither), (66, 0, 14));
}

/// Every pair of nodes that contend and are not ordered by their dependencies.
fn open_pairs(graph: &RequestGraph) -> Vec<(NodeId, NodeId)> {
    let reaches = |from: &NodeId, to: &NodeId| {
        let mut stack = vec![to.clone()];
        while let Some(at) = stack.pop() {
            if &at == from {
                return true;
            }
            stack.extend(graph.predecessors(&at).unwrap().into_iter().cloned());
        }
        false
    };
    let uses = |name: &NodeId| -> Vec<String> {
        graph
            .node(name)
            .unwrap()
            .demand()
            .segments()
            .iter()
            .map(|segment| segment.resource().to_string())
            .collect()
    };
    let names: Vec<NodeId> = graph.nodes().iter().map(|spec| spec.id().clone()).collect();
    let mut pairs = Vec::new();
    for (i, a) in names.iter().enumerate() {
        for b in &names[i + 1..] {
            let shared = uses(a).iter().any(|resource| uses(b).contains(resource));
            if shared && !reaches(a, b) && !reaches(b, a) {
                pairs.push((a.clone(), b.clone()));
            }
        }
    }
    pairs
}

#[test]
fn the_oracle_is_no_worse_than_any_orientation_of_conflict_edges() {
    let mut rng = SeededRng::new(0x7206);
    let mut checked = 0;
    while checked < 25 {
        let shape = Shape {
            nodes: rng.between(4, 6),
            max_transient_percent: 70,
            retained: false,
        };
        let (graph, capacities) = random_case(&mut rng, shape);
        let pairs = open_pairs(&graph);
        if pairs.len() > 7 {
            continue;
        }
        checked += 1;
        let best = oracle::oracle(&graph, &capacities, ORACLE_STEPS).unwrap();
        let mut feasible = 0;
        for code in 0..3u32.pow(pairs.len() as u32) {
            let mut rest = code;
            let mut edges = Vec::new();
            for (a, b) in &pairs {
                match rest % 3 {
                    1 => edges.push((a.clone(), b.clone())),
                    2 => edges.push((b.clone(), a.clone())),
                    _ => {}
                }
                rest /= 3;
            }
            if let Ok(fixed) = evaluate_fixed(&graph, &capacities, &edges) {
                feasible += 1;
                assert!(best.first_token() <= fixed.first_token());
            }
        }
        assert!(feasible > 0);
    }
}

#[test]
fn the_heuristic_stays_within_its_work_bound_and_refuses_beyond_it() {
    let mut rng = SeededRng::new(0x7306);
    for _ in 0..60 {
        let shape = Shape {
            nodes: rng.between(4, 10),
            max_transient_percent: 50,
            retained: true,
        };
        let (graph, capacities) = random_case(&mut rng, shape);
        let bound = WorkBound::for_graph(&graph);
        let spent = heuristic::schedule(&graph, &capacities, bound)
            .unwrap()
            .work_spent();
        assert!(spent <= bound.max_units());
        let short = WorkBound::new(spent - 1);
        assert_eq!(
            heuristic::schedule(&graph, &capacities, short).unwrap_err(),
            ScheduleError::WorkBoundExceeded { bound: spent - 1 }
        );
    }
    assert_eq!(
        WorkBound::sufficient(2, 1).max_units(),
        9 * 4 + 1 + 1 + 2 * 2 * (1 + 3 + 4 + 2)
    );
}

/// `weights` hold 6 of 10 until the request ends; `staging` needs 6 while it runs.
fn weights_and_staging() -> (RequestGraph, Capacities) {
    let vram = || resource("gpu0.vram");
    let graph = GraphBuilder::new()
        .node(
            node("weights", NodeKind::ArtifactExtent, 4).with_demand(DemandProfile::new(vec![
                DemandSegment::retained(vram(), ResourceUnit::Bytes, 6, ms(0)).unwrap(),
            ])),
        )
        .node(
            node("staging", NodeKind::KvBlock, 2).with_demand(DemandProfile::new(vec![
                DemandSegment::transient(vram(), ResourceUnit::Bytes, 6, ms(0), ms(2)).unwrap(),
            ])),
        )
        .node(node("prefill", NodeKind::Compute, 2))
        .node(first_token("respond", 1))
        .edge(&id("weights"), &id("prefill"))
        .edge(&id("staging"), &id("prefill"))
        .edge(&id("prefill"), &id("respond"))
        .build(Policy::new())
        .unwrap();
    let capacities = Capacities::new()
        .with(vram(), ResourceUnit::Bytes, 10)
        .unwrap();
    (graph, capacities)
}

#[test]
fn the_memory_pressure_retry_places_what_the_critical_path_rule_cannot() {
    let (graph, capacities) = weights_and_staging();
    // Critical path places the weights first (7 ms to go against 5 ms); their hold then
    // leaves staging no room at any start. The retry runs staging first.
    let fast = heuristic::schedule(&graph, &capacities, WorkBound::for_graph(&graph)).unwrap();
    assert_eq!(fast.node(&id("staging")).unwrap().start, ms(0));
    assert_eq!(fast.node(&id("weights")).unwrap().start, ms(2));
    assert_eq!(fast.conflict_edges(), &[(id("staging"), id("weights"))]);
    assert_eq!(fast.first_token(), ms(9));
    let best = oracle::oracle(&graph, &capacities, ORACLE_STEPS).unwrap();
    assert_eq!(best.first_token(), ms(9));
    // Both rules run within the one bound, and nothing less than what they spent.
    let spent = fast.work_spent();
    assert!(spent <= WorkBound::for_graph(&graph).max_units());
    assert_eq!(
        heuristic::schedule(&graph, &capacities, WorkBound::new(spent - 1)).unwrap_err(),
        ScheduleError::WorkBoundExceeded { bound: spent - 1 }
    );
}

#[test]
fn the_heuristic_refuses_only_when_both_rules_find_no_start() {
    let vram = || resource("gpu0.vram");
    let graph = GraphBuilder::new()
        .node(
            node("weights", NodeKind::ArtifactExtent, 2).with_demand(DemandProfile::new(vec![
                DemandSegment::retained(vram(), ResourceUnit::Bytes, 6, ms(0)).unwrap(),
            ])),
        )
        .node(
            node("scratch", NodeKind::Compute, 2).with_demand(DemandProfile::new(vec![
                DemandSegment::transient(vram(), ResourceUnit::Bytes, 6, ms(0), ms(2)).unwrap(),
            ])),
        )
        .node(first_token("respond", 1))
        .edge(&id("weights"), &id("scratch"))
        .edge(&id("scratch"), &id("respond"))
        .build(Policy::new())
        .unwrap();
    let capacities = Capacities::new()
        .with(vram(), ResourceUnit::Bytes, 10)
        .unwrap();
    assert_eq!(
        heuristic::schedule(&graph, &capacities, WorkBound::for_graph(&graph)).unwrap_err(),
        ScheduleError::NoFeasiblePlacement {
            node: id("scratch")
        }
    );
    assert_eq!(
        oracle::oracle(&graph, &capacities, ORACLE_STEPS).unwrap_err(),
        ScheduleError::NoFeasibleSchedule
    );
}

#[test]
fn the_oracle_is_only_for_tiny_graphs_and_bounded_too() {
    let mut builder = GraphBuilder::new()
        .node(node("prefill", NodeKind::Compute, 1))
        .node(first_token("respond", 1))
        .edge(&id("prefill"), &id("respond"));
    for number in 0..ORACLE_MAX_NODES - 1 {
        let name = format!("ext{number}");
        builder = builder
            .node(node(&name, NodeKind::ArtifactExtent, 1))
            .edge(&id(&name), &id("prefill"));
    }
    let graph = builder.build(Policy::new()).unwrap();
    assert_eq!(
        oracle::oracle(&graph, &Capacities::new(), ORACLE_STEPS).unwrap_err(),
        ScheduleError::TooLargeForOracle {
            nodes: ORACLE_MAX_NODES + 1,
            max: ORACLE_MAX_NODES
        }
    );
    assert_eq!(
        oracle::oracle(&example_graph(true), &pcie_capacity(), 3).unwrap_err(),
        ScheduleError::WorkBoundExceeded { bound: 3 }
    );
}

#[test]
fn work_off_the_first_token_path_never_delays_the_first_token() {
    let prefetch = on_pcie(
        node("prefetch", NodeKind::ArtifactExtent, 60),
        20 * GB_PER_SECOND,
    );
    let graph = example(true)
        .node(prefetch)
        .node(node("later", NodeKind::NetworkResponse, 4))
        .edge(&id("prefetch"), &id("later"))
        .edge(&id("respond"), &id("later"))
        .build(Policy::new())
        .unwrap();
    assert!(!graph.on_objective_path(&id("prefetch")));
    let fast = heuristic::schedule(&graph, &pcie_capacity(), WorkBound::for_graph(&graph)).unwrap();
    assert_eq!(fast.first_token(), ms(113));
    // It contends for the link, so it waits for both extents.
    assert_eq!(fast.node(&id("prefetch")).unwrap().start, ms(70));
    let best = oracle::oracle(&graph, &pcie_capacity(), ORACLE_STEPS).unwrap();
    assert_eq!(best.first_token(), ms(108));
}
