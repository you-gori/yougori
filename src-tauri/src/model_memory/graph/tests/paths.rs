//! GPU §1 at graph level: use what is ready, materialize only what is missing, and
//! overlap the remaining work where dependencies allow. Advertisements are hints with an
//! expiry, matched by identity and rechecked for trust scope (§3.2).

use std::time::Duration;

use crate::foundation::ids::{ManualClock, MonotonicTime};

use super::super::dag::Policy;
use super::super::heuristic::WorkBound;
use super::super::paths::{plan, Disposition, ReadyRejection, ReadyState};
use super::super::schedule::Capacities;
use super::super::ScheduleError;
use super::support::{example, example_graph, id, identity, ms, pcie_capacity, scope};

fn at_seconds(seconds: u64) -> MonotonicTime {
    MonotonicTime::from_nanos(seconds * 1_000_000_000)
}

fn ready(name: &str, tenant: &str, expires_seconds: u64) -> ReadyState {
    ReadyState::new(identity(name), scope(tenant), at_seconds(expires_seconds))
}

fn bound() -> WorkBound {
    WorkBound::new(1_000_000)
}

#[test]
fn already_ready_nodes_are_skipped() {
    let graph = example_graph(true);
    let clock = ManualClock::new(at_seconds(5));
    let cold = plan(&graph, &[], &clock, &pcie_capacity(), bound()).unwrap();
    assert_eq!(cold.schedule().first_token(), ms(113));
    assert!(cold.nodes_with(Disposition::Ready).is_empty());

    let warm = plan(
        &graph,
        &[ready("init", "tenant-a", 10), ready("ext1", "tenant-a", 10)],
        &clock,
        &pcie_capacity(),
        bound(),
    )
    .unwrap();
    assert_eq!(
        warm.nodes_with(Disposition::Ready),
        vec![&id("ext1"), &id("init")]
    );
    assert_eq!(warm.disposition(&id("init")), Some(Disposition::Ready));
    assert!(warm.schedule().node(&id("init")).is_none());
    assert!(warm.schedule().node(&id("ext1")).is_none());
    // layout's inputs are ready at time zero; ext2 has the link to itself.
    let start = |name: &str| warm.schedule().node(&id(name)).unwrap().start;
    assert_eq!(start("layout"), Duration::ZERO);
    assert_eq!(start("ext2"), Duration::ZERO);
    assert_eq!(start("adapter"), ms(30));
    assert_eq!(start("prefill"), ms(45));
    assert_eq!(warm.schedule().first_token(), ms(73));
    assert!(warm.schedule().conflict_edges().is_empty());
    assert_eq!(warm.planned_at(), at_seconds(5));
    assert_eq!(
        warm.first_token_at(),
        at_seconds(5).checked_add(ms(73)).unwrap()
    );
    assert!(warm.rejections().is_empty());
}

#[test]
fn only_missing_state_that_is_still_needed_is_materialized() {
    let graph = example_graph(true);
    let clock = ManualClock::new(at_seconds(1));
    let warm = plan(
        &graph,
        &[ready("layout", "tenant-a", 9)],
        &clock,
        &pcie_capacity(),
        bound(),
    )
    .unwrap();
    // ext1 only feeds the ready layout; init still feeds the adapter.
    assert_eq!(warm.nodes_with(Disposition::NotNeeded), vec![&id("ext1")]);
    assert_eq!(warm.disposition(&id("init")), Some(Disposition::Missing));
    assert_eq!(
        warm.nodes_with(Disposition::Missing),
        vec![
            &id("tok"),
            &id("ext2"),
            &id("init"),
            &id("adapter"),
            &id("prefill"),
            &id("respond")
        ]
    );
    assert!(warm.schedule().node(&id("ext1")).is_none());
    assert_eq!(warm.schedule().first_token(), ms(73));
    assert_eq!(warm.disposition(&id("ghost")), None);
}

#[test]
fn remaining_work_overlaps_where_dependencies_allow() {
    let clock = ManualClock::new(MonotonicTime::ZERO);
    let free = plan(
        &example_graph(false),
        &[],
        &clock,
        &Capacities::new(),
        bound(),
    )
    .unwrap();
    for name in ["tok", "ext1", "ext2", "init"] {
        assert_eq!(
            free.schedule().node(&id(name)).unwrap().start,
            Duration::ZERO,
            "{name}"
        );
    }
    assert_eq!(
        free.schedule().runs_concurrently(&id("ext1"), &id("ext2")),
        Some(true)
    );
    assert_eq!(free.schedule().first_token(), ms(78));
    assert_eq!(free.schedule().overlap(), ms(70));

    // A shared link takes that overlap away from the two extents only.
    let shared = plan(&example_graph(true), &[], &clock, &pcie_capacity(), bound()).unwrap();
    assert_eq!(
        shared
            .schedule()
            .runs_concurrently(&id("ext1"), &id("ext2")),
        Some(false)
    );
    assert_eq!(
        shared
            .schedule()
            .runs_concurrently(&id("ext1"), &id("init")),
        Some(true)
    );
}

#[test]
fn an_expired_advertisement_is_not_ready_state() {
    let graph = example_graph(false);
    let clock = ManualClock::new(at_seconds(5));
    let advertised = [ready("init", "tenant-a", 10)];
    let before = plan(&graph, &advertised, &clock, &Capacities::new(), bound()).unwrap();
    assert_eq!(before.disposition(&id("init")), Some(Disposition::Ready));

    clock.advance_to(at_seconds(10));
    let after = plan(&graph, &advertised, &clock, &Capacities::new(), bound()).unwrap();
    assert_eq!(after.disposition(&id("init")), Some(Disposition::Missing));
    assert_eq!(after.rejections(), &[(id("init"), ReadyRejection::Expired)]);
}

#[test]
fn ready_state_from_another_trust_scope_needs_an_allowance() {
    let clock = ManualClock::new(at_seconds(1));
    let advertised = [ready("init", "tenant-b", 9)];
    let strict = plan(
        &example_graph(false),
        &advertised,
        &clock,
        &Capacities::new(),
        bound(),
    )
    .unwrap();
    assert_eq!(strict.disposition(&id("init")), Some(Disposition::Missing));
    assert_eq!(
        strict.rejections(),
        &[(id("init"), ReadyRejection::OtherTrustScope)]
    );

    let allowed = example(false)
        .build(Policy::new().allow(scope("tenant-b"), scope("tenant-a"), identity("init")))
        .unwrap();
    let shared = plan(&allowed, &advertised, &clock, &Capacities::new(), bound()).unwrap();
    assert_eq!(shared.disposition(&id("init")), Some(Disposition::Ready));
}

#[test]
fn advertisements_match_by_identity_only() {
    let clock = ManualClock::new(at_seconds(1));
    // Different state that happens to share the node's name pattern does nothing.
    let other_version = ReadyState::new(identity("init-v2"), scope("tenant-a"), at_seconds(9));
    let result = plan(
        &example_graph(false),
        &[other_version],
        &clock,
        &Capacities::new(),
        bound(),
    )
    .unwrap();
    assert!(result.nodes_with(Disposition::Ready).is_empty());
    assert!(result.rejections().is_empty());
}

#[test]
fn ready_state_never_satisfies_compute_or_response_work() {
    let clock = ManualClock::new(at_seconds(1));
    let graph = example_graph(false);
    assert_eq!(
        plan(
            &graph,
            &[ready("prefill", "tenant-a", 9)],
            &clock,
            &Capacities::new(),
            bound()
        )
        .unwrap_err(),
        ScheduleError::ReadyStateForRequestWork {
            node: id("prefill"),
            kind: super::super::node::NodeKind::Compute
        }
    );
    assert!(matches!(
        plan(&graph, &[ready("respond", "tenant-a", 9)], &clock, &Capacities::new(), bound())
            .unwrap_err(),
        ScheduleError::ReadyStateForRequestWork { node, .. } if node == id("respond")
    ));
}
