//! Test helpers: an explicitly seeded generator, node builders, the hand-worked example
//! graph and a generator of small random graphs.

use std::time::Duration;

use crate::foundation::ids::{digest, Digest, ExecutionCategory};

use super::super::dag::{GraphBuilder, Policy, RequestGraph};
use super::super::node::{
    CompletionEvent, DemandProfile, DemandSegment, DurationEstimate, NodeKind, NodeSpec,
    ResourceUnit,
};
use super::super::schedule::Capacities;
use super::super::{NodeId, ResourceId, TrustScope};

/// SplitMix64: a small deterministic generator, seeded explicitly by each test.
pub(super) struct SeededRng(u64);

impl SeededRng {
    pub(super) fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub(super) fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A value in [low, high].
    pub(super) fn between(&mut self, low: u64, high: u64) -> u64 {
        low + self.next_u64() % (high - low + 1)
    }

    pub(super) fn percent(&mut self, chance: u64) -> bool {
        self.next_u64() % 100 < chance
    }

    pub(super) fn bytes(&mut self, length: usize) -> Vec<u8> {
        (0..length).map(|_| (self.next_u64() >> 56) as u8).collect()
    }
}

pub(super) fn ms(value: u64) -> Duration {
    Duration::from_millis(value)
}

pub(super) fn id(name: &str) -> NodeId {
    NodeId::new(name).unwrap()
}

/// A VM sandbox scope named by text.
pub(super) fn scope(name: &str) -> TrustScope {
    TrustScope::named(ExecutionCategory::VmSandbox, name)
}

pub(super) fn resource(name: &str) -> ResourceId {
    ResourceId::new(name).unwrap()
}

/// A stand-in for the identity T07 will supply.
pub(super) fn identity(name: &str) -> Digest {
    digest("yougori/test/graph/state/v1", &[name.as_bytes()])
}

/// The event that establishes usability for `kind`; later response work for responses.
pub(super) fn usable_event(kind: NodeKind) -> CompletionEvent {
    match kind {
        NodeKind::ArtifactExtent => CompletionEvent::ExtentVerified,
        NodeKind::EngineInitialization => CompletionEvent::EngineReady,
        NodeKind::RankLayout => CompletionEvent::LayoutPublished,
        NodeKind::Adapter => CompletionEvent::AdapterActivated,
        NodeKind::TokenizerConfiguration => CompletionEvent::TokenizerLoaded,
        NodeKind::KvBlock => CompletionEvent::KvBlockPublished,
        NodeKind::GraphCapture => CompletionEvent::GraphKeyValidated,
        NodeKind::Communicator => CompletionEvent::CommunicatorReady,
        NodeKind::Compute => CompletionEvent::ComputeCompleted,
        NodeKind::NetworkResponse => CompletionEvent::ResponseDelivered,
    }
}

/// A node in trust scope `tenant-a` with an exact duration.
pub(super) fn node(name: &str, kind: NodeKind, millis: u64) -> NodeSpec {
    NodeSpec::new(
        id(name),
        kind,
        identity(name),
        scope("tenant-a"),
        DurationEstimate::exact(ms(millis)).unwrap(),
        usable_event(kind),
    )
}

/// The network/client response work that delivers the first token.
pub(super) fn first_token(name: &str, millis: u64) -> NodeSpec {
    NodeSpec::new(
        id(name),
        NodeKind::NetworkResponse,
        identity(name),
        scope("tenant-a"),
        DurationEstimate::exact(ms(millis)).unwrap(),
        CompletionEvent::FirstTokenDelivered,
    )
}

pub(super) const PCIE: &str = "pcie.h2d";
pub(super) const GB_PER_SECOND: u64 = 1_000_000_000;

/// `rate` bytes per second of the host-to-device link for the node's whole duration.
pub(super) fn on_pcie(spec: NodeSpec, rate: u64) -> NodeSpec {
    let duration = spec.duration().expected();
    spec.with_demand(DemandProfile::new(vec![DemandSegment::transient(
        resource(PCIE),
        ResourceUnit::BytesPerSecond,
        rate,
        Duration::ZERO,
        duration,
    )
    .unwrap()]))
}

/// 25 GB/s of host-to-device link.
pub(super) fn pcie_capacity() -> Capacities {
    Capacities::new()
        .with(
            resource(PCIE),
            ResourceUnit::BytesPerSecond,
            25 * GB_PER_SECOND,
        )
        .unwrap()
}

/// The hand-worked request (milliseconds):
///
/// ```text
/// tok 5 ─────────────────────────────┐
/// ext1 40 ──┬─> layout 10 ───────────┼─> prefill 25 ─> respond 3 (first token)
/// init 20 ──┤                        │
///           └─> adapter 15 ──────────┘
/// ext2 30 ──────^
/// ```
///
/// With `pcie`, both extents need 20 GB/s of a 25 GB/s link, so they contend.
pub(super) fn example(pcie: bool) -> GraphBuilder {
    example_with_ext1(pcie, DurationEstimate::exact(ms(40)).unwrap())
}

/// [`example`] with another duration estimate for `ext1`.
pub(super) fn example_with_ext1(pcie: bool, ext1: DurationEstimate) -> GraphBuilder {
    let extent = |spec: NodeSpec| {
        if pcie {
            on_pcie(spec, 20 * GB_PER_SECOND)
        } else {
            spec
        }
    };
    let first = NodeSpec::new(
        id("ext1"),
        NodeKind::ArtifactExtent,
        identity("ext1"),
        scope("tenant-a"),
        ext1,
        CompletionEvent::ExtentVerified,
    );
    GraphBuilder::new()
        .node(node("tok", NodeKind::TokenizerConfiguration, 5))
        .node(extent(first))
        .node(extent(node("ext2", NodeKind::ArtifactExtent, 30)))
        .node(node("init", NodeKind::EngineInitialization, 20))
        .node(node("layout", NodeKind::RankLayout, 10))
        .node(node("adapter", NodeKind::Adapter, 15))
        .node(node("prefill", NodeKind::Compute, 25))
        .node(first_token("respond", 3))
        .edge(&id("ext1"), &id("layout"))
        .edge(&id("init"), &id("layout"))
        .edge(&id("ext2"), &id("adapter"))
        .edge(&id("init"), &id("adapter"))
        .edge(&id("tok"), &id("prefill"))
        .edge(&id("layout"), &id("prefill"))
        .edge(&id("adapter"), &id("prefill"))
        .edge(&id("prefill"), &id("respond"))
}

pub(super) fn example_graph(pcie: bool) -> RequestGraph {
    example(pcie).build(Policy::new()).unwrap()
}

/// Shape of the random graphs.
#[derive(Clone, Copy)]
pub(super) struct Shape {
    pub(super) nodes: u64,
    /// Largest transient demand, in percent of capacity.
    pub(super) max_transient_percent: u64,
    /// Whether some demand is held until the request ends.
    pub(super) retained: bool,
}

const RESOURCES: [(&str, ResourceUnit, u64); 2] = [
    ("slots", ResourceUnit::Slots, 10),
    ("vram", ResourceUnit::Bytes, 1000),
];

/// A random request graph: `shape.nodes - 1` state and compute nodes in topological
/// order, then the first-token response, which depends on a compute node.
pub(super) fn random_case(rng: &mut SeededRng, shape: Shape) -> (RequestGraph, Capacities) {
    let kinds = [
        NodeKind::ArtifactExtent,
        NodeKind::EngineInitialization,
        NodeKind::RankLayout,
        NodeKind::Adapter,
        NodeKind::KvBlock,
        NodeKind::GraphCapture,
        NodeKind::Compute,
    ];
    let inner = shape.nodes - 1;
    let compute = rng.between(0, inner - 1);
    let mut builder = GraphBuilder::new();
    let mut retained_left = [RESOURCES[0].2 / 2, RESOURCES[1].2 / 2];
    for number in 0..inner {
        let kind = if number == compute {
            NodeKind::Compute
        } else {
            kinds[rng.between(0, kinds.len() as u64 - 1) as usize]
        };
        let millis = rng.between(1, 20);
        let mut spec = node(&format!("n{number}"), kind, millis);
        let mut segments = Vec::new();
        for (which, &(name, unit, capacity)) in RESOURCES.iter().enumerate() {
            if !rng.percent(55) {
                continue;
            }
            let high = (capacity * shape.max_transient_percent / 100).max(1);
            let quantity = rng.between(1, high);
            let from = rng.between(0, millis - 1);
            let until = rng.between(from + 1, millis);
            segments.push(
                DemandSegment::transient(resource(name), unit, quantity, ms(from), ms(until))
                    .unwrap(),
            );
            if shape.retained && rng.percent(30) && retained_left[which] > 0 {
                let held = rng.between(1, retained_left[which].min(capacity / 5));
                retained_left[which] -= held;
                segments
                    .push(DemandSegment::retained(resource(name), unit, held, ms(until)).unwrap());
            }
        }
        spec = spec.with_demand(DemandProfile::new(segments));
        builder = builder.node(spec);
        for earlier in 0..number {
            if rng.percent(30) {
                builder = builder.edge(&id(&format!("n{earlier}")), &id(&format!("n{number}")));
            }
        }
    }
    builder = builder
        .node(first_token("respond", rng.between(1, 5)))
        .edge(&id(&format!("n{compute}")), &id("respond"));
    for number in 0..inner {
        if number != compute && rng.percent(30) {
            builder = builder.edge(&id(&format!("n{number}")), &id("respond"));
        }
    }
    let mut capacities = Capacities::new();
    for (name, unit, capacity) in RESOURCES {
        capacities = capacities.with(resource(name), unit, capacity).unwrap();
    }
    (builder.build(Policy::new()).unwrap(), capacities)
}
