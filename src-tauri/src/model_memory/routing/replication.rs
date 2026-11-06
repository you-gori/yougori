//! GPU §4.7, topology-aware replication, not a mandatory chain (lines 722–730): "choose
//! a transfer tree or schedule from measured topology and donor load."
//!
//! Star, chain, binomial tree and multiple independent sources are each planned over the
//! measured topology, and [`choose_schedule`] picks the best feasible one; no shape is
//! assumed. Schedules run in rounds of concurrent chunk moves; a round lasts its
//! overhead, any transport setup and the GPU §2.2 lower bound of its moves over the
//! transport's measured resources ([`transfer_lower_bound`]), so links and cuts shared by
//! concurrent moves count once and advertised bandwidth is never used. Multiple
//! independent sources are planned per target by the GPU §2.5 planner
//! ([`MultiSourceLoad`]) and bounded across targets by the same lower bound.
//!
//! Startup overhead, reuse of an established communicator versus fresh communicator
//! setup versus direct handles, donor HBM pressure (staging buffers per concurrent
//! stream), donor serving impact and target readiness order are inputs.
//! [`replicate_with_failures`] recovers from failed nodes by bounded re-planning from the
//! surviving holders. FlashBoot-like arena paths, RDMA fabrics, paid hardware and host
//! driver changes are gated ([`GatedPath`]): they need a separately provisioned
//! compatible environment (line 730).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::foundation::ids::{validate_identifier, IdError, ResourceId};
use crate::foundation::transfer::Endpoint;
use crate::model_memory::math::bounds::{
    transfer_lower_bound, BandwidthRating, ResourceTable, TransferDemand,
};
use crate::model_memory::math::sources::{
    CutSpec, MultiSourceLoad, SourceAuthorization, SourceSpec, StealPolicy,
};
use crate::model_memory::math::{non_negative, CutId, InputError, SourceId};

use super::error::RoutingError;
use super::numbers::{approx_f64, count_u64};

/// A node of a replication topology: a donor holding the model, or a target.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(String);

impl NodeId {
    /// Follows the shared identifier grammar.
    pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
        let value = value.into();
        validate_identifier(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One node and its load (§4.7 "donor HBM pressure").
#[derive(Clone, Debug, PartialEq)]
pub struct ReplicationNode {
    pub id: NodeId,
    /// How the node is reached: a typed CORE-05 endpoint, never an address.
    pub endpoint: Endpoint,
    /// GPU memory free for staging buffers after the node's own serving.
    pub free_staging_bytes: u64,
    /// Delay each byte the node sends causes its own serving, in seconds of the declared
    /// objective.
    pub serving_impact_seconds_per_byte: f64,
}

/// The resources a stream from one node to another crosses, such as the sender's NIC
/// transmit side, a switch uplink and the receiver's NIC receive side.
#[derive(Clone, Debug, PartialEq)]
pub struct LinkSpec {
    pub from: NodeId,
    pub to: NodeId,
    pub resources: Vec<ResourceId>,
}

/// How chunks move (§4.7: "Use already-established NCCL communicators when they win;
/// compare direct handle/fabric transports when fresh communicator setup dominates").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TransportKind {
    /// A communicator that already spans the participants; it serves no other node.
    EstablishedCommunicator,
    /// A communicator set up for this replication.
    FreshCommunicator,
    /// Direct handles between pairs, set up when a link is first used.
    DirectHandle,
}

/// One transport, with its setup cost and its own measured bandwidth.
#[derive(Clone, Debug)]
pub struct Transport {
    pub kind: TransportKind,
    /// Communicators pay it once before the first round; direct handles pay it in each
    /// round that opens new links, which set up concurrently.
    pub setup_seconds: f64,
    /// Measured usable directional bandwidth of every link resource under this
    /// transport, each registered once.
    pub resources: ResourceTable,
    /// For an established communicator, the nodes it spans.
    pub spans: BTreeSet<NodeId>,
}

/// The measured topology.
#[derive(Clone, Debug)]
pub struct Topology {
    pub nodes: Vec<ReplicationNode>,
    pub links: Vec<LinkSpec>,
    pub transports: Vec<Transport>,
}

/// A target and its place in the readiness order: higher weights become ready first and
/// count more in [`ScheduleObjective::WeightedReadiness`] (§4.7 "target readiness
/// order").
#[derive(Clone, Debug, PartialEq)]
pub struct TargetSpec {
    pub node: NodeId,
    pub priority_weight: f64,
}

/// What a schedule minimizes, besides donor serving impact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScheduleObjective {
    /// When the last target is ready.
    Makespan,
    /// The priority-weighted sum of target ready times.
    WeightedReadiness,
}

/// One replication: an immutable object from holders to targets.
#[derive(Clone, Debug, PartialEq)]
pub struct ReplicationProblem {
    pub object_bytes: u64,
    /// Chunks pipeline through chains and stars; a binomial tree moves the whole object
    /// per step.
    pub chunk_bytes: u64,
    /// Synchronization and launch cost of every round.
    pub round_overhead_seconds: f64,
    /// Staging memory each concurrent outgoing stream needs on its sender.
    pub staging_bytes_per_stream: u64,
    /// Nodes that hold the complete object.
    pub sources: Vec<NodeId>,
    pub targets: Vec<TargetSpec>,
    pub objective: ScheduleObjective,
}

/// The schedule shapes of §4.7 line 726.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ScheduleShape {
    Star,
    Chain,
    BinomialTree,
    MultiSource,
}

/// Chunks moved from one node to another in one round.
#[derive(Clone, Debug, PartialEq)]
pub struct ChunkMove {
    pub from: NodeId,
    pub to: NodeId,
    pub chunks: u64,
    pub bytes: u64,
}

/// One round of concurrent moves.
#[derive(Clone, Debug, PartialEq)]
pub struct Round {
    pub moves: Vec<ChunkMove>,
    pub started_seconds: f64,
    pub ended_seconds: f64,
}

/// The bytes one pair exchanges over a whole schedule, between typed endpoints. A pair
/// with a peer end needs its own CORE-05 envelope per host.
#[derive(Clone, Debug, PartialEq)]
pub struct TransferLeg {
    pub from: Endpoint,
    pub to: Endpoint,
    pub bytes: u64,
    pub needs_peer_envelope: bool,
}

/// A planned schedule.
#[derive(Clone, Debug, PartialEq)]
pub struct Schedule {
    pub shape: ScheduleShape,
    /// The single source star, chain and tree start from.
    pub root: Option<NodeId>,
    pub transport: TransportKind,
    /// Empty for multiple sources, which the GPU §2.5 planner schedules.
    pub rounds: Vec<Round>,
    pub ready_seconds: BTreeMap<NodeId, f64>,
    pub makespan_seconds: f64,
    pub sent_bytes: BTreeMap<NodeId, u64>,
    /// Σ bytes sent × the sender's serving impact.
    pub donor_impact_seconds: f64,
    /// The declared objective plus donor impact.
    pub objective_seconds: f64,
    pub legs: Vec<TransferLeg>,
}

impl Schedule {
    /// Targets by ready time, earliest first.
    pub fn readiness_order(&self) -> Vec<NodeId> {
        let mut order: Vec<(&NodeId, f64)> = self
            .ready_seconds
            .iter()
            .map(|(node, ready)| (node, *ready))
            .collect();
        order.sort_by(|left, right| left.1.total_cmp(&right.1).then_with(|| left.0.cmp(right.0)));
        order.into_iter().map(|(node, _)| node.clone()).collect()
    }
}

/// Why one shape could not be planned.
#[derive(Clone, Debug, PartialEq)]
pub enum ScheduleRefusal {
    /// A sender would need more staging memory than its free HBM.
    DonorHbmPressure {
        node: NodeId,
        needed_bytes: u64,
        available_bytes: u64,
    },
    /// The topology has no link between two nodes the shape needs.
    NoLink {
        from: NodeId,
        to: NodeId,
    },
    /// The established communicator does not span this participant.
    CommunicatorDoesNotSpan {
        node: NodeId,
    },
    /// Multiple independent sources need at least two holders.
    NeedsSeveralSources,
    /// The path needs provisioned compatible hardware (line 730).
    Gated(GatedPath),
    Invalid(RoutingError),
}

impl From<RoutingError> for ScheduleRefusal {
    fn from(error: RoutingError) -> Self {
        Self::Invalid(error)
    }
}

impl From<InputError> for ScheduleRefusal {
    fn from(error: InputError) -> Self {
        Self::Invalid(error.into())
    }
}

/// Paths §4.7 keeps out of ordinary local development (lines 728–730).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GatedPath {
    /// A FlashBoot-like path over a large immutable arena on compatible hardware.
    FlashBootArena,
    /// RDMA or fabric transports (GPU-W09: only on provisioned compatible
    /// infrastructure).
    RdmaFabric,
    /// Allocating paid hardware.
    PaidHardware,
    /// Changing host drivers.
    HostDriverChange,
}

impl GatedPath {
    pub const ALL: [Self; 4] = [
        Self::FlashBootArena,
        Self::RdmaFabric,
        Self::PaidHardware,
        Self::HostDriverChange,
    ];

    /// Why the path is gated.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::FlashBootArena => {
                "rack-scale hardware-specific evidence, implementation availability is future work; \
                 needs a separately provisioned compatible test environment"
            }
            Self::RdmaFabric => "only on provisioned compatible test infrastructure (GPU-W09)",
            Self::PaidHardware => "never allocated as part of ordinary local development",
            Self::HostDriverChange => "host drivers are never changed as part of ordinary local development",
        }
    }
}

/// Every gated path is refused here; none is planned or simulated as if available.
pub fn plan_gated(path: GatedPath) -> Result<Schedule, ScheduleRefusal> {
    Err(ScheduleRefusal::Gated(path))
}

/// One evaluated candidate of [`choose_schedule`].
#[derive(Clone, Debug, PartialEq)]
pub struct EvaluatedSchedule {
    pub shape: ScheduleShape,
    pub root: Option<NodeId>,
    pub transport: TransportKind,
    pub outcome: Result<f64, ScheduleRefusal>,
}

/// The chosen schedule and every candidate considered.
#[derive(Clone, Debug, PartialEq)]
pub struct ScheduleChoice {
    pub chosen: Schedule,
    pub evaluated: Vec<EvaluatedSchedule>,
}

/// Why no schedule was chosen.
#[derive(Clone, Debug, PartialEq)]
pub enum ReplicationError {
    Invalid(RoutingError),
    /// Every candidate was refused.
    NoFeasibleSchedule {
        evaluated: Vec<EvaluatedSchedule>,
    },
}

impl From<RoutingError> for ReplicationError {
    fn from(error: RoutingError) -> Self {
        Self::Invalid(error)
    }
}

impl From<InputError> for ReplicationError {
    fn from(error: InputError) -> Self {
        Self::Invalid(error.into())
    }
}

struct Plan<'a> {
    topology: &'a Topology,
    problem: &'a ReplicationProblem,
    transport: &'a Transport,
    chunks: u64,
}

impl Topology {
    fn node(&self, id: &NodeId) -> Result<&ReplicationNode, InputError> {
        self.nodes
            .iter()
            .find(|node| &node.id == id)
            .ok_or_else(|| InputError::Unknown {
                field: "node",
                name: id.to_string(),
            })
    }

    fn link(&self, from: &NodeId, to: &NodeId) -> Result<&LinkSpec, ScheduleRefusal> {
        self.links
            .iter()
            .find(|link| &link.from == from && &link.to == to)
            .ok_or_else(|| ScheduleRefusal::NoLink {
                from: from.clone(),
                to: to.clone(),
            })
    }

    fn check(&self) -> Result<(), InputError> {
        for (index, node) in self.nodes.iter().enumerate() {
            if self
                .nodes
                .iter()
                .take(index)
                .any(|other| other.id == node.id)
            {
                return Err(InputError::Duplicate {
                    field: "nodes",
                    name: node.id.to_string(),
                });
            }
            non_negative(
                "serving_impact_seconds_per_byte",
                node.serving_impact_seconds_per_byte,
            )?;
        }
        for link in &self.links {
            self.node(&link.from)?;
            self.node(&link.to)?;
            if link.resources.is_empty() {
                return Err(InputError::Empty {
                    field: "LinkSpec.resources",
                });
            }
        }
        if self.transports.is_empty() {
            return Err(InputError::Empty {
                field: "transports",
            });
        }
        for transport in &self.transports {
            non_negative("Transport.setup_seconds", transport.setup_seconds)?;
        }
        Ok(())
    }
}

impl ReplicationProblem {
    fn check(&self, topology: &Topology) -> Result<u64, InputError> {
        if self.object_bytes == 0 {
            return Err(InputError::NotPositive {
                field: "object_bytes",
            });
        }
        if self.chunk_bytes == 0 {
            return Err(InputError::NotPositive {
                field: "chunk_bytes",
            });
        }
        non_negative("round_overhead_seconds", self.round_overhead_seconds)?;
        if self.sources.is_empty() {
            return Err(InputError::Empty { field: "sources" });
        }
        if self.targets.is_empty() {
            return Err(InputError::Empty { field: "targets" });
        }
        let mut seen = BTreeSet::new();
        for node in self
            .sources
            .iter()
            .chain(self.targets.iter().map(|target| &target.node))
        {
            topology.node(node)?;
            if !seen.insert(node) {
                return Err(InputError::Duplicate {
                    field: "sources and targets",
                    name: node.to_string(),
                });
            }
        }
        for target in &self.targets {
            non_negative("priority_weight", target.priority_weight)?;
        }
        Ok(self.object_bytes.div_ceil(self.chunk_bytes))
    }

    /// Targets in readiness order: higher weight first, then as listed.
    fn ordered_targets(&self) -> Vec<NodeId> {
        let mut order: Vec<(usize, &TargetSpec)> = self.targets.iter().enumerate().collect();
        order.sort_by(|left, right| {
            right
                .1
                .priority_weight
                .total_cmp(&left.1.priority_weight)
                .then_with(|| left.0.cmp(&right.0))
        });
        order
            .into_iter()
            .map(|(_, target)| target.node.clone())
            .collect()
    }
}

impl Plan<'_> {
    fn chunk_size(&self, index: u64) -> u64 {
        let start = index.saturating_mul(self.problem.chunk_bytes);
        self.problem
            .chunk_bytes
            .min(self.problem.object_bytes.saturating_sub(start))
    }

    fn check_participants(&self, participants: &[&NodeId]) -> Result<(), ScheduleRefusal> {
        if self.transport.kind == TransportKind::EstablishedCommunicator {
            if let Some(node) = participants
                .iter()
                .find(|node| !self.transport.spans.contains(**node))
            {
                return Err(ScheduleRefusal::CommunicatorDoesNotSpan {
                    node: (*node).clone(),
                });
            }
        }
        Ok(())
    }

    fn check_staging(&self, node: &NodeId, streams: u64) -> Result<(), ScheduleRefusal> {
        let available_bytes = self.topology.node(node)?.free_staging_bytes;
        let needed_bytes = streams.saturating_mul(self.problem.staging_bytes_per_stream);
        if needed_bytes > available_bytes {
            return Err(ScheduleRefusal::DonorHbmPressure {
                node: node.clone(),
                needed_bytes,
                available_bytes,
            });
        }
        Ok(())
    }

    /// Times rounds of moves: overhead, setup and the §2.2 bound of the moves over the
    /// transport's measured resources.
    fn time_rounds(&self, rounds: Vec<Vec<ChunkMove>>) -> Result<Vec<Round>, ScheduleRefusal> {
        let mut used: BTreeSet<(NodeId, NodeId)> = BTreeSet::new();
        let mut clock = match self.transport.kind {
            TransportKind::DirectHandle => 0.0,
            _ => self.transport.setup_seconds,
        };
        let mut timed = Vec::with_capacity(rounds.len());
        for moves in rounds {
            let mut senders: BTreeMap<&NodeId, u64> = BTreeMap::new();
            let mut demands = Vec::with_capacity(moves.len());
            let mut opens_link = false;
            for chunk_move in &moves {
                let streams = senders.entry(&chunk_move.from).or_default();
                *streams = streams.saturating_add(1);
                let link = self.topology.link(&chunk_move.from, &chunk_move.to)?;
                demands.push(TransferDemand {
                    bytes: chunk_move.bytes,
                    resources: link.resources.clone(),
                });
                opens_link |= !used.contains(&(chunk_move.from.clone(), chunk_move.to.clone()));
            }
            for (sender, streams) in senders {
                self.check_staging(sender, streams)?;
            }
            let bound = transfer_lower_bound(&self.transport.resources, &demands, 0.0)
                .map_err(RoutingError::from)?;
            let setup = if self.transport.kind == TransportKind::DirectHandle && opens_link {
                self.transport.setup_seconds
            } else {
                0.0
            };
            let started_seconds = clock;
            clock += self.problem.round_overhead_seconds + setup + bound.lower_bound_seconds;
            for chunk_move in &moves {
                used.insert((chunk_move.from.clone(), chunk_move.to.clone()));
            }
            timed.push(Round {
                moves,
                started_seconds,
                ended_seconds: clock,
            });
        }
        Ok(timed)
    }

    fn star(&self, root: &NodeId) -> Result<Vec<Vec<ChunkMove>>, ScheduleRefusal> {
        let targets = self.problem.ordered_targets();
        Ok((0..self.chunks)
            .map(|chunk| {
                targets
                    .iter()
                    .map(|target| ChunkMove {
                        from: root.clone(),
                        to: target.clone(),
                        chunks: 1,
                        bytes: self.chunk_size(chunk),
                    })
                    .collect()
            })
            .collect())
    }

    fn chain(&self, root: &NodeId) -> Result<Vec<Vec<ChunkMove>>, ScheduleRefusal> {
        let mut path = vec![root.clone()];
        path.extend(self.problem.ordered_targets());
        let links: Vec<(&NodeId, &NodeId)> = path
            .windows(2)
            .filter_map(|pair| match pair {
                [from, to] => Some((from, to)),
                _ => None,
            })
            .collect();
        let hops = count_u64(links.len());
        let mut rounds = Vec::new();
        for round in 0..self.chunks.saturating_add(hops).saturating_sub(1) {
            let mut moves = Vec::new();
            for (hop, (from, to)) in (0u64..).zip(&links) {
                if let Some(chunk) = round.checked_sub(hop).filter(|chunk| *chunk < self.chunks) {
                    moves.push(ChunkMove {
                        from: (*from).clone(),
                        to: (*to).clone(),
                        chunks: 1,
                        bytes: self.chunk_size(chunk),
                    });
                }
            }
            rounds.push(moves);
        }
        Ok(rounds)
    }

    fn binomial(&self, root: &NodeId) -> Result<Vec<Vec<ChunkMove>>, ScheduleRefusal> {
        let mut holders = vec![root.clone()];
        let mut pending = self.problem.ordered_targets().into_iter();
        let mut rounds = Vec::new();
        loop {
            let mut moves = Vec::new();
            for holder in &holders {
                match pending.next() {
                    Some(target) => moves.push(ChunkMove {
                        from: holder.clone(),
                        to: target,
                        chunks: self.chunks,
                        bytes: self.problem.object_bytes,
                    }),
                    None => break,
                }
            }
            if moves.is_empty() {
                break;
            }
            holders.extend(moves.iter().map(|chunk_move| chunk_move.to.clone()));
            rounds.push(moves);
        }
        Ok(rounds)
    }

    fn from_rounds(
        &self,
        shape: ScheduleShape,
        root: &NodeId,
        rounds: Vec<Vec<ChunkMove>>,
    ) -> Result<Schedule, ScheduleRefusal> {
        let mut participants: Vec<&NodeId> = vec![root];
        participants.extend(self.problem.targets.iter().map(|target| &target.node));
        self.check_participants(&participants)?;
        let rounds = self.time_rounds(rounds)?;
        let mut received: BTreeMap<NodeId, u64> = BTreeMap::new();
        let mut ready_seconds = BTreeMap::new();
        let mut sent_bytes: BTreeMap<NodeId, u64> = BTreeMap::new();
        let mut pairs: BTreeMap<(NodeId, NodeId), u64> = BTreeMap::new();
        for round in &rounds {
            for chunk_move in &round.moves {
                let count = received.entry(chunk_move.to.clone()).or_default();
                *count = count.saturating_add(chunk_move.chunks);
                if *count >= self.chunks {
                    ready_seconds
                        .entry(chunk_move.to.clone())
                        .or_insert(round.ended_seconds);
                }
                let sent = sent_bytes.entry(chunk_move.from.clone()).or_default();
                *sent = sent.saturating_add(chunk_move.bytes);
                let pair = pairs
                    .entry((chunk_move.from.clone(), chunk_move.to.clone()))
                    .or_default();
                *pair = pair.saturating_add(chunk_move.bytes);
            }
        }
        self.finish(
            shape,
            Some(root.clone()),
            rounds,
            ready_seconds,
            sent_bytes,
            pairs,
        )
    }

    fn finish(
        &self,
        shape: ScheduleShape,
        root: Option<NodeId>,
        rounds: Vec<Round>,
        ready_seconds: BTreeMap<NodeId, f64>,
        sent_bytes: BTreeMap<NodeId, u64>,
        pairs: BTreeMap<(NodeId, NodeId), u64>,
    ) -> Result<Schedule, ScheduleRefusal> {
        let makespan_seconds = ready_seconds.values().copied().fold(0.0, f64::max);
        let mut donor_impact_seconds = 0.0;
        for (node, bytes) in &sent_bytes {
            donor_impact_seconds +=
                approx_f64(*bytes) * self.topology.node(node)?.serving_impact_seconds_per_byte;
        }
        let declared = match self.problem.objective {
            ScheduleObjective::Makespan => makespan_seconds,
            ScheduleObjective::WeightedReadiness => self
                .problem
                .targets
                .iter()
                .map(|target| {
                    target.priority_weight
                        * ready_seconds
                            .get(&target.node)
                            .copied()
                            .unwrap_or(f64::INFINITY)
                })
                .sum(),
        };
        let mut legs = Vec::with_capacity(pairs.len());
        for ((from, to), bytes) in pairs {
            let from = self.topology.node(&from)?.endpoint.clone();
            let to = self.topology.node(&to)?.endpoint.clone();
            legs.push(TransferLeg {
                needs_peer_envelope: !from.is_local() || !to.is_local(),
                from,
                to,
                bytes,
            });
        }
        Ok(Schedule {
            shape,
            root,
            transport: self.transport.kind,
            rounds,
            ready_seconds,
            makespan_seconds,
            sent_bytes,
            donor_impact_seconds,
            objective_seconds: declared + donor_impact_seconds,
            legs,
        })
    }

    /// Multiple independent sources: each target plans its chunks over every source with
    /// the GPU §2.5 planner (startup, per-source caps and the target's shared cuts), and
    /// the union of all targets' bytes is bounded by §2.2 so cuts shared across targets
    /// count once.
    fn multi_source(&self) -> Result<Schedule, ScheduleRefusal> {
        let sources = &self.problem.sources;
        if sources.len() < 2 {
            return Err(ScheduleRefusal::NeedsSeveralSources);
        }
        let mut participants: Vec<&NodeId> = sources.iter().collect();
        participants.extend(self.problem.targets.iter().map(|target| &target.node));
        self.check_participants(&participants)?;
        let targets = self.problem.ordered_targets();
        for source in sources {
            self.check_staging(source, count_u64(targets.len()))?;
        }
        let batches: Vec<u64> = (0..self.chunks)
            .map(|chunk| self.chunk_size(chunk))
            .collect();
        let no_stealing = StealPolicy {
            min_gain_seconds: 0.0,
            min_gain_fraction: 0.0,
            max_moves_per_batch: 0,
            max_moves_per_rebalance: 0,
        };
        let setup = self.transport.setup_seconds;
        let mut ready_seconds = BTreeMap::new();
        let mut sent_bytes: BTreeMap<NodeId, u64> = BTreeMap::new();
        let mut pairs: BTreeMap<(NodeId, NodeId), u64> = BTreeMap::new();
        let mut union = Vec::new();
        for (position, target) in targets.iter().enumerate() {
            // Each target lists the sources from a different first one, so the planner's
            // tie-breaking spreads leftover chunks across donors instead of piling them on
            // the first.
            let mut order: Vec<&NodeId> = sources.iter().collect();
            order.rotate_left(position.checked_rem(sources.len()).unwrap_or(0));
            let mut cuts: Vec<CutSpec> = Vec::new();
            let mut specs = Vec::with_capacity(sources.len());
            for source in order {
                let link = self.topology.link(source, target)?;
                let mut slowest = f64::INFINITY;
                let mut source_cuts = Vec::with_capacity(link.resources.len());
                for resource in &link.resources {
                    let bytes_per_second = self
                        .transport
                        .resources
                        .bandwidth_bytes_per_second(resource)
                        .ok_or_else(|| InputError::Unknown {
                            field: "LinkSpec.resources",
                            name: resource.to_string(),
                        })?;
                    slowest = slowest.min(bytes_per_second);
                    let cut = CutId::new(resource.as_str())?;
                    if !cuts.iter().any(|known| known.id == cut) {
                        cuts.push(CutSpec {
                            id: cut.clone(),
                            bandwidth: BandwidthRating::measured_directional(bytes_per_second)?,
                        });
                    }
                    source_cuts.push(cut);
                }
                let node = self.topology.node(source)?;
                let streams = node
                    .free_staging_bytes
                    .checked_div(self.problem.staging_bytes_per_stream.max(1))
                    .and_then(|streams| streams.checked_div(count_u64(targets.len()).max(1)))
                    .unwrap_or(0);
                specs.push(SourceSpec {
                    id: SourceId::new(source.as_str())?,
                    authorization: SourceAuthorization::Authorized,
                    startup_seconds: setup,
                    bandwidth: BandwidthRating::measured_directional(slowest)?,
                    cuts: source_cuts,
                    max_in_flight: u32::try_from(streams.max(1)).unwrap_or(u32::MAX),
                    interference_seconds_per_byte: node.serving_impact_seconds_per_byte,
                });
            }
            let load = MultiSourceLoad::plan(specs, cuts, &batches, no_stealing)
                .map_err(RoutingError::from)?;
            let mut longest_queue = 0usize;
            for source in sources {
                let id = SourceId::new(source.as_str())?;
                let assigned = load.batches_of(&id);
                longest_queue = longest_queue.max(assigned.len());
                let bytes = assigned
                    .iter()
                    .filter_map(|batch| batches.get(*batch))
                    .fold(0u64, |total, bytes| total.saturating_add(*bytes));
                if bytes > 0 {
                    let sent = sent_bytes.entry(source.clone()).or_default();
                    *sent = sent.saturating_add(bytes);
                    let pair = pairs.entry((source.clone(), target.clone())).or_default();
                    *pair = pair.saturating_add(bytes);
                    union.push(TransferDemand {
                        bytes,
                        resources: self.topology.link(source, target)?.resources.clone(),
                    });
                }
            }
            ready_seconds.insert(
                target.clone(),
                load.predicted_completion_seconds()
                    + self.problem.round_overhead_seconds * approx_f64(count_u64(longest_queue)),
            );
        }
        let bound = transfer_lower_bound(&self.transport.resources, &union, 0.0)
            .map_err(RoutingError::from)?;
        let shared_floor = setup + bound.lower_bound_seconds;
        let latest = ready_seconds.values().copied().fold(0.0, f64::max);
        if shared_floor > latest {
            // A cut shared across targets binds: every target waits for it.
            for ready in ready_seconds.values_mut() {
                *ready = shared_floor;
            }
        }
        self.finish(
            ScheduleShape::MultiSource,
            None,
            Vec::new(),
            ready_seconds,
            sent_bytes,
            pairs,
        )
    }
}

/// Plans one shape from `root` (ignored for multiple sources) over transport
/// `transport_index`.
pub fn plan_schedule(
    topology: &Topology,
    problem: &ReplicationProblem,
    shape: ScheduleShape,
    root: Option<&NodeId>,
    transport_index: usize,
) -> Result<Schedule, ScheduleRefusal> {
    topology.check()?;
    let chunks = problem.check(topology)?;
    let transport = topology
        .transports
        .get(transport_index)
        .ok_or(InputError::OutOfRange {
            field: "transport_index",
        })?;
    let plan = Plan {
        topology,
        problem,
        transport,
        chunks,
    };
    if shape == ScheduleShape::MultiSource {
        return plan.multi_source();
    }
    let root = root.ok_or(InputError::Empty { field: "root" })?;
    if !problem.sources.contains(root) {
        return Err(InputError::Unknown {
            field: "root",
            name: root.to_string(),
        }
        .into());
    }
    let rounds = match shape {
        ScheduleShape::Star => plan.star(root)?,
        ScheduleShape::Chain => plan.chain(root)?,
        _ => plan.binomial(root)?,
    };
    plan.from_rounds(shape, root, rounds)
}

/// Evaluates every shape, root and transport over the measured topology and returns the
/// lowest objective (§4.7: "choose a transfer tree or schedule from measured topology
/// and donor load"). Ties go to the earlier shape, root and transport.
pub fn choose_schedule(
    topology: &Topology,
    problem: &ReplicationProblem,
) -> Result<ScheduleChoice, ReplicationError> {
    topology.check()?;
    problem.check(topology)?;
    let mut evaluated = Vec::new();
    let mut best: Option<Schedule> = None;
    for (transport_index, transport) in topology.transports.iter().enumerate() {
        let mut candidates: Vec<(ScheduleShape, Option<&NodeId>)> = Vec::new();
        for shape in [
            ScheduleShape::Star,
            ScheduleShape::Chain,
            ScheduleShape::BinomialTree,
        ] {
            for root in &problem.sources {
                candidates.push((shape, Some(root)));
            }
        }
        candidates.push((ScheduleShape::MultiSource, None));
        for (shape, root) in candidates {
            let outcome = plan_schedule(topology, problem, shape, root, transport_index);
            evaluated.push(EvaluatedSchedule {
                shape,
                root: root.cloned(),
                transport: transport.kind,
                outcome: outcome
                    .as_ref()
                    .map(|schedule| schedule.objective_seconds)
                    .map_err(Clone::clone),
            });
            if let Ok(schedule) = outcome {
                if best
                    .as_ref()
                    .is_none_or(|current| schedule.objective_seconds < current.objective_seconds)
                {
                    best = Some(schedule);
                }
            }
        }
    }
    match best {
        Some(chosen) => Ok(ScheduleChoice { chosen, evaluated }),
        None => Err(ReplicationError::NoFeasibleSchedule { evaluated }),
    }
}

/// A node that fails at a time on the replication clock.
#[derive(Clone, Debug, PartialEq)]
pub struct NodeFailure {
    pub node: NodeId,
    pub at_seconds: f64,
}

/// How failures are recovered: detected after `detection_seconds`, then re-planned at
/// most `max_replans` times in total (GPU-W09 "bounded recovery").
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RecoveryPolicy {
    pub detection_seconds: f64,
    pub max_replans: u32,
}

/// The replication after recovery.
#[derive(Clone, Debug, PartialEq)]
pub struct RecoveryOutcome {
    /// Every surviving target's ready time.
    pub ready_seconds: BTreeMap<NodeId, f64>,
    pub failed: BTreeSet<NodeId>,
    pub replans: u32,
    /// Each schedule with the time it started.
    pub schedules: Vec<(f64, Schedule)>,
}

/// Why recovery could not finish.
#[derive(Clone, Debug, PartialEq)]
pub enum RecoveryRefusal {
    /// More failures needed re-planning than the bound allows.
    RecoveryExhausted {
        max_replans: u32,
    },
    /// No complete copy survives.
    NoSurvivingSource,
    Replication(ReplicationError),
}

impl From<ReplicationError> for RecoveryRefusal {
    fn from(error: ReplicationError) -> Self {
        Self::Replication(error)
    }
}

impl From<InputError> for RecoveryRefusal {
    fn from(error: InputError) -> Self {
        Self::Replication(error.into())
    }
}

/// Replicates with `failures`. Chunks delivered by rounds that ended before a failure are
/// kept; after detection the unfinished surviving targets are re-planned from every
/// surviving complete holder for the most chunks any of them still lacks (conservative
/// for the others). Re-planning is bounded by `policy.max_replans`.
pub fn replicate_with_failures(
    topology: &Topology,
    problem: &ReplicationProblem,
    failures: &[NodeFailure],
    policy: RecoveryPolicy,
) -> Result<RecoveryOutcome, RecoveryRefusal> {
    non_negative("detection_seconds", policy.detection_seconds)?;
    let chunks = problem.check(topology)?;
    let mut failures: Vec<&NodeFailure> = failures.iter().collect();
    for failure in &failures {
        non_negative("NodeFailure.at_seconds", failure.at_seconds)?;
    }
    failures.sort_by(|left, right| left.at_seconds.total_cmp(&right.at_seconds));

    let mut received: BTreeMap<NodeId, u64> = problem
        .targets
        .iter()
        .map(|target| (target.node.clone(), 0))
        .collect();
    let mut ready: BTreeMap<NodeId, f64> = BTreeMap::new();
    let mut failed: BTreeSet<NodeId> = BTreeSet::new();
    let mut replans = 0u32;
    let mut start = 0.0;
    let mut current = choose_schedule(topology, problem)?.chosen;
    let mut current_missing = chunks;
    let mut schedules = Vec::new();

    for failure in failures {
        let involved = current.ready_seconds.contains_key(&failure.node)
            || current.sent_bytes.contains_key(&failure.node);
        if !involved || failed.contains(&failure.node) {
            continue;
        }
        credit(
            &current,
            start,
            failure.at_seconds,
            current_missing,
            chunks,
            &mut received,
            &mut ready,
        );
        schedules.push((start, current.clone()));
        failed.insert(failure.node.clone());
        received.remove(&failure.node);
        ready.remove(&failure.node);
        replans = replans.saturating_add(1);
        if replans > policy.max_replans {
            return Err(RecoveryRefusal::RecoveryExhausted {
                max_replans: policy.max_replans,
            });
        }
        let remaining: Vec<TargetSpec> = problem
            .targets
            .iter()
            .filter(|target| {
                received
                    .get(&target.node)
                    .is_some_and(|count| *count < chunks)
            })
            .cloned()
            .collect();
        if remaining.is_empty() {
            return Ok(RecoveryOutcome {
                ready_seconds: ready,
                failed,
                replans,
                schedules,
            });
        }
        let mut sources: Vec<NodeId> = problem
            .sources
            .iter()
            .filter(|source| !failed.contains(*source))
            .cloned()
            .collect();
        sources.extend(
            received
                .iter()
                .filter(|(_, count)| **count >= chunks)
                .map(|(node, _)| node.clone()),
        );
        if sources.is_empty() {
            return Err(RecoveryRefusal::NoSurvivingSource);
        }
        let missing = remaining
            .iter()
            .filter_map(|target| received.get(&target.node))
            .map(|count| chunks.saturating_sub(*count))
            .max()
            .unwrap_or(chunks);
        let replanned = ReplicationProblem {
            object_bytes: missing.saturating_mul(problem.chunk_bytes),
            sources,
            targets: remaining,
            ..problem.clone()
        };
        start = failure.at_seconds + policy.detection_seconds;
        current = choose_schedule(topology, &replanned)?.chosen;
        current_missing = missing;
    }
    for (target, ready_at) in &current.ready_seconds {
        ready.entry(target.clone()).or_insert(start + ready_at);
        if let Some(count) = received.get_mut(target) {
            *count = chunks;
        }
    }
    schedules.push((start, current));
    Ok(RecoveryOutcome {
        ready_seconds: ready,
        failed,
        replans,
        schedules,
    })
}

/// Credits the chunks a schedule started at `start` delivered by `until`: whole rounds
/// that ended by then, or a whole multi-source plan for targets ready by then.
fn credit(
    schedule: &Schedule,
    start: f64,
    until: f64,
    schedule_chunks: u64,
    chunks: u64,
    received: &mut BTreeMap<NodeId, u64>,
    ready: &mut BTreeMap<NodeId, f64>,
) {
    let mut delivered: BTreeMap<&NodeId, u64> = BTreeMap::new();
    if schedule.rounds.is_empty() {
        for (target, ready_at) in &schedule.ready_seconds {
            if start + ready_at <= until {
                delivered.insert(target, schedule_chunks);
            }
        }
    } else {
        for round in &schedule.rounds {
            if start + round.ended_seconds > until {
                break;
            }
            for chunk_move in &round.moves {
                let count = delivered.entry(&chunk_move.to).or_default();
                *count = count.saturating_add(chunk_move.chunks);
            }
        }
    }
    for (target, count) in delivered {
        if let Some(total) = received.get_mut(target) {
            let before = *total;
            *total = total.saturating_add(count.min(schedule_chunks)).min(chunks);
            if before < chunks && *total >= chunks {
                if let Some(ready_at) = schedule.ready_seconds.get(target) {
                    ready.insert(target.clone(), start + ready_at);
                }
            }
        }
    }
}
