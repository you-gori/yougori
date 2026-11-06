//! Typed refusals of the request graph, its schedules and the granularity map.

use std::fmt;
use std::time::Duration;

use crate::foundation::ids::Digest;

use super::node::{CompletionEvent, NodeKind, ResourceUnit};
use super::{NodeId, ResourceId, TrustScope};

/// Why a node or a request graph was refused (GPU §2.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GraphError {
    /// A name is empty, too long or contains control characters.
    InvalidName { field: &'static str, value: String },
    /// A duration estimate is not `low <= expected <= high` with `expected > 0`.
    InvalidDuration { reason: &'static str },
    /// A demand segment is empty or demands nothing.
    InvalidDemand { reason: &'static str },
    /// A demand segment starts or ends after the node's expected duration.
    DemandOutsideDuration { node: NodeId },
    /// The graph has no nodes.
    Empty,
    /// Two nodes have the same name.
    DuplicateNodeId { node: NodeId },
    /// Two nodes require the same state: same kind, identity and trust scope.
    DuplicateState { first: NodeId, second: NodeId },
    /// An edge is listed twice.
    DuplicateEdge { from: NodeId, to: NodeId },
    /// An edge names a node that was never added.
    UnknownNode { node: NodeId },
    /// The edges close a cycle through these nodes, in order.
    Cycle { nodes: Vec<NodeId> },
    /// The completion event does not establish usability for this kind of node.
    CompletionEventMismatch {
        node: NodeId,
        kind: NodeKind,
        event: CompletionEvent,
    },
    /// A node consumes state from another trust scope without an explicit allowance.
    CrossScopeConsumption {
        producer: NodeId,
        consumer: NodeId,
        producer_scope: TrustScope,
        consumer_scope: TrustScope,
    },
    /// A node can run longer without a cancellation point than the policy allows.
    NonPreemptibleTooLong {
        node: NodeId,
        non_preemptible: Duration,
        limit: Duration,
    },
    /// No node delivers the first token.
    NoObjective,
    /// More than one node claims to deliver the first token.
    AmbiguousObjective { first: NodeId, second: NodeId },
    /// The first token does not depend on any compute: ready weights do not eliminate
    /// prompt computation (GPU §1.1).
    ObjectiveWithoutCompute { objective: NodeId },
}

impl fmt::Display for GraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName { field, value } => {
                write!(
                    f,
                    "{field} {value:?} must be 1–128 characters without control characters"
                )
            }
            Self::InvalidDuration { reason } => write!(f, "invalid duration estimate: {reason}"),
            Self::InvalidDemand { reason } => write!(f, "invalid demand segment: {reason}"),
            Self::DemandOutsideDuration { node } => {
                write!(
                    f,
                    "node {node} demands resources outside its expected duration"
                )
            }
            Self::Empty => f.write_str("the request graph has no nodes"),
            Self::DuplicateNodeId { node } => write!(f, "node {node} is listed twice"),
            Self::DuplicateState { first, second } => {
                write!(f, "nodes {first} and {second} require the same state")
            }
            Self::DuplicateEdge { from, to } => write!(f, "edge {from} -> {to} is listed twice"),
            Self::UnknownNode { node } => write!(f, "an edge names unknown node {node}"),
            Self::Cycle { nodes } => {
                let names: Vec<&str> = nodes.iter().map(NodeId::as_str).collect();
                write!(f, "the edges form a cycle: {}", names.join(" -> "))
            }
            Self::CompletionEventMismatch { node, kind, event } => write!(
                f,
                "node {node}: {event:?} does not establish usability of a {kind:?} node"
            ),
            Self::CrossScopeConsumption {
                producer,
                consumer,
                producer_scope,
                consumer_scope,
            } => write!(
                f,
                "node {consumer} in trust scope {} consumes {producer} from trust scope {} \
                 without an explicit allowance",
                scope_text(consumer_scope),
                scope_text(producer_scope)
            ),
            Self::NonPreemptibleTooLong {
                node,
                non_preemptible,
                limit,
            } => write!(
                f,
                "node {node} can run {non_preemptible:?} without a cancellation point; the \
                 policy allows {limit:?}"
            ),
            Self::NoObjective => f.write_str("no node delivers the first token"),
            Self::AmbiguousObjective { first, second } => {
                write!(
                    f,
                    "nodes {first} and {second} both claim to deliver the first token"
                )
            }
            Self::ObjectiveWithoutCompute { objective } => {
                write!(
                    f,
                    "first-token node {objective} does not depend on any compute"
                )
            }
        }
    }
}

impl std::error::Error for GraphError {}

/// A trust scope as text: its execution category's label and its domain digest.
fn scope_text(scope: &TrustScope) -> String {
    format!("{} {}", scope.category.label(), scope.domain)
}

/// Why a schedule could not be evaluated or found (GPU §2.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScheduleError {
    /// A conflict edge names a node that is not in the graph.
    UnknownNode { node: NodeId },
    /// A resource is declared twice.
    DuplicateResource { resource: ResourceId },
    /// A resource is declared with zero capacity.
    ZeroCapacity { resource: ResourceId },
    /// A node demands a resource with no declared capacity.
    UnknownResource { node: NodeId, resource: ResourceId },
    /// A node demands a resource in a different unit from its capacity.
    UnitMismatch {
        node: NodeId,
        resource: ResourceId,
        declared: ResourceUnit,
        demanded: ResourceUnit,
    },
    /// One node alone demands more than the capacity.
    NodeExceedsCapacity {
        node: NodeId,
        resource: ResourceId,
        demand: u64,
        capacity: u64,
    },
    /// The demand held until the request ends exceeds the capacity in every order.
    RetainedDemandExceedsCapacity {
        resource: ResourceId,
        demand: u64,
        capacity: u64,
    },
    /// The schedule exceeds a capacity at this offset.
    CapacityExceeded {
        resource: ResourceId,
        at: Duration,
        demand: u64,
        capacity: u64,
    },
    /// A conflict ordering edge joins nodes that share no capacity-limited resource.
    NotAConflict { from: NodeId, to: NodeId },
    /// Conflict ordering edges close a cycle with the dependencies.
    ConflictEdgeCycle { nodes: Vec<NodeId> },
    /// Neither of the heuristic's priority rules found a feasible start; the node is
    /// where the memory-pressure retry stopped.
    NoFeasiblePlacement { node: NodeId },
    /// No schedule satisfies the capacities.
    NoFeasibleSchedule,
    /// The search used up its explicit work bound.
    WorkBoundExceeded { bound: u64 },
    /// The oracle accepts only tiny graphs.
    TooLargeForOracle { nodes: usize, max: usize },
    /// A time does not fit in 64-bit nanoseconds.
    TimeOverflow,
    /// A demand total does not fit in 64 bits.
    QuantityOverflow { resource: ResourceId },
    /// Ready state claims to satisfy work that belongs to this one request.
    ReadyStateForRequestWork { node: NodeId, kind: NodeKind },
    /// The node that delivers the first token is not among the scheduled nodes.
    ObjectiveNotScheduled,
}

impl fmt::Display for ScheduleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownNode { node } => write!(f, "a conflict edge names unknown node {node}"),
            Self::DuplicateResource { resource } => {
                write!(f, "resource {resource} is declared twice")
            }
            Self::ZeroCapacity { resource } => write!(f, "resource {resource} has zero capacity"),
            Self::UnknownResource { node, resource } => {
                write!(f, "node {node} demands undeclared resource {resource}")
            }
            Self::UnitMismatch {
                node,
                resource,
                declared,
                demanded,
            } => write!(
                f,
                "node {node} demands {resource} in {demanded:?}; its capacity is in {declared:?}"
            ),
            Self::NodeExceedsCapacity {
                node,
                resource,
                demand,
                capacity,
            } => write!(
                f,
                "node {node} alone demands {demand} of {resource}; capacity {capacity}"
            ),
            Self::RetainedDemandExceedsCapacity {
                resource,
                demand,
                capacity,
            } => write!(
                f,
                "{demand} of {resource} is held until the request ends; capacity {capacity}"
            ),
            Self::CapacityExceeded {
                resource,
                at,
                demand,
                capacity,
            } => write!(
                f,
                "{resource} reaches {demand} at {at:?}; capacity {capacity}"
            ),
            Self::NotAConflict { from, to } => {
                write!(f, "{from} and {to} share no capacity-limited resource")
            }
            Self::ConflictEdgeCycle { nodes } => {
                let names: Vec<&str> = nodes.iter().map(NodeId::as_str).collect();
                write!(f, "conflict edges form a cycle: {}", names.join(" -> "))
            }
            Self::NoFeasiblePlacement { node } => write!(f, "no feasible start for node {node}"),
            Self::NoFeasibleSchedule => f.write_str("no schedule satisfies the capacities"),
            Self::WorkBoundExceeded { bound } => {
                write!(f, "the search exceeded its bound of {bound} work units")
            }
            Self::TooLargeForOracle { nodes, max } => {
                write!(f, "{nodes} nodes; the oracle accepts at most {max}")
            }
            Self::TimeOverflow => f.write_str("a time does not fit in 64-bit nanoseconds"),
            Self::QuantityOverflow { resource } => {
                write!(f, "the demand on {resource} does not fit in 64 bits")
            }
            Self::ReadyStateForRequestWork { node, kind } => write!(
                f,
                "ready state claims to satisfy {kind:?} node {node}, which only this request can do"
            ),
            Self::ObjectiveNotScheduled => {
                f.write_str("the first-token node is not among the scheduled nodes")
            }
        }
    }
}

impl std::error::Error for ScheduleError {}

/// Why a granularity, map or padded buffer was refused (GPU §2.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GranularityError {
    /// A granularity or unit is zero.
    Zero { field: &'static str },
    /// The artifact has no bytes.
    EmptyArtifact,
    /// The codec reported a different number of blocks from ceil(decoded / g_c).
    CodecBlockCount { expected: u64, actual: usize },
    /// A codec block encodes to zero bytes.
    EmptyEncodedBlock { block: usize },
    /// A buffer has a different length from the one the map records.
    LengthMismatch {
        field: &'static str,
        expected: u64,
        actual: u64,
    },
    /// g_v was reported for other allocation properties than the ones being mapped.
    MappingUnitForOtherProperties { reported: Digest, requested: Digest },
    /// A size does not fit in 64 bits.
    Overflow { field: &'static str },
    /// An offset lies at or past the end.
    OffsetOutOfRange { offset: u64, length: u64 },
    /// An index names no unit.
    IndexOutOfRange {
        field: &'static str,
        index: usize,
        count: usize,
    },
    /// A gather received a different number of pieces from the map.
    PieceCount {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    /// A gathered piece has the wrong length.
    PieceLength {
        field: &'static str,
        index: usize,
        expected: u64,
        actual: u64,
    },
    /// Gathered bytes do not match this extent's integrity identity.
    ExtentMismatch { extent: usize },
    /// Padding breaks the canonical rule.
    NonCanonicalPadding { reason: &'static str },
}

impl fmt::Display for GranularityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero { field } => write!(f, "{field} must be more than zero"),
            Self::EmptyArtifact => f.write_str("the artifact has no bytes"),
            Self::CodecBlockCount { expected, actual } => {
                write!(f, "the codec reported {actual} blocks; expected {expected}")
            }
            Self::EmptyEncodedBlock { block } => write!(f, "codec block {block} encodes to zero bytes"),
            Self::LengthMismatch {
                field,
                expected,
                actual,
            } => write!(f, "the {field} has {actual} bytes; expected {expected}"),
            Self::MappingUnitForOtherProperties {
                reported,
                requested,
            } => write!(
                f,
                "the mapping unit was reported for allocation properties {reported}, not {requested}"
            ),
            Self::Overflow { field } => write!(f, "{field} does not fit in 64 bits"),
            Self::OffsetOutOfRange { offset, length } => {
                write!(f, "offset {offset} is outside a length of {length}")
            }
            Self::IndexOutOfRange { field, index, count } => {
                write!(f, "{field} {index} does not exist; there are {count}")
            }
            Self::PieceCount {
                field,
                expected,
                actual,
            } => write!(f, "{actual} {field} pieces; expected {expected}"),
            Self::PieceLength {
                field,
                index,
                expected,
                actual,
            } => write!(f, "{field} {index} has {actual} bytes; expected {expected}"),
            Self::ExtentMismatch { extent } => {
                write!(f, "extent {extent} does not match its integrity identity")
            }
            Self::NonCanonicalPadding { reason } => write!(f, "non-canonical padding: {reason}"),
        }
    }
}

impl std::error::Error for GranularityError {}
