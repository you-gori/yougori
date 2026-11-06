//! The request DAG G=(V,E) of required state (GPU §2.3): duplicate nodes, unknown
//! references and cycles are refused, no node consumes state from another trust scope
//! without an explicit allowance, and exactly one node delivers the first correct token.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use crate::foundation::ids::Digest;

use super::node::{CompletionEvent, NodeKind, NodeSpec};
use super::{GraphError, NodeId, TrustScope};

/// The policy a request graph is built under (GPU §2.3: "subject to capacity and
/// policy").
///
/// Cross-scope consumption is refused unless an allowance names the producer scope, the
/// consumer scope and the exact identity of the state; equal names or sizes never stand
/// in for that (§3.2).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    allowances: BTreeSet<(TrustScope, TrustScope, Digest)>,
    max_non_preemptible: Option<Duration>,
}

impl Policy {
    /// No cross-scope allowances and no limit on non-preemptible stretches.
    pub fn new() -> Self {
        Self::default()
    }

    /// Lets nodes in `consumer` consume the state with `identity` produced in `producer`.
    pub fn allow(mut self, producer: TrustScope, consumer: TrustScope, identity: Digest) -> Self {
        self.allowances.insert((producer, consumer, identity));
        self
    }

    /// Refuses nodes that can run longer than `limit` without a cancellation point,
    /// judged at their high duration.
    pub fn with_max_non_preemptible(mut self, limit: Duration) -> Self {
        self.max_non_preemptible = Some(limit);
        self
    }

    /// Whether state with `identity` from `producer` may be consumed in `consumer`.
    pub fn allows(&self, producer: &TrustScope, consumer: &TrustScope, identity: &Digest) -> bool {
        producer == consumer || self.allowances.contains(&(*producer, *consumer, *identity))
    }

    /// The longest stretch without a cancellation point the policy allows, if limited.
    pub fn max_non_preemptible(&self) -> Option<Duration> {
        self.max_non_preemptible
    }
}

/// Collects nodes and edges; [`GraphBuilder::build`] validates them together.
#[derive(Clone, Debug, Default)]
pub struct GraphBuilder {
    nodes: Vec<NodeSpec>,
    edges: Vec<(NodeId, NodeId)>,
}

impl GraphBuilder {
    /// An empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a node; duplicates are refused when the graph is built.
    pub fn node(mut self, spec: NodeSpec) -> Self {
        self.nodes.push(spec);
        self
    }

    /// `consumer` requires the state that `producer` establishes.
    pub fn edge(mut self, producer: &NodeId, consumer: &NodeId) -> Self {
        self.edges.push((producer.clone(), consumer.clone()));
        self
    }

    /// Validates the graph under `policy` (GPU §2.3).
    pub fn build(self, policy: Policy) -> Result<RequestGraph, GraphError> {
        let nodes = self.nodes;
        if nodes.is_empty() {
            return Err(GraphError::Empty);
        }
        let mut index = BTreeMap::new();
        let mut states: BTreeMap<(NodeKind, Digest, TrustScope), usize> = BTreeMap::new();
        for (position, spec) in nodes.iter().enumerate() {
            if index.insert(spec.id().clone(), position).is_some() {
                return Err(GraphError::DuplicateNodeId {
                    node: spec.id().clone(),
                });
            }
            let state = (spec.kind(), *spec.identity(), *spec.trust_scope());
            if let Some(first) = states.insert(state, position) {
                return Err(GraphError::DuplicateState {
                    first: nodes[first].id().clone(),
                    second: spec.id().clone(),
                });
            }
            check_node(spec, &policy)?;
        }

        let mut seen = BTreeSet::new();
        let mut edges = Vec::with_capacity(self.edges.len());
        for (producer, consumer) in &self.edges {
            let from = lookup(&index, producer)?;
            let to = lookup(&index, consumer)?;
            if from == to {
                return Err(GraphError::Cycle {
                    nodes: vec![producer.clone()],
                });
            }
            if !seen.insert((from, to)) {
                return Err(GraphError::DuplicateEdge {
                    from: producer.clone(),
                    to: consumer.clone(),
                });
            }
            edges.push((from, to));
        }

        let mut predecessors = vec![Vec::new(); nodes.len()];
        let mut successors = vec![Vec::new(); nodes.len()];
        for &(from, to) in &edges {
            predecessors[to].push(from);
            successors[from].push(to);
        }
        for list in predecessors.iter_mut().chain(successors.iter_mut()) {
            list.sort_unstable();
        }
        let order =
            topological_order(&predecessors, &successors).map_err(|cycle| GraphError::Cycle {
                nodes: cycle.iter().map(|&at| nodes[at].id().clone()).collect(),
            })?;

        for &(from, to) in &edges {
            let (producer, consumer) = (&nodes[from], &nodes[to]);
            if !policy.allows(
                producer.trust_scope(),
                consumer.trust_scope(),
                producer.identity(),
            ) {
                return Err(GraphError::CrossScopeConsumption {
                    producer: producer.id().clone(),
                    consumer: consumer.id().clone(),
                    producer_scope: *producer.trust_scope(),
                    consumer_scope: *consumer.trust_scope(),
                });
            }
        }

        let objective = find_objective(&nodes)?;
        let on_path = ancestors_of(objective, &predecessors);
        let computes =
            (0..nodes.len()).any(|at| on_path[at] && nodes[at].kind() == NodeKind::Compute);
        if !computes {
            return Err(GraphError::ObjectiveWithoutCompute {
                objective: nodes[objective].id().clone(),
            });
        }

        Ok(RequestGraph {
            nodes,
            index,
            predecessors,
            successors,
            order,
            objective,
            on_path,
            policy,
        })
    }
}

fn lookup(index: &BTreeMap<NodeId, usize>, node: &NodeId) -> Result<usize, GraphError> {
    index
        .get(node)
        .copied()
        .ok_or_else(|| GraphError::UnknownNode { node: node.clone() })
}

fn check_node(spec: &NodeSpec, policy: &Policy) -> Result<(), GraphError> {
    if !spec.kind().accepts(spec.completion()) {
        return Err(GraphError::CompletionEventMismatch {
            node: spec.id().clone(),
            kind: spec.kind(),
            event: spec.completion(),
        });
    }
    let expected = spec.duration().expected();
    if !spec
        .demand()
        .segments()
        .iter()
        .all(|segment| segment.fits_within(expected))
    {
        return Err(GraphError::DemandOutsideDuration {
            node: spec.id().clone(),
        });
    }
    if let Some(limit) = policy.max_non_preemptible() {
        let non_preemptible = spec.cancellation().non_preemptible(spec.duration().high());
        if non_preemptible > limit {
            return Err(GraphError::NonPreemptibleTooLong {
                node: spec.id().clone(),
                non_preemptible,
                limit,
            });
        }
    }
    Ok(())
}

fn find_objective(nodes: &[NodeSpec]) -> Result<usize, GraphError> {
    let mut found = nodes
        .iter()
        .enumerate()
        .filter(|(_, spec)| spec.completion() == CompletionEvent::FirstTokenDelivered)
        .map(|(position, _)| position);
    let first = found.next().ok_or(GraphError::NoObjective)?;
    if let Some(second) = found.next() {
        return Err(GraphError::AmbiguousObjective {
            first: nodes[first].id().clone(),
            second: nodes[second].id().clone(),
        });
    }
    Ok(first)
}

/// Kahn's algorithm, taking the lowest index first so the order is deterministic. On a
/// cycle, returns the nodes of one cycle in edge order, starting from its lowest index.
pub(crate) fn topological_order(
    predecessors: &[Vec<usize>],
    successors: &[Vec<usize>],
) -> Result<Vec<usize>, Vec<usize>> {
    let mut remaining: Vec<usize> = predecessors.iter().map(Vec::len).collect();
    let mut ready: BTreeSet<usize> = (0..remaining.len())
        .filter(|&at| remaining[at] == 0)
        .collect();
    let mut order = Vec::with_capacity(remaining.len());
    while let Some(next) = ready.pop_first() {
        order.push(next);
        for &successor in &successors[next] {
            remaining[successor] -= 1;
            if remaining[successor] == 0 {
                ready.insert(successor);
            }
        }
    }
    if order.len() == remaining.len() {
        return Ok(order);
    }
    // Every unordered node keeps an unordered predecessor, so walking back must repeat.
    let mut walk: Vec<usize> = Vec::new();
    let mut position_in_walk = vec![None; remaining.len()];
    let mut at = (0..remaining.len())
        .find(|&candidate| remaining[candidate] > 0)
        .unwrap_or(0);
    loop {
        if let Some(start) = position_in_walk[at] {
            let mut cycle: Vec<usize> = walk[start..].iter().rev().copied().collect();
            let lowest = (0..cycle.len()).min_by_key(|&i| cycle[i]).unwrap_or(0);
            cycle.rotate_left(lowest);
            return Err(cycle);
        }
        position_in_walk[at] = Some(walk.len());
        walk.push(at);
        match predecessors[at].iter().find(|&&p| remaining[p] > 0) {
            Some(&previous) => at = previous,
            None => return Err(walk),
        }
    }
}

/// `target` and everything it transitively requires.
fn ancestors_of(target: usize, predecessors: &[Vec<usize>]) -> Vec<bool> {
    let mut marked = vec![false; predecessors.len()];
    let mut stack = vec![target];
    while let Some(at) = stack.pop() {
        if !marked[at] {
            marked[at] = true;
            stack.extend(predecessors[at].iter().copied());
        }
    }
    marked
}

/// A validated request graph (GPU §2.3). Edges run from producer to consumer.
#[derive(Clone, Debug)]
pub struct RequestGraph {
    nodes: Vec<NodeSpec>,
    index: BTreeMap<NodeId, usize>,
    predecessors: Vec<Vec<usize>>,
    successors: Vec<Vec<usize>>,
    order: Vec<usize>,
    objective: usize,
    on_path: Vec<bool>,
    policy: Policy,
}

impl RequestGraph {
    /// The number of nodes.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Always false: an empty graph is refused.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// The nodes in the order they were added.
    pub fn nodes(&self) -> &[NodeSpec] {
        &self.nodes
    }

    /// The node named `id`, if any.
    pub fn node(&self, id: &NodeId) -> Option<&NodeSpec> {
        self.index.get(id).map(|&at| &self.nodes[at])
    }

    /// The nodes whose state `id` requires; `None` for an unknown node.
    pub fn predecessors(&self, id: &NodeId) -> Option<Vec<&NodeId>> {
        self.index.get(id).map(|&at| {
            self.predecessors[at]
                .iter()
                .map(|&p| self.nodes[p].id())
                .collect()
        })
    }

    /// The node whose completion delivers the first correct token (GPU §2.3).
    pub fn objective(&self) -> &NodeId {
        self.nodes[self.objective].id()
    }

    /// Whether the first token transitively requires `id`; work off this path can never
    /// delay the objective in an optimal schedule.
    pub fn on_objective_path(&self, id: &NodeId) -> bool {
        self.index.get(id).is_some_and(|&at| self.on_path[at])
    }

    /// A deterministic topological order: among available nodes, the earliest added
    /// first.
    pub fn topological_order(&self) -> Vec<&NodeId> {
        self.order.iter().map(|&at| self.nodes[at].id()).collect()
    }

    /// The policy the graph was validated under; ready state is checked against it too.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    pub(crate) fn index_of(&self, id: &NodeId) -> Option<usize> {
        self.index.get(id).copied()
    }

    pub(crate) fn spec(&self, at: usize) -> &NodeSpec {
        &self.nodes[at]
    }

    pub(crate) fn predecessor_indices(&self, at: usize) -> &[usize] {
        &self.predecessors[at]
    }

    pub(crate) fn successor_indices(&self, at: usize) -> &[usize] {
        &self.successors[at]
    }

    pub(crate) fn order_indices(&self) -> &[usize] {
        &self.order
    }

    pub(crate) fn objective_index(&self) -> usize {
        self.objective
    }

    pub(crate) fn on_path_index(&self, at: usize) -> bool {
        self.on_path[at]
    }
}
