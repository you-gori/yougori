//! VM §2.1: domains, interfaces and privileges as an attack graph.
//!
//! An edge is crossed only when every control guarding it has failed. Guest compromise is
//! an initial condition, not a probability multiplier: the attacker starts at the initial
//! nodes, and controls located in the guest are failed from the start (guest root
//! controls the guest kernel, VM §1.2). A control fails on its own or through a common
//! dependency (shared parser, kernel, privilege, update key, policy error), which can
//! defeat several supposed walls at once.
//!
//! The graph enumerates prohibited paths (initial node to protected node), the common
//! dependencies of the controls on them, and the minimal sets of failed controls and
//! dependencies that open a prohibited path, by bounded exhaustive search. It is for
//! design review and bounded checking. The product
//! `P(step1) · P(step2 | step1) · P(step3 | step1, step2) · …` is generally unknown, so no
//! number is ever computed from it, and different mechanisms never establish independence.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::contract::{Dependency, Guard, Location};
use super::explore::subsets;
use super::ModelError;

/// The largest number of failure units a minimal-set search accepts.
pub const MAX_SEARCH_UNITS: usize = 24;
/// The largest failure set a minimal-set search enumerates.
pub const MAX_SET_SIZE: usize = 4;

/// A node of the graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct NodeId(usize);

/// A control of the graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct ControlId(usize);

/// What a node stands for (§2.1 "domains, interfaces and privileges").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Domain,
    Interface,
    Privilege,
    Asset,
}

/// A control guarding one or more edges.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Control {
    pub name: String,
    pub location: Location,
    /// The mechanism, such as a language or enforcement technology. Recorded for review;
    /// it never establishes independence.
    pub mechanism: String,
    pub dependencies: BTreeSet<Dependency>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct Node {
    name: String,
    kind: NodeKind,
    initial: bool,
    protected: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct Edge {
    from: NodeId,
    to: NodeId,
    controls: Vec<ControlId>,
}

/// A unit that can fail: one control, or a common dependency failing every control that
/// depends on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureUnit {
    Control(ControlId),
    Dependency(Dependency),
}

/// A prohibited path: a simple path from an initial node to a protected node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProhibitedPath {
    pub nodes: Vec<NodeId>,
    /// Controls on the path that are counted (not guest-side), in path order.
    pub walls: Vec<ControlId>,
    /// Guest-side controls on the path, failed from the start under guest root.
    pub guest_side: Vec<ControlId>,
    /// Dependencies shared by two or more walls of the path.
    pub shared_dependencies: BTreeMap<Dependency, Vec<ControlId>>,
}

/// A minimal set of failures that opens a prohibited path. An empty set means a
/// protected node is reachable under the initial conditions alone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EnablingSet {
    pub units: BTreeSet<FailureUnit>,
    pub reaches: Vec<NodeId>,
}

/// What can be said about the probability of a compromise along a path. It has no
/// numeric field: the conditional step probabilities are generally unknown (§2.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProbabilityStatement {
    GenerallyUnknown {
        formula: &'static str,
        reasons: Vec<&'static str>,
        shared_dependencies: Vec<Dependency>,
    },
}

/// The attack graph.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct AttackGraph {
    nodes: Vec<Node>,
    controls: Vec<Control>,
    edges: Vec<Edge>,
}

impl AttackGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_node(&mut self, name: &str, kind: NodeKind) -> Result<NodeId, ModelError> {
        if self.nodes.iter().any(|node| node.name == name) {
            return Err(ModelError::DuplicateName {
                name: name.to_string(),
            });
        }
        self.nodes.push(Node {
            name: name.to_string(),
            kind,
            initial: false,
            protected: false,
        });
        Ok(NodeId(self.nodes.len() - 1))
    }

    /// Marks where the attacker starts; under the guest-root threat model this is the
    /// guest itself, an initial condition rather than a step.
    pub fn mark_initial(&mut self, node: NodeId) -> Result<(), ModelError> {
        self.node_mut(node)?.initial = true;
        Ok(())
    }

    /// Marks a protected asset; any path reaching it is prohibited.
    pub fn mark_protected(&mut self, node: NodeId) -> Result<(), ModelError> {
        self.node_mut(node)?.protected = true;
        Ok(())
    }

    pub fn add_control(
        &mut self,
        name: &str,
        location: Location,
        mechanism: &str,
        dependencies: &[Dependency],
    ) -> Result<ControlId, ModelError> {
        if self.controls.iter().any(|control| control.name == name) {
            return Err(ModelError::DuplicateName {
                name: name.to_string(),
            });
        }
        self.controls.push(Control {
            name: name.to_string(),
            location,
            mechanism: mechanism.to_string(),
            dependencies: dependencies.iter().copied().collect(),
        });
        Ok(ControlId(self.controls.len() - 1))
    }

    /// Adds a contract guard as a control, with its location and dependencies.
    pub fn add_guard(&mut self, guard: Guard) -> Result<ControlId, ModelError> {
        self.add_control(
            &format!("{guard:?}"),
            guard.location(),
            &format!("{:?}", guard.point()),
            guard.dependencies(),
        )
    }

    /// Adds an interface from `from` to `to`, crossed only when every control fails.
    pub fn add_edge(
        &mut self,
        from: NodeId,
        to: NodeId,
        controls: &[ControlId],
    ) -> Result<(), ModelError> {
        self.node(from)?;
        self.node(to)?;
        for control in controls {
            self.control(*control)?;
        }
        self.edges.push(Edge {
            from,
            to,
            controls: controls.to_vec(),
        });
        Ok(())
    }

    pub fn control(&self, id: ControlId) -> Result<&Control, ModelError> {
        self.controls
            .get(id.0)
            .ok_or(ModelError::UnknownId { id: id.0 })
    }

    pub fn node_name(&self, id: NodeId) -> Result<&str, ModelError> {
        Ok(self.node(id)?.name.as_str())
    }

    pub fn node_kind(&self, id: NodeId) -> Result<NodeKind, ModelError> {
        Ok(self.node(id)?.kind)
    }

    fn node(&self, id: NodeId) -> Result<&Node, ModelError> {
        self.nodes
            .get(id.0)
            .ok_or(ModelError::UnknownId { id: id.0 })
    }

    fn node_mut(&mut self, id: NodeId) -> Result<&mut Node, ModelError> {
        self.nodes
            .get_mut(id.0)
            .ok_or(ModelError::UnknownId { id: id.0 })
    }

    fn counted(&self, control: ControlId) -> bool {
        self.controls
            .get(control.0)
            .is_some_and(|found| found.location != Location::Guest)
    }

    fn failed(&self, control: ControlId, failures: &BTreeSet<FailureUnit>) -> bool {
        let Some(found) = self.controls.get(control.0) else {
            return false;
        };
        found.location == Location::Guest
            || failures.contains(&FailureUnit::Control(control))
            || found
                .dependencies
                .iter()
                .any(|dependency| failures.contains(&FailureUnit::Dependency(*dependency)))
    }

    /// The protected nodes reachable from the initial nodes when `failures` have failed.
    pub fn reachable_assets(&self, failures: &BTreeSet<FailureUnit>) -> Vec<NodeId> {
        let mut seen: BTreeSet<usize> = (0..self.nodes.len())
            .filter(|index| self.nodes[*index].initial)
            .collect();
        let mut frontier: Vec<usize> = seen.iter().copied().collect();
        while let Some(at) = frontier.pop() {
            for edge in self.edges.iter().filter(|edge| edge.from.0 == at) {
                let open = edge
                    .controls
                    .iter()
                    .all(|control| self.failed(*control, failures));
                if open && seen.insert(edge.to.0) {
                    frontier.push(edge.to.0);
                }
            }
        }
        seen.into_iter()
            .filter(|index| self.nodes[*index].protected)
            .map(NodeId)
            .collect()
    }

    /// Every simple path of at most `max_edges` edges from an initial node to a
    /// protected node.
    pub fn prohibited_paths(&self, max_edges: usize) -> Vec<ProhibitedPath> {
        let mut paths = Vec::new();
        for start in (0..self.nodes.len()).filter(|index| self.nodes[*index].initial) {
            let mut stack = vec![(vec![start], Vec::<usize>::new())];
            while let Some((nodes, edges)) = stack.pop() {
                let Some(&last) = nodes.last() else {
                    continue;
                };
                if !edges.is_empty() && self.nodes[last].protected {
                    paths.push(self.describe(&nodes, &edges));
                }
                if edges.len() >= max_edges {
                    continue;
                }
                for (index, edge) in self.edges.iter().enumerate().rev() {
                    if edge.from.0 == last && !nodes.contains(&edge.to.0) {
                        let mut more_nodes = nodes.clone();
                        more_nodes.push(edge.to.0);
                        let mut more_edges = edges.clone();
                        more_edges.push(index);
                        stack.push((more_nodes, more_edges));
                    }
                }
            }
        }
        paths
    }

    fn describe(&self, nodes: &[usize], edges: &[usize]) -> ProhibitedPath {
        let controls: Vec<ControlId> = edges
            .iter()
            .flat_map(|edge| self.edges[*edge].controls.iter().copied())
            .collect();
        let (walls, guest_side): (Vec<ControlId>, Vec<ControlId>) = controls
            .into_iter()
            .partition(|control| self.counted(*control));
        ProhibitedPath {
            nodes: nodes.iter().copied().map(NodeId).collect(),
            shared_dependencies: self.shared_among(&walls),
            walls,
            guest_side,
        }
    }

    fn shared_among(&self, controls: &[ControlId]) -> BTreeMap<Dependency, Vec<ControlId>> {
        let mut by_dependency: BTreeMap<Dependency, Vec<ControlId>> = BTreeMap::new();
        for control in controls {
            if let Some(found) = self.controls.get(control.0) {
                for dependency in &found.dependencies {
                    let users = by_dependency.entry(*dependency).or_default();
                    if !users.contains(control) {
                        users.push(*control);
                    }
                }
            }
        }
        by_dependency.retain(|_, users| users.len() >= 2);
        by_dependency
    }

    /// Dependencies shared by two or more counted controls anywhere in the graph.
    pub fn common_dependencies(&self) -> BTreeMap<Dependency, Vec<ControlId>> {
        let counted: Vec<ControlId> = (0..self.controls.len())
            .map(ControlId)
            .filter(|control| self.counted(*control))
            .collect();
        self.shared_among(&counted)
    }

    /// The minimal sets of failed controls and dependencies, of at most `max_size`
    /// units, that make a protected node reachable (minimal cut sets of "a prohibited
    /// path is open"). Refuses a search beyond [`MAX_SEARCH_UNITS`] units or
    /// [`MAX_SET_SIZE`].
    pub fn minimal_enabling_sets(&self, max_size: usize) -> Result<Vec<EnablingSet>, ModelError> {
        let mut units: Vec<FailureUnit> = (0..self.controls.len())
            .map(ControlId)
            .filter(|control| self.counted(*control))
            .map(FailureUnit::Control)
            .collect();
        let dependencies: BTreeSet<Dependency> = self
            .controls
            .iter()
            .filter(|control| control.location != Location::Guest)
            .flat_map(|control| control.dependencies.iter().copied())
            .collect();
        units.extend(dependencies.into_iter().map(FailureUnit::Dependency));
        if units.len() > MAX_SEARCH_UNITS || max_size > MAX_SET_SIZE {
            return Err(ModelError::SearchBoundTooLarge {
                units: units.len(),
                max_size,
            });
        }
        let open = self.reachable_assets(&BTreeSet::new());
        if !open.is_empty() {
            return Ok(vec![EnablingSet {
                units: BTreeSet::new(),
                reaches: open,
            }]);
        }
        let mut found: Vec<EnablingSet> = Vec::new();
        for chosen in subsets(units.len(), max_size) {
            let candidate: BTreeSet<FailureUnit> =
                chosen.iter().map(|index| units[*index]).collect();
            if found.iter().any(|set| set.units.is_subset(&candidate)) {
                continue;
            }
            let reaches = self.reachable_assets(&candidate);
            if !reaches.is_empty() {
                found.push(EnablingSet {
                    units: candidate,
                    reaches,
                });
            }
        }
        Ok(found)
    }

    /// Always refused: different languages or mechanisms do not establish independence
    /// (§2.1). The refusal lists the dependencies the two controls are known to share.
    pub fn independence(&self, first: ControlId, second: ControlId) -> Result<(), ModelError> {
        let a = self.control(first)?;
        let b = self.control(second)?;
        Err(ModelError::IndependenceNotEstablished {
            shared: a
                .dependencies
                .intersection(&b.dependencies)
                .copied()
                .collect(),
        })
    }

    /// The probability of compromise along `path`: generally unknown, never a number.
    pub fn compromise_probability(&self, path: &ProhibitedPath) -> ProbabilityStatement {
        ProbabilityStatement::GenerallyUnknown {
            formula: "P(compromise) = P(step1) * P(step2 | step1) * P(step3 | step1, step2) * ...",
            reasons: vec![
                "the conditional step probabilities are generally unknown",
                "different languages or mechanisms do not establish independence",
                "under the guest-root threat model guest compromise is an initial condition",
            ],
            shared_dependencies: path.shared_dependencies.keys().copied().collect(),
        }
    }

    /// The perimeter part of the contract as an attack graph: guest root can reach a
    /// forbidden destination by a raw socket, through the relay under another tenant's
    /// identity, or through a rebound connection.
    pub fn egress_reference() -> Result<Self, ModelError> {
        let mut graph = Self::new();
        let guest = graph.add_node("guest root", NodeKind::Domain)?;
        let socket = graph.add_node("guest raw socket", NodeKind::Interface)?;
        let relay = graph.add_node("relay channel", NodeKind::Interface)?;
        let other = graph.add_node("other tenant route", NodeKind::Privilege)?;
        let rebound = graph.add_node("rebound connection", NodeKind::Interface)?;
        let forbidden = graph.add_node("forbidden destination", NodeKind::Asset)?;
        graph.mark_initial(guest)?;
        graph.mark_protected(forbidden)?;
        let policy = graph.add_guard(Guard::GuestEgressPolicy)?;
        let firewall = graph.add_guard(Guard::HostFirewall)?;
        let identity = graph.add_guard(Guard::RelayChannelIdentity)?;
        let address = graph.add_guard(Guard::RelayAddressCheck)?;
        graph.add_edge(guest, socket, &[policy])?;
        graph.add_edge(socket, forbidden, &[firewall])?;
        graph.add_edge(guest, relay, &[])?;
        graph.add_edge(relay, other, &[identity])?;
        graph.add_edge(other, forbidden, &[])?;
        graph.add_edge(relay, rebound, &[])?;
        graph.add_edge(rebound, forbidden, &[address])?;
        Ok(graph)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A hand-built graph: guest root reaches the credential store through a host parser
    /// guarded by a Rust wall and a Go wall that share one parser library, or through a
    /// management API guarded by an authentication check and a firewall.
    struct Fixture {
        graph: AttackGraph,
        rust_wall: ControlId,
        go_wall: ControlId,
        auth: ControlId,
        firewall: ControlId,
        inner: ControlId,
        store: NodeId,
    }

    fn fixture() -> Fixture {
        let mut graph = AttackGraph::new();
        let guest = graph.add_node("guest root", NodeKind::Domain).unwrap();
        let container = graph
            .add_node("inner container", NodeKind::Privilege)
            .unwrap();
        let parser = graph.add_node("host parser", NodeKind::Interface).unwrap();
        let host = graph.add_node("host user", NodeKind::Privilege).unwrap();
        let api = graph
            .add_node("management API", NodeKind::Interface)
            .unwrap();
        let store = graph.add_node("credential store", NodeKind::Asset).unwrap();
        graph.mark_initial(guest).unwrap();
        graph.mark_protected(store).unwrap();
        let inner = graph
            .add_control("inner container seccomp", Location::Guest, "seccomp", &[])
            .unwrap();
        let rust_wall = graph
            .add_control(
                "relay frame decoder",
                Location::Host,
                "rust",
                &[Dependency::SharedParser],
            )
            .unwrap();
        let go_wall = graph
            .add_control(
                "agent message decoder",
                Location::Host,
                "go",
                &[Dependency::SharedParser],
            )
            .unwrap();
        let auth = graph
            .add_control(
                "API authentication",
                Location::Host,
                "token",
                &[Dependency::SharedPrivilege],
            )
            .unwrap();
        let firewall = graph
            .add_control(
                "host firewall",
                Location::Host,
                "wfp",
                &[Dependency::HostKernel],
            )
            .unwrap();
        graph.add_edge(guest, container, &[inner]).unwrap();
        graph.add_edge(container, parser, &[]).unwrap();
        graph.add_edge(guest, parser, &[]).unwrap();
        graph.add_edge(parser, host, &[rust_wall, go_wall]).unwrap();
        graph.add_edge(host, store, &[]).unwrap();
        graph.add_edge(guest, api, &[firewall]).unwrap();
        graph.add_edge(api, store, &[auth]).unwrap();
        Fixture {
            graph,
            rust_wall,
            go_wall,
            auth,
            firewall,
            inner,
            store,
        }
    }

    fn set(units: &[FailureUnit]) -> BTreeSet<FailureUnit> {
        units.iter().copied().collect()
    }

    #[test]
    fn minimal_enabling_sets_of_a_hand_built_graph() {
        let f = fixture();
        let sets = f.graph.minimal_enabling_sets(2).unwrap();
        let found: Vec<BTreeSet<FailureUnit>> = sets.iter().map(|s| s.units.clone()).collect();
        let expected = vec![
            set(&[FailureUnit::Dependency(Dependency::SharedParser)]),
            set(&[
                FailureUnit::Control(f.rust_wall),
                FailureUnit::Control(f.go_wall),
            ]),
            set(&[
                FailureUnit::Control(f.auth),
                FailureUnit::Control(f.firewall),
            ]),
            set(&[
                FailureUnit::Control(f.auth),
                FailureUnit::Dependency(Dependency::HostKernel),
            ]),
            set(&[
                FailureUnit::Control(f.firewall),
                FailureUnit::Dependency(Dependency::SharedPrivilege),
            ]),
            set(&[
                FailureUnit::Dependency(Dependency::HostKernel),
                FailureUnit::Dependency(Dependency::SharedPrivilege),
            ]),
        ];
        assert_eq!(found.len(), expected.len(), "{found:?}");
        for minimal in &expected {
            assert!(found.contains(minimal), "{minimal:?}");
        }
        assert!(sets.iter().all(|s| s.reaches == vec![f.store]));
        // No set contains another.
        for a in &found {
            for b in &found {
                assert!(a == b || !a.is_subset(b));
            }
        }
    }

    #[test]
    fn a_common_dependency_defeats_two_independent_looking_walls() {
        let f = fixture();
        let parser_failure = set(&[FailureUnit::Dependency(Dependency::SharedParser)]);
        assert_eq!(f.graph.reachable_assets(&parser_failure), vec![f.store]);
        // One wall alone does not open the path.
        assert!(f
            .graph
            .reachable_assets(&set(&[FailureUnit::Control(f.rust_wall)]))
            .is_empty());
        let paths = f.graph.prohibited_paths(4);
        let parser_path = paths
            .iter()
            .find(|path| path.walls == vec![f.rust_wall, f.go_wall])
            .unwrap();
        assert_eq!(
            parser_path
                .shared_dependencies
                .get(&Dependency::SharedParser),
            Some(&vec![f.rust_wall, f.go_wall])
        );
        assert_eq!(
            f.graph
                .common_dependencies()
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            vec![Dependency::SharedParser]
        );
    }

    #[test]
    fn different_mechanisms_never_establish_independence() {
        let f = fixture();
        assert_eq!(
            f.graph.independence(f.rust_wall, f.go_wall),
            Err(ModelError::IndependenceNotEstablished {
                shared: vec![Dependency::SharedParser]
            })
        );
        // Even with no known shared dependency, independence is not established.
        assert_eq!(
            f.graph.independence(f.auth, f.firewall),
            Err(ModelError::IndependenceNotEstablished { shared: vec![] })
        );
    }

    #[test]
    fn no_probability_is_computed_from_the_product_formula() {
        let f = fixture();
        let path = &f.graph.prohibited_paths(4)[0];
        let statement = f.graph.compromise_probability(path);
        let json = serde_json::to_value(&statement).unwrap();
        assert_eq!(json["kind"], "generally_unknown");
        let has_number = |value: &serde_json::Value| -> bool {
            fn walk(value: &serde_json::Value) -> bool {
                match value {
                    serde_json::Value::Number(_) => true,
                    serde_json::Value::Array(items) => items.iter().any(walk),
                    serde_json::Value::Object(map) => map.values().any(walk),
                    _ => false,
                }
            }
            walk(value)
        };
        assert!(!has_number(&json));
    }

    #[test]
    fn guest_compromise_is_an_initial_condition_not_a_counted_wall() {
        let f = fixture();
        let paths = f.graph.prohibited_paths(4);
        let through_container = paths
            .iter()
            .find(|path| path.guest_side == vec![f.inner])
            .unwrap();
        assert!(!through_container.walls.contains(&f.inner));
        // The inner container never appears in a minimal set.
        let sets = f.graph.minimal_enabling_sets(3).unwrap();
        assert!(sets
            .iter()
            .all(|s| !s.units.contains(&FailureUnit::Control(f.inner))));
        // A path guarded only by a guest-side control is open from the start.
        let mut open = AttackGraph::new();
        let guest = open.add_node("guest root", NodeKind::Domain).unwrap();
        let asset = open.add_node("LAN", NodeKind::Asset).unwrap();
        open.mark_initial(guest).unwrap();
        open.mark_protected(asset).unwrap();
        let inner = open
            .add_control("guest iptables", Location::Guest, "netfilter", &[])
            .unwrap();
        open.add_edge(guest, asset, &[inner]).unwrap();
        let sets = open.minimal_enabling_sets(2).unwrap();
        assert_eq!(sets.len(), 1);
        assert!(sets[0].units.is_empty());
    }

    #[test]
    fn the_search_and_the_builder_refuse_what_they_cannot_honour() {
        let f = fixture();
        assert_eq!(
            f.graph.minimal_enabling_sets(MAX_SET_SIZE + 1),
            Err(ModelError::SearchBoundTooLarge {
                units: 7,
                max_size: MAX_SET_SIZE + 1
            })
        );
        let mut graph = AttackGraph::new();
        graph.add_node("a", NodeKind::Domain).unwrap();
        assert!(matches!(
            graph.add_node("a", NodeKind::Asset),
            Err(ModelError::DuplicateName { .. })
        ));
        assert_eq!(
            graph.add_edge(NodeId(0), NodeId(9), &[]),
            Err(ModelError::UnknownId { id: 9 })
        );
    }

    #[test]
    fn the_egress_reference_graph_has_seven_single_failure_openings() {
        let graph = AttackGraph::egress_reference().unwrap();
        let sets = graph.minimal_enabling_sets(2).unwrap();
        assert_eq!(sets.len(), 7);
        assert!(sets.iter().all(|s| s.units.len() == 1));
        assert_eq!(graph.prohibited_paths(3).len(), 3);
    }
}
