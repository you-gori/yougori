//! The v2 resource graph: logical IDs, dependencies, cycles, namespacing and bounds.
//!
//! A node is one resource as declared, placeholders included. Edges are readiness only: a node
//! waits for what it depends on and for what it references, and nothing more. Connectivity is a
//! resource of its own. Imported components are flattened under their namespace, so two
//! components may both have a `web` without colliding.
use crate::{
    condition::Condition,
    dto::Diagnostic,
    format::{Access, Borrow, Checked, Retention},
    limits,
    resource::Kind,
};
use serde_yaml_ng::{Mapping, Value as Yaml};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug)]
pub struct Node {
    pub id: String,
    pub kind: Kind,
    /// The template capability the node belongs to; off means the node is left out.
    pub capability: Option<String>,
    /// The namespace of the imported component the node comes from; `None` for the template's own.
    pub component: Option<String>,
    /// Explicit `depends_on` plus every resource the spec references.
    pub depends_on: BTreeSet<String>,
    pub when: Option<Condition>,
    pub borrow: Option<Borrow>,
    pub retention: Option<Retention>,
    pub spec: Yaml,
    /// A v1-style environment: every answer is text, and the template's `tools:` apply.
    pub legacy: bool,
    /// Where the node comes from, for messages: `environment web`, `public: web`, `resource x`.
    pub origin: String,
}

#[derive(Clone, Debug, Default)]
pub struct Graph {
    pub nodes: BTreeMap<String, Node>,
}

fn problem(code: &'static str, message: String) -> Diagnostic {
    Diagnostic::error(code, message)
}

/// A generated id from a name that may hold dots or dashes: `public_web`, `connection_web_db`.
pub fn sanitize(name: &str) -> String {
    name.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '_' }).collect()
}

/// The id of a node the v1 adapter makes: the readable `base`, unless another node has it
/// (`a -> b_c` and `a_b -> c` both read `connection_a_b_c`, `my-web` and `my_web` both read
/// `public_my_web`). Then the base gains a short digest of what the node stands for, so the id
/// stays the same whatever else the template lists, and the first node keeps the plain one.
fn free_id(base: String, stands_for: &str, taken: &mut BTreeSet<String>) -> String {
    use sha2::{Digest as _, Sha256};
    let id = if taken.contains(&base) {
        let digest: String = Sha256::digest(stands_for.as_bytes()).iter().take(4).map(|b| format!("{b:02x}")).collect();
        format!("{base}_{digest}")
    } else {
        base
    };
    taken.insert(id.clone());
    id
}

/// The resources a resource of `kind` waits for because its spec references them: every
/// reference, except a volume's `backup_through`. That names the sandbox a backup reads the volume
/// through, which mounts the volume and so is made after it; it is used when a backup runs, never
/// when the volume is made, and counting it would put the sandbox before its own volume.
pub fn readiness_references(kind: Kind, spec: &Yaml, found: &mut BTreeSet<String>) {
    match (kind, spec) {
        (Kind::Volume, Yaml::Mapping(map)) => map.iter().filter(|(key, _)| key.as_str() != Some("backup_through")).for_each(|(_, value)| references_in(value, found)),
        _ => references_in(spec, found),
    }
}

/// Every resource a raw spec references: mappings that are exactly `{resource: id}` or
/// `{resource: id, output: name}`.
pub fn references_in(value: &Yaml, found: &mut BTreeSet<String>) {
    match value {
        Yaml::Mapping(map) => {
            if is_reference(map) {
                if let Some(Yaml::String(id)) = map.get("resource") {
                    found.insert(id.clone());
                }
            } else {
                map.values().for_each(|item| references_in(item, found));
            }
        }
        Yaml::Sequence(items) => items.iter().for_each(|item| references_in(item, found)),
        Yaml::Tagged(tagged) => references_in(&tagged.value, found),
        _ => {}
    }
}

/// The volumes an environment spec mounts by name (`volumes: [{source: data, target: /data}]`),
/// leaving out `bind` mounts, which name a folder rather than a volume. A name that is a volume
/// resource of the same package is a dependency like a `{resource: id}` reference: the volume is
/// made before the sandbox that mounts it, and the sandbox goes before the volume on removal.
pub fn mounted_volumes(spec: &Yaml) -> Vec<String> {
    spec.get("volumes")
        .and_then(Yaml::as_sequence)
        .into_iter()
        .flatten()
        .filter(|mount| mount.get("bind").and_then(Yaml::as_bool) != Some(true))
        .filter_map(|mount| mount.get("source").and_then(Yaml::as_str).map(str::to_owned))
        .collect()
}

fn is_reference(map: &Mapping) -> bool {
    !map.is_empty()
        && map.keys().all(|key| matches!(key.as_str(), Some("resource" | "output" | "binding")))
        && (matches!(map.get("resource"), Some(Yaml::String(_))) || matches!(map.get("binding"), Some(Yaml::String(_))))
}

fn rewrite_references(value: &mut Yaml, prefix: &str) {
    match value {
        Yaml::Mapping(map) => {
            if is_reference(map) {
                if let Some(Yaml::String(id)) = map.get_mut("resource") {
                    *id = format!("{prefix}.{id}");
                }
            } else {
                map.values_mut().for_each(|item| rewrite_references(item, prefix));
            }
        }
        Yaml::Sequence(items) => items.iter_mut().for_each(|item| rewrite_references(item, prefix)),
        Yaml::Tagged(tagged) => rewrite_references(&mut tagged.value, prefix),
        _ => {}
    }
}

fn mapping(pairs: Vec<(&str, Yaml)>) -> Yaml {
    let mut map = Mapping::new();
    for (key, value) in pairs {
        map.insert(Yaml::String(key.to_owned()), value);
    }
    Yaml::Mapping(map)
}

fn reference(id: &str) -> Yaml {
    mapping(vec![("resource", Yaml::String(id.to_owned()))])
}

impl Graph {
    pub fn new() -> Graph {
        Graph::default()
    }

    /// Adds a node; an id used twice is refused.
    pub fn insert(&mut self, node: Node) -> Result<(), Diagnostic> {
        if let Some(existing) = self.nodes.get(&node.id) {
            return Err(problem("duplicate_id", format!("{} and {} would both be the resource {}. Rename one of them.", existing.origin, node.origin, node.id)));
        }
        self.nodes.insert(node.id.clone(), node);
        Ok(())
    }

    /// The graph of one checked package: its v1-style environments, public entries and
    /// connections become nodes beside its resources.
    pub fn from_checked(checked: &Checked) -> Result<Graph, Vec<Diagnostic>> {
        let mut graph = Graph::new();
        let mut problems = Vec::new();
        // The names the template chose itself come first; the adapter's ids go around them.
        let mut taken: BTreeSet<String> = checked.environments.keys().chain(checked.resources.keys()).cloned().collect();
        for (name, spec) in &checked.environments {
            let depends_on: BTreeSet<String> = spec.get("depends_on").and_then(Yaml::as_sequence).into_iter().flatten().filter_map(Yaml::as_str).map(str::to_owned).collect();
            let node = Node { id: name.clone(), kind: Kind::Environment, capability: None, component: None, depends_on, when: None, borrow: None, retention: None, spec: spec.clone(), legacy: true, origin: format!("environment {name}") };
            if let Err(error) = graph.insert(node) {
                problems.push(error);
            }
        }
        for entry in &checked.public {
            let access = match &entry.access {
                Access::Fixed(text) => Yaml::String(text.clone()),
                Access::Asked(id) => Yaml::String(format!("{{{{inputs.{id}}}}}")),
            };
            let mut pairs = vec![("target", reference(&entry.environment)), ("port", Yaml::Number(entry.port.into())), ("access", access)];
            if let Some(domain) = &entry.domain {
                pairs.push(("domain", Yaml::String(domain.clone())));
            }
            let id = free_id(format!("public_{}", sanitize(&entry.environment)), &format!("public {}:{}", entry.environment, entry.port), &mut taken);
            let node = Node { id, kind: Kind::ServicePublication, capability: None, component: None, depends_on: [entry.environment.clone()].into(), when: None, borrow: None, retention: None, spec: mapping(pairs), legacy: false, origin: format!("public: {}", entry.environment) };
            if let Err(error) = graph.insert(node) {
                problems.push(error);
            }
        }
        for connection in &checked.connections {
            let pairs = vec![
                ("from", reference(&connection.from)),
                ("to", reference(&connection.to)),
                ("ports", Yaml::Sequence(connection.ports.iter().map(|p| Yaml::Number((*p).into())).collect())),
                ("permissions", Yaml::Sequence(connection.permissions.iter().map(|p| Yaml::String(p.clone())).collect())),
            ];
            let id = free_id(format!("connection_{}_{}", sanitize(&connection.from), sanitize(&connection.to)), &format!("connection {} -> {}", connection.from, connection.to), &mut taken);
            let node = Node { id, kind: Kind::Connection, capability: None, component: None, depends_on: [connection.from.clone(), connection.to.clone()].into(), when: None, borrow: None, retention: None, spec: mapping(pairs), legacy: false, origin: format!("connection {} -> {}", connection.from, connection.to) };
            if let Err(error) = graph.insert(node) {
                problems.push(error);
            }
        }
        for resource in checked.resources.values() {
            let mut depends_on: BTreeSet<String> = resource.depends_on.iter().cloned().collect();
            readiness_references(resource.kind, &resource.spec, &mut depends_on);
            let node = Node { id: resource.id.clone(), kind: resource.kind, capability: resource.capability.clone(), component: None, depends_on, when: resource.when.clone(), borrow: resource.borrow.clone(), retention: resource.retention, spec: resource.spec.clone(), legacy: false, origin: format!("resource {}", resource.id) };
            if let Err(error) = graph.insert(node) {
                problems.push(error);
            }
        }
        // A sandbox needs the package's own volumes it mounts by name.
        let volumes: BTreeSet<String> = graph.nodes.values().filter(|node| node.kind == Kind::Volume).map(|node| node.id.clone()).collect();
        for node in graph.nodes.values_mut().filter(|node| node.kind == Kind::Environment) {
            let mounted = mounted_volumes(&node.spec).into_iter().filter(|source| volumes.contains(source) && source != &node.id);
            node.depends_on.extend(mounted.collect::<Vec<_>>());
        }
        if problems.is_empty() { Ok(graph) } else { Err(problems) }
    }

    /// The same graph under a namespace: every id, dependency and reference becomes `prefix.id`.
    pub fn namespaced(self, prefix: &str) -> Graph {
        let mut out = Graph::new();
        for (_, mut node) in self.nodes {
            node.id = format!("{prefix}.{}", node.id);
            node.depends_on = node.depends_on.iter().map(|d| format!("{prefix}.{d}")).collect();
            node.component = Some(match node.component.take() {
                Some(inner) => format!("{prefix}.{inner}"),
                None => prefix.to_owned(),
            });
            rewrite_references(&mut node.spec, prefix);
            node.origin = format!("{prefix}: {}", node.origin);
            out.nodes.insert(node.id.clone(), node);
        }
        out
    }

    /// Adds every node of `other`.
    pub fn merge(&mut self, other: Graph) -> Result<(), Vec<Diagnostic>> {
        let mut problems = Vec::new();
        for (_, node) in other.nodes {
            if let Err(error) = self.insert(node) {
                problems.push(error);
            }
        }
        if problems.is_empty() { Ok(()) } else { Err(problems) }
    }

    pub fn edges(&self) -> usize {
        self.nodes.values().map(|n| n.depends_on.len()).sum()
    }

    /// Unknown or self dependencies, the bounds, and a cycle: each refusal names what it hit.
    pub fn check(&self) -> Result<(), Vec<Diagnostic>> {
        let mut problems = Vec::new();
        if !limits::RESOURCES.allows(self.nodes.len()) {
            problems.push(problem("limit_exceeded", limits::RESOURCES.exceeded(self.nodes.len())));
        }
        if !limits::EDGES.allows(self.edges()) {
            problems.push(problem("limit_exceeded", limits::EDGES.exceeded(self.edges())));
        }
        for node in self.nodes.values() {
            if !limits::DEPENDS_ON.allows(node.depends_on.len()) {
                problems.push(problem("limit_exceeded", format!("{}: {}", node.origin, limits::DEPENDS_ON.exceeded(node.depends_on.len()))).at(node.id.clone()));
            }
            for dependency in &node.depends_on {
                if dependency == &node.id {
                    problems.push(problem("dependency_cycle", format!("{} depends on itself.", node.origin)).at(node.id.clone()));
                } else if !self.nodes.contains_key(dependency) {
                    problems.push(problem("unknown_resource", format!("{} depends on {}, which is not a resource of this setup.", node.origin, crate::text::shown(dependency))).at(node.id.clone()));
                }
            }
        }
        if !problems.is_empty() {
            return Err(problems);
        }
        if let Some(path) = self.cycle() {
            return Err(vec![problem("dependency_cycle", format!("The resources depend on each other in a cycle: {}. Remove one of these dependencies.", path.join(" -> ")))]);
        }
        let depth = self.depth();
        if !limits::DEPENDENCY_DEPTH.allows(depth) {
            return Err(vec![problem("limit_exceeded", limits::DEPENDENCY_DEPTH.exceeded(depth))]);
        }
        Ok(())
    }

    /// A dependency cycle as the ids along it, ending where it started; `None` when there is none.
    pub fn cycle(&self) -> Option<Vec<String>> {
        #[derive(Clone, Copy, PartialEq)]
        enum Mark {
            Open,
            Done,
        }
        fn visit(graph: &Graph, id: &str, marks: &mut BTreeMap<String, Mark>, stack: &mut Vec<String>) -> Option<Vec<String>> {
            match marks.get(id) {
                Some(Mark::Done) => return None,
                Some(Mark::Open) => {
                    let start = stack.iter().position(|s| s == id).unwrap_or(0);
                    let mut path: Vec<String> = stack[start..].to_vec();
                    path.push(id.to_owned());
                    return Some(path);
                }
                None => {}
            }
            marks.insert(id.to_owned(), Mark::Open);
            stack.push(id.to_owned());
            if let Some(node) = graph.nodes.get(id) {
                for dependency in &node.depends_on {
                    if graph.nodes.contains_key(dependency) {
                        if let Some(path) = visit(graph, dependency, marks, stack) {
                            return Some(path);
                        }
                    }
                }
            }
            stack.pop();
            marks.insert(id.to_owned(), Mark::Done);
            None
        }
        let mut marks = BTreeMap::new();
        for id in self.nodes.keys() {
            if let Some(path) = visit(self, id, &mut marks, &mut Vec::new()) {
                return Some(path);
            }
        }
        None
    }

    /// The longest chain of dependencies, counted in nodes: 1 when nothing depends on anything.
    /// Zero for an empty graph. Only meaningful without a cycle.
    pub fn depth(&self) -> usize {
        fn deep(graph: &Graph, id: &str, memo: &mut BTreeMap<String, usize>, open: &mut BTreeSet<String>) -> usize {
            if let Some(known) = memo.get(id) {
                return *known;
            }
            if !open.insert(id.to_owned()) {
                return 0;
            }
            let below = graph.nodes.get(id).map(|node| node.depends_on.iter().filter(|d| graph.nodes.contains_key(*d)).map(|d| deep(graph, d, memo, open)).max().unwrap_or(0)).unwrap_or(0);
            open.remove(id);
            memo.insert(id.to_owned(), below + 1);
            below + 1
        }
        let mut memo = BTreeMap::new();
        self.nodes.keys().map(|id| deep(self, id, &mut memo, &mut BTreeSet::new())).max().unwrap_or(0)
    }

    /// Every node in dependency order; among nodes that could go next, the smaller id goes first,
    /// so the same graph always gives the same order.
    pub fn order(&self) -> Result<Vec<String>, Diagnostic> {
        let mut remaining: BTreeMap<&str, BTreeSet<&str>> = self.nodes.values().map(|n| (n.id.as_str(), n.depends_on.iter().map(String::as_str).filter(|d| self.nodes.contains_key(*d)).collect())).collect();
        let mut order = Vec::with_capacity(self.nodes.len());
        while !remaining.is_empty() {
            let next = remaining.iter().find(|(_, deps)| deps.is_empty()).map(|(id, _)| *id);
            let Some(id) = next else {
                let path = self.cycle().unwrap_or_default();
                return Err(problem("dependency_cycle", format!("The resources depend on each other in a cycle: {}.", path.join(" -> "))));
            };
            remaining.remove(id);
            for deps in remaining.values_mut() {
                deps.remove(id);
            }
            order.push(id.to_owned());
        }
        Ok(order)
    }

    /// The graph without the nodes `keep` rejects. A kept node that depends on a dropped one is
    /// a refusal: the template left a dependency out of the setup.
    pub fn retain(&self, keep: &dyn Fn(&Node) -> bool) -> Result<Graph, Vec<Diagnostic>> {
        let kept: BTreeMap<String, Node> = self.nodes.iter().filter(|(_, node)| keep(node)).map(|(id, node)| (id.clone(), node.clone())).collect();
        let mut problems = Vec::new();
        for node in kept.values() {
            for dependency in &node.depends_on {
                if !kept.contains_key(dependency) && self.nodes.contains_key(dependency) {
                    problems.push(problem("dependency_left_out", format!("{} needs {}, which is not part of this setup: its condition or capability is off. Give {} the same condition, or turn the capability on.", node.origin, dependency, node.id)).at(node.id.clone()));
                }
            }
        }
        if problems.is_empty() { Ok(Graph { nodes: kept }) } else { Err(problems) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, deps: &[&str]) -> Node {
        Node { id: id.into(), kind: Kind::Environment, capability: None, component: None, depends_on: deps.iter().map(|d| d.to_string()).collect(), when: None, borrow: None, retention: None, spec: Yaml::Null, legacy: false, origin: format!("resource {id}") }
    }

    fn graph(edges: &[(&str, &[&str])]) -> Graph {
        let mut graph = Graph::new();
        for (id, deps) in edges {
            graph.insert(node(id, deps)).unwrap();
        }
        graph
    }

    #[test]
    fn order_is_topological_and_deterministic() {
        let graph = graph(&[("web", &["db", "cache"]), ("db", &[]), ("cache", &[]), ("worker", &["db"])]);
        assert!(graph.check().is_ok());
        assert_eq!(graph.order().unwrap(), ["cache", "db", "web", "worker"]);
        assert_eq!(graph.depth(), 2);
        assert_eq!(graph.edges(), 3);
        assert!(graph.cycle().is_none());
    }

    #[test]
    fn cycles_and_limits_are_named() {
        let cyclic = graph(&[("a", &["b"]), ("b", &["c"]), ("c", &["a"])]);
        let said = cyclic.check().unwrap_err();
        assert_eq!(said[0].code, "dependency_cycle");
        assert!(said[0].message.contains("a -> b -> c -> a"), "{}", said[0].message);
        assert!(cyclic.order().is_err());
        let unknown = graph(&[("a", &["ghost"])]).check().unwrap_err();
        assert_eq!(unknown[0].code, "unknown_resource");
        let mut deep = Graph::new();
        for i in 0..10 {
            let deps: Vec<String> = if i == 0 { vec![] } else { vec![format!("n{}", i - 1)] };
            deep.insert(node(&format!("n{i}"), &deps.iter().map(String::as_str).collect::<Vec<_>>())).unwrap();
        }
        let said = deep.check().unwrap_err();
        assert!(said[0].message.contains("levels of dependencies: 10, and the limit is 8"), "{}", said[0].message);
        let mut wide = Graph::new();
        for i in 0..257 {
            wide.insert(node(&format!("n{i}"), &[])).unwrap();
        }
        assert!(wide.check().unwrap_err()[0].message.contains("resources in a plan: 257"));
        assert!(graph(&[("a", &[])]).insert(node("a", &[])).unwrap_err().message.contains("both be the resource a"));
    }

    #[test]
    fn namespaces_keep_two_components_apart_and_rewrite_references() {
        let mut spec_graph = Graph::new();
        let mut web = node("web", &[]);
        web.spec = serde_yaml_ng::from_str("target: {resource: db, output: name}\nlist: [{resource: db}]\n").unwrap();
        web.depends_on.insert("db".into());
        spec_graph.insert(web).unwrap();
        spec_graph.insert(node("db", &[])).unwrap();
        let mut whole = spec_graph.clone().namespaced("shop");
        whole.merge(spec_graph.namespaced("blog")).unwrap();
        assert_eq!(whole.nodes.keys().collect::<Vec<_>>(), ["blog.db", "blog.web", "shop.db", "shop.web"]);
        let web = &whole.nodes["shop.web"];
        assert_eq!(web.depends_on, ["shop.db".to_owned()].into());
        assert_eq!(web.spec["target"]["resource"].as_str(), Some("shop.db"));
        assert_eq!(web.spec["list"][0]["resource"].as_str(), Some("shop.db"));
        assert_eq!(web.component.as_deref(), Some("shop"));
        assert!(whole.check().is_ok());
        let mut found = BTreeSet::new();
        references_in(&web.spec, &mut found);
        assert_eq!(found, ["shop.db".to_owned()].into());
    }

    #[test]
    fn dropping_a_dependency_is_a_refusal() {
        let graph = graph(&[("web", &["db"]), ("db", &[])]);
        let said = graph.retain(&|node| node.id != "db").unwrap_err();
        assert_eq!(said[0].code, "dependency_left_out");
        assert!(graph.retain(&|node| node.id != "web").is_ok());
    }
}
