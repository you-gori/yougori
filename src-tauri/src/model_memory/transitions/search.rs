//! The planners of GPU §4.15 line 862.
//!
//! - [`SearchMethod::ExactDp`]: for a short linear workflow, a bounded dynamic program
//!   over valid retained-state configurations. States are sets of shared physical
//!   resources ([`ResourceSet`]), never one copy per model, and every transition is
//!   checked with its peak (see [`super::memory`]).
//! - [`SearchMethod::Beam`]: for branching workflows, the same program with only the
//!   `width` most promising configurations and preparations expanded at each node. Its
//!   policies lie in the oracle's space, so it can never beat the oracle.
//! - [`SearchMethod::ExhaustiveOracle`]: a small offline oracle that enumerates every
//!   complete policy (no solver crate) and evaluates each one independently.
//!
//! Costs aggregate over branches by evidence probabilities, or by the worst branch when a
//! branch point has no evidence (line 849). Every search is bounded by the model's work
//! units.

use std::collections::{BTreeMap, HashMap};

use serde::Serialize;

use super::declaration::{Aggregation, TreeNode};
use super::model::{Context, CostModel, Infeasibility, Knowledge, Transition};
use super::{ResourceSet, TransitionError};

/// Which planner compiles a plan (line 862).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum SearchMethod {
    /// The bounded dynamic program over every valid configuration.
    ExactDp,
    /// Beam search keeping `width` candidates per node.
    Beam { width: usize },
    /// The exhaustive offline oracle, for small workflows only.
    ExhaustiveOracle,
}

/// One node's decision: what is resident during its stage and what is prepared beside it
/// for its children.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Decision {
    pub(crate) config: ResourceSet,
    pub(crate) prefetch: ResourceSet,
}

/// A searched policy.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Searched {
    pub(crate) decisions: BTreeMap<usize, Decision>,
    /// Ranked alternatives per node: configuration and cost to go from the chosen parent
    /// decision.
    pub(crate) alternatives: BTreeMap<usize, Vec<(ResourceSet, f64)>>,
}

/// A policy evaluated node by node.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Evaluation {
    pub(crate) cost_seconds: f64,
    /// The context each node was entered from and the transition into it.
    pub(crate) transitions: BTreeMap<usize, (Context, Transition)>,
}

/// Combines children's costs by the node's aggregation.
pub(crate) fn aggregate(node: &TreeNode, costs: &[f64]) -> f64 {
    match node.aggregation {
        Aggregation::Leaf => 0.0,
        Aggregation::Single => costs.first().copied().unwrap_or(0.0),
        Aggregation::Expected => costs
            .iter()
            .zip(&node.weights)
            .map(|(cost, weight)| cost * weight)
            .sum(),
        Aggregation::WorstCase => costs.iter().copied().fold(0.0, f64::max),
    }
}

/// Every valid configuration of tree node `node`: its stage's requirement plus any
/// prerequisite-closed set of immutable resources and session states that still matter,
/// smallest first.
pub(crate) fn configurations(
    model: &CostModel<'_>,
    node: usize,
    knowledge: Knowledge,
) -> Result<Vec<ResourceSet>, TransitionError> {
    let workflow = model.workflow;
    let entry = model.tree.get(node).ok_or(TransitionError::Internal {
        what: "tree node out of range",
    })?;
    let stage = &workflow.stages[entry.stage];
    let sessions = match knowledge {
        Knowledge::Declared => entry.available.intersection(entry.live),
        Knowledge::Online => entry.available,
    };
    let pool: Vec<usize> = workflow
        .immutables()
        .union(sessions)
        .difference(stage.requires)
        .iter()
        .collect();
    let limit = workflow.limits.max_configurations_per_stage;
    let too_many = || TransitionError::StateLimit {
        stage: stage.id.clone(),
        configurations: limit.saturating_add(1),
        limit,
    };
    if pool.len() >= 32 {
        return Err(too_many());
    }
    let mut found = Vec::new();
    for mask in 0u64..(1u64 << pool.len()) {
        let mut set = stage.requires;
        for (bit, at) in pool.iter().enumerate() {
            if mask & (1u64 << bit) != 0 {
                set = set.with(*at);
            }
        }
        if workflow.is_closed(set) {
            found.push(set);
            if found.len() > limit {
                return Err(too_many());
            }
        }
    }
    found.sort_by_key(|set| (set.len(), set.bits()));
    Ok(found)
}

/// Immutable resources a node's children require that could be prepared ahead.
fn preparation_pool(model: &CostModel<'_>, node: usize) -> ResourceSet {
    let workflow = model.workflow;
    model.tree.get(node).map_or(ResourceSet::EMPTY, |entry| {
        entry
            .children
            .iter()
            .filter_map(|child| model.tree.get(*child))
            .fold(ResourceSet::EMPTY, |set, child| {
                set.union(workflow.stages[child.stage].requires)
            })
            .intersection(workflow.immutables())
    })
}

/// Every subset of `pool` within the preparation budget, smallest first.
fn subsets_within(
    model: &CostModel<'_>,
    pool: ResourceSet,
) -> Result<Vec<ResourceSet>, TransitionError> {
    let members: Vec<usize> = pool.iter().collect();
    if members.len() >= 20 {
        return Err(TransitionError::Internal {
            what: "too many resources to prepare at one node",
        });
    }
    let budget = model.workflow.budgets.max_preparation_bytes;
    let mut found = Vec::new();
    for mask in 0u64..(1u64 << members.len()) {
        let mut set = ResourceSet::EMPTY;
        for (bit, at) in members.iter().enumerate() {
            if mask & (1u64 << bit) != 0 {
                set = set.with(*at);
            }
        }
        if model.workflow.bytes(set) <= budget {
            found.push(set);
        }
    }
    found.sort_by_key(|set| (set.len(), set.bits()));
    Ok(found)
}

#[derive(Clone, Debug)]
enum Valued {
    Feasible { cost: f64, prefetch: ResourceSet },
    Infeasible(Infeasibility),
}

#[derive(Clone, Debug)]
enum Best {
    Feasible {
        cost: f64,
        config: ResourceSet,
        copies: ResourceSet,
        ranked: Vec<(ResourceSet, f64)>,
    },
    Infeasible(Infeasibility),
}

struct Searcher<'s, 'a> {
    model: &'s mut CostModel<'a>,
    width: Option<usize>,
    configs: HashMap<usize, Vec<ResourceSet>>,
    values: HashMap<(usize, ResourceSet, ResourceSet), Valued>,
    bests: HashMap<(usize, Context), Best>,
}

impl Searcher<'_, '_> {
    fn configurations(&mut self, node: usize) -> Result<Vec<ResourceSet>, TransitionError> {
        if let Some(found) = self.configs.get(&node) {
            return Ok(found.clone());
        }
        let found = configurations(self.model, node, Knowledge::Declared)?;
        self.configs.insert(node, found.clone());
        Ok(found)
    }

    /// Lookahead for beam ranking: the load seconds the node's children would still pay
    /// with `config` resident.
    fn lookahead(&self, node: usize, config: ResourceSet) -> f64 {
        let model = &*self.model;
        let workflow = model.workflow;
        let Some(entry) = model.tree.get(node) else {
            return 0.0;
        };
        let missing: Vec<f64> = entry
            .children
            .iter()
            .filter_map(|child| model.tree.get(*child))
            .map(|child| {
                let needed = workflow.stages[child.stage]
                    .requires
                    .intersection(workflow.immutables())
                    .difference(config);
                model.load_seconds(workflow.bytes(needed))
            })
            .collect();
        aggregate(entry, &missing)
    }

    fn value(
        &mut self,
        node: usize,
        config: ResourceSet,
        copies: ResourceSet,
    ) -> Result<Valued, TransitionError> {
        let key = (node, config, copies);
        if let Some(found) = self.values.get(&key) {
            return Ok(found.clone());
        }
        let entry = self
            .model
            .tree
            .get(node)
            .ok_or(TransitionError::Internal {
                what: "tree node out of range",
            })?
            .clone();
        if entry.children.is_empty() {
            let leaf = Valued::Feasible {
                cost: 0.0,
                prefetch: ResourceSet::EMPTY,
            };
            self.values.insert(key, leaf.clone());
            return Ok(leaf);
        }
        let pool = preparation_pool(self.model, node).difference(config);
        let mut candidates: Vec<ResourceSet> = subsets_within(self.model, pool)?
            .into_iter()
            .filter(|set| set.iter().all(|at| self.model.prefetchable(at, copies)))
            .collect();
        if let Some(width) = self.width {
            let ranked: Vec<(f64, ResourceSet)> = candidates
                .iter()
                .map(|prefetch| {
                    let saved = self.lookahead(node, config)
                        - self.lookahead(node, config.union(*prefetch));
                    let charge = self.model.workflow.weights.preparation_seconds_per_byte
                        * self.model.workflow.bytes(*prefetch) as f64;
                    (charge - saved, *prefetch)
                })
                .collect();
            let mut ranked = ranked;
            ranked.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.bits().cmp(&b.1.bits())));
            let mut kept: Vec<ResourceSet> = vec![ResourceSet::EMPTY];
            for (_, prefetch) in ranked {
                if kept.len() >= width.max(1) {
                    break;
                }
                if !kept.contains(&prefetch) {
                    kept.push(prefetch);
                }
            }
            candidates = kept;
        }
        let weight = self.model.workflow.weights.preparation_seconds_per_byte;
        let mut best: Option<(f64, ResourceSet)> = None;
        let mut refusal: Option<Infeasibility> = None;
        for prefetch in candidates {
            if let Err(infeasible) = self.model.preparation_fits(node, config, prefetch)? {
                refusal.get_or_insert(infeasible);
                continue;
            }
            let context = self.model.context_after(node, config, prefetch, copies)?;
            let mut costs = Vec::with_capacity(entry.children.len());
            let mut feasible = true;
            for child in &entry.children {
                match self.best(*child, &context)? {
                    Best::Feasible { cost, .. } => costs.push(cost),
                    Best::Infeasible(infeasible) => {
                        refusal.get_or_insert(infeasible);
                        feasible = false;
                        break;
                    }
                }
            }
            if !feasible {
                continue;
            }
            let total =
                weight * self.model.workflow.bytes(prefetch) as f64 + aggregate(&entry, &costs);
            if best.is_none_or(|(current, _)| total < current) {
                best = Some((total, prefetch));
            }
        }
        let valued = match best {
            Some((cost, prefetch)) => Valued::Feasible { cost, prefetch },
            None => Valued::Infeasible(refusal.unwrap_or(Infeasibility::Structure {
                reason: "no preparation option",
            })),
        };
        self.values.insert(key, valued.clone());
        Ok(valued)
    }

    fn best(&mut self, node: usize, context: &Context) -> Result<Best, TransitionError> {
        let key = (node, *context);
        if let Some(found) = self.bests.get(&key) {
            return Ok(found.clone());
        }
        let workflow = self.model.workflow;
        let stage = self.model.tree.get(node).map(|entry| entry.stage).ok_or(
            TransitionError::Internal {
                what: "tree node out of range",
            },
        )?;
        let required = workflow.stages[stage].requires;
        let available = context.resident_before(workflow);
        let mut evaluated: Vec<(ResourceSet, Transition)> = Vec::new();
        let mut refusal: Option<Infeasibility> = None;
        for config in self.configurations(node)? {
            if !config.difference(available).is_subset(required) {
                continue;
            }
            match self
                .model
                .transition(context, node, config, Knowledge::Declared)?
            {
                Ok(transition) => evaluated.push((config, transition)),
                Err(infeasible) => {
                    refusal.get_or_insert(infeasible);
                }
            }
        }
        if let Some(width) = self.width {
            let mut ranked: Vec<(f64, ResourceSet, Transition)> = evaluated
                .into_iter()
                .map(|(config, transition)| {
                    (
                        transition.cost_seconds + self.lookahead(node, config),
                        config,
                        transition,
                    )
                })
                .collect();
            ranked.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.bits().cmp(&b.1.bits())));
            ranked.truncate(width.max(1));
            evaluated = ranked
                .into_iter()
                .map(|(_, config, transition)| (config, transition))
                .collect();
        }
        // A refusal below a feasible transition explains more than a sibling's.
        let mut deeper: Option<Infeasibility> = None;
        let mut ranked: Vec<(ResourceSet, f64, ResourceSet)> = Vec::new();
        for (config, transition) in evaluated {
            match self.value(node, config, transition.copies)? {
                Valued::Feasible { cost, .. } => {
                    ranked.push((config, transition.cost_seconds + cost, transition.copies))
                }
                Valued::Infeasible(infeasible) => {
                    deeper.get_or_insert(infeasible);
                }
            }
        }
        let refusal = deeper.or(refusal);
        ranked.sort_by(|a, b| a.1.total_cmp(&b.1).then(a.0.bits().cmp(&b.0.bits())));
        let best = match ranked.first() {
            Some((config, cost, copies)) => Best::Feasible {
                cost: *cost,
                config: *config,
                copies: *copies,
                ranked: ranked
                    .iter()
                    .take(workflow.limits.max_alternatives)
                    .map(|(config, cost, _)| (*config, *cost))
                    .collect(),
            },
            None => Best::Infeasible(refusal.unwrap_or(Infeasibility::Structure {
                reason: "no configuration",
            })),
        };
        self.bests.insert(key, best.clone());
        Ok(best)
    }

    /// Reads the chosen policy back out of the memo.
    fn reconstruct(&mut self, root: usize, context: Context) -> Result<Searched, TransitionError> {
        let mut decisions = BTreeMap::new();
        let mut alternatives = BTreeMap::new();
        let mut pending = vec![(root, context)];
        while let Some((node, context)) = pending.pop() {
            let Best::Feasible {
                config,
                copies,
                ranked,
                ..
            } = self.best(node, &context)?
            else {
                return Err(TransitionError::Internal {
                    what: "a chosen node is feasible",
                });
            };
            let Valued::Feasible { prefetch, .. } = self.value(node, config, copies)? else {
                return Err(TransitionError::Internal {
                    what: "a chosen configuration is feasible",
                });
            };
            decisions.insert(node, Decision { config, prefetch });
            alternatives.insert(node, ranked);
            let next = self.model.context_after(node, config, prefetch, copies)?;
            let children = self
                .model
                .tree
                .get(node)
                .map(|entry| entry.children.clone())
                .unwrap_or_default();
            for child in children {
                pending.push((child, next));
            }
        }
        Ok(Searched {
            decisions,
            alternatives,
        })
    }
}

/// Searches the subtree at `root`, entered from `context`, with `method`.
pub(crate) fn search(
    model: &mut CostModel<'_>,
    root: usize,
    context: Context,
    method: SearchMethod,
) -> Result<Searched, TransitionError> {
    let width = match method {
        SearchMethod::ExactDp => None,
        SearchMethod::Beam { width } => Some(width),
        SearchMethod::ExhaustiveOracle => return oracle(model, root, context),
    };
    let stage_id = |model: &CostModel<'_>| {
        model
            .tree
            .get(root)
            .map(|entry| model.workflow.stages[entry.stage].id.clone())
    };
    let mut searcher = Searcher {
        model,
        width,
        configs: HashMap::new(),
        values: HashMap::new(),
        bests: HashMap::new(),
    };
    match searcher.best(root, &context)? {
        Best::Infeasible(infeasibility) => Err(TransitionError::NoFeasiblePlan {
            stage: stage_id(searcher.model).ok_or(TransitionError::Internal {
                what: "tree node out of range",
            })?,
            infeasibility,
        }),
        Best::Feasible { .. } => searcher.reconstruct(root, context),
    }
}

/// The nodes of the subtree at `root`, parents before children.
fn subtree(tree: &[TreeNode], root: usize) -> Vec<usize> {
    let mut order = Vec::new();
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        order.push(node);
        if let Some(entry) = tree.get(node) {
            pending.extend(entry.children.iter().rev());
        }
    }
    order
}

/// The exhaustive offline oracle: enumerates every complete policy over every valid
/// configuration and preparation of every node and evaluates each one with [`evaluate`].
fn oracle(
    model: &mut CostModel<'_>,
    root: usize,
    context: Context,
) -> Result<Searched, TransitionError> {
    let nodes = subtree(model.tree, root);
    let mut options: Vec<Vec<Decision>> = Vec::with_capacity(nodes.len());
    for node in &nodes {
        let configs = configurations(model, *node, Knowledge::Declared)?;
        let preparations = subsets_within(model, preparation_pool(model, *node))?;
        let mut list = Vec::with_capacity(configs.len() * preparations.len());
        for config in &configs {
            for prefetch in &preparations {
                if prefetch.intersection(*config).is_empty() {
                    list.push(Decision {
                        config: *config,
                        prefetch: *prefetch,
                    });
                }
            }
        }
        options.push(list);
    }
    let limit = model.workflow.limits.max_oracle_policies;
    let policies = options
        .iter()
        .try_fold(1u128, |total, list| total.checked_mul(list.len() as u128))
        .unwrap_or(u128::MAX);
    if policies > u128::from(limit) {
        return Err(TransitionError::OracleTooLarge { policies, limit });
    }
    let mut indices = vec![0usize; nodes.len()];
    let mut best: Option<(f64, BTreeMap<usize, Decision>)> = None;
    let mut refusal: Option<Infeasibility> = None;
    if options.iter().all(|list| !list.is_empty()) {
        loop {
            let decisions: BTreeMap<usize, Decision> = nodes
                .iter()
                .enumerate()
                .map(|(position, node)| {
                    options
                        .get(position)
                        .and_then(|list| list.get(indices[position]))
                        .map(|decision| (*node, *decision))
                })
                .collect::<Option<BTreeMap<_, _>>>()
                .ok_or(TransitionError::Internal {
                    what: "oracle option out of range",
                })?;
            match evaluate(model, root, context, &decisions)? {
                Ok(evaluation) => {
                    if best
                        .as_ref()
                        .is_none_or(|(cost, _)| evaluation.cost_seconds < *cost)
                    {
                        best = Some((evaluation.cost_seconds, decisions));
                    }
                }
                Err(infeasible) => {
                    refusal.get_or_insert(infeasible);
                }
            }
            // Advance the odometer.
            let mut position = 0;
            loop {
                if position == indices.len() {
                    break;
                }
                indices[position] += 1;
                if indices[position] < options[position].len() {
                    break;
                }
                indices[position] = 0;
                position += 1;
            }
            if position == indices.len() {
                break;
            }
        }
    }
    match best {
        Some((_, decisions)) => Ok(Searched {
            decisions,
            alternatives: BTreeMap::new(),
        }),
        None => Err(TransitionError::NoFeasiblePlan {
            stage: model
                .tree
                .get(root)
                .map(|entry| model.workflow.stages[entry.stage].id.clone())
                .ok_or(TransitionError::Internal {
                    what: "tree node out of range",
                })?,
            infeasibility: refusal.unwrap_or(Infeasibility::Structure {
                reason: "no policy",
            }),
        }),
    }
}

/// Evaluates a complete policy over the subtree at `root`, entered from `context`: every
/// transition, every preparation and the aggregated cost.
pub(crate) fn evaluate(
    model: &mut CostModel<'_>,
    root: usize,
    context: Context,
    decisions: &BTreeMap<usize, Decision>,
) -> Result<Result<Evaluation, Infeasibility>, TransitionError> {
    let mut transitions = BTreeMap::new();
    let cost = evaluate_node(model, root, context, decisions, &mut transitions)?;
    Ok(cost.map(|cost_seconds| Evaluation {
        cost_seconds,
        transitions,
    }))
}

fn evaluate_node(
    model: &mut CostModel<'_>,
    node: usize,
    context: Context,
    decisions: &BTreeMap<usize, Decision>,
    transitions: &mut BTreeMap<usize, (Context, Transition)>,
) -> Result<Result<f64, Infeasibility>, TransitionError> {
    let Some(decision) = decisions.get(&node).copied() else {
        return Ok(Err(Infeasibility::Structure {
            reason: "a node has no decision",
        }));
    };
    let transition = match model.transition(&context, node, decision.config, Knowledge::Declared)? {
        Ok(transition) => transition,
        Err(infeasible) => return Ok(Err(infeasible)),
    };
    let entry = model
        .tree
        .get(node)
        .ok_or(TransitionError::Internal {
            what: "tree node out of range",
        })?
        .clone();
    let copies = transition.copies;
    let own = transition.cost_seconds;
    transitions.insert(node, (context, transition));
    if entry.children.is_empty() {
        if !decision.prefetch.is_empty() {
            return Ok(Err(Infeasibility::Structure {
                reason: "nothing is prepared after the last stage",
            }));
        }
        return Ok(Ok(own));
    }
    let pool = preparation_pool(model, node);
    if !decision.prefetch.intersection(decision.config).is_empty()
        || !decision.prefetch.is_subset(pool)
        || !decision
            .prefetch
            .iter()
            .all(|at| model.prefetchable(at, copies))
    {
        return Ok(Err(Infeasibility::Structure {
            reason: "only missing state a child needs is prepared, by a transfer",
        }));
    }
    if let Err(infeasible) = model.preparation_fits(node, decision.config, decision.prefetch)? {
        return Ok(Err(infeasible));
    }
    let next = model.context_after(node, decision.config, decision.prefetch, copies)?;
    let mut costs = Vec::with_capacity(entry.children.len());
    for child in &entry.children {
        match evaluate_node(model, *child, next, decisions, transitions)? {
            Ok(cost) => costs.push(cost),
            Err(infeasible) => return Ok(Err(infeasible)),
        }
    }
    let charge = model.workflow.weights.preparation_seconds_per_byte
        * model.workflow.bytes(decision.prefetch) as f64;
    Ok(Ok(own + charge + aggregate(&entry, &costs)))
}
