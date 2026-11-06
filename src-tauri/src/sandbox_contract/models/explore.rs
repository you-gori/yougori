//! Bounded exhaustive enumeration of a small transition system (§12.3: "bounded model
//! checking or exhaustive small-state enumeration before adopting a heavier prover").
//!
//! Breadth-first search from the initial states visits every reachable state once, so the
//! first state found violating an invariant ends a shortest counterexample (fewest
//! actions). Invariants are predicates over states; properties about histories use ghost
//! fields that the model sets on the offending transition.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;
use std::hash::Hash;

use serde::Serialize;

use super::contract::{InvariantId, ModelKind};
use super::ModelError;

/// The bounds of one exploration (§12.3 "state the model's assumptions and state-space
/// bounds"). A depth bound that cuts the search leaves [`Exploration::complete`] false;
/// exceeding the state bound is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct Bounds {
    pub max_depth: usize,
    pub max_states: usize,
}

impl Bounds {
    /// Large enough for every model in this module to be explored completely.
    pub const DEFAULT: Self = Self {
        max_depth: 64,
        max_states: 100_000,
    };
}

/// A finite transition system with named invariants.
pub trait TransitionSystem {
    type State: Clone + Eq + Hash + fmt::Debug;
    type Action: Clone + fmt::Display;

    fn kind(&self) -> ModelKind;
    fn initial_states(&self) -> Vec<Self::State>;
    fn successors(&self, state: &Self::State) -> Vec<(Self::Action, Self::State)>;
    fn holds(&self, invariant: InvariantId, state: &Self::State) -> bool;
}

/// A sequence of actions from an initial state, and the state it ends in.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct Trace {
    pub steps: Vec<String>,
    pub final_state: String,
}

/// An invariant that fails in a reachable state, with a shortest trace to such a state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Violation {
    pub invariant: InvariantId,
    pub trace: Trace,
}

/// The result of one exploration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Exploration {
    pub model: ModelKind,
    /// Distinct reachable states visited.
    pub states: usize,
    /// Transitions examined, including those to states already visited.
    pub transitions: usize,
    /// The longest shortest path to a visited state.
    pub depth: usize,
    /// Every reachable state was visited (the depth bound did not cut the search).
    pub complete: bool,
    /// Violated invariants, in [`InvariantId`] order, each with a shortest trace.
    pub violations: Vec<Violation>,
}

impl Exploration {
    pub fn violation(&self, invariant: InvariantId) -> Option<&Violation> {
        self.violations
            .iter()
            .find(|violation| violation.invariant == invariant)
    }

    /// No reachable state within the bounds violates `invariant`.
    pub fn holds(&self, invariant: InvariantId) -> bool {
        self.violation(invariant).is_none()
    }

    pub fn is_clean(&self) -> bool {
        self.violations.is_empty()
    }
}

struct Node<S, A> {
    state: S,
    parent: Option<(usize, A)>,
    depth: usize,
}

/// The visited states of one search and the first violating state of each invariant.
struct Search<'m, M: TransitionSystem> {
    model: &'m M,
    bounds: Bounds,
    index: HashMap<M::State, usize>,
    nodes: Vec<Node<M::State, M::Action>>,
    found: BTreeMap<InvariantId, usize>,
}

impl<M: TransitionSystem> Search<'_, M> {
    fn admit(
        &mut self,
        state: M::State,
        parent: Option<(usize, M::Action)>,
        depth: usize,
    ) -> Result<usize, ModelError> {
        if self.nodes.len() >= self.bounds.max_states {
            return Err(ModelError::StateBoundExceeded {
                model: self.model.kind(),
                max_states: self.bounds.max_states,
            });
        }
        let at = self.nodes.len();
        for invariant in self.model.kind().invariants() {
            if !self.found.contains_key(invariant) && !self.model.holds(*invariant, &state) {
                self.found.insert(*invariant, at);
            }
        }
        self.index.insert(state.clone(), at);
        self.nodes.push(Node {
            state,
            parent,
            depth,
        });
        Ok(at)
    }
}

/// Explores every state reachable from `model`'s initial states within `bounds`.
pub fn explore<M: TransitionSystem>(model: &M, bounds: Bounds) -> Result<Exploration, ModelError> {
    let mut search = Search {
        model,
        bounds,
        index: HashMap::new(),
        nodes: Vec::new(),
        found: BTreeMap::new(),
    };
    let mut queue = VecDeque::new();
    let mut transitions = 0usize;
    let mut depth = 0usize;
    let mut complete = true;
    for state in model.initial_states() {
        if search.index.contains_key(&state) {
            continue;
        }
        queue.push_back(search.admit(state, None, 0)?);
    }
    while let Some(at) = queue.pop_front() {
        let here = search.nodes[at].depth;
        for (action, next) in model.successors(&search.nodes[at].state) {
            transitions += 1;
            if search.index.contains_key(&next) {
                continue;
            }
            if here >= bounds.max_depth {
                complete = false;
                continue;
            }
            queue.push_back(search.admit(next, Some((at, action)), here + 1)?);
            depth = depth.max(here + 1);
        }
    }
    let violations = search
        .found
        .iter()
        .map(|(invariant, at)| Violation {
            invariant: *invariant,
            trace: trace_to(&search.nodes, *at),
        })
        .collect();
    Ok(Exploration {
        model: model.kind(),
        states: search.nodes.len(),
        transitions,
        depth,
        complete,
        violations,
    })
}

fn trace_to<S: fmt::Debug, A: fmt::Display>(nodes: &[Node<S, A>], at: usize) -> Trace {
    let mut steps = Vec::new();
    let mut cursor = at;
    while let Some((parent, action)) = &nodes[cursor].parent {
        steps.push(action.to_string());
        cursor = *parent;
    }
    steps.reverse();
    Trace {
        steps,
        final_state: format!("{:?}", nodes[at].state),
    }
}

/// Whether a scripted step must be available (setup) or may be refused (an attack the
/// model is expected to block).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum ScriptStep {
    Setup(&'static str),
    Attack(&'static str),
}

impl ScriptStep {
    pub fn action(self) -> &'static str {
        match self {
            Self::Setup(action) | Self::Attack(action) => action,
        }
    }
}

/// The result of running a fixed script (a hand-written probe) on a model.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ScriptOutcome {
    /// Steps applied.
    pub executed: usize,
    /// The attack step the model refused, if any; the script stops there.
    pub refused_at: Option<usize>,
    /// Invariants violated after some step, with the first such step (1-based).
    pub violations: Vec<(InvariantId, usize)>,
}

/// Runs `steps` from the model's first initial state, matching each step to an offered
/// action by its display text. A setup step that is not offered aborts the script.
pub fn run_steps<M: TransitionSystem>(
    model: &M,
    steps: &[ScriptStep],
) -> Result<ScriptOutcome, ModelError> {
    let invariants = model.kind().invariants();
    let mut state = model
        .initial_states()
        .into_iter()
        .next()
        .ok_or(ModelError::ScriptAborted {
            step: 0,
            action: "initial state".to_string(),
        })?;
    let mut outcome = ScriptOutcome {
        executed: 0,
        refused_at: None,
        violations: Vec::new(),
    };
    for (position, step) in steps.iter().enumerate() {
        let next = model
            .successors(&state)
            .into_iter()
            .find(|(action, _)| action.to_string() == step.action());
        match (next, step) {
            (Some((_, next)), _) => state = next,
            (None, ScriptStep::Attack(_)) => {
                outcome.refused_at = Some(position + 1);
                break;
            }
            (None, ScriptStep::Setup(action)) => {
                return Err(ModelError::ScriptAborted {
                    step: position + 1,
                    action: (*action).to_string(),
                })
            }
        }
        outcome.executed += 1;
        for invariant in invariants {
            let seen = outcome.violations.iter().any(|(id, _)| id == invariant);
            if !seen && !model.holds(*invariant, &state) {
                outcome.violations.push((*invariant, position + 1));
            }
        }
    }
    Ok(outcome)
}

/// Every subset of `0..n` with 1 to `max_size` elements, smallest first and in
/// lexicographic order within a size.
pub(super) fn subsets(n: usize, max_size: usize) -> Vec<Vec<usize>> {
    let mut all = Vec::new();
    for size in 1..=max_size.min(n) {
        let mut chosen: Vec<usize> = (0..size).collect();
        loop {
            all.push(chosen.clone());
            // Advance the rightmost index that can still move.
            let Some(slot) = (0..size).rev().find(|&slot| chosen[slot] < n - size + slot) else {
                break;
            };
            chosen[slot] += 1;
            for later in slot + 1..size {
                chosen[later] = chosen[later - 1] + 1;
            }
        }
    }
    all
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subsets_come_smallest_first_without_repeats() {
        let all = subsets(4, 2);
        assert_eq!(all.len(), 4 + 6);
        assert_eq!(all[0], vec![0]);
        assert_eq!(all[4], vec![0, 1]);
        assert_eq!(all[9], vec![2, 3]);
        assert_eq!(subsets(3, 5).len(), 7);
        assert!(subsets(0, 3).is_empty());
    }
}
