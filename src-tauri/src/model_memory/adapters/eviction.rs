//! Dependency-aware eviction: the five rules of GPU §3.9 lines 640–644 as policy over
//! the [`DependencyGraph`] (§1.1 line 304), on T08's clean-eviction rule and retention
//! policies ([`crate::model_memory::residency`]).
//!
//! 1. An idle adapter is released without its frequently used base: a node is released
//!    only once nothing resident depends on it, so releasing a dependent never takes its
//!    prerequisite, and a base that a held node needs is held with it.
//! 2. Dead session KV goes first, while the base and graph pool stay.
//!    A graph pool never keeps its weights node resident (T08's
//!    `ObjectKind::GraphPool`): the node is a legal victim with its pools resident, and
//!    a plan releases them first.
//! 3. Costly long-prefix KV that is likely to resume, and that a resident engine can
//!    use, is retained.
//! 4. Clean weights are parked without a device-to-host copy only when T08's
//!    [`eviction_action`] finds a verified copy of the same content in pinned host RAM
//!    or local storage. Otherwise they are copied back first, into a tier that
//!    guarantees availability, or kept when no copy back is configured.
//! 5. When leased, pinned or retained state leaves too little to release, the request
//!    queues: [`plan_eviction`] decides that before choosing any victim, releases
//!    nothing, and never retries.
//!
//! Live session KV passes the same clean-eviction rule over its current state
//! ([`Content::SessionState`](crate::model_memory::residency::eviction::Content)): it is
//! dropped only against a verified copy of that state in pinned host RAM or local
//! storage, and otherwise copied back or kept. It is never dropped to be recomputed;
//! recomputation (§2.8) only prices its return. Live KV with no exact way back is
//! required context and stays (line 461). After dead KV, every victim is chosen by a T08
//! [`RetentionPolicy`], one at a time among the nodes it may legally take; this module
//! never ranks retention value itself.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::foundation::ids::{Clock, LeaseId};
use crate::model_memory::math::{non_negative, probability, InputError};
use crate::model_memory::residency::eviction::{
    eviction_action, CopyTier, EvictionAction as CleanEviction, NotDroppable, WriteBack,
};
use crate::model_memory::residency::retention::{ObjectView, RetentionPolicy};

use super::graph::{
    restore_seconds, DependencyGraph, Hold, Node, NodeData, NodeId, NodeKind, SessionState,
};
use super::kv::EngineKvProfile;

/// Thresholds of rule 3 (line 642), which the plan does not give and are therefore
/// required configuration, and where state without a reconstructible copy is copied
/// back (line 643).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct EvictionPolicy {
    /// "Likely to resume": the least resume probability that retains KV.
    pub min_resume_probability: f64,
    /// "Costly": the least completion of the cheapest exact restore, in seconds.
    pub min_restore_seconds: f64,
    /// "Long-prefix": the fewest prefix tokens.
    pub min_prefix_tokens: u64,
    /// Where state without a reconstructible copy is copied back before release. The
    /// tier must guarantee availability, as pinned host RAM and local storage do (§1.1
    /// line 307, §3.4); `None` keeps such state resident.
    pub copy_back_tier: Option<CopyTier>,
}

impl EvictionPolicy {
    fn write_back(&self) -> WriteBack {
        match self.copy_back_tier {
            Some(_) => WriteBack::Available,
            None => WriteBack::Unavailable,
        }
    }

    fn check(&self) -> Result<(), EvictionError> {
        probability(
            "EvictionPolicy.min_resume_probability",
            self.min_resume_probability,
        )?;
        non_negative(
            "EvictionPolicy.min_restore_seconds",
            self.min_restore_seconds,
        )?;
        match self.copy_back_tier {
            Some(tier) if !tier.guarantees_availability() => {
                Err(EvictionError::CopyBackTierNotGuaranteed { tier })
            }
            _ => Ok(()),
        }
    }
}

/// What the waiting request needs (line 644).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EvictionRequest {
    pub needed_bytes: u64,
    /// Resident nodes the request will use. They, and everything they depend on, are
    /// never released to make room for it.
    pub uses: BTreeSet<NodeId>,
}

impl EvictionRequest {
    /// `needed_bytes` for a request that uses no resident node.
    pub fn bytes(needed_bytes: u64) -> Self {
        Self {
            needed_bytes,
            uses: BTreeSet::new(),
        }
    }
}

/// Why a node stays resident in a plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HoldReason {
    Leased {
        lease: LeaseId,
    },
    Pinned,
    /// The waiting request uses the node.
    UsedByRequest,
    /// Rule 3 (line 642).
    LikelyToResume,
    /// Live KV with no exact way back (§2.8 line 461).
    RequiredContext,
    /// T08's clean-eviction rule keeps the node: it may not be dropped, and no copy back
    /// is configured (line 643, §1.1 line 307).
    CannotCopyBack {
        because: NotDroppable,
    },
    /// A held node depends on this one.
    DependentHeld {
        dependent: NodeId,
    },
}

/// One release in a plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvictionAction {
    /// Rule 2: KV of an ended session (line 641).
    DropDeadKv { node: NodeId, bytes: u64 },
    /// Rule 4: state that `source` holds exactly, released without a device-to-host
    /// copy (line 643): clean weights, or live KV whose current state has a verified
    /// copy there.
    ParkWithoutCopyBack {
        node: NodeId,
        bytes: u64,
        source: CopyTier,
    },
    /// State without a reconstructible copy, copied back to `to` before release.
    CopyBackThenRelease {
        node: NodeId,
        bytes: u64,
        to: CopyTier,
        because: NotDroppable,
    },
    /// A graph pool, captured again on demand.
    ReleaseGraphPool { node: NodeId, bytes: u64 },
}

impl EvictionAction {
    pub fn node(self) -> NodeId {
        match self {
            Self::DropDeadKv { node, .. }
            | Self::ParkWithoutCopyBack { node, .. }
            | Self::CopyBackThenRelease { node, .. }
            | Self::ReleaseGraphPool { node, .. } => node,
        }
    }

    pub fn bytes(self) -> u64 {
        match self {
            Self::DropDeadKv { bytes, .. }
            | Self::ParkWithoutCopyBack { bytes, .. }
            | Self::CopyBackThenRelease { bytes, .. }
            | Self::ReleaseGraphPool { bytes, .. } => bytes,
        }
    }

    /// Device-to-host bytes the release moves first.
    pub fn copy_back_bytes(self) -> u64 {
        match self {
            Self::CopyBackThenRelease { bytes, .. } => bytes,
            _ => 0,
        }
    }
}

/// Releases that free at least the needed bytes, in the order chosen, which always
/// puts dependents before their prerequisites.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvictionPlan {
    pub actions: Vec<EvictionAction>,
    pub freed_bytes: u64,
    /// Bytes copied from device to host before release.
    pub copy_back_bytes: u64,
}

impl EvictionPlan {
    /// The released nodes, for [`DependencyGraph::release`].
    pub fn nodes(&self) -> BTreeSet<NodeId> {
        self.actions.iter().map(|action| action.node()).collect()
    }
}

/// Rule 5: why the request waits (line 644).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueReason {
    pub needed_bytes: u64,
    /// Everything a plan could release, each node counted once.
    pub releasable_bytes: u64,
    pub held: BTreeMap<NodeId, HoldReason>,
}

/// Release now, or queue (line 644).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvictionOutcome {
    Release(EvictionPlan),
    Queue(QueueReason),
}

/// Why no outcome was produced.
#[derive(Clone, Debug, PartialEq)]
pub enum EvictionError {
    Input(InputError),
    Overflow,
    /// The request uses a node that is not resident.
    UnknownNode {
        node: NodeId,
    },
    /// A copy back into this tier would not leave a reconstructible copy (§1.1
    /// line 307).
    CopyBackTierNotGuaranteed {
        tier: CopyTier,
    },
    /// The retention policy named no victim although one was required.
    PolicyChoseNothing {
        policy: String,
    },
    /// The retention policy named a node it may not take now, or an index past the
    /// residents (`node` is then `None`).
    PolicyChoseIneligible {
        policy: String,
        node: Option<NodeId>,
    },
}

impl From<InputError> for EvictionError {
    fn from(error: InputError) -> Self {
        Self::Input(error)
    }
}

impl fmt::Display for EvictionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(error) => error.fmt(f),
            Self::Overflow => f.write_str("the byte total does not fit in 64 bits"),
            Self::UnknownNode { node } => {
                write!(f, "the request uses {node}, which is not resident")
            }
            Self::CopyBackTierNotGuaranteed { tier } => write!(
                f,
                "a copy back to {tier:?} would not leave a reconstructible copy"
            ),
            Self::PolicyChoseNothing { policy } => {
                write!(f, "retention policy {policy} chose no victim")
            }
            Self::PolicyChoseIneligible { policy, node } => write!(
                f,
                "retention policy {policy} chose {node:?}, which may not be released now"
            ),
        }
    }
}

impl std::error::Error for EvictionError {}

/// What one pass learns about each node: why it stays, or how it would be released,
/// and what bringing it back costs.
struct Assessment {
    holds: BTreeMap<NodeId, HoldReason>,
    releases: BTreeMap<NodeId, EvictionAction>,
    restore_seconds: BTreeMap<NodeId, f64>,
}

/// How a node may leave under T08's clean-eviction rule: dropped against a verified copy
/// of its exact content in pinned host RAM or local storage, copied back first, or kept.
/// A graph pool has no copy and is captured again.
fn clean_eviction(
    id: NodeId,
    node: &Node,
    policy: &EvictionPolicy,
) -> Result<EvictionAction, HoldReason> {
    let bytes = node.bytes();
    let Some(gpu) = node.gpu_copy() else {
        return Ok(EvictionAction::ReleaseGraphPool { node: id, bytes });
    };
    let action = eviction_action(&gpu, node.data().copies(), policy.write_back());
    match (action, policy.copy_back_tier) {
        (CleanEviction::DropClean { source }, _) => Ok(EvictionAction::ParkWithoutCopyBack {
            node: id,
            bytes,
            source,
        }),
        (CleanEviction::WriteBackThenDrop { because, .. }, Some(to)) => {
            Ok(EvictionAction::CopyBackThenRelease {
                node: id,
                bytes,
                to,
                because,
            })
        }
        (CleanEviction::WriteBackThenDrop { because, .. }, None)
        | (CleanEviction::Retain { because }, _) => Err(HoldReason::CannotCopyBack { because }),
        (CleanEviction::Recapture, _) => Ok(EvictionAction::ReleaseGraphPool { node: id, bytes }),
    }
}

fn assess(
    graph: &DependencyGraph,
    request: &EvictionRequest,
    clock: &dyn Clock,
    policy: &EvictionPolicy,
    engines: &[EngineKvProfile],
) -> Result<Assessment, EvictionError> {
    let now = clock.now();
    let mut assessment = Assessment {
        holds: BTreeMap::new(),
        releases: BTreeMap::new(),
        restore_seconds: BTreeMap::new(),
    };
    for (id, node) in graph.nodes() {
        let restore = restore_seconds(node.data())?;
        // A node with no known way back reports no cost; it is always held.
        assessment
            .restore_seconds
            .insert(id, restore.unwrap_or(0.0));
        let hold = match node.hold() {
            Hold::Pinned => Some(HoldReason::Pinned),
            hold @ Hold::Leased { lease, .. } if hold.is_active(now) => {
                Some(HoldReason::Leased { lease })
            }
            _ if request.uses.contains(&id) => Some(HoldReason::UsedByRequest),
            _ => None,
        };
        let outcome = match (hold, node.data()) {
            (Some(hold), _) => Err(hold),
            (
                None,
                NodeData::SessionKv {
                    state: SessionState::Dead,
                    ..
                },
            ) => Ok(EvictionAction::DropDeadKv {
                node: id,
                bytes: node.bytes(),
            }),
            (
                None,
                NodeData::SessionKv {
                    stored,
                    state: SessionState::Live { resume_probability },
                    ..
                },
            ) => match restore {
                None => Err(HoldReason::RequiredContext),
                Some(seconds)
                    if *resume_probability >= policy.min_resume_probability
                        && seconds >= policy.min_restore_seconds
                        && stored.spec.scope.prefix.token_count() >= policy.min_prefix_tokens
                        && engines.iter().any(|engine| engine.can_use(&stored.spec)) =>
                {
                    Err(HoldReason::LikelyToResume)
                }
                Some(_) => clean_eviction(id, node, policy),
            },
            (None, _) => clean_eviction(id, node, policy),
        };
        match outcome {
            Ok(release) => {
                assessment.releases.insert(id, release);
            }
            Err(reason) => {
                assessment.holds.insert(id, reason);
            }
        }
    }
    Ok(assessment)
}

/// Plans releases that free at least `request.needed_bytes` under the five rules of
/// lines 640–644, or queues.
///
/// A held node (leased, pinned, used by the request, retained by rule 3, required
/// context, or kept by T08's clean-eviction rule) stays, and so does everything it
/// depends on. If the rest cannot free the bytes, the request queues and nothing is
/// released. Otherwise dead KV goes first, in node order, and then `retention` chooses
/// each further victim among the nodes with no resident dependent other than unheld
/// graph pools, which are released with the victim, before it; the policy sees every
/// resident node once with its own bytes, so a shared base is charged once (line 304).
///
/// The pass runs on a copy of `retention`. With a release plan, `retention` takes that
/// copy's state, as if the plan were carried out: the caller copies back where the plan
/// says, then calls [`DependencyGraph::release`] with [`EvictionPlan::nodes`]. With a
/// queue or an error, `retention` is unchanged.
pub fn plan_eviction<P: RetentionPolicy + Clone>(
    graph: &DependencyGraph,
    request: &EvictionRequest,
    clock: &dyn Clock,
    policy: &EvictionPolicy,
    engines: &[EngineKvProfile],
    retention: &mut P,
) -> Result<EvictionOutcome, EvictionError> {
    policy.check()?;
    if let Some(node) = request
        .uses
        .iter()
        .find(|node| graph.node(**node).is_none())
    {
        return Err(EvictionError::UnknownNode { node: *node });
    }
    let assessment = assess(graph, request, clock, policy, engines)?;
    let mut held = assessment.holds.clone();
    for holder in assessment.holds.keys() {
        for prerequisite in graph.prerequisites_of(*holder) {
            held.entry(prerequisite)
                .or_insert(HoldReason::DependentHeld { dependent: *holder });
        }
    }
    let releasable_bytes = assessment
        .releases
        .iter()
        .filter(|(id, _)| !held.contains_key(id))
        .try_fold(0u64, |total, (_, release)| {
            total
                .checked_add(release.bytes())
                .ok_or(EvictionError::Overflow)
        })?;
    if releasable_bytes < request.needed_bytes {
        return Ok(EvictionOutcome::Queue(QueueReason {
            needed_bytes: request.needed_bytes,
            releasable_bytes,
            held,
        }));
    }

    let mut scratch = retention.clone();
    let keys: BTreeMap<NodeId, String> = graph
        .nodes()
        .map(|(id, _)| (id, id.retention_key()))
        .collect();
    let mut released = BTreeSet::new();
    let mut actions = Vec::new();
    let mut freed_bytes = 0u64;
    let dead_kv = assessment
        .releases
        .values()
        .filter(|release| matches!(release, EvictionAction::DropDeadKv { .. }))
        .filter(|release| !held.contains_key(&release.node()));
    for release in dead_kv {
        if freed_bytes >= request.needed_bytes {
            break;
        }
        freed_bytes = freed_bytes
            .checked_add(release.bytes())
            .ok_or(EvictionError::Overflow)?;
        released.insert(release.node());
        actions.push(*release);
        if let Some(key) = keys.get(&release.node()) {
            scratch.on_evict(key);
        }
    }
    while freed_bytes < request.needed_bytes {
        let mut residents = Vec::new();
        let mut views = Vec::new();
        // A dependent that is released, or an unheld graph pool, does not keep its
        // prerequisite resident.
        let goes_with = |dependent: &NodeId| {
            released.contains(dependent)
                || (!held.contains_key(dependent)
                    && graph
                        .node(*dependent)
                        .is_some_and(|node| node.kind() == NodeKind::GraphPool))
        };
        for (id, node) in graph.nodes().filter(|(id, _)| !released.contains(id)) {
            let protected = held.contains_key(&id);
            residents.push(id);
            views.push(ObjectView {
                key: keys.get(&id).map_or("", String::as_str),
                kind: node.kind().retention_kind(),
                bytes: node.bytes(),
                reload_seconds: assessment.restore_seconds.get(&id).copied().unwrap_or(0.0),
                last_use_step: node.last_use_step(),
                use_count: node.uses(),
                protected,
                evictable: !protected && graph.dependents(id).iter().all(goes_with),
            });
        }
        let victim = match scratch.choose_victim(&views, graph.step()) {
            None => {
                return Err(EvictionError::PolicyChoseNothing {
                    policy: scratch.name().to_string(),
                })
            }
            Some(index) => match (residents.get(index), views.get(index)) {
                (Some(node), Some(view)) if view.evictable => *node,
                (node, _) => {
                    return Err(EvictionError::PolicyChoseIneligible {
                        policy: scratch.name().to_string(),
                        node: node.copied(),
                    })
                }
            },
        };
        // An evictable node is never held, so it has a release.
        let Some(release) = assessment.releases.get(&victim).copied() else {
            return Err(EvictionError::PolicyChoseIneligible {
                policy: scratch.name().to_string(),
                node: Some(victim),
            });
        };
        // The victim's graph pools go first, later nodes before earlier ones, so that a
        // pool over a pool precedes it; an unheld node always has a release.
        let pools: Vec<EvictionAction> = graph
            .dependents(victim)
            .into_iter()
            .rev()
            .filter(|pool| !released.contains(pool))
            .filter_map(|pool| assessment.releases.get(&pool).copied())
            .collect();
        for action in pools.into_iter().chain([release]) {
            freed_bytes = freed_bytes
                .checked_add(action.bytes())
                .ok_or(EvictionError::Overflow)?;
            released.insert(action.node());
            actions.push(action);
            if let Some(key) = keys.get(&action.node()) {
                scratch.on_evict(key);
            }
        }
    }
    let copy_back_bytes = actions.iter().try_fold(0u64, |total, action| {
        total
            .checked_add(action.copy_back_bytes())
            .ok_or(EvictionError::Overflow)
    })?;
    *retention = scratch;
    Ok(EvictionOutcome::Release(EvictionPlan {
        actions,
        freed_bytes,
        copy_back_bytes,
    }))
}

#[cfg(test)]
mod tests;
