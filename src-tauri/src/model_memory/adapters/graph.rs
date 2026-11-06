//! The dependency graph of resident model state (GPU §3.9 lines 632–644; §1.1 line 304).
//!
//! Immutable nodes (bases, adapters, merged variants and graph pools) are kept apart
//! from mutable session KV (line 632): only session KV accepts writes, and no immutable
//! node may depend on mutable state. An adapter becomes a node only after the
//! compatibility check, and a merged variant only with a
//! [`super::merge::MergeJustified`] proof made for that base and adapter, as a separate
//! node whose identity comes from T07's `LogicalModelSpec::with_merged`; the base is left
//! untouched (line 634). Nodes are released per node, never as one model unit
//! (line 304); releasing a node requires releasing everything that depends on it.
//!
//! What a node's GPU bytes hold, and the copies outside the GPU, are T08's
//! [`Content`] and [`ReconstructibleCopy`], so the clean-eviction rule of
//! [`crate::model_memory::residency::eviction`] decides every release without a copy
//! back (§1.1 line 307; line 643).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::foundation::ids::{ContentKey, Digest, LeaseId, MonotonicTime};
use crate::model_memory::identity::{
    AdapterIdentity, ExecutionIdentity, ExecutionSpec, IdentityError, LogicalModelIdentity,
    LogicalModelSpec, LoraRefusal, TokenPrefix,
};
use crate::model_memory::math::recompute::{
    choose_kv_restore, classify_discard, KvRecompute, KvRequirement, KvTransfer, RecomputeError,
};
use crate::model_memory::math::{non_negative, InputError};
use crate::model_memory::residency::eviction::{
    Content, ContentState, GpuCopy, ReconstructibleCopy, Verification,
};
use crate::model_memory::residency::retention::ObjectKind;

use super::adapter::{is_layer_name, AdapterReference, AdapterRefusal, LayerTable};
use super::kv::{kv_state_key, StoredKv};

/// One node, numbered in insertion order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(u64);

impl NodeId {
    pub fn get(self) -> u64 {
        self.0
    }

    /// The node's key for T08's retention policies; key order is node order.
    pub fn retention_key(self) -> String {
        format!("node-{:020}", self.0)
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "node {}", self.0)
    }
}

/// What keeps a node resident whatever its retention value (§1.1 line 304; line 644).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hold {
    Unheld,
    /// An execution lease from the coordination authority, active until `until`.
    Leased {
        lease: LeaseId,
        until: MonotonicTime,
    },
    Pinned,
}

impl Hold {
    /// True while the hold keeps the node resident.
    pub fn is_active(self, now: MonotonicTime) -> bool {
        match self {
            Self::Unheld => false,
            Self::Leased { until, .. } => now < until,
            Self::Pinned => true,
        }
    }
}

/// Whether a node's content may change after creation (line 632).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mutability {
    Immutable,
    Mutable,
}

/// What a node is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NodeKind {
    Base,
    Adapter,
    MergedVariant,
    GraphPool,
    SessionKv,
}

impl NodeKind {
    /// Only session KV is mutable (line 632).
    pub fn mutability(self) -> Mutability {
        match self {
            Self::SessionKv => Mutability::Mutable,
            _ => Mutability::Immutable,
        }
    }

    /// The kind T08's retention policies see, one to one. T08's policies rank by bytes,
    /// cost and use; the kind carries the object's prerequisite and copy semantics
    /// (`ObjectKind`): a merged variant is a base to its sessions and keeps no source
    /// base resident, and a graph pool goes with its weights node rather than holding it.
    pub fn retention_kind(self) -> ObjectKind {
        match self {
            Self::Base => ObjectKind::BaseWeights,
            Self::Adapter => ObjectKind::Adapter,
            Self::MergedVariant => ObjectKind::MergedVariant,
            Self::GraphPool => ObjectKind::GraphPool,
            Self::SessionKv => ObjectKind::SessionKv,
        }
    }
}

/// Whether a session will use its KV again (lines 641–642).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SessionState {
    Live {
        resume_probability: f64,
    },
    /// The session has ended; its KV has no further use.
    Dead,
}

/// How a KV state could be restored after release (§2.8 line 461), in the terms of
/// [`crate::model_memory::math::recompute`]. These price the return only: whether the
/// GPU copy may go without a copy back is decided by the node's copies.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct KvRestorePaths {
    pub requirement: KvRequirement,
    /// Transferring the exact state back from a reconstructible copy: one that exists,
    /// or the one a copy back would make.
    pub transfer: Option<KvTransfer>,
    pub recompute: Option<KvRecompute>,
}

/// Residency facts of immutable weights.
#[derive(Clone, Debug, PartialEq)]
pub struct WeightsResidency {
    /// Key of the exact bytes resident on the GPU, which T08 sees as
    /// `Content::Immutable`.
    pub content: ContentKey,
    pub bytes: u64,
    /// Copies outside the GPU, in T08's terms: only a verified copy in pinned host RAM or
    /// local storage lets the GPU copy go without a copy back (§1.1 line 307; line 643).
    pub copies: Vec<ReconstructibleCopy>,
    /// Seconds to load the weights again after release.
    pub reload_seconds: f64,
}

/// A base model to make resident (line 632), with T07's specs so that merged variants
/// derive their identities from it.
#[derive(Clone, Debug, PartialEq)]
pub struct BaseSpec {
    pub logical: LogicalModelSpec,
    /// Its `logical` field must be the identity of `logical`.
    pub execution: ExecutionSpec,
    pub layers: LayerTable,
    pub residency: WeightsResidency,
}

/// A captured graph pool and the immutable weights it was captured over (line 641).
#[derive(Clone, Debug, PartialEq)]
pub struct GraphPoolSpec {
    pub execution_key: Digest,
    pub bytes: u64,
    pub recapture_seconds: f64,
    pub prerequisites: BTreeSet<NodeId>,
}

/// Session KV to make resident (line 632).
#[derive(Clone, Debug, PartialEq)]
pub struct SessionKvSpec {
    pub stored: StoredKv,
    pub bytes: u64,
    /// The base or merged variant that computed the KV.
    pub weights: NodeId,
    /// The unmerged adapter applied on top, if any.
    pub adapter: Option<NodeId>,
    pub state: SessionState,
    pub restore: KvRestorePaths,
    /// Copies of KV states outside the GPU, in T08's terms. Only a verified copy of the
    /// current state ([`kv_state_key`]) in pinned host RAM or local storage lets the GPU
    /// copy go without a copy back; KV computed on the GPU has none.
    pub copies: Vec<ReconstructibleCopy>,
}

/// A write to session KV: the prefix grew, and with it the bytes and restore paths.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct KvWrite {
    pub bytes: u64,
    pub token_prefix: TokenPrefix,
    pub restore: KvRestorePaths,
}

/// What a node holds.
#[derive(Clone, Debug, PartialEq)]
pub enum NodeData {
    Base {
        logical: LogicalModelSpec,
        execution: ExecutionSpec,
        identity: ExecutionIdentity,
        content: ContentKey,
        layers: LayerTable,
        copies: Vec<ReconstructibleCopy>,
        reload_seconds: f64,
    },
    Adapter {
        reference: AdapterReference,
        content: ContentKey,
        copies: Vec<ReconstructibleCopy>,
        reload_seconds: f64,
    },
    MergedVariant {
        logical: LogicalModelSpec,
        execution: ExecutionSpec,
        identity: ExecutionIdentity,
        base: ExecutionIdentity,
        adapter: AdapterIdentity,
        content: ContentKey,
        copies: Vec<ReconstructibleCopy>,
        materialize_seconds: f64,
    },
    GraphPool {
        execution_key: Digest,
        recapture_seconds: f64,
    },
    SessionKv {
        stored: StoredKv,
        state: SessionState,
        restore: KvRestorePaths,
        copies: Vec<ReconstructibleCopy>,
    },
}

impl NodeData {
    pub fn kind(&self) -> NodeKind {
        match self {
            Self::Base { .. } => NodeKind::Base,
            Self::Adapter { .. } => NodeKind::Adapter,
            Self::MergedVariant { .. } => NodeKind::MergedVariant,
            Self::GraphPool { .. } => NodeKind::GraphPool,
            Self::SessionKv { .. } => NodeKind::SessionKv,
        }
    }

    /// The T07 identity digest of immutable weights; `None` for graph pools and session
    /// KV.
    pub fn weights_identity(&self) -> Option<Digest> {
        match self {
            Self::Base { identity, .. } | Self::MergedVariant { identity, .. } => {
                Some(*identity.digest())
            }
            Self::Adapter { reference, .. } => Some(*reference.adapter.digest()),
            Self::GraphPool { .. } | Self::SessionKv { .. } => None,
        }
    }

    /// What the node's GPU bytes hold, in T08's terms: weights by the key of their
    /// bytes, session KV by its current state key ([`kv_state_key`]). `None` for a graph
    /// pool, which is captured again rather than copied.
    pub fn content(&self) -> Option<Content> {
        match self {
            Self::Base { content, .. }
            | Self::Adapter { content, .. }
            | Self::MergedVariant { content, .. } => Some(Content::Immutable(*content)),
            Self::SessionKv { stored, .. } => Some(Content::SessionState(kv_state_key(stored))),
            Self::GraphPool { .. } => None,
        }
    }

    /// Copies outside the GPU, in T08's terms; none for a graph pool.
    pub fn copies(&self) -> &[ReconstructibleCopy] {
        match self {
            Self::Base { copies, .. }
            | Self::Adapter { copies, .. }
            | Self::MergedVariant { copies, .. }
            | Self::SessionKv { copies, .. } => copies,
            Self::GraphPool { .. } => &[],
        }
    }

    /// The execution and logical identities of a model a session can run: a base or a
    /// merged variant.
    pub fn model(&self) -> Option<(ExecutionIdentity, LogicalModelIdentity)> {
        match self {
            Self::Base {
                identity,
                execution,
                ..
            }
            | Self::MergedVariant {
                identity,
                execution,
                ..
            } => Some((*identity, execution.logical)),
            _ => None,
        }
    }
}

/// One resident node. Read-only outside the graph.
#[derive(Clone, Debug, PartialEq)]
pub struct Node {
    data: NodeData,
    bytes: u64,
    prerequisites: BTreeSet<NodeId>,
    hold: Hold,
    last_use_step: u64,
    uses: u64,
}

impl Node {
    pub fn data(&self) -> &NodeData {
        &self.data
    }

    pub fn kind(&self) -> NodeKind {
        self.data.kind()
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// The nodes this one cannot be used without.
    pub fn prerequisites(&self) -> &BTreeSet<NodeId> {
        &self.prerequisites
    }

    pub fn hold(&self) -> Hold {
        self.hold
    }

    /// The request step that last needed the node ([`DependencyGraph::record_request`]).
    pub fn last_use_step(&self) -> u64 {
        self.last_use_step
    }

    pub fn uses(&self) -> u64 {
        self.uses
    }

    /// The node's GPU copy for T08's clean-eviction rule (§1.1 line 307). Weights are
    /// immutable, so always clean. Session KV is clean only while a copy is verified to
    /// hold its current state: every write makes a new state that no copy holds yet.
    /// `None` for a graph pool.
    pub fn gpu_copy(&self) -> Option<GpuCopy> {
        let content = self.data.content()?;
        let state = match &self.data {
            NodeData::SessionKv { copies, .. }
                if !copies
                    .iter()
                    .any(|copy| copy.verification == Verification::Verified { content }) =>
            {
                ContentState::Dirty
            }
            _ => ContentState::Clean,
        };
        Some(GpuCopy {
            content,
            state,
            bytes: self.bytes,
        })
    }
}

/// Where the model without a merged adapter comes from (line 634): the untouched base
/// or an earlier variant, never subtraction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WithoutMerge {
    /// Resident and untouched.
    Resident(NodeId),
    /// Load this identity from its own immutable artifact.
    Load(LogicalModelIdentity),
}

/// Why the graph refused a change.
#[derive(Clone, Debug, PartialEq)]
pub enum GraphError {
    UnknownNode {
        node: NodeId,
    },
    Input(InputError),
    /// A T07 identity could not be built.
    Identity(IdentityError),
    /// The execution spec names another logical model than the one given.
    LogicalMismatch,
    InvalidLayer {
        layer: String,
    },
    ZeroBytes,
    /// Weights of this identity are already resident; identical representations share
    /// one copy (§3.2 line 504).
    DuplicateWeights {
        identity: Digest,
        existing: NodeId,
    },
    NotABase {
        node: NodeId,
    },
    NotAnAdapter {
        node: NodeId,
    },
    NotAVariant {
        node: NodeId,
    },
    /// The adapter failed the compatibility check before admission (line 632).
    AdapterRefused(AdapterRefusal),
    /// The adapter was admitted for another base.
    AdapterNotForBase {
        adapter: NodeId,
        base: NodeId,
    },
    /// The merge proof was made for another base or adapter (line 634).
    ProofForAnotherMerge {
        base: ExecutionIdentity,
        adapter: AdapterIdentity,
    },
    /// T07 refused an adapter change, such as subtracting a merged adapter (line 634).
    Lora(LoraRefusal),
    /// An immutable node cannot depend on mutable session KV (line 632).
    MutablePrerequisite {
        node: NodeId,
    },
    NoPrerequisites,
    /// The KV was not computed by these weights.
    KvModelMismatch {
        node: NodeId,
    },
    /// The KV's adapter is not this adapter node, or not one admitted for its weights.
    KvAdapterMismatch,
    /// The restore requirement names another state than the KV's key.
    KvStateMismatch {
        expected: Digest,
        actual: Digest,
    },
    /// Only session KV accepts writes (lines 632 and 634).
    Immutable {
        node: NodeId,
        kind: NodeKind,
    },
    /// Public-prefix KV is shared across tenants, so no session extends it.
    SharedKvIsReadOnly {
        node: NodeId,
    },
    NotSessionKv {
        node: NodeId,
    },
    /// A graph pool is captured again, never copied.
    NoCopies {
        node: NodeId,
    },
    SessionEnded {
        node: NodeId,
    },
    /// A node cannot be released while something that depends on it stays.
    DependentStillResident {
        node: NodeId,
        dependent: NodeId,
    },
    /// A leased or pinned node cannot be released.
    Held {
        node: NodeId,
    },
    Overflow,
}

impl From<InputError> for GraphError {
    fn from(error: InputError) -> Self {
        Self::Input(error)
    }
}

impl From<IdentityError> for GraphError {
    fn from(error: IdentityError) -> Self {
        Self::Identity(error)
    }
}

impl From<AdapterRefusal> for GraphError {
    fn from(refusal: AdapterRefusal) -> Self {
        Self::AdapterRefused(refusal)
    }
}

impl fmt::Display for GraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownNode { node } => write!(f, "{node} does not exist"),
            Self::Input(error) => error.fmt(f),
            Self::Identity(error) => error.fmt(f),
            Self::LogicalMismatch => f.write_str("the execution spec names another logical model"),
            Self::InvalidLayer { layer } => write!(f, "invalid layer {layer:?}"),
            Self::ZeroBytes => f.write_str("a resident node needs more than zero bytes"),
            Self::DuplicateWeights { identity, existing } => {
                write!(f, "weights {identity} are already resident as {existing}")
            }
            Self::NotABase { node } => write!(f, "{node} is not a base"),
            Self::NotAnAdapter { node } => write!(f, "{node} is not an adapter"),
            Self::NotAVariant { node } => write!(f, "{node} is not a merged variant"),
            Self::AdapterRefused(refusal) => write!(f, "adapter refused: {refusal}"),
            Self::AdapterNotForBase { adapter, base } => {
                write!(f, "{adapter} was not admitted for {base}")
            }
            Self::ProofForAnotherMerge { base, adapter } => write!(
                f,
                "the merge proof was made for adapter {adapter} on base {base}"
            ),
            Self::Lora(refusal) => refusal.fmt(f),
            Self::MutablePrerequisite { node } => {
                write!(f, "an immutable node cannot depend on mutable {node}")
            }
            Self::NoPrerequisites => f.write_str("the node needs at least one prerequisite"),
            Self::KvModelMismatch { node } => write!(f, "the KV was not computed by {node}"),
            Self::KvAdapterMismatch => f.write_str("the KV's adapter does not match"),
            Self::KvStateMismatch { expected, actual } => write!(
                f,
                "the restore requirement names state {actual}, not the KV's key {expected}"
            ),
            Self::Immutable { node, kind } => {
                write!(f, "{node} is an immutable {kind:?} and is never written")
            }
            Self::SharedKvIsReadOnly { node } => {
                write!(f, "{node} is shared public-prefix KV and is never extended")
            }
            Self::NotSessionKv { node } => write!(f, "{node} is not session KV"),
            Self::NoCopies { node } => {
                write!(
                    f,
                    "{node} is a graph pool, captured again rather than copied"
                )
            }
            Self::SessionEnded { node } => write!(f, "the session of {node} has ended"),
            Self::DependentStillResident { node, dependent } => {
                write!(
                    f,
                    "{node} cannot be released while {dependent} depends on it"
                )
            }
            Self::Held { node } => write!(f, "{node} is leased or pinned"),
            Self::Overflow => f.write_str("the byte total does not fit in 64 bits"),
        }
    }
}

impl std::error::Error for GraphError {}

mod build;

/// Resident nodes and their dependencies (lines 632–644). Prerequisites must exist
/// before a node is added and never change, so the graph has no cycles.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DependencyGraph {
    nodes: BTreeMap<NodeId, Node>,
    dependents: BTreeMap<NodeId, BTreeSet<NodeId>>,
    next_id: u64,
    step: u64,
}

impl DependencyGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn node(&self, id: NodeId) -> Option<&Node> {
        self.nodes.get(&id)
    }

    /// The number of requests recorded so far; T08's policies count time in these steps.
    pub fn step(&self) -> u64 {
        self.step
    }

    /// Every node that `id` cannot be used without, directly or through others.
    pub fn prerequisites_of(&self, id: NodeId) -> BTreeSet<NodeId> {
        let mut found = BTreeSet::new();
        let mut pending = vec![id];
        while let Some(current) = pending.pop() {
            if let Some(node) = self.nodes.get(&current) {
                for prerequisite in &node.prerequisites {
                    if found.insert(*prerequisite) {
                        pending.push(*prerequisite);
                    }
                }
            }
        }
        found
    }

    pub fn nodes(&self) -> impl Iterator<Item = (NodeId, &Node)> {
        self.nodes.iter().map(|(id, node)| (*id, node))
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Every node that depends on `id`, directly or through others.
    pub fn dependents(&self, id: NodeId) -> BTreeSet<NodeId> {
        let mut found = BTreeSet::new();
        let mut pending = vec![id];
        while let Some(current) = pending.pop() {
            if let Some(direct) = self.dependents.get(&current) {
                for dependent in direct {
                    if found.insert(*dependent) {
                        pending.push(*dependent);
                    }
                }
            }
        }
        found
    }

    /// Bytes of every resident node, each counted once.
    pub fn resident_bytes(&self) -> Result<u64, GraphError> {
        self.nodes.values().try_fold(0u64, |total, node| {
            total.checked_add(node.bytes).ok_or(GraphError::Overflow)
        })
    }

    pub(crate) fn get(&self, id: NodeId) -> Result<&Node, GraphError> {
        self.nodes
            .get(&id)
            .ok_or(GraphError::UnknownNode { node: id })
    }

    fn get_mut(&mut self, id: NodeId) -> Result<&mut Node, GraphError> {
        self.nodes
            .get_mut(&id)
            .ok_or(GraphError::UnknownNode { node: id })
    }

    fn insert(&mut self, data: NodeData, bytes: u64, prerequisites: BTreeSet<NodeId>) -> NodeId {
        self.next_id += 1;
        let id = NodeId(self.next_id);
        for prerequisite in &prerequisites {
            self.dependents.entry(*prerequisite).or_default().insert(id);
        }
        self.dependents.entry(id).or_default();
        self.nodes.insert(
            id,
            Node {
                data,
                bytes,
                prerequisites,
                hold: Hold::Unheld,
                last_use_step: 0,
                uses: 0,
            },
        );
        id
    }
}

/// Seconds to bring a node back after release: the reload, materialization or recapture
/// time, nothing for dead KV, and for live KV the cheapest exact restore (§2.8).
/// `None` for live KV without an exact restore path, which is required context rather
/// than cache.
pub(crate) fn restore_seconds(data: &NodeData) -> Result<Option<f64>, InputError> {
    Ok(match data {
        NodeData::Base { reload_seconds, .. } | NodeData::Adapter { reload_seconds, .. } => {
            Some(*reload_seconds)
        }
        NodeData::MergedVariant {
            materialize_seconds,
            ..
        } => Some(*materialize_seconds),
        NodeData::GraphPool {
            recapture_seconds, ..
        } => Some(*recapture_seconds),
        NodeData::SessionKv {
            state: SessionState::Dead,
            ..
        } => Some(0.0),
        NodeData::SessionKv { restore, .. } => {
            let transfer = restore.transfer.as_ref();
            let recompute = restore.recompute.as_ref();
            let discard = classify_discard(&restore.requirement, transfer, recompute);
            if discard.authorize_cache_eviction().is_err() {
                return Ok(None);
            }
            match choose_kv_restore(&restore.requirement, transfer, recompute) {
                Ok(decision) => Some(decision.completion_seconds),
                Err(RecomputeError::Input(error)) => return Err(error),
                Err(_) => None,
            }
        }
    })
}

fn check_bytes(bytes: u64) -> Result<u64, GraphError> {
    if bytes == 0 {
        return Err(GraphError::ZeroBytes);
    }
    Ok(bytes)
}

/// Refuses invalid restore numbers on entry, including those of a recomputation that
/// would be refused, so no later pass meets them (§2.8).
fn check_restore(restore: &KvRestorePaths) -> Result<(), GraphError> {
    if let Some(transfer) = &restore.transfer {
        non_negative("KvTransfer.queue_seconds", transfer.queue_seconds)?;
        non_negative("KvTransfer.transfer_seconds", transfer.transfer_seconds)?;
    }
    if let Some(recompute) = &restore.recompute {
        non_negative("KvRecompute.queue_seconds", recompute.queue_seconds)?;
        non_negative("KvRecompute.compute_seconds", recompute.compute_seconds)?;
    }
    Ok(())
}

fn check_layers(layers: &LayerTable) -> Result<(), GraphError> {
    for (layer, shape) in layers {
        if !is_layer_name(layer) || shape.input_features == 0 || shape.output_features == 0 {
            return Err(GraphError::InvalidLayer {
                layer: layer.clone(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
