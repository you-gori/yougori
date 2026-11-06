//! Adding, writing and releasing nodes (GPU §3.9 lines 632–644).

use std::collections::BTreeSet;

use crate::foundation::ids::{Clock, ContentKey, Digest};
use crate::model_memory::identity::{
    AdaptedModel, AdapterChange, ExecutionSpec, LoraRefusal, MergedAdapter, VersionedName,
};
use crate::model_memory::math::{non_negative, probability};
use crate::model_memory::residency::eviction::ReconstructibleCopy;
use crate::model_memory::residency::retention::{ObjectView, RetentionPolicy};

use super::super::adapter::{check_compatibility, AdapterLimits, AdapterReference};
use super::super::kv::{kv_state_key, KvSharing, StoredKv};
use super::super::merge::MergeJustified;
use super::{
    check_bytes, check_layers, check_restore, restore_seconds, BaseSpec, DependencyGraph,
    GraphError, GraphPoolSpec, Hold, KvRestorePaths, KvWrite, Mutability, NodeData, NodeId,
    SessionKvSpec, SessionState, WeightsResidency, WithoutMerge,
};

fn check_residency(residency: &WeightsResidency) -> Result<(), GraphError> {
    check_bytes(residency.bytes)?;
    non_negative("WeightsResidency.reload_seconds", residency.reload_seconds)?;
    Ok(())
}

fn check_session_state(state: SessionState) -> Result<(), GraphError> {
    if let SessionState::Live { resume_probability } = state {
        probability("SessionState.resume_probability", resume_probability)?;
    }
    Ok(())
}

/// The restore requirement must name the KV's own key as its state, so a recomputation
/// is semantically identical only if it reproduces that key (§2.8).
fn check_kv_state(stored: &StoredKv, restore: &KvRestorePaths) -> Result<(), GraphError> {
    let expected = kv_state_key(stored);
    let actual = restore.requirement.state_identity;
    if actual != expected {
        return Err(GraphError::KvStateMismatch { expected, actual });
    }
    Ok(())
}

impl DependencyGraph {
    fn find_weights(&self, identity: &Digest) -> Option<NodeId> {
        self.nodes()
            .find(|(_, node)| node.data().weights_identity() == Some(*identity))
            .map(|(id, _)| id)
    }

    fn refuse_duplicate(&self, identity: &Digest) -> Result<(), GraphError> {
        match self.find_weights(identity) {
            Some(existing) => Err(GraphError::DuplicateWeights {
                identity: *identity,
                existing,
            }),
            None => Ok(()),
        }
    }

    /// Makes an immutable base resident (line 632) under its T07 execution identity.
    pub fn add_base(&mut self, spec: BaseSpec) -> Result<NodeId, GraphError> {
        check_residency(&spec.residency)?;
        check_layers(&spec.layers)?;
        if spec.execution.logical != spec.logical.identity() {
            return Err(GraphError::LogicalMismatch);
        }
        let identity = spec.execution.identity()?;
        self.refuse_duplicate(identity.digest())?;
        let WeightsResidency {
            content,
            bytes,
            copies,
            reload_seconds,
        } = spec.residency;
        Ok(self.insert(
            NodeData::Base {
                logical: spec.logical,
                execution: spec.execution,
                identity,
                content,
                layers: spec.layers,
                copies,
                reload_seconds,
            },
            bytes,
            BTreeSet::new(),
        ))
    }

    /// Admits an adapter only after [`check_compatibility`] against the resident base
    /// passes (line 632). The adapter depends on the base; the base never depends on it.
    pub fn admit_adapter(
        &mut self,
        base: NodeId,
        reference: AdapterReference,
        limits: &AdapterLimits,
        residency: WeightsResidency,
    ) -> Result<NodeId, GraphError> {
        match &self.get(base)?.data {
            NodeData::Base {
                execution, layers, ..
            } => check_compatibility(&execution.logical, layers, &reference, limits)?,
            _ => return Err(GraphError::NotABase { node: base }),
        }
        check_residency(&residency)?;
        self.refuse_duplicate(reference.adapter.digest())?;
        let WeightsResidency {
            content,
            bytes,
            copies,
            reload_seconds,
        } = residency;
        Ok(self.insert(
            NodeData::Adapter {
                reference,
                content,
                copies,
                reload_seconds,
            },
            bytes,
            BTreeSet::from([base]),
        ))
    }

    /// Materializes a merged variant as a separate node from the canonical base and an
    /// adapter admitted for it (line 634). Its identity is T07's: the base's logical
    /// spec with the adapter merged ([`crate::model_memory::identity::LogicalModelSpec::with_merged`])
    /// under the base's execution settings. The base node is not touched, and the
    /// variant does not depend on it: it holds its own weights, keyed by `content`, and
    /// has no copy outside the GPU until one is recorded. Merging needs the
    /// [`MergeJustified`] proof that [`super::super::merge::decide_merge`] made for this
    /// base and adapter; a proof for another pair is refused.
    pub fn materialize_merged(
        &mut self,
        base: NodeId,
        adapter: NodeId,
        procedure: VersionedName,
        content: ContentKey,
        justified: MergeJustified,
    ) -> Result<NodeId, GraphError> {
        let (logical, execution, base_identity) = match &self.get(base)?.data {
            NodeData::Base {
                logical,
                execution,
                identity,
                ..
            } => (logical, execution, *identity),
            _ => return Err(GraphError::NotABase { node: base }),
        };
        let reference = match &self.get(adapter)?.data {
            NodeData::Adapter { reference, .. } if reference.base == execution.logical => reference,
            NodeData::Adapter { .. } => {
                return Err(GraphError::AdapterNotForBase { adapter, base });
            }
            _ => return Err(GraphError::NotAnAdapter { node: adapter }),
        };
        let adapter_identity = reference.adapter;
        if justified.base() != base_identity || justified.adapter() != adapter_identity {
            return Err(GraphError::ProofForAnotherMerge {
                base: justified.base(),
                adapter: justified.adapter(),
            });
        }
        let variant_logical = logical.with_merged(MergedAdapter {
            adapter: adapter_identity,
            scale: reference.scale,
            procedure,
        });
        let variant_execution = ExecutionSpec {
            logical: variant_logical.identity(),
            ..execution.clone()
        };
        let identity = variant_execution.identity()?;
        self.refuse_duplicate(identity.digest())?;
        Ok(self.insert(
            NodeData::MergedVariant {
                logical: variant_logical,
                execution: variant_execution,
                identity,
                base: base_identity,
                adapter: adapter_identity,
                content,
                copies: Vec::new(),
                materialize_seconds: justified.materialize_seconds(),
            },
            justified.variant_bytes(),
            BTreeSet::new(),
        ))
    }

    /// Where to get the model without a variant's last merged adapter (line 634).
    /// Subtracting it is T07's refused change
    /// ([`LoraRefusal::SubtractionIsNotExactUndo`]), which names the identity to load
    /// instead; that is the resident, untouched node of that identity if there is one.
    pub fn without_merge(&self, variant: NodeId) -> Result<WithoutMerge, GraphError> {
        let (logical, adapter) = match &self.get(variant)?.data {
            NodeData::MergedVariant {
                logical, adapter, ..
            } => (logical, *adapter),
            _ => return Err(GraphError::NotAVariant { node: variant }),
        };
        let subtraction =
            AdaptedModel::base(logical.clone()).apply(&AdapterChange::SubtractMerged(adapter));
        let load_instead = match subtraction {
            Err(LoraRefusal::SubtractionIsNotExactUndo { load_instead }) => load_instead,
            Err(refusal) => return Err(GraphError::Lora(refusal)),
            Ok(_) => return Err(GraphError::NotAVariant { node: variant }),
        };
        Ok(self
            .nodes()
            .find(|(_, node)| {
                node.data()
                    .model()
                    .is_some_and(|(_, logical)| logical == load_instead)
            })
            .map_or(WithoutMerge::Load(load_instead), |(id, _)| {
                WithoutMerge::Resident(id)
            }))
    }

    /// Adds a captured graph pool over immutable weights (line 641). A graph pool never
    /// depends on mutable session KV.
    pub fn add_graph_pool(&mut self, spec: GraphPoolSpec) -> Result<NodeId, GraphError> {
        check_bytes(spec.bytes)?;
        non_negative("GraphPoolSpec.recapture_seconds", spec.recapture_seconds)?;
        if spec.prerequisites.is_empty() {
            return Err(GraphError::NoPrerequisites);
        }
        for prerequisite in &spec.prerequisites {
            if self.get(*prerequisite)?.kind().mutability() == Mutability::Mutable {
                return Err(GraphError::MutablePrerequisite {
                    node: *prerequisite,
                });
            }
        }
        Ok(self.insert(
            NodeData::GraphPool {
                execution_key: spec.execution_key,
                recapture_seconds: spec.recapture_seconds,
            },
            spec.bytes,
            spec.prerequisites,
        ))
    }

    /// Adds session KV computed by resident weights: a base or a merged variant, plus
    /// the unmerged adapter its key names, admitted for those weights (line 632). The KV
    /// depends on them, never the other way round.
    pub fn add_session_kv(&mut self, spec: SessionKvSpec) -> Result<NodeId, GraphError> {
        check_bytes(spec.bytes)?;
        check_session_state(spec.state)?;
        check_restore(&spec.restore)?;
        let Some((model, logical)) = self.get(spec.weights)?.data.model() else {
            return Err(GraphError::KvModelMismatch { node: spec.weights });
        };
        if model != spec.stored.spec.scope.model {
            return Err(GraphError::KvModelMismatch { node: spec.weights });
        }
        let mut prerequisites = BTreeSet::from([spec.weights]);
        match (spec.adapter, spec.stored.spec.scope.adapter) {
            (None, None) => {}
            (Some(node), Some(expected)) => match &self.get(node)?.data {
                NodeData::Adapter { reference, .. }
                    if reference.adapter == expected && reference.base == logical =>
                {
                    prerequisites.insert(node);
                }
                _ => return Err(GraphError::KvAdapterMismatch),
            },
            _ => return Err(GraphError::KvAdapterMismatch),
        }
        check_kv_state(&spec.stored, &spec.restore)?;
        Ok(self.insert(
            NodeData::SessionKv {
                stored: spec.stored,
                state: spec.state,
                restore: spec.restore,
                copies: spec.copies,
            },
            spec.bytes,
            prerequisites,
        ))
    }

    /// Writes session KV. Every other node is immutable and refuses, so shared base
    /// weights are never written (lines 632 and 634); shared public-prefix KV is never
    /// extended either. The new state has no copy outside the GPU, so the KV is dirty
    /// until one is recorded.
    pub fn write_kv(&mut self, node: NodeId, write: KvWrite) -> Result<(), GraphError> {
        check_bytes(write.bytes)?;
        check_restore(&write.restore)?;
        let entry = self.get_mut(node)?;
        let kind = entry.kind();
        match &mut entry.data {
            NodeData::SessionKv {
                stored,
                state,
                restore,
                ..
            } => {
                if *state == SessionState::Dead {
                    return Err(GraphError::SessionEnded { node });
                }
                if let KvSharing::PublicPrefix { .. } = stored.sharing {
                    return Err(GraphError::SharedKvIsReadOnly { node });
                }
                let mut updated = stored.clone();
                updated.spec.scope.prefix = write.token_prefix;
                check_kv_state(&updated, &write.restore)?;
                *stored = updated;
                *restore = write.restore;
                entry.bytes = write.bytes;
                Ok(())
            }
            _ => Err(GraphError::Immutable { node, kind }),
        }
    }

    /// Ends a session: its KV becomes dead and its lease is released. A pin stays,
    /// because pinning is an explicit choice (line 641).
    pub fn end_session(&mut self, node: NodeId) -> Result<(), GraphError> {
        let entry = self.get_mut(node)?;
        match &mut entry.data {
            NodeData::SessionKv { state, .. } => {
                *state = SessionState::Dead;
                if let Hold::Leased { .. } = entry.hold {
                    entry.hold = Hold::Unheld;
                }
                Ok(())
            }
            _ => Err(GraphError::NotSessionKv { node }),
        }
    }

    /// Updates how likely a live session is to resume (line 642).
    pub fn set_resume_probability(
        &mut self,
        node: NodeId,
        resume_probability: f64,
    ) -> Result<(), GraphError> {
        probability("SessionState.resume_probability", resume_probability)?;
        let entry = self.get_mut(node)?;
        match &mut entry.data {
            NodeData::SessionKv {
                state: SessionState::Dead,
                ..
            } => Err(GraphError::SessionEnded { node }),
            NodeData::SessionKv { state, .. } => {
                *state = SessionState::Live { resume_probability };
                Ok(())
            }
            _ => Err(GraphError::NotSessionKv { node }),
        }
    }

    /// Sets the lease or pin of a node (§1.1 line 304; line 644).
    pub fn set_hold(&mut self, node: NodeId, hold: Hold) -> Result<(), GraphError> {
        self.get_mut(node)?.hold = hold;
        Ok(())
    }

    /// Records one request that needed `nodes`, and tells `policy` about each node it
    /// used, prerequisites first and each once, as T08's retention protocol has it: the
    /// request step advances by one, and every node used directly or as a prerequisite
    /// counts one more use at that step (§1.1 line 304: each dependent's request also
    /// refreshes its shared base). Returns the new step. Nothing changes on refusal.
    pub fn record_request(
        &mut self,
        nodes: &[NodeId],
        policy: &mut dyn RetentionPolicy,
    ) -> Result<u64, GraphError> {
        let mut used = BTreeSet::new();
        for node in nodes {
            self.get(*node)?;
            used.insert(*node);
            used.extend(self.prerequisites_of(*node));
        }
        let step = self.step.checked_add(1).ok_or(GraphError::Overflow)?;
        // Prerequisites were added first, so ascending node order puts them first.
        let mut views = Vec::with_capacity(used.len());
        for id in used {
            let node = self.get(id)?;
            let reload_seconds = restore_seconds(node.data())?.unwrap_or(0.0);
            views.push((
                id,
                id.retention_key(),
                node.kind(),
                node.bytes,
                reload_seconds,
            ));
        }
        self.step = step;
        for (id, key, kind, bytes, reload_seconds) in views {
            let entry = self.get_mut(id)?;
            entry.uses = entry.uses.saturating_add(1);
            entry.last_use_step = step;
            let use_count = entry.uses;
            policy.on_use(
                &ObjectView {
                    key: &key,
                    kind: kind.retention_kind(),
                    bytes,
                    reload_seconds,
                    last_use_step: step,
                    use_count,
                    protected: true,
                    evictable: false,
                },
                step,
            );
        }
        Ok(step)
    }

    /// Records a copy outside the GPU, in T08's terms (§1.1 line 307; line 643): of
    /// weights, or of a session KV state, such as a verified copy back. A copy counts
    /// for eviction only while it is verified for the node's current content and sits in
    /// a tier that guarantees availability; a graph pool has no copies.
    pub fn record_copy(
        &mut self,
        node: NodeId,
        copy: ReconstructibleCopy,
    ) -> Result<(), GraphError> {
        let entry = self.get_mut(node)?;
        match &mut entry.data {
            NodeData::Base { copies, .. }
            | NodeData::Adapter { copies, .. }
            | NodeData::MergedVariant { copies, .. }
            | NodeData::SessionKv { copies, .. } => {
                copies.push(copy);
                Ok(())
            }
            NodeData::GraphPool { .. } => Err(GraphError::NoCopies { node }),
        }
    }

    /// Releases `nodes` and returns the bytes freed. Every dependent of a released node
    /// must be released with it, and no leased or pinned node is released
    /// (lines 640–644). Nothing changes when the release is refused.
    pub fn release(
        &mut self,
        nodes: &BTreeSet<NodeId>,
        clock: &dyn Clock,
    ) -> Result<u64, GraphError> {
        let now = clock.now();
        let mut freed_bytes = 0u64;
        for id in nodes {
            let node = self.get(*id)?;
            if node.hold.is_active(now) {
                return Err(GraphError::Held { node: *id });
            }
            if let Some(dependent) = self
                .dependents(*id)
                .into_iter()
                .find(|dependent| !nodes.contains(dependent))
            {
                return Err(GraphError::DependentStillResident {
                    node: *id,
                    dependent,
                });
            }
            freed_bytes = freed_bytes
                .checked_add(node.bytes)
                .ok_or(GraphError::Overflow)?;
        }
        for id in nodes {
            if let Some(node) = self.nodes.remove(id) {
                for prerequisite in &node.prerequisites {
                    if let Some(dependents) = self.dependents.get_mut(prerequisite) {
                        dependents.remove(id);
                    }
                }
            }
            self.dependents.remove(id);
        }
        Ok(freed_bytes)
    }
}
