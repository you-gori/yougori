//! The declared workflow and the inputs of GPU §4.15 (lines 846–852), validated into a
//! [`CheckedWorkflow`] and unrolled into a decision tree.
//!
//! - Resources are shared physical state (line 862): one per base, adapter or session
//!   state, keyed by exact identity, never one copy per model. Two resources with the same
//!   identity are refused.
//! - Stages name the resources they require and the session state they produce; the
//!   workflow edges between stages carry branch weights only where evidence supports them
//!   (line 849): either every branch of a stage has observed counts or none has.
//! - Measured curves, budgets, deadlines, the trust scope and the maximum preparation cost
//!   are explicit inputs (lines 850–851). Nothing is clamped into range.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Serialize;

use crate::foundation::ids::{
    validate_identifier, ContentKey, Digest, DigestBuilder, ExecutionId, GpuDeviceKey, IdError,
    TenantId, TrustScope,
};
use crate::model_memory::boundaries::ExternalAction;
use crate::model_memory::identity::{
    AdapterIdentity, ArtifactIdentity, ExecutionIdentity, SessionSpec, TokenState,
};
use crate::model_memory::residency::eviction::CopyTier;
use crate::model_memory::residency::retention::ObjectKind;
use crate::model_memory::residency::Capacity;

use super::recipes::{check_recipe_structure, RecoveryRecipe};
use super::{ResourceSet, TransitionError};

/// Digest domain of [`StateIdentity::digest`].
pub const STATE_DOMAIN: &str = "yougori/model-memory/transitions/state/v1";
/// Digest domain of a checked workflow's fixture digest.
pub const WORKFLOW_DOMAIN: &str = "yougori/model-memory/transitions/workflow/v1";

macro_rules! name_type {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Accepts the shared identifier grammar of `ids::validate_identifier`.
            pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
                let value = value.into();
                validate_identifier(&value)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

name_type!(
    /// One declared resource: a shared physical base, adapter or session state (line 862).
    ResourceKey
);
name_type!(
    /// One stage of the declared workflow (line 848).
    StageId
);

/// The exact identity of a resource (lines 848 and 852; GPU §3.2, §3.9). Equality is by
/// typed identity, never by name or size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StateIdentity {
    /// Immutable base weights in one execution representation, stored as one artifact.
    Base {
        execution: ExecutionIdentity,
        artifact: ArtifactIdentity,
    },
    /// A merged variant: weights of its own, materialized from a base and an adapter
    /// (§3.9, line 634) and named by the merged execution identity. It has no
    /// prerequisites; the merge is a recipe, never a copy (line 307).
    Merged {
        execution: ExecutionIdentity,
        artifact: ArtifactIdentity,
    },
    /// An unmerged adapter on one base execution identity.
    Adapter {
        adapter: AdapterIdentity,
        base: ExecutionIdentity,
    },
    /// One explicit session state (§3.9: mutable session KV kept apart from bases).
    Session { spec: SessionSpec },
}

impl StateIdentity {
    /// The residency object kind this identity is.
    pub fn kind(&self) -> ObjectKind {
        match self {
            Self::Base { .. } => ObjectKind::BaseWeights,
            Self::Merged { .. } => ObjectKind::MergedVariant,
            Self::Adapter { .. } => ObjectKind::Adapter,
            Self::Session { .. } => ObjectKind::SessionKv,
        }
    }

    /// A domain-separated digest of the typed identity.
    pub fn digest(&self) -> Digest {
        let builder = DigestBuilder::new(STATE_DOMAIN);
        match self {
            Self::Base {
                execution,
                artifact,
            } => builder
                .str("base")
                .digest(execution.digest())
                .digest(artifact.digest())
                .finish(),
            Self::Merged {
                execution,
                artifact,
            } => builder
                .str("merged")
                .digest(execution.digest())
                .digest(artifact.digest())
                .finish(),
            Self::Adapter { adapter, base } => builder
                .str("adapter")
                .digest(adapter.digest())
                .digest(base.digest())
                .finish(),
            Self::Session { spec } => builder
                .str("session")
                .digest(spec.identity().digest())
                .finish(),
        }
    }
}

/// One declared resource (lines 848 and 852).
#[derive(Clone, Debug, PartialEq)]
pub struct ResourceDeclaration {
    pub key: ResourceKey,
    pub identity: StateIdentity,
    /// The content key of an immutable representation's bytes (§3.3); `None` for session
    /// KV, whose state is named by its session identity.
    pub content: Option<ContentKey>,
    /// Device bytes while resident; more than zero.
    pub device_bytes: u64,
    /// Resources that must be resident whenever this one is (an adapter's base, a
    /// session's base and adapter).
    pub prerequisites: Vec<ResourceKey>,
    /// How the resource can be materialized again (line 866).
    pub recipes: Vec<RecoveryRecipe>,
    /// For session KV only: the device context of the parked engine that holds the state
    /// between stages. Zero for weights and adapters.
    pub holder_context_bytes: u64,
}

/// The device demand of one stage's engine process (GPU §2.7: each process's context,
/// graph pools, bounded KV and peak workspace).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct StageProcess {
    /// More than zero.
    pub context_bytes: u64,
    pub graph_pool_bytes: u64,
    /// The reserved KV pool; it holds the session the stage consumes or produces.
    pub kv_pool_bytes: u64,
    pub workspace_bytes: u64,
}

/// One stage of the declared workflow (line 848).
#[derive(Clone, Debug, PartialEq)]
pub struct StageDeclaration {
    pub id: StageId,
    /// Exactly one base (with its closure), at most one adapter and at most one consumed
    /// session.
    pub requires: Vec<ResourceKey>,
    /// The session state this stage produces, if any.
    pub produces: Option<ResourceKey>,
    pub process: StageProcess,
    /// Measured time from request to first token with all state ready (line 850).
    pub prefill_seconds: f64,
    /// Measured time from first token to the end of the stage.
    pub decode_seconds: f64,
    /// Measured time to deliver the first token to the client; more than zero.
    pub response_seconds: f64,
    /// A readiness deadline for this stage's first token (line 851).
    pub readiness_deadline_seconds: Option<f64>,
    /// External actions the workflow performs around this stage. The plan never
    /// executes, prepares or authorizes them (S3.6); they are recorded for review only.
    pub external_actions: Vec<ExternalAction>,
}

/// The weight of one workflow edge (line 849).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum BranchWeight {
    /// Observed counts: of `observed` runs that reached the branch point, `taken` took
    /// this edge.
    Evidence { taken: u64, observed: u64 },
    /// No evidence; the planner treats the branch point by its worst case.
    Unknown,
}

/// One workflow dependency edge (line 848).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkflowEdge {
    pub from: StageId,
    pub to: StageId,
    pub weight: BranchWeight,
}

/// A measured transfer curve (line 850): `fixed_seconds + bytes / bytes_per_second`.
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct LoadCurve {
    pub fixed_seconds: f64,
    pub bytes_per_second: f64,
}

impl LoadCurve {
    /// Seconds to move `bytes`.
    pub fn seconds(&self, bytes: u64) -> f64 {
        self.fixed_seconds + bytes as f64 / self.bytes_per_second
    }
}

/// Measured curves and their evidence (line 850).
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct MeasuredCurves {
    /// From a guaranteed host or local-storage copy to the device.
    pub host_to_device: LoadCurve,
    /// From the device back to a guaranteed host copy.
    pub device_to_host: LoadCurve,
    /// The relative half-width of every duration's uncertainty interval, in [0, 1).
    pub relative_spread: f64,
    /// The measured cost of one planner work unit, which charges planning time (line 870).
    pub planning_seconds_per_work_unit: f64,
    /// The longest stretch of a load without a cancellation point (transport batches).
    pub load_cancellation_interval_seconds: f64,
    /// The records the curves were fitted from.
    pub evidence: Digest,
}

/// GPU and host budgets and the maximum preparation cost (line 851).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Budgets {
    pub device: GpuDeviceKey,
    /// The device sub-budget from the CORE-03 ledger; an address reservation is refused.
    pub usable_vram: Capacity,
    /// Room kept for GPU consumers outside the plan; more than zero.
    pub safety_reserve_bytes: u64,
    /// Device staging buffers of one loading process; more than zero.
    pub staging_bytes: u64,
    /// Pinned host or local-storage bytes the plan may hold as written-back copies.
    pub host_copy_bytes: u64,
    /// Where state without a reconstructible copy is written back on eviction; `None`
    /// means such state is retained instead (line 307). The tier must guarantee
    /// availability.
    pub write_back: Option<CopyTier>,
    /// The most bytes prepared speculatively during one stage (the maximum preparation
    /// cost of line 851).
    pub max_preparation_bytes: u64,
}

/// How retained memory and preparation are charged against readiness seconds (line 870).
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct CostWeights {
    /// Seconds charged per retained byte held for one second beyond what a stage needs.
    pub retained_seconds_per_byte_second: f64,
    /// Seconds charged per byte prepared speculatively.
    pub preparation_seconds_per_byte: f64,
}

/// Explicit bounds on planning and replanning (line 862: bounded; line 864: bounded
/// replanning).
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct PlanLimits {
    /// At most [`ResourceSet::MAX_MEMBERS`].
    pub max_resources: usize,
    pub max_tree_nodes: usize,
    pub max_configurations_per_stage: usize,
    pub max_work_units: u64,
    pub beam_width: usize,
    pub max_alternatives: usize,
    pub min_branch_observations: u64,
    pub max_replans: u32,
    /// Relative timing error beyond which a stage counts as drifted; more than zero.
    pub timing_drift_tolerance: f64,
    pub max_oracle_policies: u64,
}

impl Default for PlanLimits {
    fn default() -> Self {
        Self {
            max_resources: 16,
            max_tree_nodes: 64,
            max_configurations_per_stage: 4_096,
            max_work_units: 2_000_000,
            beam_width: 3,
            max_alternatives: 3,
            min_branch_observations: 20,
            max_replans: 4,
            timing_drift_tolerance: 0.25,
            max_oracle_policies: 2_000_000,
        }
    }
}

/// A declared workflow and every input of lines 846–852.
#[derive(Clone, Debug, PartialEq)]
pub struct WorkflowDeclaration {
    /// The parent execution the workflow runs under (S3.1).
    pub execution: ExecutionId,
    pub tenant: TenantId,
    /// The one trust scope every resource is shared in (S3.3).
    pub trust_scope: TrustScope,
    pub resources: Vec<ResourceDeclaration>,
    pub stages: Vec<StageDeclaration>,
    pub edges: Vec<WorkflowEdge>,
    pub root: StageId,
    /// Resources resident when the workflow starts; weights and adapters only.
    pub initial: Vec<ResourceKey>,
    pub budgets: Budgets,
    pub curves: MeasuredCurves,
    pub weights: CostWeights,
    pub limits: PlanLimits,
}

/// Why a declaration was refused.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub enum DeclarationError {
    NoStages,
    TooManyResources {
        count: usize,
        limit: usize,
    },
    DuplicateResource {
        resource: String,
    },
    DuplicateIdentity {
        first: String,
        second: String,
    },
    ZeroBytes {
        resource: String,
    },
    /// Weights and adapters need a content key; session KV must not have one.
    ContentMismatch {
        resource: String,
    },
    /// Only session KV has a holder context, and it must be more than zero.
    HolderContext {
        resource: String,
    },
    UnknownResource {
        field: &'static str,
        resource: String,
    },
    DuplicateReference {
        field: &'static str,
        resource: String,
    },
    PrerequisiteCycle {
        resource: String,
    },
    /// A base or merged variant has prerequisites, an adapter lacks exactly one base, or
    /// a session lacks exactly one weights node.
    PrerequisiteShape {
        resource: String,
    },
    /// Graph pools are part of each stage's process demand here, not retained state.
    UnsupportedKind {
        resource: String,
    },
    /// A session identity of another tenant or parent execution (S3.1, S3.3).
    ForeignSession {
        resource: String,
    },
    /// An identity names another base than its prerequisite.
    BaseMismatch {
        resource: String,
    },
    DuplicateStage {
        stage: String,
    },
    UnknownStage {
        stage: String,
    },
    EmptyRequirement {
        stage: String,
    },
    /// A stage's requirement does not hold exactly one weights node (a base or a merged
    /// variant), at most one adapter and at most one session.
    RequirementShape {
        stage: String,
    },
    /// A produced resource is not session KV, is also required, or lacks its
    /// prerequisites in the requirement.
    ProducedShape {
        stage: String,
    },
    /// The KV pool cannot hold the session the stage consumes or produces.
    KvPoolTooSmall {
        stage: String,
    },
    NoContext {
        stage: String,
    },
    DuplicateEdge {
        from: String,
        to: String,
    },
    RootHasPredecessor {
        stage: String,
    },
    Unreachable {
        stage: String,
    },
    Cycle {
        stage: String,
    },
    /// A branch point mixes evidence and unknown weights (line 849).
    MixedBranchEvidence {
        stage: String,
    },
    /// Branch counts are inconsistent: different totals, a sum other than the total, a
    /// zero count or a single edge not taken every time.
    InconsistentBranchEvidence {
        stage: String,
    },
    /// Too few observations to support probabilities (line 849); declare the weights
    /// unknown instead.
    InsufficientBranchEvidence {
        stage: String,
        observed: u64,
        required: u64,
    },
    /// A stage consumes a session no earlier stage on some path produced.
    SessionNotProduced {
        stage: String,
        session: String,
    },
    /// A stage produces a session that already exists on its path.
    SessionProducedTwice {
        stage: String,
        session: String,
    },
    InitialNotClosed {
        resource: String,
    },
    InitialSession {
        resource: String,
    },
    /// An address reservation supplies no physical capacity (§2.7).
    VirtualCapacity,
    NotPositive {
        field: &'static str,
    },
    NotFinite {
        field: &'static str,
    },
    OutOfRange {
        field: &'static str,
    },
    WriteBackTierNotGuaranteed {
        tier: CopyTier,
    },
    TooManyTreeNodes {
        limit: usize,
    },
}

impl fmt::Display for DeclarationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for DeclarationError {}

/// A validated resource.
#[derive(Clone, Debug, PartialEq)]
pub struct Resource {
    pub(crate) key: ResourceKey,
    pub(crate) identity: StateIdentity,
    pub(crate) digest: Digest,
    pub(crate) kind: ObjectKind,
    pub(crate) content: Option<ContentKey>,
    pub(crate) bytes: u64,
    /// The resource itself and everything it transitively requires.
    pub(crate) closure: ResourceSet,
    pub(crate) recipes: Vec<RecoveryRecipe>,
    pub(crate) holder_context_bytes: u64,
}

impl Resource {
    pub fn key(&self) -> &ResourceKey {
        &self.key
    }

    pub fn identity(&self) -> &StateIdentity {
        &self.identity
    }

    pub fn kind(&self) -> ObjectKind {
        self.kind
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    pub fn recipes(&self) -> &[RecoveryRecipe] {
        &self.recipes
    }

    pub(crate) fn is_session(&self) -> bool {
        self.kind == ObjectKind::SessionKv
    }
}

/// A validated stage.
#[derive(Clone, Debug, PartialEq)]
pub struct Stage {
    pub(crate) id: StageId,
    /// The closure of the requirement.
    pub(crate) requires: ResourceSet,
    pub(crate) consumes: Option<usize>,
    pub(crate) produces: Option<usize>,
    pub(crate) process: StageProcess,
    pub(crate) prefill_seconds: f64,
    pub(crate) decode_seconds: f64,
    pub(crate) response_seconds: f64,
    pub(crate) deadline_seconds: Option<f64>,
    pub(crate) external_actions: Vec<ExternalAction>,
}

impl Stage {
    pub fn id(&self) -> &StageId {
        &self.id
    }

    /// The stage's whole duration, which preparation for its successors overlaps.
    pub fn duration_seconds(&self) -> f64 {
        self.prefill_seconds + self.decode_seconds
    }

    pub fn external_actions(&self) -> &[ExternalAction] {
        &self.external_actions
    }
}

/// How a tree node combines the costs of its children (line 849).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Aggregation {
    Leaf,
    Single,
    /// Probabilities from evidence.
    Expected,
    /// No evidence: the most expensive child counts.
    WorstCase,
}

/// One node of the unrolled decision tree: a stage reached along one path.
#[derive(Clone, Debug, PartialEq)]
pub struct TreeNode {
    pub(crate) stage: usize,
    pub(crate) parent: Option<usize>,
    pub(crate) children: Vec<usize>,
    /// Probabilities of the children for [`Aggregation::Expected`]; empty otherwise.
    pub(crate) weights: Vec<f64>,
    pub(crate) aggregation: Aggregation,
    /// Session states that exist when the stage starts.
    pub(crate) available: ResourceSet,
    /// Session states this stage or a later one on some path below consumes.
    pub(crate) live: ResourceSet,
}

impl TreeNode {
    pub fn stage(&self) -> usize {
        self.stage
    }

    pub fn parent(&self) -> Option<usize> {
        self.parent
    }

    pub fn children(&self) -> &[usize] {
        &self.children
    }

    pub fn aggregation(&self) -> Aggregation {
        self.aggregation
    }
}

/// A validated, indexed workflow with its decision tree.
#[derive(Clone, Debug, PartialEq)]
pub struct CheckedWorkflow {
    pub(crate) execution: ExecutionId,
    pub(crate) tenant: TenantId,
    pub(crate) trust_scope: TrustScope,
    pub(crate) resources: Vec<Resource>,
    pub(crate) stages: Vec<Stage>,
    pub(crate) successors: Vec<Vec<(usize, BranchWeight)>>,
    pub(crate) root: usize,
    pub(crate) initial: ResourceSet,
    pub(crate) budgets: Budgets,
    pub(crate) curves: MeasuredCurves,
    pub(crate) weights: CostWeights,
    pub(crate) limits: PlanLimits,
    pub(crate) tree: Vec<TreeNode>,
    pub(crate) digest: Digest,
}

fn positive_finite(field: &'static str, value: f64) -> Result<f64, DeclarationError> {
    if !value.is_finite() {
        Err(DeclarationError::NotFinite { field })
    } else if value <= 0.0 {
        Err(DeclarationError::NotPositive { field })
    } else {
        Ok(value)
    }
}

fn non_negative_finite(field: &'static str, value: f64) -> Result<f64, DeclarationError> {
    if !value.is_finite() {
        Err(DeclarationError::NotFinite { field })
    } else if value < 0.0 {
        Err(DeclarationError::OutOfRange { field })
    } else {
        Ok(value)
    }
}

impl CheckedWorkflow {
    /// Validates `declaration` (lines 846–852). Every refusal names its field; recipes are
    /// checked structurally here and their holds when a plan is compiled.
    pub fn check(declaration: &WorkflowDeclaration) -> Result<Self, TransitionError> {
        check_numbers(declaration)?;
        let limits = declaration.limits;
        if declaration.resources.len() > limits.max_resources {
            return Err(DeclarationError::TooManyResources {
                count: declaration.resources.len(),
                limit: limits.max_resources,
            }
            .into());
        }
        let resources = check_resources(declaration)?;
        let index: BTreeMap<&ResourceKey, usize> = resources
            .iter()
            .enumerate()
            .map(|(at, resource)| (&resource.key, at))
            .collect();
        for resource in &resources {
            for recipe in &resource.recipes {
                check_recipe_structure(resource, recipe, &index, declaration).map_err(
                    |refusal| TransitionError::Recipe {
                        resource: resource.key.clone(),
                        refusal,
                    },
                )?;
            }
        }
        let stages = check_stages(declaration, &resources, &index)?;
        let stage_index: BTreeMap<&StageId, usize> = stages
            .iter()
            .enumerate()
            .map(|(at, stage)| (&stage.id, at))
            .collect();
        let root =
            *stage_index
                .get(&declaration.root)
                .ok_or_else(|| DeclarationError::UnknownStage {
                    stage: declaration.root.to_string(),
                })?;
        let successors = check_edges(declaration, &stages, &stage_index, root)?;
        let mut initial = ResourceSet::EMPTY;
        for key in &declaration.initial {
            let at = lookup(&index, "initial", key)?;
            if resources[at].is_session() {
                return Err(DeclarationError::InitialSession {
                    resource: key.to_string(),
                }
                .into());
            }
            initial = initial.with(at);
        }
        for at in initial.iter() {
            if !resources[at].closure.is_subset(initial) {
                return Err(DeclarationError::InitialNotClosed {
                    resource: resources[at].key.to_string(),
                }
                .into());
            }
        }
        let digest = workflow_digest(declaration, &resources, &stages);
        let mut workflow = Self {
            execution: declaration.execution.clone(),
            tenant: declaration.tenant.clone(),
            trust_scope: declaration.trust_scope,
            resources,
            stages,
            successors,
            root,
            initial,
            budgets: declaration.budgets,
            curves: declaration.curves,
            weights: declaration.weights,
            limits,
            tree: Vec::new(),
            digest,
        };
        workflow.tree = workflow.unroll(root, ResourceSet::EMPTY)?;
        Ok(workflow)
    }

    /// Unrolls the stage graph from `root_stage` into a tree in which every node is one
    /// path, with the session states that exist at each node and those consumed below it.
    pub(crate) fn unroll(
        &self,
        root_stage: usize,
        available: ResourceSet,
    ) -> Result<Vec<TreeNode>, DeclarationError> {
        let limit = self.limits.max_tree_nodes;
        let mut tree: Vec<TreeNode> = Vec::new();
        let mut pending = vec![(root_stage, None::<usize>, available)];
        while let Some((stage_at, parent, available)) = pending.pop() {
            if tree.len() >= limit {
                return Err(DeclarationError::TooManyTreeNodes { limit });
            }
            let stage = self
                .stages
                .get(stage_at)
                .ok_or(DeclarationError::OutOfRange { field: "stage" })?;
            if let Some(session) = stage.consumes {
                if !available.contains(session) {
                    return Err(DeclarationError::SessionNotProduced {
                        stage: stage.id.to_string(),
                        session: self.resources[session].key.to_string(),
                    });
                }
            }
            if let Some(session) = stage.produces {
                if available.contains(session) {
                    return Err(DeclarationError::SessionProducedTwice {
                        stage: stage.id.to_string(),
                        session: self.resources[session].key.to_string(),
                    });
                }
            }
            let at = tree.len();
            let successors = &self.successors[stage_at];
            let (aggregation, weights) = branch_weights(successors);
            tree.push(TreeNode {
                stage: stage_at,
                parent,
                children: Vec::new(),
                weights,
                aggregation,
                available,
                live: ResourceSet::EMPTY,
            });
            if let Some(parent) = parent {
                tree[parent].children.push(at);
            }
            let mut next = available;
            if let Some(session) = stage.consumes {
                next = next.without(session);
            }
            if let Some(session) = stage.produces {
                next = next.with(session);
            }
            for (child, _) in successors.iter().rev() {
                pending.push((*child, Some(at), next));
            }
        }
        // Children were pushed in declaration order of the edges; restore that order.
        for node in &mut tree {
            node.children.sort_unstable();
        }
        for at in (0..tree.len()).rev() {
            let mut live = self.stages[tree[at].stage]
                .consumes
                .map_or(ResourceSet::EMPTY, ResourceSet::single);
            for child in tree[at].children.clone() {
                live = live.union(tree[child].live);
            }
            tree[at].live = live;
        }
        Ok(tree)
    }

    pub fn resources(&self) -> &[Resource] {
        &self.resources
    }

    pub fn stages(&self) -> &[Stage] {
        &self.stages
    }

    pub fn tree(&self) -> &[TreeNode] {
        &self.tree
    }

    pub fn budgets(&self) -> &Budgets {
        &self.budgets
    }

    pub fn curves(&self) -> &MeasuredCurves {
        &self.curves
    }

    pub fn weights(&self) -> &CostWeights {
        &self.weights
    }

    pub fn limits(&self) -> &PlanLimits {
        &self.limits
    }

    pub fn execution(&self) -> &ExecutionId {
        &self.execution
    }

    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    pub fn trust_scope(&self) -> TrustScope {
        self.trust_scope
    }

    /// A digest of the declared resources and stages, used as the fixture identity of
    /// recorded runs.
    pub fn digest(&self) -> Digest {
        self.digest
    }

    /// Whether every stage has at most one successor (line 862: a short linear workflow).
    pub fn is_linear(&self) -> bool {
        self.successors.iter().all(|next| next.len() <= 1)
    }

    /// The index of the resource named `key`.
    pub fn resource_index(&self, key: &ResourceKey) -> Option<usize> {
        self.resources
            .iter()
            .position(|resource| &resource.key == key)
    }

    /// The index of the stage named `id`.
    pub fn stage_index(&self, id: &StageId) -> Option<usize> {
        self.stages.iter().position(|stage| &stage.id == id)
    }

    /// The resource with exactly this identity digest.
    pub(crate) fn resource_by_digest(&self, digest: &Digest) -> Option<usize> {
        self.resources
            .iter()
            .position(|resource| &resource.digest == digest)
    }

    /// The keys of a set, in index order.
    pub fn keys(&self, set: ResourceSet) -> Vec<ResourceKey> {
        set.iter()
            .filter_map(|at| self.resources.get(at).map(|resource| resource.key.clone()))
            .collect()
    }

    /// The keys of a set as plain strings, for the admission check's allocation names.
    pub(crate) fn keys_of(&self, set: ResourceSet) -> Vec<String> {
        set.iter()
            .filter_map(|at| {
                self.resources
                    .get(at)
                    .map(|resource| resource.key.to_string())
            })
            .collect()
    }

    /// The sources of a derive recipe as a set; empty for any other recipe.
    pub(crate) fn recipe_sources(&self, resource: usize, recipe: usize) -> ResourceSet {
        match self
            .resources
            .get(resource)
            .and_then(|entry| entry.recipes.get(recipe))
        {
            Some(RecoveryRecipe::Derive { sources, .. }) => sources
                .iter()
                .filter_map(|key| self.resource_index(key))
                .fold(ResourceSet::EMPTY, ResourceSet::with),
            _ => ResourceSet::EMPTY,
        }
    }

    pub(crate) fn bytes(&self, set: ResourceSet) -> u64 {
        set.iter()
            .filter_map(|at| self.resources.get(at))
            .fold(0u64, |total, resource| total.saturating_add(resource.bytes))
    }

    pub(crate) fn immutables(&self) -> ResourceSet {
        self.resources
            .iter()
            .enumerate()
            .filter(|(_, resource)| !resource.is_session())
            .fold(ResourceSet::EMPTY, |set, (at, _)| set.with(at))
    }

    /// Whether every member's prerequisites are members too.
    pub(crate) fn is_closed(&self, set: ResourceSet) -> bool {
        set.iter().all(|at| {
            self.resources
                .get(at)
                .is_some_and(|resource| resource.closure.is_subset(set))
        })
    }

    /// The physical device bytes from the CORE-03 ledger.
    pub(crate) fn usable_vram_bytes(&self) -> u64 {
        self.budgets.usable_vram.physical_bytes().unwrap_or(0)
    }

    /// A conservative horizon for holds: every stage on the longest path plus loading
    /// every resource it requires and writing back every session, at the high end of the
    /// uncertainty interval.
    pub fn horizon_seconds(&self) -> f64 {
        let factor = 1.0 + self.curves.relative_spread;
        let session_bytes = self
            .resources
            .iter()
            .filter(|resource| resource.is_session())
            .fold(0u64, |total, resource| total.saturating_add(resource.bytes));
        let write_back = self.curves.device_to_host.seconds(session_bytes);
        let per_stage: Vec<f64> = self
            .stages
            .iter()
            .map(|stage| {
                let load = self
                    .curves
                    .host_to_device
                    .seconds(self.bytes(stage.requires));
                let recompute = stage
                    .requires
                    .iter()
                    .flat_map(|at| self.resources[at].recipes.iter())
                    .map(RecoveryRecipe::compute_seconds)
                    .fold(0.0, f64::max);
                (stage.duration_seconds() + stage.response_seconds + load + recompute + write_back)
                    * factor
            })
            .collect();
        longest_path(&self.tree, &per_stage)
    }

    /// A copy with stage `stage` requiring `requires` instead, validated by the stage
    /// rules (line 864: replanning after an unexpected but declared identity).
    pub(crate) fn with_requirement(
        &self,
        stage: usize,
        requires: ResourceSet,
    ) -> Result<Self, DeclarationError> {
        let mut copy = self.clone();
        let entry = copy
            .stages
            .get_mut(stage)
            .ok_or(DeclarationError::OutOfRange { field: "stage" })?;
        let mut closure = ResourceSet::EMPTY;
        for at in requires.iter() {
            closure = closure.union(self.resources[at].closure);
        }
        let (consumes, ok) = requirement_shape(&self.resources, closure);
        if !ok {
            return Err(DeclarationError::RequirementShape {
                stage: entry.id.to_string(),
            });
        }
        if let Some(produced) = entry.produces {
            let prerequisites = self.resources[produced].closure.without(produced);
            if closure.contains(produced) || !prerequisites.is_subset(closure) {
                return Err(DeclarationError::ProducedShape {
                    stage: entry.id.to_string(),
                });
            }
        }
        entry.requires = closure;
        entry.consumes = consumes;
        Ok(copy)
    }
}

fn longest_path(tree: &[TreeNode], per_stage: &[f64]) -> f64 {
    let mut best = vec![0.0f64; tree.len()];
    for at in (0..tree.len()).rev() {
        let below = tree[at]
            .children
            .iter()
            .map(|child| best[*child])
            .fold(0.0, f64::max);
        best[at] = per_stage.get(tree[at].stage).copied().unwrap_or(0.0) + below;
    }
    best.first().copied().unwrap_or(0.0)
}

fn branch_weights(successors: &[(usize, BranchWeight)]) -> (Aggregation, Vec<f64>) {
    match successors.len() {
        0 => (Aggregation::Leaf, Vec::new()),
        1 => (Aggregation::Single, Vec::new()),
        _ => {
            let weights: Vec<f64> = successors
                .iter()
                .filter_map(|(_, weight)| match weight {
                    BranchWeight::Evidence { taken, observed } => {
                        Some(*taken as f64 / *observed as f64)
                    }
                    BranchWeight::Unknown => None,
                })
                .collect();
            if weights.len() == successors.len() {
                (Aggregation::Expected, weights)
            } else {
                (Aggregation::WorstCase, Vec::new())
            }
        }
    }
}

fn lookup(
    index: &BTreeMap<&ResourceKey, usize>,
    field: &'static str,
    key: &ResourceKey,
) -> Result<usize, DeclarationError> {
    index
        .get(key)
        .copied()
        .ok_or_else(|| DeclarationError::UnknownResource {
            field,
            resource: key.to_string(),
        })
}

fn check_numbers(declaration: &WorkflowDeclaration) -> Result<(), DeclarationError> {
    if declaration.stages.is_empty() {
        return Err(DeclarationError::NoStages);
    }
    let budgets = &declaration.budgets;
    match budgets.usable_vram.physical_bytes() {
        None => return Err(DeclarationError::VirtualCapacity),
        Some(0) => {
            return Err(DeclarationError::NotPositive {
                field: "usable VRAM",
            })
        }
        Some(_) => {}
    }
    if budgets.safety_reserve_bytes == 0 {
        return Err(DeclarationError::NotPositive {
            field: "safety reserve",
        });
    }
    if budgets.staging_bytes == 0 {
        return Err(DeclarationError::NotPositive {
            field: "staging bytes",
        });
    }
    if let Some(tier) = budgets.write_back {
        if !tier.guarantees_availability() {
            return Err(DeclarationError::WriteBackTierNotGuaranteed { tier });
        }
    }
    let curves = &declaration.curves;
    for (field, curve) in [
        ("host-to-device curve", curves.host_to_device),
        ("device-to-host curve", curves.device_to_host),
    ] {
        non_negative_finite(field, curve.fixed_seconds)?;
        positive_finite(field, curve.bytes_per_second)?;
    }
    let spread = non_negative_finite("relative spread", curves.relative_spread)?;
    if spread >= 1.0 {
        return Err(DeclarationError::OutOfRange {
            field: "relative spread",
        });
    }
    non_negative_finite(
        "planning seconds per work unit",
        curves.planning_seconds_per_work_unit,
    )?;
    positive_finite(
        "load cancellation interval",
        curves.load_cancellation_interval_seconds,
    )?;
    non_negative_finite(
        "retained seconds per byte-second",
        declaration.weights.retained_seconds_per_byte_second,
    )?;
    non_negative_finite(
        "preparation seconds per byte",
        declaration.weights.preparation_seconds_per_byte,
    )?;
    let limits = &declaration.limits;
    if limits.max_resources == 0 || limits.max_resources > ResourceSet::MAX_MEMBERS {
        return Err(DeclarationError::OutOfRange {
            field: "max resources",
        });
    }
    for (field, value) in [
        ("max tree nodes", limits.max_tree_nodes),
        (
            "max configurations per stage",
            limits.max_configurations_per_stage,
        ),
        ("beam width", limits.beam_width),
        ("max alternatives", limits.max_alternatives),
    ] {
        if value == 0 {
            return Err(DeclarationError::NotPositive { field });
        }
    }
    if limits.max_work_units == 0 || limits.max_oracle_policies == 0 {
        return Err(DeclarationError::NotPositive {
            field: "work bound",
        });
    }
    if limits.min_branch_observations == 0 {
        return Err(DeclarationError::NotPositive {
            field: "min branch observations",
        });
    }
    positive_finite("timing drift tolerance", limits.timing_drift_tolerance)?;
    for stage in &declaration.stages {
        positive_finite("prefill seconds", stage.prefill_seconds)?;
        non_negative_finite("decode seconds", stage.decode_seconds)?;
        positive_finite("response seconds", stage.response_seconds)?;
        if let Some(deadline) = stage.readiness_deadline_seconds {
            positive_finite("readiness deadline", deadline)?;
        }
    }
    Ok(())
}

fn check_resources(declaration: &WorkflowDeclaration) -> Result<Vec<Resource>, TransitionError> {
    let mut index: BTreeMap<&ResourceKey, usize> = BTreeMap::new();
    let mut digests: BTreeMap<Digest, &ResourceKey> = BTreeMap::new();
    for (at, resource) in declaration.resources.iter().enumerate() {
        if index.insert(&resource.key, at).is_some() {
            return Err(DeclarationError::DuplicateResource {
                resource: resource.key.to_string(),
            }
            .into());
        }
        let digest = resource.identity.digest();
        if let Some(first) = digests.insert(digest, &resource.key) {
            return Err(DeclarationError::DuplicateIdentity {
                first: first.to_string(),
                second: resource.key.to_string(),
            }
            .into());
        }
        let name = || resource.key.to_string();
        if resource.device_bytes == 0 {
            return Err(DeclarationError::ZeroBytes { resource: name() }.into());
        }
        let session = resource.identity.kind() == ObjectKind::SessionKv;
        if session == resource.content.is_some() {
            return Err(DeclarationError::ContentMismatch { resource: name() }.into());
        }
        if session == (resource.holder_context_bytes == 0) {
            return Err(DeclarationError::HolderContext { resource: name() }.into());
        }
        if let StateIdentity::Session { spec } = &resource.identity {
            if spec.tenant != declaration.tenant
                || spec.authority.parent() != &declaration.execution
            {
                return Err(DeclarationError::ForeignSession { resource: name() }.into());
            }
        }
    }
    let mut direct: Vec<ResourceSet> = Vec::with_capacity(declaration.resources.len());
    for resource in &declaration.resources {
        let mut set = ResourceSet::EMPTY;
        for key in &resource.prerequisites {
            let at = lookup(&index, "prerequisite", key)?;
            if set.contains(at) || key == &resource.key {
                return Err(DeclarationError::DuplicateReference {
                    field: "prerequisite",
                    resource: key.to_string(),
                }
                .into());
            }
            set = set.with(at);
        }
        direct.push(set);
    }
    let closures = closures(&declaration.resources, &direct)?;
    let mut resources = Vec::with_capacity(declaration.resources.len());
    for (at, resource) in declaration.resources.iter().enumerate() {
        check_prerequisite_shape(declaration, at, &direct, &closures)?;
        resources.push(Resource {
            key: resource.key.clone(),
            identity: resource.identity.clone(),
            digest: resource.identity.digest(),
            kind: resource.identity.kind(),
            content: resource.content,
            bytes: resource.device_bytes,
            closure: closures[at],
            recipes: resource.recipes.clone(),
            holder_context_bytes: resource.holder_context_bytes,
        });
    }
    Ok(resources)
}

fn closures(
    resources: &[ResourceDeclaration],
    direct: &[ResourceSet],
) -> Result<Vec<ResourceSet>, DeclarationError> {
    let mut result = vec![ResourceSet::EMPTY; resources.len()];
    for start in 0..resources.len() {
        let mut closure = ResourceSet::single(start);
        let mut frontier = direct[start];
        let mut steps = 0usize;
        while !frontier.is_empty() {
            if frontier.contains(start) || steps > resources.len() {
                return Err(DeclarationError::PrerequisiteCycle {
                    resource: resources[start].key.to_string(),
                });
            }
            closure = closure.union(frontier);
            frontier = frontier
                .iter()
                .fold(ResourceSet::EMPTY, |next, at| next.union(direct[at]))
                .difference(closure.without(start));
            steps += 1;
        }
        result[start] = closure;
    }
    Ok(result)
}

fn check_prerequisite_shape(
    declaration: &WorkflowDeclaration,
    at: usize,
    direct: &[ResourceSet],
    closures: &[ResourceSet],
) -> Result<(), DeclarationError> {
    let resource = &declaration.resources[at];
    let kind_of = |index: usize| declaration.resources[index].identity.kind();
    let bases = |set: ResourceSet| {
        set.iter()
            .filter(|index| kind_of(*index) == ObjectKind::BaseWeights)
            .collect::<Vec<_>>()
    };
    let weights = |set: ResourceSet| {
        set.iter()
            .filter(|index| kind_of(*index).is_weights())
            .collect::<Vec<_>>()
    };
    let name = || resource.key.to_string();
    let shape_ok = match resource.identity.kind() {
        ObjectKind::BaseWeights | ObjectKind::MergedVariant => direct[at].is_empty(),
        ObjectKind::Adapter => direct[at].len() == 1 && bases(direct[at]).len() == 1,
        ObjectKind::GraphPool => {
            return Err(DeclarationError::UnsupportedKind { resource: name() })
        }
        ObjectKind::SessionKv => {
            let prerequisites = closures[at].without(at);
            weights(prerequisites).len() == 1
                && prerequisites
                    .iter()
                    .all(|index| kind_of(index) != ObjectKind::SessionKv)
                && prerequisites
                    .iter()
                    .filter(|index| kind_of(*index) == ObjectKind::Adapter)
                    .count()
                    <= 1
        }
    };
    if !shape_ok {
        return Err(DeclarationError::PrerequisiteShape { resource: name() });
    }
    let base_execution = |set: ResourceSet| {
        weights(set)
            .first()
            .and_then(|index| match &declaration.resources[*index].identity {
                StateIdentity::Base { execution, .. } | StateIdentity::Merged { execution, .. } => {
                    Some(*execution)
                }
                _ => None,
            })
    };
    let matches = match &resource.identity {
        StateIdentity::Base { .. } | StateIdentity::Merged { .. } => true,
        StateIdentity::Adapter { base, .. } => base_execution(direct[at]) == Some(*base),
        StateIdentity::Session { spec } => {
            base_execution(closures[at].without(at)) == Some(spec.execution)
        }
    };
    if !matches {
        return Err(DeclarationError::BaseMismatch { resource: name() });
    }
    Ok(())
}

/// The consumed session of a requirement closure and whether its shape is valid: exactly
/// one weights node (a base or a merged variant), at most one adapter and at most one
/// session.
fn requirement_shape(resources: &[Resource], closure: ResourceSet) -> (Option<usize>, bool) {
    let count = |kind: ObjectKind| {
        closure
            .iter()
            .filter(|at| resources[*at].kind == kind)
            .count()
    };
    let session = closure
        .iter()
        .find(|at| resources[*at].kind == ObjectKind::SessionKv);
    let weights = closure
        .iter()
        .filter(|at| resources[*at].kind.is_weights())
        .count();
    let ok = weights == 1 && count(ObjectKind::Adapter) <= 1 && count(ObjectKind::SessionKv) <= 1;
    (session, ok)
}

fn check_stages(
    declaration: &WorkflowDeclaration,
    resources: &[Resource],
    index: &BTreeMap<&ResourceKey, usize>,
) -> Result<Vec<Stage>, TransitionError> {
    let mut seen = BTreeSet::new();
    let mut stages = Vec::with_capacity(declaration.stages.len());
    for stage in &declaration.stages {
        let name = || stage.id.to_string();
        if !seen.insert(&stage.id) {
            return Err(DeclarationError::DuplicateStage { stage: name() }.into());
        }
        if stage.requires.is_empty() {
            return Err(DeclarationError::EmptyRequirement { stage: name() }.into());
        }
        let mut direct = ResourceSet::EMPTY;
        for key in &stage.requires {
            let at = lookup(index, "stage requirement", key)?;
            if direct.contains(at) {
                return Err(DeclarationError::DuplicateReference {
                    field: "stage requirement",
                    resource: key.to_string(),
                }
                .into());
            }
            direct = direct.with(at);
        }
        let closure = direct.iter().fold(ResourceSet::EMPTY, |set, at| {
            set.union(resources[at].closure)
        });
        let (consumes, ok) = requirement_shape(resources, closure);
        if !ok {
            return Err(DeclarationError::RequirementShape { stage: name() }.into());
        }
        let produces = match &stage.produces {
            None => None,
            Some(key) => {
                let at = lookup(index, "produced session", key)?;
                let prerequisites = resources[at].closure.without(at);
                if !resources[at].is_session()
                    || closure.contains(at)
                    || !prerequisites.is_subset(closure)
                {
                    return Err(DeclarationError::ProducedShape { stage: name() }.into());
                }
                Some(at)
            }
        };
        if stage.process.context_bytes == 0 {
            return Err(DeclarationError::NoContext { stage: name() }.into());
        }
        let pool = stage.process.kv_pool_bytes;
        if [consumes, produces]
            .into_iter()
            .flatten()
            .any(|at| resources[at].bytes > pool)
        {
            return Err(DeclarationError::KvPoolTooSmall { stage: name() }.into());
        }
        stages.push(Stage {
            id: stage.id.clone(),
            requires: closure,
            consumes,
            produces,
            process: stage.process,
            prefill_seconds: stage.prefill_seconds,
            decode_seconds: stage.decode_seconds,
            response_seconds: stage.response_seconds,
            deadline_seconds: stage.readiness_deadline_seconds,
            external_actions: stage.external_actions.clone(),
        });
    }
    Ok(stages)
}

fn check_edges(
    declaration: &WorkflowDeclaration,
    stages: &[Stage],
    stage_index: &BTreeMap<&StageId, usize>,
    root: usize,
) -> Result<Vec<Vec<(usize, BranchWeight)>>, DeclarationError> {
    let mut successors: Vec<Vec<(usize, BranchWeight)>> = vec![Vec::new(); stages.len()];
    let mut incoming = vec![0usize; stages.len()];
    let find = |id: &StageId| {
        stage_index
            .get(id)
            .copied()
            .ok_or_else(|| DeclarationError::UnknownStage {
                stage: id.to_string(),
            })
    };
    for edge in &declaration.edges {
        let from = find(&edge.from)?;
        let to = find(&edge.to)?;
        if successors[from].iter().any(|(next, _)| *next == to) {
            return Err(DeclarationError::DuplicateEdge {
                from: edge.from.to_string(),
                to: edge.to.to_string(),
            });
        }
        successors[from].push((to, edge.weight));
        incoming[to] += 1;
    }
    if incoming[root] > 0 {
        return Err(DeclarationError::RootHasPredecessor {
            stage: stages[root].id.to_string(),
        });
    }
    // Depth-first search: 0 unvisited, 1 on the stack, 2 done.
    let mut state = vec![0u8; stages.len()];
    let mut stack = vec![(root, 0usize)];
    state[root] = 1;
    while let Some((at, next)) = stack.pop() {
        if let Some((child, _)) = successors[at].get(next) {
            stack.push((at, next + 1));
            match state[*child] {
                0 => {
                    state[*child] = 1;
                    stack.push((*child, 0));
                }
                1 => {
                    return Err(DeclarationError::Cycle {
                        stage: stages[*child].id.to_string(),
                    })
                }
                _ => {}
            }
        } else {
            state[at] = 2;
        }
    }
    if let Some(unreached) = state.iter().position(|visited| *visited == 0) {
        return Err(DeclarationError::Unreachable {
            stage: stages[unreached].id.to_string(),
        });
    }
    for (at, next) in successors.iter().enumerate() {
        check_weights(
            &stages[at].id,
            next,
            declaration.limits.min_branch_observations,
        )?;
    }
    Ok(successors)
}

fn check_weights(
    stage: &StageId,
    successors: &[(usize, BranchWeight)],
    min_observations: u64,
) -> Result<(), DeclarationError> {
    let name = || stage.to_string();
    let evidence: Vec<(u64, u64)> = successors
        .iter()
        .filter_map(|(_, weight)| match weight {
            BranchWeight::Evidence { taken, observed } => Some((*taken, *observed)),
            BranchWeight::Unknown => None,
        })
        .collect();
    if evidence.is_empty() {
        return Ok(());
    }
    if evidence.len() != successors.len() {
        return Err(DeclarationError::MixedBranchEvidence { stage: name() });
    }
    let observed = evidence[0].1;
    let total = evidence
        .iter()
        .try_fold(0u64, |sum, (taken, _)| sum.checked_add(*taken));
    if evidence
        .iter()
        .any(|(taken, seen)| *taken == 0 || *seen != observed)
        || total != Some(observed)
    {
        return Err(DeclarationError::InconsistentBranchEvidence { stage: name() });
    }
    if successors.len() > 1 && observed < min_observations {
        return Err(DeclarationError::InsufficientBranchEvidence {
            stage: name(),
            observed,
            required: min_observations,
        });
    }
    Ok(())
}

fn workflow_digest(
    declaration: &WorkflowDeclaration,
    resources: &[Resource],
    stages: &[Stage],
) -> Digest {
    let mut builder = DigestBuilder::new(WORKFLOW_DOMAIN)
        .str(declaration.execution.as_str())
        .str(declaration.tenant.as_str());
    for resource in resources {
        builder = builder
            .str(resource.key.as_str())
            .digest(&resource.digest)
            .u64(resource.bytes);
    }
    for stage in stages {
        builder = builder
            .str(stage.id.as_str())
            .u64(stage.requires.bits())
            .u64(stage.produces.map_or(u64::MAX, |at| at as u64));
    }
    for edge in &declaration.edges {
        builder = builder.str(edge.from.as_str()).str(edge.to.as_str());
    }
    builder.finish()
}

/// Whether a session's token state is exactly `prefix` (line 866: a prompt the service
/// holds).
pub(crate) fn session_prefix_matches(
    identity: &StateIdentity,
    prefix: &crate::model_memory::identity::TokenPrefix,
) -> bool {
    match identity {
        StateIdentity::Session { spec } => {
            matches!(&spec.state, TokenState::Prefix(held) if held == prefix)
        }
        _ => false,
    }
}
