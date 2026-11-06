//! Boundary 4 of GPU §3.1: the runner adapter.
//!
//! Responsibility: backend lifecycle, compatibility, readiness and exact execution
//! dependencies. Must not own: a second independent host-wide scheduler. An adapter sees
//! only its own placements: it receives no ledger, governor, coordinator, queue,
//! priority or other runner, so it cannot admit, reorder or reserve anything. It computes
//! only under a lease issued for one of its placements, and serves only requests the
//! flow hands it under an [`ExecutionLease`].
//!
//! Request shapes are placement's (P04): a model can be materialized but not ready for
//! the requested context length (GPU §3.6, line 585), so readiness is checked for a
//! declared [`SupportedShape`]. Every adapter declares a native ABI version in its
//! [`RunnerProfile`]; the flow reaches it only through [`super::NativeAbi::admit`]
//! (line 489).

use std::collections::BTreeSet;
use std::fmt;

use serde::Serialize;

use super::abi::AbiDeclaration;
use super::declaration::{DependencyNode, ExecutionDependencies, NodeId, StateIdentity, StateRef};
use super::governor::{ExecutionLease, PlacementKey, PlacementOwner, PreparationLease};
use super::kv::KvLayout;
use super::preparation::PreparationToken;
use crate::foundation::evidence::Backend;
use crate::foundation::ids::{
    ExecutionCategory, ModelActivationGeneration, MonotonicTime, OperationId, TrustScope,
};
use crate::model_memory::graph::node::NodeKind;
use crate::model_memory::identity::{ExecutionIdentity, Residency, ResidentAdvertisement};
use crate::model_memory::placement::{RequestShape, ShapeRefusal, SupportedShape};
use crate::model_memory::residency::eviction::{CopyTier, EvictionAction};

/// The request's content. It goes to the runner and nowhere else: it has no serde and its
/// `Debug` form hides it, so prompts never reach events or diagnostics (§3.10).
#[derive(Clone, PartialEq, Eq)]
pub struct RequestPayload(Vec<u8>);

impl RequestPayload {
    pub fn new(content: Vec<u8>) -> Self {
        Self(content)
    }

    pub fn content(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for RequestPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RequestPayload(<{} bytes redacted>)", self.0.len())
    }
}

/// Why a runner cannot take a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum Incompatibility {
    /// The runner does not support this exact execution identity.
    UnsupportedModel,
    /// The request is outside the largest shape the runner can be ready for.
    ShapeTooLarge { refusal: ShapeRefusal },
    /// The runner's own scope is outside the request's security partition (S3.6).
    OutsidePartition,
    /// The runner needs state outside the request's security partition (S3.6).
    DependencyOutsidePartition { node: NodeId },
    /// The runner's declaration is inconsistent: a compute group reads an undeclared node.
    UndeclaredComputeInput { node: NodeId },
    /// The runner has no runtime the governor knows.
    NoRuntime,
    /// The runner's runtime belongs to another parent execution (S3.1).
    OtherExecution,
    /// The runner's runtime category is not the one its profile declares.
    CategoryMismatch,
}

/// Whether a runner supports an exact execution identity and shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "compatibility", rename_all = "snake_case")]
pub enum Compatibility {
    Compatible,
    Incompatible { reason: Incompatibility },
}

/// One residency a runner holds: the T07 advertisement (a hint with an expiry and a
/// generation, line 506), the identities of the state held under it, and the shape its
/// activation is ready for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResidentState {
    pub advertisement: ResidentAdvertisement,
    pub resident: BTreeSet<StateIdentity>,
    pub ready_for: SupportedShape,
}

/// What a runner adapter declares about itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RunnerProfile {
    /// The native ABI it was built against and the operations it calls (line 489).
    pub abi: AbiDeclaration,
    pub owner: PlacementOwner,
    /// The scope its runtime's state lives in.
    pub scope: TrustScope,
    /// The kind of runtime it is (VM-D4–VM-D6).
    pub category: ExecutionCategory,
    pub backend: Backend,
    /// Whether the backend can compute ahead while later state loads (§3.6, line 601).
    pub execute_while_load: bool,
    /// Where the runtime can write session KV back to before dropping it (T08 tiers).
    pub kv_write_back: Option<CopyTier>,
}

/// A missing node that is now usable: its whole chain completed and was verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DependencyEvent {
    pub placement: PlacementKey,
    pub node: NodeId,
    pub kind: NodeKind,
    pub identity: StateIdentity,
    pub device_bytes: u64,
}

/// Compute one group ahead for the one request the preparation lease is assigned to. The
/// request is the lease's, so no other request can be named (line 601).
#[derive(Clone, Copy, Debug)]
pub struct ComputeAssignment<'a> {
    pub lease: &'a PreparationLease,
    pub group: u32,
    pub payload: &'a RequestPayload,
}

/// Validate and run readiness checks for a declared shape before a generation is
/// published (§3.6 steps 3–4), and the residency the runner advertises once it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivationOrder {
    pub placement: PlacementKey,
    pub generation: ModelActivationGeneration,
    pub declared: SupportedShape,
    pub residency: Residency,
}

/// Serve one request under an execution lease on a published generation.
#[derive(Clone, Copy, Debug)]
pub struct ServeOrder<'a> {
    pub lease: &'a ExecutionLease,
    pub shape: RequestShape,
    pub payload: &'a RequestPayload,
    /// Groups already computed ahead under the preparation lease.
    pub computed_ahead_groups: u32,
}

/// The served result: the generation it came from and when the first token existed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ServeOutcome {
    pub generation: ModelActivationGeneration,
    pub first_token_at: MonotonicTime,
}

/// One published model in a runner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct PublishedModel {
    pub model: ExecutionIdentity,
    pub generation: ModelActivationGeneration,
}

/// What a runner reports for the API, CLI and UI: typed and handle-free.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RunnerDiagnostics {
    pub backend: Backend,
    pub owner: PlacementOwner,
    pub category: ExecutionCategory,
    pub resident_device_bytes: u64,
    pub published: Vec<PublishedModel>,
}

/// Why a runner refused an order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "runner_refusal", rename_all = "snake_case")]
pub enum RunnerRefusal {
    Incompatible {
        reason: Incompatibility,
    },
    /// The order or lease names another runner's placement.
    OtherPlacement,
    UnknownNode {
        node: NodeId,
    },
    /// Groups are computed in order, once, and only for the lease's request.
    GroupOutOfOrder {
        expected: u32,
        requested: u32,
    },
    /// The group reads state that is not usable yet.
    DependencyNotUsable {
        node: NodeId,
    },
    /// Activation validation found required state missing.
    MissingDependency {
        identities: BTreeSet<StateIdentity>,
    },
    /// Readiness checks cannot cover the declared shape.
    ReadinessFailed {
        declared: SupportedShape,
    },
    /// The generation is not ready for the request's shape.
    ShapeNotReady {
        refusal: ShapeRefusal,
    },
    /// The lease's generation is not one the runner holds.
    GenerationMismatch {
        lease: ModelActivationGeneration,
        held: Vec<ModelActivationGeneration>,
    },
    /// The runtime cannot carry out the eviction action.
    CannotEvict,
    /// The request's shape needs more KV than its lease admitted: the runner never writes
    /// past what is reserved (GPU-W10 acceptance).
    KvBeyondLease {
        needed_bytes: u64,
        leased_bytes: u64,
    },
    /// The generation still serves requests, so its KV and contexts stay.
    GenerationInUse {
        generation: ModelActivationGeneration,
    },
}

impl fmt::Display for RunnerRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incompatible { .. } => f.write_str("the runner cannot serve this model"),
            Self::OtherPlacement => f.write_str("the order names another runner's placement"),
            Self::UnknownNode { node } => write!(f, "the runner does not know {node}"),
            Self::GroupOutOfOrder {
                expected,
                requested,
            } => write!(f, "group {requested} requested before group {expected}"),
            Self::DependencyNotUsable { node } => write!(f, "{node} is not usable yet"),
            Self::MissingDependency { identities } => {
                write!(f, "{} required states are missing", identities.len())
            }
            Self::ReadinessFailed { .. } => {
                f.write_str("the runner cannot be ready for the declared shape")
            }
            Self::ShapeNotReady { refusal } => refusal.fmt(f),
            Self::GenerationMismatch { lease, .. } => {
                write!(f, "generation {lease} is not a generation the runner holds")
            }
            Self::CannotEvict => f.write_str("the runtime cannot carry out the eviction"),
            Self::KvBeyondLease {
                needed_bytes,
                leased_bytes,
            } => write!(
                f,
                "the request needs {needed_bytes} bytes of KV; its lease admits {leased_bytes}"
            ),
            Self::GenerationInUse { generation } => {
                write!(f, "generation {generation} still serves requests")
            }
        }
    }
}

/// The runner adapter boundary.
pub trait RunnerAdapter {
    fn profile(&self) -> RunnerProfile;

    fn compatibility(&self, model: &ExecutionIdentity, shape: &RequestShape) -> Compatibility;

    /// The exact state and computation the model needs for the shape.
    fn dependencies(
        &self,
        model: &ExecutionIdentity,
        shape: &RequestShape,
    ) -> Result<ExecutionDependencies, RunnerRefusal>;

    /// Every residency the runner holds now, each a hint to be rechecked (line 506).
    fn residencies(&self, now: MonotonicTime) -> Vec<ResidentState>;

    /// Rebuilds a missing node that is not transferred, such as engine initialization or
    /// a graph capture.
    fn reconstruct(
        &mut self,
        node: &DependencyNode,
        preparation: &PreparationToken,
    ) -> Result<(), RunnerRefusal>;

    /// Takes a transferred node that has been verified and copied.
    fn dependency_usable(
        &mut self,
        event: &DependencyEvent,
        preparation: &PreparationToken,
    ) -> Result<(), RunnerRefusal>;

    /// Computes one group ahead for the assigned pending request (line 601).
    fn compute_ahead(&mut self, assignment: &ComputeAssignment<'_>) -> Result<(), RunnerRefusal>;

    /// Validates the state and runs readiness checks; publishing is not the runner's.
    fn activate(
        &mut self,
        order: &ActivationOrder,
        preparation: &PreparationToken,
    ) -> Result<(), RunnerRefusal>;

    fn serve(&mut self, order: &ServeOrder<'_>) -> Result<ServeOutcome, RunnerRefusal>;

    /// Carries out T08's eviction action for a served session that will not resume: a
    /// write-back to the runtime's tier, then a drop.
    fn release_session(
        &mut self,
        operation: &OperationId,
        action: &EvictionAction,
    ) -> Result<(), RunnerRefusal>;

    /// Discards the state of a request that failed; it held nothing anyone else uses.
    /// Discarding state the runner does not hold is not an error.
    fn drop_state(&mut self, states: &[StateRef]) -> Result<(), RunnerRefusal>;

    /// Forgets a validated generation that was never published.
    fn discard_activation(
        &mut self,
        placement: &PlacementKey,
        generation: ModelActivationGeneration,
    ) -> Result<(), RunnerRefusal>;

    /// How the pinned backend fills `model`'s KV for `shape` (GPU-W10 line 182): what a
    /// token of one sequence takes, and whether the backend grows its pool in increments.
    /// The default declares nothing, and the flow bounds every request by the pool its
    /// shape was reserved for.
    fn kv_layout(&self, _model: &ExecutionIdentity, _shape: &RequestShape) -> Option<KvLayout> {
        None
    }

    /// Frees a drained generation's KV and contexts, for a reload when two generations
    /// cannot be resident together (GPU-W05 line 110); the immutable weights stay for the
    /// next generation, which acquires those it reads. Called only once none of the
    /// generation's requests holds a lease. Returns the state it freed, which the next
    /// generation makes again.
    fn release_generation(
        &mut self,
        placement: &PlacementKey,
        generation: ModelActivationGeneration,
    ) -> Result<Vec<StateIdentity>, RunnerRefusal>;

    fn diagnostics(&self) -> RunnerDiagnostics;
}
