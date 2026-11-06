//! The request router of one slot (§3.6 steps 5–6, line 599). It publishes exactly one
//! activation generation at a time and switches to a new one in a single step. Each
//! admitted request holds a lease on the generation it was admitted with and reads only
//! that generation's content, so a request never mixes generations; the previous
//! generation stops admitting at the switch and drains its leases.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::fields::{RequestShape, ShapeRefusal, SupportedShape};
use super::keys::{ExtentKey, PlacementKey, WeightPosition};
use super::ports::{CapacityRefusal, CoordinationRefusal, LeaseKind};
use crate::foundation::ids::{
    AuthorizationEpoch, ExecutionId, LeaseId, ModelActivationGeneration, MonotonicTime, OperationId,
};
use crate::model_memory::identity::{AdapterIdentity, ArtifactIdentity, ExecutionIdentity};

/// The immutable content of one activation generation. Nothing changes it after
/// publication: a weight or adapter update is a new generation with new content.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ActivationContent {
    pub generation: ModelActivationGeneration,
    pub execution: ExecutionIdentity,
    pub artifact: ArtifactIdentity,
    /// The identity of each applied adapter, by its `Component::Adapter` index.
    pub adapters: BTreeMap<u32, AdapterIdentity>,
    pub components: BTreeMap<WeightPosition, ExtentKey>,
}

/// A request asking to be served by the published generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AdmissionRequest {
    pub request: OperationId,
    /// The parent execution the request runs under; it must own the slot.
    pub execution: ExecutionId,
    /// The authorization epoch the lease binds to; it must be the slot's (S3.1).
    pub epoch: AuthorizationEpoch,
    pub shape: RequestShape,
    /// An exact adapter identity the request requires, if any.
    pub adapter: Option<AdapterIdentity>,
    pub lease_expires_at: MonotonicTime,
}

/// An admitted request: the generation it keeps and the lease it holds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestTicket {
    pub request: OperationId,
    pub kind: LeaseKind,
    pub generation: ModelActivationGeneration,
    /// The lease the request holds on `generation` until it finishes.
    pub lease: LeaseId,
    /// The placement that serves `generation`.
    pub placement: PlacementKey,
}

/// Why requests are paused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum PauseReason {
    /// Capacity permits only one resident generation, so the old one drains before the
    /// new one loads (§3.6 line 597). The refusal names the limiting resource.
    SingleGenerationCapacity { refusal: CapacityRefusal },
}

crate::foundation::strict_serde::strict_tag!(PauseReason, "reason");

/// How a pause ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum PauseOutcome {
    Resumed {
        generation: ModelActivationGeneration,
    },
    /// The activation failed; nothing serves until another activation succeeds.
    ActivationFailed,
}

crate::foundation::strict_serde::strict_tag!(PauseOutcome, "outcome");

/// A real pause in serving, reported rather than hidden (§3.6 line 597).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PauseRecord {
    pub reason: PauseReason,
    pub started_at: MonotonicTime,
    pub ended_at: Option<MonotonicTime>,
    pub outcome: Option<PauseOutcome>,
}

impl PauseRecord {
    /// How long serving was paused, up to `now` while it lasts.
    pub fn duration(&self, now: MonotonicTime) -> Duration {
        self.ended_at
            .unwrap_or(now)
            .saturating_duration_since(self.started_at)
    }
}

/// Why a request was not admitted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RouteRefusal {
    /// No generation is published.
    NotServing,
    /// Serving is paused while a single-generation activation drains and loads.
    Paused {
        since: MonotonicTime,
        reason: PauseReason,
    },
    /// The request's execution does not own this slot.
    ForeignExecution {
        owner: ExecutionId,
    },
    /// The request's authorization epoch is not the one the slot is bound to (S3.1).
    AuthorityMismatch {
        presented: AuthorizationEpoch,
        bound: Option<AuthorizationEpoch>,
    },
    /// The published generation was not checked for this shape.
    NotReadyForShape {
        refusal: ShapeRefusal,
    },
    /// The published generation does not carry the adapter identity the request needs.
    AdapterNotPublished {
        adapter: AdapterIdentity,
    },
    DuplicateRequest {
        request: OperationId,
    },
    LeaseRefused {
        refusal: CoordinationRefusal,
    },
}

impl fmt::Display for RouteRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotServing => f.write_str("no model generation is serving"),
            Self::Paused { .. } => f.write_str(
                "serving is paused while the model is replaced, because memory holds only one \
                 version at a time",
            ),
            Self::ForeignExecution { owner } => {
                write!(f, "the model slot belongs to execution {owner}")
            }
            Self::AuthorityMismatch { presented, .. } => write!(
                f,
                "authorization epoch {presented} is not the one this model slot is bound to"
            ),
            Self::NotReadyForShape { refusal } => refusal.fmt(f),
            Self::AdapterNotPublished { adapter } => {
                write!(f, "adapter {adapter} is not part of the serving generation")
            }
            Self::DuplicateRequest { request } => {
                write!(f, "request {request} is already admitted")
            }
            Self::LeaseRefused { refusal } => write!(f, "no lease was granted: {refusal}"),
        }
    }
}

impl std::error::Error for RouteRefusal {}

/// Why a ticket could not be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum TicketError {
    /// The ticket's lease is not held by this slot.
    UnknownTicket,
    UnknownPosition {
        position: WeightPosition,
    },
    /// The offered weights are not the ones of the request's generation (line 599).
    MixedGenerations {
        generation: ModelActivationGeneration,
        position: WeightPosition,
        expected: ExtentKey,
        offered: ExtentKey,
    },
}

crate::foundation::strict_serde::strict_tag!(TicketError, "error");

impl fmt::Display for TicketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownTicket => f.write_str("the request holds no lease here"),
            Self::UnknownPosition { position } => {
                write!(f, "{position} is not part of the request's generation")
            }
            Self::MixedGenerations {
                generation,
                position,
                ..
            } => write!(
                f,
                "the weights offered for {position} are not those of generation {generation}; \
                 a request never mixes generations"
            ),
        }
    }
}

impl std::error::Error for TicketError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct HeldLease {
    pub(super) kind: LeaseKind,
    pub(super) lease: LeaseId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct GenerationEntry {
    pub(super) placement: PlacementKey,
    pub(super) content: ActivationContent,
    pub(super) supported: SupportedShape,
    pub(super) published_at: MonotonicTime,
    pub(super) leases: BTreeMap<OperationId, HeldLease>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Router {
    published: Option<ModelActivationGeneration>,
    newest: Option<ModelActivationGeneration>,
    entries: BTreeMap<ModelActivationGeneration, GenerationEntry>,
}

impl Router {
    pub(super) fn published(&self) -> Option<ModelActivationGeneration> {
        self.published
    }

    pub(super) fn entry(&self, generation: ModelActivationGeneration) -> Option<&GenerationEntry> {
        self.entries.get(&generation)
    }

    pub(super) fn entry_mut(
        &mut self,
        generation: ModelActivationGeneration,
    ) -> Option<&mut GenerationEntry> {
        self.entries.get_mut(&generation)
    }

    /// Whether `generation` is newer than every generation published so far.
    pub(super) fn is_newer(&self, generation: ModelActivationGeneration) -> bool {
        self.newest.is_none_or(|newest| generation > newest)
    }

    /// Makes `entry` the published generation in one step and returns the previous one,
    /// which keeps its leases but admits nothing more. The caller has checked
    /// [`Self::is_newer`].
    pub(super) fn publish(&mut self, entry: GenerationEntry) -> Option<ModelActivationGeneration> {
        let generation = entry.content.generation;
        self.entries.insert(generation, entry);
        self.newest = Some(generation);
        self.published.replace(generation)
    }

    /// Stops admitting to the published generation; its leases stay until they end.
    pub(super) fn unpublish(&mut self) -> Option<ModelActivationGeneration> {
        self.published.take()
    }

    pub(super) fn holds_request(&self, request: &OperationId) -> bool {
        self.entries
            .values()
            .any(|entry| entry.leases.contains_key(request))
    }

    /// Leases held on every generation of `placement`.
    pub(super) fn leases_of(&self, placement: PlacementKey) -> usize {
        self.entries
            .values()
            .filter(|entry| entry.placement == placement)
            .map(|entry| entry.leases.len())
            .sum()
    }

    /// Generations of `placement` with their lease holders.
    pub(super) fn generations_of(
        &self,
        placement: PlacementKey,
    ) -> Vec<(ModelActivationGeneration, Vec<(OperationId, LeaseId)>)> {
        self.entries
            .values()
            .filter(|entry| entry.placement == placement)
            .map(|entry| {
                (
                    entry.content.generation,
                    entry
                        .leases
                        .iter()
                        .map(|(request, held)| (request.clone(), held.lease))
                        .collect(),
                )
            })
            .collect()
    }

    /// Forgets the generations of a placement that no longer serves. The caller has
    /// checked that none of them is published or holds a lease.
    pub(super) fn remove_generations_of(&mut self, placement: PlacementKey) {
        self.entries.retain(|_, entry| entry.placement != placement);
    }
}
