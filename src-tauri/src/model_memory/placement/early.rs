//! Execute-while-load (§3.6 line 601, with §2.6 for the dependency chain).
//!
//! Early computation runs for exactly one explicitly assigned pending request, under a
//! preparation-generation lease bound to the generation being prepared. It accepts no
//! other traffic: the router never admits requests to a generation before step 5, and
//! the computation refuses any request but the assigned one. A part of the chain
//! starts only once its extent is usable. The result is released only after every
//! dependency in the chain is usable and computed, the lease is still active, and the
//! generation has been published, here and by the coordination authority, so early
//! computation never gets ahead of atomic public activation. Dependencies are exact
//! positions, so another MoE expert never stands in for a missing one.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::keys::{ExtentKey, PlacementKey, WeightPosition};
use super::ports::{
    CoordinationPort, CoordinationRefusal, LeaseKind, LeaseRequest, LeaseStatus, PublicationRefusal,
};
use super::router::RequestTicket;
use super::slot::PlacementSlot;
use crate::foundation::ids::{
    AuthorizationEpoch, Clock, ExecutionId, LeaseId, ModelActivationGeneration, MonotonicTime,
    OperationId,
};

/// The pending request assigned to the generation being prepared.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssignedRequest {
    pub request: OperationId,
    pub execution: ExecutionId,
    pub epoch: AuthorizationEpoch,
    /// The dependency chain the result needs, such as every required layer and the
    /// output head for a dense model's first token (§2.6).
    pub required: BTreeSet<WeightPosition>,
    pub lease_expires_at: MonotonicTime,
}

/// A result released by early computation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EarlyResult {
    pub request: OperationId,
    pub generation: ModelActivationGeneration,
    /// When the last part of the chain finished computing.
    pub computed_until: MonotonicTime,
    pub released_at: MonotonicTime,
}

/// Why early computation refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum EarlyRefusal {
    /// No generation is being prepared.
    NoPreparation,
    AlreadyAssigned {
        assigned: OperationId,
    },
    /// Only the assigned request computes early (line 601).
    UnrelatedTraffic {
        assigned: OperationId,
        offered: OperationId,
    },
    /// An earlier assigned request has not released its result yet.
    PreviousRequestPending {
        request: OperationId,
    },
    ForeignExecution {
        owner: ExecutionId,
    },
    /// The request's authorization epoch is not the one the slot is bound to (S3.1).
    AuthorityMismatch {
        presented: AuthorizationEpoch,
        bound: Option<AuthorizationEpoch>,
    },
    RequestAlreadyAdmitted,
    EmptyDependencyChain,
    /// The position is not part of the generation being prepared.
    UnknownPosition {
        position: WeightPosition,
    },
    /// The position is not in the assigned request's dependency chain.
    NotRequired {
        position: WeightPosition,
    },
    /// The dependency's extent is not usable yet: the computation stalls.
    DependencyNotUsable {
        position: WeightPosition,
    },
    AlreadyStarted {
        position: WeightPosition,
    },
    NotStarted {
        position: WeightPosition,
    },
    AlreadyFinished {
        position: WeightPosition,
    },
    /// Parts of the chain are not usable or not computed.
    ChainIncomplete {
        waiting: Vec<WeightPosition>,
    },
    LeaseNotActive {
        status: LeaseStatus,
    },
    /// The generation is not published yet; the result waits for step 5.
    AwaitingPublication,
    /// The preparation ended without publishing; nothing computed for it is released.
    PreparationEnded,
    ResultAlreadyReleased,
    LeaseRefused {
        refusal: CoordinationRefusal,
    },
}

crate::foundation::strict_serde::strict_tag!(EarlyRefusal, "kind");

impl fmt::Display for EarlyRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoPreparation => f.write_str("no model generation is being prepared"),
            Self::AlreadyAssigned { assigned } => {
                write!(f, "request {assigned} is already assigned")
            }
            Self::UnrelatedTraffic { assigned, offered } => write!(
                f,
                "only the assigned request {assigned} computes while loading, not {offered}"
            ),
            Self::PreviousRequestPending { request } => {
                write!(f, "request {request} has not released its result yet")
            }
            Self::ForeignExecution { owner } => {
                write!(f, "the model slot belongs to execution {owner}")
            }
            Self::AuthorityMismatch { presented, .. } => write!(
                f,
                "authorization epoch {presented} is not the one this model slot is bound to"
            ),
            Self::RequestAlreadyAdmitted => f.write_str("the request is already admitted"),
            Self::EmptyDependencyChain => f.write_str("the dependency chain is empty"),
            Self::UnknownPosition { position } => {
                write!(f, "{position} is not part of the generation being prepared")
            }
            Self::NotRequired { position } => {
                write!(f, "{position} is not in the request's dependency chain")
            }
            Self::DependencyNotUsable { position } => {
                write!(f, "{position} is not usable yet")
            }
            Self::AlreadyStarted { position } => write!(f, "{position} already started"),
            Self::NotStarted { position } => write!(f, "{position} has not started"),
            Self::AlreadyFinished { position } => write!(f, "{position} already finished"),
            Self::ChainIncomplete { waiting } => write!(
                f,
                "{} part(s) of the dependency chain are not usable and computed",
                waiting.len()
            ),
            Self::LeaseNotActive { status } => {
                write!(f, "the preparation lease is no longer active ({status:?})")
            }
            Self::AwaitingPublication => f.write_str(
                "the generation is not published yet; the result waits for its activation",
            ),
            Self::PreparationEnded => {
                f.write_str("the preparation ended; nothing computed for it is released")
            }
            Self::ResultAlreadyReleased => f.write_str("the result was already released"),
            Self::LeaseRefused { refusal } => write!(f, "no lease was granted: {refusal}"),
        }
    }
}

impl std::error::Error for EarlyRefusal {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct EarlyExecution {
    pub(super) request: OperationId,
    pub(super) generation: ModelActivationGeneration,
    pub(super) placement: PlacementKey,
    pub(super) lease: LeaseId,
    pub(super) required: BTreeSet<WeightPosition>,
    pub(super) started: BTreeMap<WeightPosition, MonotonicTime>,
    pub(super) finished: BTreeMap<WeightPosition, MonotonicTime>,
    pub(super) result: Option<EarlyResult>,
    /// The preparation ended without publishing and the lease was released.
    pub(super) ended: bool,
    /// Publication moved the lease into the router, where it drains with its generation.
    pub(super) lease_in_router: bool,
}

impl<C: Clock> PlacementSlot<C> {
    /// Assigns the pending request to the generation being prepared and takes a
    /// preparation-generation lease for it (line 601).
    pub fn assign_early_request(
        &mut self,
        assigned: &AssignedRequest,
        coordination: &mut dyn CoordinationPort,
    ) -> Result<RequestTicket, EarlyRefusal> {
        let activation = self
            .activation
            .as_ref()
            .ok_or(EarlyRefusal::NoPreparation)?;
        if let Some(early) = &self.early {
            if early.generation == activation.generation && !early.ended {
                return Err(if early.request == assigned.request {
                    EarlyRefusal::AlreadyAssigned {
                        assigned: early.request.clone(),
                    }
                } else {
                    EarlyRefusal::UnrelatedTraffic {
                        assigned: early.request.clone(),
                        offered: assigned.request.clone(),
                    }
                });
            }
            if !early.ended && early.result.is_none() {
                return Err(EarlyRefusal::PreviousRequestPending {
                    request: early.request.clone(),
                });
            }
        }
        if assigned.execution != *self.spec.owner() {
            return Err(EarlyRefusal::ForeignExecution {
                owner: self.spec.owner().clone(),
            });
        }
        if let Some(bound) = self.spec.authority.epoch() {
            if assigned.epoch != bound {
                return Err(EarlyRefusal::AuthorityMismatch {
                    presented: assigned.epoch,
                    bound: Some(bound),
                });
            }
        }
        if assigned.required.is_empty() {
            return Err(EarlyRefusal::EmptyDependencyChain);
        }
        if let Some(position) = assigned
            .required
            .iter()
            .find(|position| !activation.components.contains_key(position))
        {
            return Err(EarlyRefusal::UnknownPosition {
                position: *position,
            });
        }
        if self.router.holds_request(&assigned.request) {
            return Err(EarlyRefusal::RequestAlreadyAdmitted);
        }
        let generation = activation.generation;
        let placement = activation.placement;
        let now = self.now();
        let lease = coordination
            .grant_lease(
                &LeaseRequest {
                    slot: self.spec.slot,
                    kind: LeaseKind::Preparation,
                    request: assigned.request.clone(),
                    execution: assigned.execution.clone(),
                    epoch: assigned.epoch,
                    generation,
                    expires_at: assigned.lease_expires_at,
                },
                now,
            )
            .map_err(|refusal| EarlyRefusal::LeaseRefused { refusal })?;
        self.early = Some(EarlyExecution {
            request: assigned.request.clone(),
            generation,
            placement,
            lease,
            required: assigned.required.clone(),
            started: BTreeMap::new(),
            finished: BTreeMap::new(),
            result: None,
            ended: false,
            lease_in_router: false,
        });
        Ok(RequestTicket {
            request: assigned.request.clone(),
            kind: LeaseKind::Preparation,
            generation,
            lease,
            placement,
        })
    }

    /// Starts computing one part of the chain. It stalls (is refused) until that
    /// part's extent is usable.
    pub fn start_early_compute(
        &mut self,
        request: &OperationId,
        position: WeightPosition,
    ) -> Result<(), EarlyRefusal> {
        let now = self.now();
        let early = self.live_early(request)?;
        if !early.required.contains(&position) {
            return Err(EarlyRefusal::NotRequired { position });
        }
        let extent = self.early_extent(early, position)?;
        if !self.is_usable_for(early.placement, &extent) {
            return Err(EarlyRefusal::DependencyNotUsable { position });
        }
        if early.started.contains_key(&position) {
            return Err(EarlyRefusal::AlreadyStarted { position });
        }
        if let Some(early) = self.early.as_mut() {
            early.started.insert(position, now);
        }
        Ok(())
    }

    /// Records that one part of the chain finished computing.
    pub fn finish_early_compute(
        &mut self,
        request: &OperationId,
        position: WeightPosition,
    ) -> Result<(), EarlyRefusal> {
        let now = self.now();
        let early = self.live_early(request)?;
        if !early.started.contains_key(&position) {
            return Err(EarlyRefusal::NotStarted { position });
        }
        if early.finished.contains_key(&position) {
            return Err(EarlyRefusal::AlreadyFinished { position });
        }
        if let Some(early) = self.early.as_mut() {
            early.finished.insert(position, now);
        }
        Ok(())
    }

    /// Releases the assigned request's result once the whole dependency chain is usable
    /// and computed and the generation checks pass: the lease is active and the generation
    /// has been published, as the router and the coordination authority both see it.
    pub fn release_early_result(
        &mut self,
        request: &OperationId,
        coordination: &dyn CoordinationPort,
    ) -> Result<EarlyResult, EarlyRefusal> {
        let now = self.now();
        let early = self.live_early(request)?;
        let generation_live = self
            .activation
            .as_ref()
            .is_some_and(|activation| activation.generation == early.generation)
            || self.router.entry(early.generation).is_some();
        if !generation_live {
            return Err(EarlyRefusal::PreparationEnded);
        }
        let status = coordination.lease_status(early.lease, now);
        if !status.is_active() {
            return Err(EarlyRefusal::LeaseNotActive { status });
        }
        let mut waiting = Vec::new();
        for position in &early.required {
            let extent = self.early_extent(early, *position)?;
            if !self.is_usable_for(early.placement, &extent)
                || !early.finished.contains_key(position)
            {
                waiting.push(*position);
            }
        }
        if !waiting.is_empty() {
            return Err(EarlyRefusal::ChainIncomplete { waiting });
        }
        if self.router.entry(early.generation).is_none() {
            return Err(EarlyRefusal::AwaitingPublication);
        }
        coordination
            .check_result_publication(early.lease, now)
            .map_err(|refusal| match refusal {
                PublicationRefusal::Lease { status } => EarlyRefusal::LeaseNotActive { status },
                PublicationRefusal::AwaitingPublication => EarlyRefusal::AwaitingPublication,
            })?;
        let result = EarlyResult {
            request: early.request.clone(),
            generation: early.generation,
            computed_until: early
                .finished
                .values()
                .max()
                .copied()
                .unwrap_or(MonotonicTime::ZERO),
            released_at: now,
        };
        if let Some(early) = self.early.as_mut() {
            early.result = Some(result.clone());
        }
        Ok(result)
    }

    /// The early computation of `request`, if it may still compute.
    fn live_early(&self, request: &OperationId) -> Result<&EarlyExecution, EarlyRefusal> {
        let early = self.early.as_ref().ok_or(EarlyRefusal::NoPreparation)?;
        if early.request != *request {
            return Err(EarlyRefusal::UnrelatedTraffic {
                assigned: early.request.clone(),
                offered: request.clone(),
            });
        }
        if early.ended {
            return Err(EarlyRefusal::PreparationEnded);
        }
        if early.result.is_some() {
            return Err(EarlyRefusal::ResultAlreadyReleased);
        }
        Ok(early)
    }

    /// The extent at `position` in the early computation's own generation.
    fn early_extent(
        &self,
        early: &EarlyExecution,
        position: WeightPosition,
    ) -> Result<ExtentKey, EarlyRefusal> {
        if let Some(activation) = self
            .activation
            .as_ref()
            .filter(|activation| activation.generation == early.generation)
        {
            return activation
                .components
                .get(&position)
                .map(|spec| spec.extent)
                .ok_or(EarlyRefusal::UnknownPosition { position });
        }
        match self.router.entry(early.generation) {
            Some(entry) => entry
                .content
                .components
                .get(&position)
                .copied()
                .ok_or(EarlyRefusal::UnknownPosition { position }),
            None => Err(EarlyRefusal::PreparationEnded),
        }
    }

    fn is_usable_for(&self, placement: PlacementKey, extent: &ExtentKey) -> bool {
        self.extents.holds(placement, extent) && self.extents.is_usable(extent)
    }
}
