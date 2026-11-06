//! Model readiness, keep-ready preparation, residency, memory fit and model-memory refusals
//! in the CORE-07 contract's shapes (S2 CORE-07 "memory/readiness"; GPU-W11; GPU §2.7,
//! §3.6, §4.1).
//!
//! Each conversion reads the model-memory type that owns the field: the placement state,
//! a keep-ready preparation, the GPU extents a placement holds, a host copy and what may
//! be relied on staying in RAM, a device's demand against its usable memory, the request
//! shape readiness checks covered, and the refusals of a request shape or a memory plan
//! that does not fit.

use crate::foundation::events::format_bytes;
use crate::foundation::product::{
    HostCopyShown, MemoryFit, ModelMemoryCode, ModelReadiness, Preparation, Readiness, ReadyFor,
    Refusal, RefusalCode, Remedy, Residency, ShownText,
};
use crate::model_memory::placement::{
    GpuResidency, PlacementState, ShapeRefusal, StateKind, SupportedShape,
};
use crate::model_memory::readiness::intent::{CancelReason, PrepareState, ReleaseReason};
use crate::model_memory::residency::host::{
    HostCopy, HostResidency, HostScopeKind, ScopeOvercommit,
};
use crate::model_memory::residency::vram::{device_label, VramEvaluation, VramOvercommit};

impl From<StateKind> for Readiness {
    fn from(state: StateKind) -> Self {
        match state {
            StateKind::Absent => Self::NotLoaded,
            StateKind::Preparing => Self::Preparing,
            StateKind::Materialized => Self::Loaded,
            StateKind::Activating => Self::Activating,
            StateKind::Serving => Self::Ready,
            StateKind::Draining => Self::Draining,
            StateKind::Parked => Self::Parked,
            StateKind::Failed => Self::Failed,
        }
    }
}

/// A placement's readiness and, when it failed, its recorded failure.
impl From<&PlacementState> for ModelReadiness {
    fn from(state: &PlacementState) -> Self {
        match state {
            PlacementState::Failed { failure } => Self::failed(&failure.to_string()),
            other => Self::in_state(Readiness::from(other.kind())),
        }
    }
}

impl From<&PrepareState> for Preparation {
    fn from(state: &PrepareState) -> Self {
        match *state {
            PrepareState::Running { started_at } => Self::Running { started_at },
            PrepareState::Ready {
                ready_at,
                expires_at,
            } => Self::Ready {
                ready_at,
                expires_at,
            },
            PrepareState::Consumed { at } => Self::Used { at },
            PrepareState::Released { at, reason } => Self::Released {
                at,
                reason: ShownText::new(release_reason(reason)),
            },
        }
    }
}

fn release_reason(reason: ReleaseReason) -> &'static str {
    match reason {
        ReleaseReason::Cancelled { reason } => match reason {
            CancelReason::Requester => "cancelled: the request for it was withdrawn",
            CancelReason::Superseded => "cancelled: a newer request replaced it",
            CancelReason::Lease { .. } => "cancelled: the lease it ran under is being cancelled",
            CancelReason::LeaseEnded => "cancelled: the lease it ran under ended",
            CancelReason::DemandOnly { .. } => {
                "cancelled: scheduling fell back to loading on demand"
            }
        },
        ReleaseReason::DeadlineMissed => "it was not ready by its deadline",
        ReleaseReason::Expired => "its keep-ready time ran out with no request",
        ReleaseReason::NotRequested => "a request for another model arrived",
    }
}

/// What may be relied on staying in RAM: all of a pinned copy and none of a reclaimable
/// one, with model memory's own advisory estimate.
impl From<&HostCopy> for HostCopyShown {
    fn from(copy: &HostCopy) -> Self {
        match copy.residency {
            HostResidency::Pinned => Self::pinned(copy.bytes),
            HostResidency::Reclaimable { .. } => {
                Self::reclaimable(copy.bytes, copy.advisory_resident_bytes())
            }
        }
    }
}

/// A placement's GPU residency and its host copy, if any.
pub fn residency(gpu: &GpuResidency, host: Option<&HostCopy>) -> Residency {
    Residency::new(
        u64::try_from(gpu.extents).unwrap_or(u64::MAX),
        gpu.bytes,
        host.map(HostCopyShown::from),
    )
}

impl From<&VramEvaluation> for MemoryFit {
    fn from(evaluation: &VramEvaluation) -> Self {
        Self::new(
            &device_label(&evaluation.device),
            evaluation.usable_vram_bytes,
            evaluation.peak().map_or(0, |piece| piece.total_bytes),
        )
    }
}

impl From<SupportedShape> for ReadyFor {
    fn from(shape: SupportedShape) -> Self {
        Self {
            max_context_tokens: shape.max_context_tokens,
            max_batch_sequences: shape.max_batch_sequences,
        }
    }
}

impl From<&ShapeRefusal> for Refusal {
    fn from(refusal: &ShapeRefusal) -> Self {
        let code = match refusal {
            ShapeRefusal::ContextTooLong { .. } => ModelMemoryCode::ContextTooLong,
            ShapeRefusal::BatchTooLarge { .. } => ModelMemoryCode::BatchTooLarge,
        };
        Self::new(
            RefusalCode::ModelMemory { code },
            &refusal.to_string(),
            Remedy::ShortenRequest,
        )
    }
}

impl From<&VramOvercommit> for Refusal {
    fn from(overcommit: &VramOvercommit) -> Self {
        Self::new(
            RefusalCode::ModelMemory {
                code: ModelMemoryCode::GpuMemoryShort,
            },
            &format!(
                "{} needs {} of GPU memory at its peak, and {} is usable, {} short",
                device_label(&overcommit.device),
                format_bytes(overcommit.peak.total_bytes),
                format_bytes(overcommit.usable_vram_bytes),
                format_bytes(overcommit.excess_bytes())
            ),
            Remedy::FreeMemory,
        )
    }
}

impl From<&ScopeOvercommit> for Refusal {
    fn from(overcommit: &ScopeOvercommit) -> Self {
        let scope = match overcommit.kind {
            HostScopeKind::HostRam => "host memory",
            HostScopeKind::WslVm => "the WSL VM's memory",
            HostScopeKind::Cgroup => "a cgroup's memory limit",
            HostScopeKind::PinnedRam => "pinned host memory",
        };
        Self::new(
            RefusalCode::ModelMemory {
                code: ModelMemoryCode::HostMemoryShort,
            },
            &format!(
                "{scope} \"{}\" needs {} at its peak, and its capacity is {}, {} short",
                overcommit.scope,
                format_bytes(overcommit.peak.total_bytes),
                format_bytes(overcommit.capacity_bytes),
                format_bytes(overcommit.excess_bytes())
            ),
            Remedy::FreeMemory,
        )
    }
}
