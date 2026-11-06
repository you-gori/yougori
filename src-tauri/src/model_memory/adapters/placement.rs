//! Where a request with stored KV runs: on its current worker, or on a target worker
//! after a KV transfer or an exact prefix recomputation (GPU §3.9 line 636, §2.8
//! line 461).
//!
//! "A transfer may lose to recomputation or to leaving the request on its current
//! worker." Transfer versus recomputation is [`choose_kv_restore`], which counts queues
//! and allows recomputation only when the original state is available, authorized and
//! semantically identical. This module adds the third option around it and compares
//! completion of the whole request, queues included.

use std::fmt;

use crate::foundation::ids::{AuthorizationEpoch, Digest};
use crate::model_memory::math::recompute::{
    choose_kv_restore, KvRecompute, KvRequirement, KvRestoreMethod, KvTransfer, RecomputeError,
    RecomputeRefusal,
};
use crate::model_memory::math::{non_negative, positive, InputError};

use super::kv::KvReuseGrant;

/// Serving the request where its KV already is (line 636).
#[derive(Clone, Debug, PartialEq)]
pub struct StayOnCurrent {
    /// Proof that the current worker's engine may reuse the KV for this requester.
    pub grant: KvReuseGrant,
    pub queue_seconds: f64,
    pub serve_seconds: f64,
}

/// Copying the KV to the target worker (line 636).
#[derive(Clone, Debug, PartialEq)]
pub struct KvTransferEstimate {
    /// Proof that the target worker's engine may reuse the KV for this requester.
    pub grant: KvReuseGrant,
    pub kv_bytes: u64,
    pub link_bytes_per_second: f64,
    pub link_queue_seconds: f64,
}

/// Recomputing the exact prefix on the target worker (§2.8 line 461). It runs on the
/// target, so it waits for the target's queue.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct KvRecomputeEstimate {
    /// Identity of the prefix inputs still held, or `None` once they are gone.
    pub held_prefix: Option<Digest>,
    /// Identity of the state the recomputation would produce.
    pub produces_state: Digest,
    /// The epoch the recomputation was authorized under, if any.
    pub authorized_epoch: Option<AuthorizationEpoch>,
    pub prefix_tokens: u64,
    pub prefill_tokens_per_second: f64,
}

/// Moving the request to a target worker (line 636).
#[derive(Clone, Debug, PartialEq)]
pub struct MoveToTarget {
    pub target_queue_seconds: f64,
    pub serve_seconds: f64,
    pub transfer: Option<KvTransferEstimate>,
    pub recompute: Option<KvRecomputeEstimate>,
}

/// Where the request runs (line 636).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KvPlacement {
    Stay,
    Transfer,
    Recompute,
}

/// The chosen placement and the completion of every option considered.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct KvPlacementDecision {
    pub placement: KvPlacement,
    pub completion_seconds: f64,
    pub stay_completion_seconds: Option<f64>,
    pub transfer_completion_seconds: Option<f64>,
    pub recompute_completion_seconds: Option<f64>,
    /// Why recomputation was not allowed, when it was offered.
    pub recompute_refusal: Option<RecomputeRefusal>,
}

/// Why no placement was chosen.
#[derive(Clone, Debug, PartialEq)]
pub enum KvPlacementError {
    Input(InputError),
    /// A reuse grant is for another KV state than the one required.
    GrantForAnotherState {
        granted: Digest,
        required: Digest,
    },
    /// No option can serve the request with its exact state.
    NoOption {
        recompute_refusal: Option<RecomputeRefusal>,
    },
    /// The restore decision refused for another reason.
    Restore(RecomputeError),
}

impl From<InputError> for KvPlacementError {
    fn from(error: InputError) -> Self {
        Self::Input(error)
    }
}

impl fmt::Display for KvPlacementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(error) => error.fmt(f),
            Self::GrantForAnotherState { granted, required } => write!(
                f,
                "the reuse grant is for KV state {granted}, not the required {required}"
            ),
            Self::NoOption { recompute_refusal } => write!(
                f,
                "no option serves the request with its exact KV state (recomputation: \
                 {recompute_refusal:?})"
            ),
            Self::Restore(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for KvPlacementError {}

fn check_grant(grant: &KvReuseGrant, required: Digest) -> Result<(), KvPlacementError> {
    if grant.key() != required {
        return Err(KvPlacementError::GrantForAnotherState {
            granted: grant.key(),
            required,
        });
    }
    Ok(())
}

/// Chooses between staying, transferring and recomputing by completion of the request,
/// queues included (line 636, §2.8). The target option uses [`choose_kv_restore`]; a
/// transferred request starts when both the KV has arrived and the target's queue has
/// cleared. On equal completion the request stays, because moving adds work.
pub fn decide_kv_placement(
    requirement: &KvRequirement,
    stay: Option<&StayOnCurrent>,
    target: Option<&MoveToTarget>,
) -> Result<KvPlacementDecision, KvPlacementError> {
    let stay_completion_seconds = match stay {
        Some(option) => {
            check_grant(&option.grant, requirement.state_identity)?;
            Some(
                non_negative("StayOnCurrent.queue_seconds", option.queue_seconds)?
                    + non_negative("StayOnCurrent.serve_seconds", option.serve_seconds)?,
            )
        }
        None => None,
    };
    let mut transfer_completion_seconds = None;
    let mut recompute_completion_seconds = None;
    let mut recompute_refusal = None;
    let mut moved = None;
    if let Some(option) = target {
        let target_queue_seconds = non_negative(
            "MoveToTarget.target_queue_seconds",
            option.target_queue_seconds,
        )?;
        let serve_seconds = non_negative("MoveToTarget.serve_seconds", option.serve_seconds)?;
        let transfer = match &option.transfer {
            Some(estimate) => {
                check_grant(&estimate.grant, requirement.state_identity)?;
                let rate = positive(
                    "KvTransferEstimate.link_bytes_per_second",
                    estimate.link_bytes_per_second,
                )?;
                Some(KvTransfer {
                    queue_seconds: estimate.link_queue_seconds,
                    transfer_seconds: estimate.kv_bytes as f64 / rate,
                })
            }
            None => None,
        };
        let recompute = match &option.recompute {
            Some(estimate) => {
                let rate = positive(
                    "KvRecomputeEstimate.prefill_tokens_per_second",
                    estimate.prefill_tokens_per_second,
                )?;
                Some(KvRecompute {
                    held_prefix: estimate.held_prefix,
                    produces_state: estimate.produces_state,
                    authorized_epoch: estimate.authorized_epoch,
                    queue_seconds: target_queue_seconds,
                    compute_seconds: estimate.prefix_tokens as f64 / rate,
                })
            }
            None => None,
        };
        match choose_kv_restore(requirement, transfer.as_ref(), recompute.as_ref()) {
            Ok(decision) => {
                recompute_refusal = decision.recompute_refusal;
                transfer_completion_seconds = decision
                    .transfer_completion_seconds
                    .map(|arrival| arrival.max(target_queue_seconds) + serve_seconds);
                recompute_completion_seconds = decision
                    .recompute_completion_seconds
                    .map(|ready| ready + serve_seconds);
                moved = match decision.method {
                    KvRestoreMethod::Transfer => transfer_completion_seconds
                        .map(|completion| (KvPlacement::Transfer, completion)),
                    KvRestoreMethod::Recompute => recompute_completion_seconds
                        .map(|completion| (KvPlacement::Recompute, completion)),
                };
            }
            Err(RecomputeError::NoExactRestore {
                recompute_refusal: refusal,
            }) => recompute_refusal = refusal,
            Err(RecomputeError::Input(error)) => return Err(KvPlacementError::Input(error)),
            Err(error) => return Err(KvPlacementError::Restore(error)),
        }
    }
    let (placement, completion_seconds) = match (stay_completion_seconds, moved) {
        (Some(stayed), Some((_, completion))) if stayed <= completion => {
            (KvPlacement::Stay, stayed)
        }
        (_, Some(chosen)) => chosen,
        (Some(stayed), None) => (KvPlacement::Stay, stayed),
        (None, None) => return Err(KvPlacementError::NoOption { recompute_refusal }),
    };
    Ok(KvPlacementDecision {
        placement,
        completion_seconds,
        stay_completion_seconds,
        transfer_completion_seconds,
        recompute_completion_seconds,
        recompute_refusal,
    })
}

#[cfg(test)]
mod tests;
