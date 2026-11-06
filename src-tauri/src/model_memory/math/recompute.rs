//! KV state: exact prefix recomputation versus transfer (GPU §2.8).
//!
//! Transfer completion is compared with exact prefix recomputation, queues included.
//! Recomputation is allowed only when the original state is available, authorized under
//! the current epoch and semantically identical. Discarding recoverable cache is a
//! different act from discarding required context.

use std::fmt;

use super::{non_negative, InputError};
use crate::foundation::ids::{AuthorizationEpoch, Digest};

/// The KV state a session needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KvRequirement {
    /// Identity of the exact KV state, bound to the model, adapter and execution.
    pub state_identity: Digest,
    /// Identity of the original prefix inputs (tokens and any multimodal inputs).
    pub prefix_identity: Digest,
    /// The authorization epoch in force now.
    pub current_epoch: AuthorizationEpoch,
}

/// Restoring the state by transferring a verified copy.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct KvTransfer {
    pub queue_seconds: f64,
    pub transfer_seconds: f64,
}

/// Restoring the state by recomputing the prefix.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct KvRecompute {
    /// Identity of the prefix inputs still held, or `None` once they are gone.
    pub held_prefix: Option<Digest>,
    /// Identity of the state this recomputation would produce.
    pub produces_state: Digest,
    /// The epoch the recomputation was authorized under, if any.
    pub authorized_epoch: Option<AuthorizationEpoch>,
    pub queue_seconds: f64,
    pub compute_seconds: f64,
}

/// Why recomputation may not stand in for the original state (GPU §2.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecomputeRefusal {
    /// The original prefix inputs are not held; different inputs do not count.
    OriginalStateUnavailable,
    /// Not authorized, or authorized only under an older epoch.
    NotAuthorized,
    /// It would produce a different state, for example on another model or adapter.
    NotSemanticallyIdentical,
}

/// Why a KV decision was refused.
#[derive(Clone, Debug, PartialEq)]
pub enum RecomputeError {
    Input(InputError),
    /// Neither a verified copy nor an allowed exact recomputation can restore the
    /// state: the required context is lost and must be reported as lost.
    NoExactRestore {
        recompute_refusal: Option<RecomputeRefusal>,
    },
    /// Evicting this state as cache would discard required context.
    RequiredContext,
}

impl From<InputError> for RecomputeError {
    fn from(error: InputError) -> Self {
        Self::Input(error)
    }
}

impl fmt::Display for RecomputeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(error) => error.fmt(f),
            Self::NoExactRestore { recompute_refusal } => write!(
                f,
                "no exact way to restore the KV state (recomputation: {recompute_refusal:?})"
            ),
            Self::RequiredContext => {
                f.write_str("this KV state is required context, not recoverable cache")
            }
        }
    }
}

impl std::error::Error for RecomputeError {}

/// Checks the three conditions of GPU §2.8, in order: available, authorized, identical.
pub fn check_recompute(
    requirement: &KvRequirement,
    recompute: &KvRecompute,
) -> Result<(), RecomputeRefusal> {
    if recompute.held_prefix != Some(requirement.prefix_identity) {
        return Err(RecomputeRefusal::OriginalStateUnavailable);
    }
    if recompute.authorized_epoch != Some(requirement.current_epoch) {
        return Err(RecomputeRefusal::NotAuthorized);
    }
    if recompute.produces_state != requirement.state_identity {
        return Err(RecomputeRefusal::NotSemanticallyIdentical);
    }
    Ok(())
}

/// How the state is restored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KvRestoreMethod {
    Transfer,
    Recompute,
}

/// The chosen restore and both completions, queues included.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct KvRestoreDecision {
    pub method: KvRestoreMethod,
    pub completion_seconds: f64,
    pub transfer_completion_seconds: Option<f64>,
    pub recompute_completion_seconds: Option<f64>,
    /// Why recomputation was not allowed, when it was offered.
    pub recompute_refusal: Option<RecomputeRefusal>,
}

/// Chooses the faster exact restore (GPU §2.8). Recomputation competes only when
/// [`check_recompute`] allows it; on equal completion the transfer is chosen because it
/// adds no compute load.
pub fn choose_kv_restore(
    requirement: &KvRequirement,
    transfer: Option<&KvTransfer>,
    recompute: Option<&KvRecompute>,
) -> Result<KvRestoreDecision, RecomputeError> {
    let transfer_completion_seconds = match transfer {
        Some(option) => Some(
            non_negative("KvTransfer.queue_seconds", option.queue_seconds)?
                + non_negative("KvTransfer.transfer_seconds", option.transfer_seconds)?,
        ),
        None => None,
    };
    let mut recompute_refusal = None;
    let mut recompute_completion_seconds = None;
    if let Some(option) = recompute {
        let completion = non_negative("KvRecompute.queue_seconds", option.queue_seconds)?
            + non_negative("KvRecompute.compute_seconds", option.compute_seconds)?;
        match check_recompute(requirement, option) {
            Ok(()) => recompute_completion_seconds = Some(completion),
            Err(refusal) => recompute_refusal = Some(refusal),
        }
    }
    let (method, completion_seconds) =
        match (transfer_completion_seconds, recompute_completion_seconds) {
            (Some(transfer), Some(recompute)) if recompute < transfer => {
                (KvRestoreMethod::Recompute, recompute)
            }
            (Some(transfer), _) => (KvRestoreMethod::Transfer, transfer),
            (None, Some(recompute)) => (KvRestoreMethod::Recompute, recompute),
            (None, None) => return Err(RecomputeError::NoExactRestore { recompute_refusal }),
        };
    Ok(KvRestoreDecision {
        method,
        completion_seconds,
        transfer_completion_seconds,
        recompute_completion_seconds,
        recompute_refusal,
    })
}

/// What discarding a KV state means (GPU §2.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KvDiscard {
    /// An exact restore path remains, so only a cache is lost.
    RecoverableCache,
    /// No exact restore path remains: discarding loses context the session needs.
    RequiredContext,
}

impl KvDiscard {
    /// Cache eviction may only discard recoverable cache; losing required context is a
    /// separate, reported act.
    pub fn authorize_cache_eviction(self) -> Result<(), RecomputeError> {
        match self {
            Self::RecoverableCache => Ok(()),
            Self::RequiredContext => Err(RecomputeError::RequiredContext),
        }
    }
}

/// Classifies a discard by whether an exact restore path would remain: a verified copy
/// to transfer, or a recomputation that [`check_recompute`] allows.
pub fn classify_discard(
    requirement: &KvRequirement,
    transfer: Option<&KvTransfer>,
    recompute: Option<&KvRecompute>,
) -> KvDiscard {
    let recomputable = recompute.is_some_and(|option| check_recompute(requirement, option).is_ok());
    if transfer.is_some() || recomputable {
        KvDiscard::RecoverableCache
    } else {
        KvDiscard::RequiredContext
    }
}

#[cfg(test)]
mod tests;
