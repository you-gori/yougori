//! Keeping valuable state after serving (GPU §1 step 5: "release leases and retain
//! valuable state") under the T08 clean-eviction rule (§1.1 line 307).
//!
//! Immutable state stays resident with its activation: it is what lets the next request
//! take the ready path, and nothing is evicted to make room (capacity refusals say
//! whether a retry can progress instead). The request's session KV is dirty once served.
//! When the caller expects to resume the session it stays. Otherwise T08's
//! [`eviction_action`] decides how it may leave: written back to a tier that guarantees
//! availability and then dropped, or kept when the runtime has no such tier. Dirty KV is
//! never dropped without a write-back (T08).

use serde::Serialize;

use crate::foundation::ids::{DigestBuilder, ModelActivationGeneration, OperationId};
use crate::model_memory::residency::eviction::{
    eviction_action, Content, ContentState, CopyTier, EvictionAction, GpuCopy, NotDroppable,
    WriteBack,
};

/// Digest domain of the state marker a served session's KV takes.
pub const SESSION_STATE_DOMAIN: &str = "yougori/model-memory/boundaries/session-state/v1";

/// The state one request's session KV holds after it was served on `generation`: a marker
/// that names the state, never hashed bytes (T08 [`Content::SessionState`]).
pub fn served_session(operation: &OperationId, generation: ModelActivationGeneration) -> Content {
    Content::SessionState(
        DigestBuilder::new(SESSION_STATE_DOMAIN)
            .str(operation.as_str())
            .u64(generation.get())
            .finish(),
    )
}

/// What becomes of a served session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "session", rename_all = "snake_case")]
pub enum SessionRetention {
    /// The caller expects to resume it, or it holds no device memory: it stays.
    Kept,
    /// Not resumed: the runtime carries out T08's action, a write-back then a drop.
    Released { action: EvictionAction },
    /// Not resumed, but T08 keeps it: no tier could hold a copy.
    Retained { because: NotDroppable },
}

/// T08's decision for a session of `bytes` holding `content` after serving. `write_back`
/// is the tier the runtime writes KV back to, if it has one; only a tier that guarantees
/// availability (pinned host RAM held by the runtime, or local storage) makes a
/// write-back count.
pub fn retain_session(
    bytes: u64,
    content: Content,
    resume_expected: bool,
    write_back: Option<CopyTier>,
) -> SessionRetention {
    if resume_expected || bytes == 0 {
        return SessionRetention::Kept;
    }
    let write_back = match write_back {
        Some(tier) if tier.guarantees_availability() => WriteBack::Available,
        _ => WriteBack::Unavailable,
    };
    let copy = GpuCopy {
        content,
        state: ContentState::Dirty,
        bytes,
    };
    match eviction_action(&copy, &[], write_back) {
        EvictionAction::Retain { because } => SessionRetention::Retained { because },
        action => SessionRetention::Released { action },
    }
}
