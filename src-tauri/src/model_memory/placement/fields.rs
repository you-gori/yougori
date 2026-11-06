//! The independent fields of a placement (§3.6 line 585) and the request shapes that
//! readiness checks cover (§3.6 step 4).
//!
//! Artifact validity, process liveness and GPU residency are separate fields rather than
//! one loaded flag: a parked process can exist with no GPU weights, a valid GPU
//! allocation may outlive one serving process, and a model can be materialized but not
//! ready for the requested context length.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::keys::ProcessInstance;
use crate::foundation::ids::{GpuAllocationGeneration, MonotonicTime};
use crate::model_memory::identity::ArtifactIdentity;

/// Whether the placement's artifact is valid (§3.6 line 585). Only a verified artifact
/// may be materialized or activated; serving from already verified resident weights
/// does not depend on it. Identities are built from their specs, never deserialized.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "validity", rename_all = "snake_case")]
pub enum ArtifactValidity {
    /// Not yet checked by the artifact catalog.
    Unverified,
    /// Verified as this exact artifact.
    Verified { artifact: ArtifactIdentity },
    /// Found invalid after it was resolved.
    Invalid {
        artifact: ArtifactIdentity,
        problem: ArtifactProblem,
    },
}

impl ArtifactValidity {
    /// Whether the artifact is verified as exactly `artifact`.
    pub fn is_verified_as(&self, artifact: &ArtifactIdentity) -> bool {
        matches!(self, Self::Verified { artifact: verified } if verified == artifact)
    }
}

/// Why an artifact stopped being valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactProblem {
    /// Its content no longer matches its digest.
    DigestMismatch,
    /// Its publisher or trust policy no longer accepts it.
    TrustWithdrawn,
    /// It is no longer present.
    Missing,
}

impl fmt::Display for ArtifactProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::DigestMismatch => "its content no longer matches its digest",
            Self::TrustWithdrawn => "its trust policy no longer accepts it",
            Self::Missing => "it is no longer present",
        })
    }
}

/// Whether the placement's runtime process is alive (§3.6 line 585).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "process", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum ProcessLiveness {
    /// No runtime process holds the placement.
    NoProcess,
    /// This process instance runs.
    Alive { instance: ProcessInstance },
    /// This process instance exited at `at`.
    Exited {
        instance: ProcessInstance,
        at: MonotonicTime,
    },
}

crate::foundation::strict_serde::strict_tag!(ProcessLiveness, "process");

impl ProcessLiveness {
    /// Whether a live runtime process holds the placement.
    pub fn is_alive(&self) -> bool {
        matches!(self, Self::Alive { .. })
    }
}

/// What the placement holds on GPUs (§3.6 line 585), computed from the extents it
/// holds rather than stored beside them.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpuResidency {
    pub extents: usize,
    pub bytes: u64,
    /// The allocation generations of the held extents (S3.1: they change only when
    /// memory is reallocated, never with an activation).
    pub allocations: BTreeSet<GpuAllocationGeneration>,
}

impl GpuResidency {
    /// Whether the placement holds any GPU extent.
    pub fn is_resident(&self) -> bool {
        self.extents > 0
    }
}

/// The shape of one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestShape {
    /// Prompt plus generated tokens the request may hold.
    pub context_tokens: u64,
    /// Sequences the request runs together.
    pub batch_sequences: u32,
}

/// The request shape a generation's readiness checks cover (§3.6 step 4). A request
/// outside it is refused, never routed to a generation that was not checked for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupportedShape {
    /// The longest context the readiness checks covered.
    pub max_context_tokens: u64,
    /// The most sequences per request the readiness checks covered.
    pub max_batch_sequences: u32,
}

impl SupportedShape {
    /// Accepts `request` when it is within both bounds.
    pub fn check(&self, request: &RequestShape) -> Result<(), ShapeRefusal> {
        if request.context_tokens > self.max_context_tokens {
            return Err(ShapeRefusal::ContextTooLong {
                requested_tokens: request.context_tokens,
                supported_tokens: self.max_context_tokens,
            });
        }
        if request.batch_sequences > self.max_batch_sequences {
            return Err(ShapeRefusal::BatchTooLarge {
                requested_sequences: request.batch_sequences,
                supported_sequences: self.max_batch_sequences,
            });
        }
        Ok(())
    }

    /// Whether every request within `other` is also within `self`.
    pub fn covers(&self, other: &SupportedShape) -> bool {
        self.max_context_tokens >= other.max_context_tokens
            && self.max_batch_sequences >= other.max_batch_sequences
    }
}

/// Why a request shape is outside what a generation was checked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum ShapeRefusal {
    ContextTooLong {
        requested_tokens: u64,
        supported_tokens: u64,
    },
    BatchTooLarge {
        requested_sequences: u32,
        supported_sequences: u32,
    },
}

crate::foundation::strict_serde::strict_tag!(ShapeRefusal, "refusal");

impl fmt::Display for ShapeRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ContextTooLong {
                requested_tokens,
                supported_tokens,
            } => write!(
                f,
                "the request needs {requested_tokens} context tokens, but the model is ready \
                 for at most {supported_tokens}"
            ),
            Self::BatchTooLarge {
                requested_sequences,
                supported_sequences,
            } => write!(
                f,
                "the request has {requested_sequences} sequences, but the model is ready for \
                 at most {supported_sequences}"
            ),
        }
    }
}

impl std::error::Error for ShapeRefusal {}
