//! Merged variants (GPU §3.9 line 634; §1.1 line 308).
//!
//! A merged variant is materialized separately from the canonical base and adapter,
//! under its own T07 identity, by [`super::graph::DependencyGraph::materialize_merged`].
//! Shared base weights are never mutated. Adding then subtracting an adapter never
//! counts as restoring the base's bits: T07 refuses the subtraction as an identity
//! change, and [`accept_as_base`] refuses subtracted bytes offered as the base. Merging
//! is chosen only when amortized work and memory justify it ([`decide_merge`]), and the
//! proof names the base and adapter it was made for.

use std::fmt;

use crate::foundation::ids::ContentKey;
use crate::model_memory::identity::{AdapterIdentity, ExecutionIdentity};
use crate::model_memory::math::{non_negative, InputError};

/// What merging one adapter into one base would save and cost (line 634).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MergeEconomics {
    /// T07's execution identity of the base the adapter would be merged into.
    pub base: ExecutionIdentity,
    /// T07's identity of the adapter.
    pub adapter: AdapterIdentity,
    /// Requests expected to use the adapter while the variant would be resident.
    pub expected_requests: u64,
    /// Extra seconds each request spends on the unmerged adapter path.
    pub unmerged_overhead_seconds_per_request: f64,
    /// Seconds to materialize the variant.
    pub materialize_seconds: f64,
    /// Saved latency lost by displacing other residents to hold the variant, in
    /// seconds.
    pub retention_penalty_seconds: f64,
    pub variant_bytes: u64,
    /// Bytes the variant may occupy without evicting leased, pinned or retained state.
    pub available_bytes: u64,
}

/// Proof that merging one adapter into one base was justified; made only by
/// [`decide_merge`] and consumed, once, by
/// [`super::graph::DependencyGraph::materialize_merged`] for that base and adapter.
#[derive(Debug, PartialEq)]
pub struct MergeJustified {
    base: ExecutionIdentity,
    adapter: AdapterIdentity,
    saving_seconds: f64,
    cost_seconds: f64,
    materialize_seconds: f64,
    variant_bytes: u64,
}

impl MergeJustified {
    /// The base this proof justifies merging into.
    pub fn base(&self) -> ExecutionIdentity {
        self.base
    }

    /// The adapter this proof justifies merging.
    pub fn adapter(&self) -> AdapterIdentity {
        self.adapter
    }

    pub fn saving_seconds(&self) -> f64 {
        self.saving_seconds
    }

    pub fn cost_seconds(&self) -> f64 {
        self.cost_seconds
    }

    /// Seconds to materialize the variant again after release.
    pub fn materialize_seconds(&self) -> f64 {
        self.materialize_seconds
    }

    pub fn variant_bytes(&self) -> u64 {
        self.variant_bytes
    }
}

/// Why the adapter stays unmerged (line 634).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum KeepUnmerged {
    /// The variant does not fit in the bytes it may occupy.
    DoesNotFit {
        variant_bytes: u64,
        available_bytes: u64,
    },
    /// The amortized saving does not exceed the cost.
    WorkNotAmortized {
        saving_seconds: f64,
        cost_seconds: f64,
    },
}

/// Whether to materialize a merged variant (line 634).
#[derive(Debug, PartialEq)]
pub enum MergeChoice {
    Merge(MergeJustified),
    KeepUnmerged(KeepUnmerged),
}

/// Merges only when the variant fits and
/// `expected_requests × unmerged_overhead_seconds_per_request > materialize_seconds +
/// retention_penalty_seconds` (line 634). At equality the adapter stays unmerged.
pub fn decide_merge(economics: &MergeEconomics) -> Result<MergeChoice, InputError> {
    let overhead_seconds = non_negative(
        "MergeEconomics.unmerged_overhead_seconds_per_request",
        economics.unmerged_overhead_seconds_per_request,
    )?;
    let materialize_seconds = non_negative(
        "MergeEconomics.materialize_seconds",
        economics.materialize_seconds,
    )?;
    let cost_seconds = materialize_seconds
        + non_negative(
            "MergeEconomics.retention_penalty_seconds",
            economics.retention_penalty_seconds,
        )?;
    if economics.variant_bytes == 0 {
        return Err(InputError::NotPositive {
            field: "MergeEconomics.variant_bytes",
        });
    }
    if economics.variant_bytes > economics.available_bytes {
        return Ok(MergeChoice::KeepUnmerged(KeepUnmerged::DoesNotFit {
            variant_bytes: economics.variant_bytes,
            available_bytes: economics.available_bytes,
        }));
    }
    let saving_seconds = economics.expected_requests as f64 * overhead_seconds;
    if saving_seconds > cost_seconds {
        Ok(MergeChoice::Merge(MergeJustified {
            base: economics.base,
            adapter: economics.adapter,
            saving_seconds,
            cost_seconds,
            materialize_seconds,
            variant_bytes: economics.variant_bytes,
        }))
    } else {
        Ok(MergeChoice::KeepUnmerged(KeepUnmerged::WorkNotAmortized {
            saving_seconds,
            cost_seconds,
        }))
    }
}

/// Where weights offered as the base came from (line 634, §1.1 line 308).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WeightsOrigin {
    /// A canonical copy whose bytes were verified to have this content key.
    VerifiedCanonical { content: ContentKey },
    /// A merged variant.
    MergedVariant { variant: ExecutionIdentity },
    /// A merged variant with the adapter subtracted again.
    SubtractedFromVariant {
        variant: ExecutionIdentity,
        adapter: AdapterIdentity,
    },
}

/// Why weights were not accepted as the base (line 634).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BaseClaimRefusal {
    /// Floating-point subtraction is not an exact undo of addition.
    ArithmeticUndoIsNotRestore,
    /// A merged variant has its own identity and never stands in for the base.
    MergedVariantIsNotTheBase,
    /// The verified bytes are other content.
    ContentMismatch {
        expected: ContentKey,
        actual: ContentKey,
    },
}

impl fmt::Display for BaseClaimRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArithmeticUndoIsNotRestore => f.write_str(
                "subtracting an adapter does not restore the base's bits; use the canonical base",
            ),
            Self::MergedVariantIsNotTheBase => f.write_str("a merged variant is not the base"),
            Self::ContentMismatch { expected, actual } => {
                write!(f, "the content is {actual}, not the base {expected}")
            }
        }
    }
}

impl std::error::Error for BaseClaimRefusal {}

/// Accepts weights as the base only from a verified canonical copy of the base's exact
/// bytes, `base_content`; a variant, with or without the adapter subtracted again,
/// never counts (line 634).
pub fn accept_as_base(
    base_content: &ContentKey,
    origin: &WeightsOrigin,
) -> Result<(), BaseClaimRefusal> {
    match origin {
        WeightsOrigin::VerifiedCanonical { content } if content == base_content => Ok(()),
        WeightsOrigin::VerifiedCanonical { content } => Err(BaseClaimRefusal::ContentMismatch {
            expected: *base_content,
            actual: *content,
        }),
        WeightsOrigin::MergedVariant { .. } => Err(BaseClaimRefusal::MergedVariantIsNotTheBase),
        WeightsOrigin::SubtractedFromVariant { .. } => {
            Err(BaseClaimRefusal::ArithmeticUndoIsNotRestore)
        }
    }
}

#[cfg(test)]
mod tests;
