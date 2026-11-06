//! Ports to other plan modules (docs/combined-plan-agent-rollout.md §15): the immutable
//! object catalog (T05, CORE-02), the identity layers (T07, §3.2) and the four-granularity
//! extent model (T06, §2.4). Each trait covers only what the importer needs.
//!
//! The catalog and identity ports have adapters over the committed modules
//! ([`CatalogArtifacts`](super::CatalogArtifacts) and
//! [`IdentityLayers`](super::IdentityLayers)); the extent port waits for T06. Identities
//! cross the ports as digests: an adapter returns the digest of the typed identity its
//! module builds, so the importer and its fakes do not depend on how identities are formed.

use std::fmt;
use std::io;

use crate::foundation::ids::Digest;

use super::digests::ManifestDigest;
use super::source::SourceListing;
use super::validate::ValidatedManifest;

/// Source identity (§3.2 layer 1: repository or local source, immutable revision, file
/// digests, configuration and license/provenance): the digest of the identity layer's
/// typed identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceIdentity(pub Digest);

/// Execution identity (§3.2 layer 3: logical identity plus runner, adapter, kernel and
/// layout versions, GPU constraints, rank topology and processed-weight format).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExecutionIdentity(pub Digest);

/// Artifact identity (§3.2 layer 4: the canonical manifest digest bound under the identity
/// layer's own domain), so it differs from the bare manifest digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArtifactIdentity(pub Digest);

/// What one import produces an artifact for. Imports are single-flight per key, and a
/// published artifact is reused per key (§3.3: "locking/singleflight per
/// source+execution identity").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ImportKey {
    pub source: SourceIdentity,
    pub execution: ExecutionIdentity,
}

/// Why an identity could not be formed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityError {
    /// A field the identity layer needs is missing or has no counterpart there.
    Incomplete {
        field: &'static str,
    },
    /// The manifest and the identity inputs disagree on a field.
    Inconsistent {
        field: &'static str,
    },
    /// The identity layer refused its inputs; the detail is its own.
    Refused {
        detail: String,
    },
    Unavailable,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete { field } => write!(f, "the identity needs {field}"),
            Self::Inconsistent { field } => {
                write!(
                    f,
                    "the manifest and the identity inputs disagree on {field}"
                )
            }
            Self::Refused { detail } => write!(f, "the identity layer refused: {detail}"),
            Self::Unavailable => f.write_str("the identity service is unavailable"),
        }
    }
}

impl std::error::Error for IdentityError {}

/// Port to the model identity layers (T07).
pub trait ModelIdentities {
    /// Per-import inputs the listing and manifest do not carry, such as the license or
    /// the GPU architectures an execution is built for.
    type Context;

    /// The source identity of a verified listing whose model configuration digests to
    /// `configuration`.
    fn source_identity(
        &self,
        listing: &SourceListing,
        configuration: &Digest,
        context: &Self::Context,
    ) -> Result<SourceIdentity, IdentityError>;

    /// The execution identity a validated manifest describes; refused unless the
    /// manifest's own source is `source`.
    fn execution_identity(
        &self,
        source: &SourceIdentity,
        manifest: &ValidatedManifest,
        context: &Self::Context,
    ) -> Result<ExecutionIdentity, IdentityError>;

    /// The artifact identity of a canonical manifest digest (§3.2 layer 4).
    fn artifact_identity(&self, manifest: &ManifestDigest) -> ArtifactIdentity;
}

/// One integrity extent of a file's logical bytes, with its true length (§2.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExtentSpan {
    pub offset_bytes: u64,
    pub true_length_bytes: u64,
}

/// Why an extent plan was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExtentPlanError {
    /// The planner refused the request.
    Refused,
    /// The plan does not tile the file with extents of 1 to the maximum bytes, in order.
    InvalidPlan { offset_bytes: u64 },
}

impl fmt::Display for ExtentPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused => f.write_str("the extent planner refused the file"),
            Self::InvalidPlan { offset_bytes } => {
                write!(
                    f,
                    "the extent plan does not tile the file at byte {offset_bytes}"
                )
            }
        }
    }
}

impl std::error::Error for ExtentPlanError {}

/// Port to the four-granularity model (T06) for integrity extents g_h.
pub trait ExtentPlanner {
    /// Integrity extents covering `[0, logical_length_bytes)` for a requested size of
    /// `integrity_extent_bytes`. Every final extent keeps its true length.
    fn integrity_extents(
        &self,
        logical_length_bytes: u64,
        integrity_extent_bytes: u64,
    ) -> Result<Vec<ExtentSpan>, ExtentPlanError>;
}

/// Checks a plan before use: spans in order, each 1 to `max_extent_bytes` long, tiling
/// `[0, logical_length_bytes)` exactly. A planner's output is never trusted unchecked.
pub fn check_extent_plan(
    spans: &[ExtentSpan],
    logical_length_bytes: u64,
    max_extent_bytes: u64,
) -> Result<(), ExtentPlanError> {
    let mut covered_bytes = 0u64;
    for span in spans {
        if span.offset_bytes != covered_bytes
            || span.true_length_bytes == 0
            || span.true_length_bytes > max_extent_bytes
        {
            return Err(ExtentPlanError::InvalidPlan {
                offset_bytes: covered_bytes,
            });
        }
        covered_bytes = span
            .offset_bytes
            .checked_add(span.true_length_bytes)
            .ok_or(ExtentPlanError::InvalidPlan {
                offset_bytes: covered_bytes,
            })?;
    }
    if covered_bytes != logical_length_bytes {
        return Err(ExtentPlanError::InvalidPlan {
            offset_bytes: covered_bytes,
        });
    }
    Ok(())
}

/// A temporary area in the catalog for one import.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StagingId(pub u64);

/// An artifact visible in the catalog for its key: its manifest digest and its artifact
/// identity (§3.2 layer 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublishedArtifact {
    pub key: ImportKey,
    pub manifest: ManifestDigest,
    pub artifact: ArtifactIdentity,
}

/// Why the catalog refused an operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CatalogError {
    /// The bounded disk reservation could not be made.
    ReservationRefused {
        requested_bytes: u64,
    },
    /// A write would exceed the reservation.
    ReservationExceeded {
        reserved_bytes: u64,
        requested_bytes: u64,
    },
    UnknownStaging,
    /// Another artifact is already published for the key.
    Conflict,
    /// The catalog refused or failed the step; the detail is the catalog's own.
    Refused {
        detail: String,
    },
    Storage {
        kind: io::ErrorKind,
    },
}

impl fmt::Display for CatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReservationRefused { requested_bytes } => {
                write!(f, "the catalog cannot reserve {requested_bytes} bytes")
            }
            Self::ReservationExceeded {
                reserved_bytes,
                requested_bytes,
            } => write!(
                f,
                "{requested_bytes} bytes exceed the {reserved_bytes}-byte reservation"
            ),
            Self::UnknownStaging => f.write_str("the catalog has no such temporary area"),
            Self::Conflict => f.write_str("another artifact is already published for this key"),
            Self::Refused { detail } => write!(f, "the catalog refused: {detail}"),
            Self::Storage { kind } => write!(f, "catalog storage failed: {kind}"),
        }
    }
}

impl std::error::Error for CatalogError {}

/// Port to the immutable object catalog (T05, CORE-02). Only the importer writes
/// committed content (§3.4).
pub trait ArtifactCatalog {
    /// Per-import inputs the key does not carry, such as the owning scope and the trust
    /// claim.
    type Context;

    /// The artifact already published for `key`; a repeated import reuses it instead of
    /// storing another copy (GPU-W03: "Repeated imports do not multiply disk usage").
    /// `None` also when the published sidecar was written under an earlier manifest
    /// schema: it needs a re-import, which publishes a new sidecar for the key and leaves
    /// the old one as it is.
    fn published(
        &self,
        key: &ImportKey,
        context: &Self::Context,
    ) -> Result<Option<PublishedArtifact>, CatalogError>;

    /// Opens a temporary area holding at most `reserved_bytes` (Appendix C: a bounded
    /// disk reservation).
    fn begin_staging(
        &self,
        key: &ImportKey,
        reserved_bytes: u64,
        context: &Self::Context,
    ) -> Result<StagingId, CatalogError>;

    /// Writes the sidecar into the temporary area, declaring the record it will be
    /// published under.
    fn write_staged(
        &self,
        staging: StagingId,
        sidecar: &[u8],
        artifact: &PublishedArtifact,
    ) -> Result<(), CatalogError>;

    /// Reads the staged sidecar back from the temporary area, at most `max_bytes`.
    fn read_staged(&self, staging: StagingId, max_bytes: u64) -> Result<Vec<u8>, CatalogError>;

    /// Makes the temporary representation durable, still unpublished.
    fn commit(&self, staging: StagingId) -> Result<(), CatalogError>;

    /// Publishes the committed artifact atomically under the record declared when it was
    /// staged.
    fn publish(&self, staging: StagingId) -> Result<PublishedArtifact, CatalogError>;

    /// Discards a temporary area or an unpublished commit; nothing becomes visible, and
    /// the catalog reclaims it as unreachable.
    fn discard(&self, staging: StagingId) -> Result<(), CatalogError>;
}
