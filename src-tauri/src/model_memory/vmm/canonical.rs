//! The proof clean-drop parking needs: a verified canonical copy of exactly the weights'
//! content (Appendix E step 5; GPU-W05: clean-drop parking only when canonical state can
//! reconstruct exact weights; §1.1 line 307).
//!
//! A [`VerifiedCanonicalCopy`] is made only by a real check. It has no public fields and
//! no deserializer, so it is never written as a literal or read back from JSON. Either
//! the CORE-02 catalog holds the content as a published, healthy object in the reader's
//! own scope, or a copy passes the residency rule of clean eviction: verified for exactly
//! this content, in a tier that guarantees it stays available.
//!
//! A catalog proof holds a catalog lease on the object, so garbage collection cannot
//! remove the copy while the GPU copy is dropped. The lease has exactly one holder, which
//! renews it while parked and releases it once the artifact is refilled
//! ([`VmmModel::release_canonical_copy`](super::VmmModel::release_canonical_copy)); a clone
//! of the proof never carries the lease, and a park refuses it.

use std::fmt;
use std::time::Duration;

use serde::Serialize;

use crate::foundation::catalog::{ArtifactClass, Catalog, LeaseId, ObjectId, ReadRefusal, Scope};
use crate::foundation::ids::{ContentKey, ExecutionId, MonotonicTime};
use crate::model_memory::residency::eviction::{
    Content, CopyTier, ReconstructibleCopy, Verification,
};

/// What vouched for a canonical copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum CanonicalSource {
    /// A published, healthy catalog object in the reader's own scope (CORE-02).
    Catalog { object: ObjectId },
    /// A copy verified for this content in a tier that guarantees availability (GPU §1.1
    /// line 307, as the residency module decides it).
    Reconstructible { tier: CopyTier },
}

/// The catalog lease a catalog proof holds, and who holds it.
#[derive(Debug, PartialEq, Eq, Serialize)]
struct CatalogHold {
    reader: Scope,
    execution: ExecutionId,
    /// Local to the catalog that granted it; never serialized.
    #[serde(skip)]
    lease: LeaseId,
}

/// Proof that a verified canonical copy of `content` exists, so a park may drop the GPU
/// copy without copying it back (Appendix E step 5). Made only by
/// [`VerifiedCanonicalCopy::in_catalog`] or [`VerifiedCanonicalCopy::reconstructing`].
///
/// A catalog proof is the one holder of its lease, so a clone keeps the content and source
/// but never the lease: a clone of a catalog proof holds nothing, and a park refuses it.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct VerifiedCanonicalCopy {
    content: ContentKey,
    source: CanonicalSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    hold: Option<CatalogHold>,
}

impl Clone for VerifiedCanonicalCopy {
    /// The same facts without the lease.
    fn clone(&self) -> Self {
        Self {
            content: self.content,
            source: self.source,
            hold: None,
        }
    }
}

/// Why no canonical copy was established, renewed or released.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum CanonicalCopyRefusal {
    /// The catalog holds no published, healthy object of this class and content in the
    /// reader's scope. It is absent, quarantined or held only by another scope, and equal
    /// content elsewhere is never permission (S3.3).
    NotInCatalog {
        scope: Scope,
        class: ArtifactClass,
        content: ContentKey,
    },
    /// The catalog would not lease the object, so the copy could vanish while the GPU copy
    /// is dropped.
    LeaseRefused {
        object: ObjectId,
        #[serde(skip)]
        reason: ReadRefusal,
    },
    /// The catalog would not renew or release the lease.
    LeaseUnchanged {
        #[serde(skip)]
        reason: ReadRefusal,
    },
    /// The copy was never verified, or its check failed.
    Unverified { tier: CopyTier },
    /// The copy is verified for other content.
    OtherContent { tier: CopyTier, verified: Content },
    /// The copy sits where it may vanish before it is needed again: reclaimable host RAM,
    /// a peer or a remote source.
    MayVanish { tier: CopyTier },
}

impl fmt::Display for CanonicalCopyRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInCatalog {
                scope,
                class,
                content,
            } => write!(
                f,
                "the catalog holds no published, healthy {class} object with content {content} \
                 in scope {scope}; copy the weights back to the host instead"
            ),
            Self::LeaseRefused { object, reason } => write!(
                f,
                "the catalog would not lease object {object} ({reason}), so it could vanish \
                 while the GPU copy is dropped"
            ),
            Self::LeaseUnchanged { reason } => {
                write!(f, "the catalog would not change the lease: {reason}")
            }
            Self::Unverified { tier } => write!(
                f,
                "the {tier:?} copy is not verified, so it cannot rebuild the weights"
            ),
            Self::OtherContent { tier, verified } => write!(
                f,
                "the {tier:?} copy is verified for {verified:?}, not for these weights"
            ),
            Self::MayVanish { tier } => write!(
                f,
                "a {tier:?} copy may vanish before it is needed, so it cannot stand in for \
                 the GPU copy"
            ),
        }
    }
}

impl std::error::Error for CanonicalCopyRefusal {}

impl VerifiedCanonicalCopy {
    /// The catalog's published, healthy object of `class` with `content` in `reader`'s own
    /// scope, leased to `reader` and `execution` for `hold_for`; another scope's equal
    /// content is invisible (CORE-02, S3.3). Renew the lease while the artifact stays
    /// parked, and release it once the artifact is refilled.
    pub fn in_catalog(
        catalog: &mut Catalog,
        reader: &Scope,
        execution: &ExecutionId,
        class: ArtifactClass,
        content: ContentKey,
        hold_for: Duration,
    ) -> Result<Self, CanonicalCopyRefusal> {
        let object = catalog.find(reader, class, content).ok_or_else(|| {
            CanonicalCopyRefusal::NotInCatalog {
                scope: reader.clone(),
                class,
                content,
            }
        })?;
        let lease = catalog
            .acquire_lease(reader, execution, object, hold_for)
            .map_err(|reason| CanonicalCopyRefusal::LeaseRefused { object, reason })?;
        Ok(Self {
            content,
            source: CanonicalSource::Catalog { object },
            hold: Some(CatalogHold {
                reader: reader.clone(),
                execution: execution.clone(),
                lease,
            }),
        })
    }

    /// `copy`, if it reconstructs exactly the weights with `content` by the residency
    /// rule of clean eviction ([`ReconstructibleCopy::reconstructs`]). It holds no lease.
    pub fn reconstructing(
        copy: &ReconstructibleCopy,
        content: ContentKey,
    ) -> Result<Self, CanonicalCopyRefusal> {
        let weights = Content::Immutable(content);
        if copy.reconstructs(&weights) {
            return Ok(Self {
                content,
                source: CanonicalSource::Reconstructible { tier: copy.tier },
                hold: None,
            });
        }
        Err(match copy.verification {
            Verification::Unverified => CanonicalCopyRefusal::Unverified { tier: copy.tier },
            Verification::Verified { content: verified } if verified != weights => {
                CanonicalCopyRefusal::OtherContent {
                    tier: copy.tier,
                    verified,
                }
            }
            Verification::Verified { .. } => CanonicalCopyRefusal::MayVanish { tier: copy.tier },
        })
    }

    /// The content the copy holds.
    pub fn content(&self) -> ContentKey {
        self.content
    }

    pub fn source(&self) -> CanonicalSource {
        self.source
    }

    /// The catalog lease the proof holds; `None` for a residency proof.
    pub fn lease(&self) -> Option<LeaseId> {
        self.hold.as_ref().map(|hold| hold.lease)
    }

    /// Extends the catalog lease by `hold_for` from now, on the catalog that granted it;
    /// returns when it ends. A residency proof holds nothing and is refused.
    pub fn renew(
        &self,
        catalog: &mut Catalog,
        hold_for: Duration,
    ) -> Result<MonotonicTime, CanonicalCopyRefusal> {
        let Some(hold) = &self.hold else {
            return Err(CanonicalCopyRefusal::LeaseUnchanged {
                reason: ReadRefusal::UnknownLease,
            });
        };
        catalog
            .renew_lease(&hold.reader, &hold.execution, hold.lease, hold_for)
            .map_err(|reason| CanonicalCopyRefusal::LeaseUnchanged { reason })
    }

    /// Ends the proof and releases its catalog lease on the catalog that granted it. A
    /// lease the catalog already revoked, such as by quarantine, counts as released.
    pub fn release(self, catalog: &mut Catalog) -> Result<(), CanonicalCopyRefusal> {
        let Some(hold) = self.hold else {
            return Ok(());
        };
        match catalog.release_lease(&hold.reader, &hold.execution, hold.lease) {
            Ok(()) | Err(ReadRefusal::UnknownLease) => Ok(()),
            Err(reason) => Err(CanonicalCopyRefusal::LeaseUnchanged { reason }),
        }
    }
}
