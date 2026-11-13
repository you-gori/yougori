//! CORE-02: the immutable object catalog (docs/combined-gpu-memory-and-vm-sandbox-plan.md,
//! S2 CORE-02, S3.3, INT-05, INT-09, GPU part §1.1 line 306 and §3.3–§3.4).
//!
//! The catalog is the shared storage and provenance contract. It stores immutable
//! objects under one root directory the caller owns:
//!
//! - **Scoped content identity.** Bytes are named by the shared
//!   [`ContentKey`](crate::foundation::ids::ContentKey), a domain-separated digest of the
//!   true length and the bytes (line 529) that transfer and manifests use too. Objects are
//!   addressed by [`ObjectId`], which binds the owning [`Scope`] and the
//!   [`ArtifactClass`], so equal content is never permission (S3.3).
//! - **Atomic publication.** The importer runs bounded source verification, a temporary
//!   representation, a complete index, read-back validation, a durable commit and then
//!   catalog publication (line 533). An interrupted or cancelled import never publishes,
//!   and imports are single-flight per tenant scope, source and model execution identity:
//!   another execution of the tenant subscribes to the running import.
//! - **One owner per root.** Opening a catalog takes the root's exclusive lock
//!   ([`LOCK_FILE`]), an operating-system file lock released when its process ends, so a
//!   crash leaves none behind. A second open of a held root, from another engine or this
//!   one, is refused before it reads, creates or removes anything there, so recovery on open
//!   never removes the files of another catalog's writes in progress.
//! - **Resumable verified data.** Objects are made of extents, each with its own digest;
//!   an interrupted import resumes from re-verified extents only and fetches corrupt ones
//!   again.
//! - **Quotas** per scope with typed refusals; nothing is evicted to make room.
//! - **Leases, grants and garbage collection.** Consumers read under leases through
//!   read-only handles (line 546). Another scope reads only under a grant for that exact
//!   object, and private metadata never crosses scopes (INT-05). Garbage collection
//!   removes only unreachable, unleased prepared representations after a grace period;
//!   never an original and never a quarantined object.
//! - **Typed verifiers and trust per artifact class** (INT-09). A checksum alone is never
//!   trust (S2 CORE-08), and the trust an object was published under is re-checked
//!   against the current policy at open, on every read and on verification: a withdrawn
//!   publisher's objects are quarantined, reported and kept, never served.
//! - **Versioned records.** Every persisted record declares its format; known older
//!   formats migrate forward on open, atomically per record and resumably, and newer or
//!   unknown ones are refused and kept untouched. Migration never rewrites, moves or
//!   deletes a published object.
//! - **Separate deletions.** Local model deletion, cache eviction and source-file
//!   deletion are distinct operations, and only source-file deletion ever deletes a
//!   user's original (line 552).
//!
//! The tensor manifest of §3.3 is MODELS-specific and is not built here; model sidecars,
//! OCI extraction, guest images and document manifests stay specialized importers that
//! supply [`ImportSource`]s and [`ArtifactVerifier`]s (S2 CORE-02).

/// Declares a newtype over [`crate::foundation::ids::Digest`] with the catalog's common
/// traits; the hex text form is canonical.
macro_rules! digest_type {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(
            Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(crate::foundation::ids::Digest);

        impl $name {
            /// The underlying digest.
            pub const fn digest(self) -> crate::foundation::ids::Digest {
                self.0
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0.to_hex())
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0.to_hex())
            }
        }
    };
}

mod access;
mod amortize;
mod content;
mod identity;
mod import;
mod lifecycle;
mod lock;
mod migrate;
mod provenance;
mod state;
mod store;
mod summary;
mod trust;

#[cfg(test)]
mod fakes;
#[cfg(test)]
mod tests;

pub use access::{
    GrantId, GrantRefusal, GrantRequest, LeaseId, MetadataRefusal, ObjectView, PrivateMetadata,
    ReadError, ReadHandle, ReadRefusal,
};
pub use amortize::{AmortizationError, ImportAmortization};
pub use content::{
    ExtentDigest, ExtentEntry, ImportManifest, ManifestBuilder, ManifestError, ManifestLimits,
    EXTENT_DOMAIN, MANIFEST_DOMAIN,
};
pub use identity::{
    ArtifactClass, ModelExecutionKey, ObjectId, ObjectRole, PublisherId, RootId, RootKind,
    RootName, Scope, SourceIdentity, OBJECT_DOMAIN, ROOT_DOMAIN, SOURCE_DOMAIN,
};
pub use import::{
    ByteSpan, CancelFlag, CancelOutcome, Checkpoint, ImportControl, ImportError, ImportProgress,
    ImportRefusal, ImportRequest, ImportSource, ImportStage, ImportStart, ImportStatus,
    ImportTicket, Proceed, SourceError, StagedExtents, Uninterrupted, FLIGHT_DOMAIN,
};
pub use lifecycle::{
    CacheEviction, DeleteRefusal, EvictionCandidate, EvictionRefusal, GcRefusal, GcReport, Holder,
    ImportEvictionRefusal, LocalModelDeletion, RootRefusal, RootView, SourceFileDeletion,
    SourceFileTarget, VerifyError,
};
pub use lock::LOCK_FILE;
pub use migrate::{
    FormatRefusal, MigrationReport, RecordKind, Rekeyed, Unresumable, UnresumableReason,
    CATALOG_FORMAT,
};
pub use provenance::{
    FailureReason, FailureRecord, StorageFailure, StorageOperation, FAILURE_COMPONENT,
    MAX_DETAIL_BYTES,
};
pub use state::{
    Catalog, CatalogConfig, CatalogLimits, IntegrityFailure, MetadataError, ObjectMetadata,
    ObjectStatus, OpenFailure, OpenReport, QuotaRefusal, QuotaUsage, TrustRevision,
};
pub use summary::{CatalogSummary, ClassSummary, ObjectTally, QuotaCharge, ScopeSummary};
pub use trust::{
    ArtifactVerifier, ContentDescriptor, DuplicateVerifier, ObjectBytes, TrustBasis, TrustClaim,
    TrustPolicy, TrustRefusal, VerifierRegistry, VerifierRejection,
};
