//! Model identity layers: GPU §3.2 of docs/combined-gpu-memory-and-vm-sandbox-plan.md,
//! with the identity rules of S3.1, S3.3, §1.1 (lines 305 and 308), §1.3, FAST-03 and
//! the KV sharing of §3.9 (line 636).
//!
//! - Six distinct typed identities: source, logical model, execution, artifact,
//!   placement and session (§3.2). Each is a digest of a canonical encoding of typed
//!   fields under its own domain; placements and sessions bind to the parent execution
//!   and, where applicable, the VM authorization epoch (S3.1).
//! - Adapter identities: LoRA keeps an immutable base with unmerged adapters, or gives a
//!   merged variant its own identity; subtracting a merged adapter is refused (§1.1,
//!   line 308).
//! - The CUDA graph execution key over every graph resource (§1.1, line 305).
//! - The FAST-03 KV-reuse scope key (S13, line 243), enforced only on CORE-01 evidence,
//!   and explicitly configured public-prefix sharing within one trust scope (line 636),
//!   whose allowances end when the coordination authority revokes their authority (T09).
//! - A revocation port over the coordinator's revocation notices (S3.1, VM part §6.3).
//! - Trust scopes, scoped grants and the storage-sharing decision (S3.3; §3.2, line 504).
//!   A scoped grant stands on a CORE-02 catalog grant and is checked against the
//!   catalog at every use (INT-05).
//! - Resident advertisements as expiring hints that are always rechecked (line 506).
//! - The separate fidelity categories of §1.3, which no memory setting changes.
//!
//! Identities are equal only when their typed inputs are equal; no name, size or
//! advertisement establishes equivalence or authority (§3.2, lines 504–506). Everything
//! here is pure, synchronous and deterministic; time comes from the shared clock.

mod adapter;
mod advertisement;
mod encoding;
mod error;
mod fidelity;
mod fields;
mod graph;
mod kv_scope;
mod layers;
mod revocation;
mod sharing;

#[cfg(test)]
pub(crate) mod fakes;
#[cfg(test)]
mod tests;

pub use adapter::{
    AdaptedModel, AdapterChange, AdapterIdentity, AdapterRecipe, AdapterSpec, LoraRefusal,
    MergeScale, MergedAdapter, MergedAdapters,
};
pub use advertisement::{
    AdvertisementPurpose, AdvertisementRefusal, AdvertisementRequest, CurrentResidency,
    RecheckedFacts, RecheckedResidency, Residency, ResidentAdvertisement,
};
pub use error::{IdentityError, PathProblem};
pub use fidelity::{
    AccuracyEvaluation, Approximation, FidelityCategory, FidelityConfiguration, FidelityRefusal,
    MemorySettings, Technique,
};
pub use fields::{
    AuthorityBinding, CommitId, Dtype, KvRepresentation, Label, PositionalEncoding, Quantization,
    QuantizationScheme, RelativePath, TokenPrefix, VersionedName, MAX_LABEL_BYTES, MAX_PATH_BYTES,
};
pub use graph::{
    CaptureShape, GraphCaptureSpec, GraphDifference, GraphExecutionKey, GraphResource,
    GraphResourceField, GraphResourceKind, GraphReuseRefusal,
};
pub use kv_scope::{
    check_kv_reuse, check_scoped_kv_reuse, KvAuthority, KvPosition, KvReuseKey, KvReuseRefusal,
    KvReuseRequest, KvReuseScope, KvScopeComponent, KvScopeKey, KvScopeSpec, KvSharing,
    PublicPrefixScope, PublicPrefixSharing, ScopeEnforcement,
};
pub use layers::{
    ArtifactIdentity, CodePolicy, CompileConfiguration, ExecutionIdentity, ExecutionSpec,
    ImmutableRevision, LogicalModelIdentity, LogicalModelSpec, PlacementIdentity, PlacementSpec,
    RankTopology, SessionIdentity, SessionSpec, SourceFile, SourceIdentity, SourceLocation,
    SourceSpec, TokenState,
};
pub use revocation::{RevocationPort, RevokedAuthorities};
pub use sharing::{
    check_grant, decide_storage_sharing, GrantNeed, GrantRefusal, GrantTerms, GrantedUse,
    ScopedGrant, ShareRequest, SharingApproval, SharingMedium, SharingRefusal,
    StoredRepresentation,
};

/// The shared trust scope, re-exported so `identity::TrustScope` stays stable.
pub use crate::foundation::ids::TrustScope;
