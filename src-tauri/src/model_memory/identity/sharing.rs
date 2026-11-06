//! Storage sharing between identical execution representations (§3.2, line 504; S3.3).
//!
//! Equal identities make sharing possible; they never make it allowed. Storage equality
//! is not permission: sharing physical storage needs one authorized trust scope and a
//! scoped grant from the owner. A scoped grant stands on the CORE-02 catalog's grant
//! (S3.3, INT-05): it is made only by checking the catalog, and every use checks the
//! catalog again, so a revocation, the catalog grant's expiry or a quarantine refuses the
//! next use. Device memory (CUDA IPC, processed weights) is never shared across a VM
//! boundary. Trust scopes are the shared `ids::TrustScope`: a runtime category and a
//! domain digest.

use std::collections::BTreeSet;
use std::fmt;
use std::ops::Deref;
use std::sync::{Arc, Mutex};

use crate::foundation::catalog::{Catalog, ObjectId, ReadRefusal, Scope};
use crate::foundation::ids::{Clock, ExecutionId, MonotonicTime, TenantId, TrustScope};

use super::layers::{ArtifactIdentity, ExecutionIdentity};

/// What a [`ScopedGrant`] allows. Every use is read-only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GrantedUse {
    /// Share the immutable artifact's physical storage (S3.3 "read-only artifact reuse").
    ShareImmutableStorage,
    /// Share processed weights in device memory, as through CUDA IPC (S3.3).
    ShareDeviceMemory,
    /// Have requests served by a resident copy (line 506).
    Serve,
    /// Copy the artifact's bytes into the grant's scope (line 506).
    Transfer,
    /// Reuse exact intermediate state computed from the artifact, such as a shared
    /// subgraph's output at a branch boundary (GPU §4.16, line 894). Sharing the state is
    /// not sharing the artifact's device memory.
    ShareIntermediateState,
}

/// The terms a [`ScopedGrant`] is checked for (S3.3): the owner granting, the tenant
/// granted, the artifact, the trust scope it may be used in, the uses and an expiry.
/// Terms alone authorize nothing; only [`ScopedGrant::from_catalog`] binds them to a
/// catalog grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantTerms {
    pub grantor: TenantId,
    pub grantee: TenantId,
    pub artifact: ArtifactIdentity,
    /// Where the grantee may use the data.
    pub scope: TrustScope,
    pub uses: BTreeSet<GrantedUse>,
    /// The latest moment the grant may be used; the catalog grant can end it earlier.
    pub expires_at: MonotonicTime,
}

/// A grant from an artifact's owner to one tenant, for one artifact, within one trust
/// scope, for listed uses, until an expiry (S3.3: "Read-only artifact reuse needs a
/// scoped grant").
///
/// It stands on a CORE-02 catalog grant. [`ScopedGrant::from_catalog`] is the only way
/// to make one, and every [`check_grant`] asks the catalog again whether the grantee's
/// execution may still read the artifact's object, so the owner's revocation, the
/// catalog grant's expiry or a quarantine refuses the next use (INT-05). The terms are
/// read through `Deref` and never changed. Checking a grant locks the catalog, so never
/// check one while holding that lock.
#[derive(Clone)]
pub struct ScopedGrant {
    terms: GrantTerms,
    catalog: Arc<Mutex<Catalog>>,
    object: ObjectId,
    execution: ExecutionId,
}

impl ScopedGrant {
    /// Checks `catalog` now and binds `terms` to what it records (S3.3, INT-05).
    ///
    /// `object` is the catalog object holding the artifact in the grantor's scope, and
    /// `execution` the grantee's execution that the catalog grant names. Refused unless
    /// the object is published, healthy and trusted, belongs to the grantor's scope, and
    /// the grantee's execution may read it now: under a live catalog grant for exactly
    /// that object, or as its owner, since the catalog refuses a grant to the owning
    /// scope. The catalog records no uses or trust scope, so those terms, like an expiry
    /// later than the catalog's, only narrow what the catalog grant allows.
    pub fn from_catalog(
        catalog: &Arc<Mutex<Catalog>>,
        object: ObjectId,
        execution: ExecutionId,
        terms: GrantTerms,
    ) -> Result<Self, GrantRefusal> {
        let grant = Self {
            terms,
            catalog: Arc::clone(catalog),
            object,
            execution,
        };
        grant.check_catalog()?;
        Ok(grant)
    }

    /// The terms this grant was checked for.
    pub fn terms(&self) -> &GrantTerms {
        &self.terms
    }

    /// The catalog object the grant stands on.
    pub fn object(&self) -> ObjectId {
        self.object
    }

    /// The grantee's execution the catalog grant was checked for.
    pub fn execution(&self) -> &ExecutionId {
        &self.execution
    }

    /// Asks the catalog whether the grantee's execution may read the object now, and
    /// whether the object is the grantor's: its identity recomputes from the grantor's
    /// scope and the object's class and content key.
    fn check_catalog(&self) -> Result<(), GrantRefusal> {
        let catalog = self
            .catalog
            .lock()
            .map_err(|_| GrantRefusal::CatalogUnavailable)?;
        let reader = Scope::tenant(self.terms.grantee.clone());
        let view = catalog
            .object_view(&reader, &self.execution, self.object)
            .map_err(GrantRefusal::CatalogRefused)?;
        let owner = Scope::tenant(self.terms.grantor.clone());
        if ObjectId::new(&owner, view.class, view.content_key) != self.object {
            return Err(GrantRefusal::NotFromOwner);
        }
        Ok(())
    }
}

impl Deref for ScopedGrant {
    type Target = GrantTerms;

    fn deref(&self) -> &GrantTerms {
        &self.terms
    }
}

/// Equal when the terms, the object and the execution are, on the same catalog.
impl PartialEq for ScopedGrant {
    fn eq(&self, other: &Self) -> bool {
        self.terms == other.terms
            && self.object == other.object
            && self.execution == other.execution
            && Arc::ptr_eq(&self.catalog, &other.catalog)
    }
}

impl Eq for ScopedGrant {}

impl fmt::Debug for ScopedGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScopedGrant")
            .field("terms", &self.terms)
            .field("object", &self.object)
            .field("execution", &self.execution)
            .finish_non_exhaustive()
    }
}

/// What a grant must cover for one use.
#[derive(Clone, Copy, Debug)]
pub struct GrantNeed<'a> {
    pub owner: &'a TenantId,
    pub grantee: &'a TenantId,
    pub artifact: &'a ArtifactIdentity,
    pub scope: &'a TrustScope,
    pub granted_use: GrantedUse,
}

/// Why a grant does not authorize a use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GrantRefusal {
    /// No grant was presented. Equal storage is not permission (S3.3).
    Missing,
    /// The grant names another owner, or its catalog object is not the grantor's.
    NotFromOwner,
    ForAnotherTenant,
    ForAnotherArtifact,
    ForAnotherScope,
    UseNotGranted {
        requested: GrantedUse,
    },
    Expired {
        expires_at: MonotonicTime,
        now: MonotonicTime,
    },
    /// The catalog does not let the grantee's execution read the object now: no live
    /// grant (never made, revoked or expired), no longer published, or quarantined
    /// (S3.3, INT-05, INT-09).
    CatalogRefused(ReadRefusal),
    /// The catalog's lock was poisoned by a panic, so its grants cannot be read; the use
    /// is refused rather than assumed.
    CatalogUnavailable,
}

impl fmt::Display for GrantRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => {
                f.write_str("no scoped grant was presented; equal storage is not permission")
            }
            Self::NotFromOwner => f.write_str("the grant is not from the artifact's owner"),
            Self::ForAnotherTenant => f.write_str("the grant is for another tenant"),
            Self::ForAnotherArtifact => f.write_str("the grant is for another artifact"),
            Self::ForAnotherScope => f.write_str("the grant is for another trust scope"),
            Self::UseNotGranted { requested } => {
                write!(f, "the grant does not allow {requested:?}")
            }
            Self::Expired { expires_at, now } => write!(
                f,
                "the grant expired at {} ns; it is now {} ns",
                expires_at.as_nanos(),
                now.as_nanos()
            ),
            Self::CatalogRefused(refusal) => {
                write!(f, "the catalog no longer backs the grant: {refusal}")
            }
            Self::CatalogUnavailable => {
                f.write_str("the catalog cannot be read, so the grant cannot be checked")
            }
        }
    }
}

impl std::error::Error for GrantRefusal {}

/// Checks that `grant` covers `need` at `now` and that the catalog still backs it;
/// returns the terms' expiry, the latest moment the grant may be used. A missing grant
/// is refused like a wrong one (S3.3), and every call asks the catalog again (INT-05).
pub fn check_grant(
    grant: Option<&ScopedGrant>,
    need: &GrantNeed<'_>,
    now: MonotonicTime,
) -> Result<MonotonicTime, GrantRefusal> {
    let grant = grant.ok_or(GrantRefusal::Missing)?;
    let terms = grant.terms();
    if terms.grantor != *need.owner {
        return Err(GrantRefusal::NotFromOwner);
    }
    if terms.grantee != *need.grantee {
        return Err(GrantRefusal::ForAnotherTenant);
    }
    if terms.artifact != *need.artifact {
        return Err(GrantRefusal::ForAnotherArtifact);
    }
    if terms.scope != *need.scope {
        return Err(GrantRefusal::ForAnotherScope);
    }
    if !terms.uses.contains(&need.granted_use) {
        return Err(GrantRefusal::UseNotGranted {
            requested: need.granted_use,
        });
    }
    if now >= terms.expires_at {
        return Err(GrantRefusal::Expired {
            expires_at: terms.expires_at,
            now,
        });
    }
    grant.check_catalog()?;
    Ok(terms.expires_at)
}

/// Which physical storage would be shared.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SharingMedium {
    /// Immutable artifact files and their page cache.
    ImmutableStorage,
    /// Processed weights in GPU memory, as through CUDA IPC.
    DeviceMemory,
}

impl SharingMedium {
    /// The grant use that sharing this medium needs.
    pub const fn granted_use(self) -> GrantedUse {
        match self {
            Self::ImmutableStorage => GrantedUse::ShareImmutableStorage,
            Self::DeviceMemory => GrantedUse::ShareDeviceMemory,
        }
    }
}

/// A stored execution representation that someone else may want to share.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredRepresentation {
    pub execution: ExecutionIdentity,
    pub artifact: ArtifactIdentity,
    pub owner: TenantId,
    pub scope: TrustScope,
}

/// A request to share a [`StoredRepresentation`] instead of holding a copy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareRequest {
    pub execution: ExecutionIdentity,
    pub tenant: TenantId,
    pub scope: TrustScope,
    pub medium: SharingMedium,
}

/// Sharing is allowed until `valid_until`, the grant's expiry, and only while the
/// catalog still backs the grant; decide again before each use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharingApproval {
    pub artifact: ArtifactIdentity,
    pub scope: TrustScope,
    pub medium: SharingMedium,
    pub valid_until: MonotonicTime,
}

/// Why storage may not be shared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SharingRefusal {
    /// The execution identities differ; names and sizes never stand in for them.
    DifferentExecutionRepresentation,
    /// Device memory would cross a VM boundary (S3.3: no cross-VM CUDA-handle sharing).
    CrossVmDeviceMemory,
    DifferentTrustScope,
    Unauthorized(GrantRefusal),
}

impl fmt::Display for SharingRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DifferentExecutionRepresentation => {
                f.write_str("the execution representations are not identical")
            }
            Self::CrossVmDeviceMemory => {
                f.write_str("device memory is never shared across a VM boundary")
            }
            Self::DifferentTrustScope => {
                f.write_str("physical storage is shared only within one trust scope")
            }
            Self::Unauthorized(refusal) => write!(f, "sharing is not authorized: {refusal}"),
        }
    }
}

impl std::error::Error for SharingRefusal {}

/// §3.2 line 504 and S3.3: identical execution representations share physical storage
/// only within one authorized trust scope, under a grant from the owner that covers the
/// requester, the artifact, the scope and the medium, and that the catalog still backs
/// (INT-05). The owner's own other executions need a grant too.
pub fn decide_storage_sharing(
    stored: &StoredRepresentation,
    request: &ShareRequest,
    grant: Option<&ScopedGrant>,
    clock: &dyn Clock,
) -> Result<SharingApproval, SharingRefusal> {
    if stored.execution != request.execution {
        return Err(SharingRefusal::DifferentExecutionRepresentation);
    }
    if stored.scope != request.scope {
        let crosses_vm =
            stored.scope.category.is_vm_sandbox() || request.scope.category.is_vm_sandbox();
        return Err(
            if request.medium == SharingMedium::DeviceMemory && crosses_vm {
                SharingRefusal::CrossVmDeviceMemory
            } else {
                SharingRefusal::DifferentTrustScope
            },
        );
    }
    let need = GrantNeed {
        owner: &stored.owner,
        grantee: &request.tenant,
        artifact: &stored.artifact,
        scope: &stored.scope,
        granted_use: request.medium.granted_use(),
    };
    let valid_until =
        check_grant(grant, &need, clock.now()).map_err(SharingRefusal::Unauthorized)?;
    Ok(SharingApproval {
        artifact: stored.artifact,
        scope: stored.scope,
        medium: request.medium,
        valid_until,
    })
}
