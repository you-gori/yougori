//! Test fixtures over the real CORE-02 catalog and CORE-01 probe registry. A scoped
//! grant is always checked through a catalog that holds the owner's grant, and scope
//! enforcement is always evidence a registry evaluated; neither is written by hand.

use std::collections::BTreeSet;
use std::fs;
use std::num::NonZeroU64;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use crate::foundation::catalog::{
    ArtifactClass, ArtifactVerifier, Catalog, CatalogConfig, ContentDescriptor, GrantId,
    GrantRequest, ImportManifest, ImportRequest, ImportSource, ImportStart, ImportStatus,
    ObjectBytes, ObjectId, ObjectMetadata, ObjectRole, PublisherId, Scope, SourceError,
    SourceIdentity, TrustClaim, TrustPolicy, Uninterrupted, VerifierRegistry, VerifierRejection,
};
use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    Backend, BackendRelease, Capability, ConfigurationFingerprint, Observation, ProbeRegistry,
    Requirement, RuntimeSubject, SourceClass, Subject, SupportDetail,
};
use crate::foundation::ids::{
    digest, Clock, ContentKey, ExecutionCategory, ExecutionId, ManualClock, MonotonicTime,
    OperationId, TenantId,
};

use super::kv_scope::ScopeEnforcement;
use super::layers::ArtifactIdentity;
use super::sharing::{GrantTerms, ScopedGrant};

/// What each owner may store in a fixture catalog.
const OWNER_QUOTA_BYTES: u64 = 1 << 20;
/// Extent size of fixture objects.
const EXTENT_BYTES: u64 = 64;

/// A CORE-02 catalog in a temporary directory, where owners publish their own model
/// weights and grant them to other tenants (S3.3, INT-05).
pub(crate) struct GrantCatalog {
    catalog: Arc<Mutex<Catalog>>,
    dir: tempfile::TempDir,
}

impl GrantCatalog {
    /// A catalog on `clock` in which each of `owners` may publish 1 MiB of user-selected
    /// model weights.
    pub(crate) fn open(clock: Arc<dyn Clock>, owners: &[TenantId]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut verifiers = VerifierRegistry::new();
        verifiers.register(Box::new(AnyWeights)).unwrap();
        let config = owners.iter().fold(
            CatalogConfig::new(Duration::from_secs(60)).with_trust(
                ArtifactClass::ModelWeights,
                TrustPolicy::new().accept_user_selected(),
            ),
            |config, owner| config.with_quota(Scope::tenant(owner.clone()), OWNER_QUOTA_BYTES),
        );
        let (catalog, _) = Catalog::open(dir.path(), config, verifiers, clock).unwrap();
        Self {
            catalog: Arc::new(Mutex::new(catalog)),
            dir,
        }
    }

    /// The shared catalog grants are checked against.
    pub(crate) fn catalog(&self) -> &Arc<Mutex<Catalog>> {
        &self.catalog
    }

    /// The catalog, locked. Drop the guard before checking a grant.
    pub(crate) fn lock(&self) -> MutexGuard<'_, Catalog> {
        self.catalog.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Publishes `bytes` as `owner`'s original model weights; the same bytes publish the
    /// same object.
    pub(crate) fn publish(&self, owner: &TenantId, bytes: &[u8]) -> ObjectId {
        let mut source = MemorySource {
            name: ContentKey::of(bytes).digest().to_hex(),
            bytes: bytes.to_vec(),
        };
        let request = ImportRequest {
            operation: OperationId::new("op-identity-fixture").unwrap(),
            execution: ExecutionId::new("exe-identity-fixture").unwrap(),
            scope: Scope::tenant(owner.clone()),
            class: ArtifactClass::ModelWeights,
            role: ObjectRole::Original,
            manifest: ImportManifest::describe(bytes, NonZeroU64::new(EXTENT_BYTES).unwrap()),
            trust: TrustClaim::UserSelected,
            depends_on: BTreeSet::new(),
            metadata: ObjectMetadata::new(),
        };
        let mut catalog = self.lock();
        let ticket = match catalog.begin_import(request, source.identity()).unwrap() {
            ImportStart::Started(ticket) | ImportStart::Attached(ticket) => ticket,
            ImportStart::AlreadyPublished(object) => return object,
        };
        match catalog
            .drive_import(&ticket, &mut source, &mut Uninterrupted)
            .unwrap()
        {
            ImportStatus::Published { object, .. } => object,
            status => panic!("the fixture object was not published: {status:?}"),
        }
    }

    /// The object standing for `artifact` in `owner`'s scope, published if need be.
    pub(crate) fn publish_artifact(
        &self,
        owner: &TenantId,
        artifact: &ArtifactIdentity,
    ) -> ObjectId {
        self.publish(owner, artifact.digest().as_bytes())
    }

    /// `owner` lets `grantee`'s `execution` read `object` until `expires_at`.
    pub(crate) fn grant(
        &self,
        owner: &TenantId,
        object: ObjectId,
        grantee: &TenantId,
        execution: &ExecutionId,
        expires_at: MonotonicTime,
    ) -> GrantId {
        self.lock()
            .grant(
                &Scope::tenant(owner.clone()),
                GrantRequest {
                    object,
                    grantee: Scope::tenant(grantee.clone()),
                    execution: Some(execution.clone()),
                    expires_at,
                },
            )
            .unwrap()
    }

    /// `owner` revokes `grant`.
    pub(crate) fn revoke(&self, owner: &TenantId, grant: GrantId) {
        self.lock()
            .revoke_grant(&Scope::tenant(owner.clone()), grant)
            .unwrap();
    }

    /// A scoped grant for `terms`, checked through this catalog. The artifact's object is
    /// published in the grantor's scope and, unless the grantee is the grantor, granted to
    /// the grantee's `execution` without a catalog expiry, so the terms bound it.
    pub(crate) fn scoped_grant(&self, execution: &ExecutionId, terms: GrantTerms) -> ScopedGrant {
        let object = self.publish_artifact(&terms.grantor, &terms.artifact);
        if terms.grantee != terms.grantor {
            self.grant(
                &terms.grantor,
                object,
                &terms.grantee,
                execution,
                MonotonicTime::from_nanos(u64::MAX),
            );
        }
        ScopedGrant::from_catalog(&self.catalog, object, execution.clone(), terms).unwrap()
    }
}

/// A scoped grant for `terms` checked through a catalog of its own, for tests that need
/// no other catalog: the grantee's `execution` holds a catalog grant that never expires,
/// so the terms bound it.
pub(crate) fn checked_grant(execution: &ExecutionId, terms: GrantTerms) -> ScopedGrant {
    let clock = Arc::new(ManualClock::new(MonotonicTime::ZERO));
    let grants = GrantCatalog::open(clock, std::slice::from_ref(&terms.grantor));
    grants.scoped_grant(execution, terms)
}

impl Drop for GrantCatalog {
    /// Committed files are read-only; make them writable so the directory can go.
    fn drop(&mut self) {
        make_writable(self.dir.path());
    }
}

fn make_writable(path: &Path) {
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            make_writable(&entry.path());
        }
    }
    if let Ok(metadata) = fs::metadata(path) {
        let mut permissions = metadata.permissions();
        if permissions.readonly() {
            #[allow(clippy::permissions_set_readonly_false)]
            permissions.set_readonly(false);
            let _ = fs::set_permissions(path, permissions);
        }
    }
}

/// Bytes held in memory.
struct MemorySource {
    name: String,
    bytes: Vec<u8>,
}

impl ImportSource for MemorySource {
    fn identity(&self) -> SourceIdentity {
        SourceIdentity::describe("identity-fixture", &self.name)
    }

    fn length_bytes(&mut self) -> Result<u64, SourceError> {
        Ok(self.bytes.len() as u64)
    }

    fn read_at(&mut self, offset_bytes: u64, buffer: &mut [u8]) -> Result<usize, SourceError> {
        let start = usize::try_from(offset_bytes).unwrap_or(usize::MAX);
        let available = self.bytes.get(start..).unwrap_or(&[]);
        let count = available.len().min(buffer.len());
        buffer[..count].copy_from_slice(&available[..count]);
        Ok(count)
    }
}

/// The fixture's verifier of model weights: no publisher is authenticated, and any bytes
/// are structurally acceptable.
struct AnyWeights;

impl ArtifactVerifier for AnyWeights {
    fn class(&self) -> ArtifactClass {
        ArtifactClass::ModelWeights
    }

    fn authenticate(
        &self,
        _content: &ContentDescriptor,
        _publisher: &PublisherId,
        _attestation: &[u8],
    ) -> Result<(), VerifierRejection> {
        Err(VerifierRejection::AttestationInvalid)
    }

    fn validate(
        &self,
        _content: &ContentDescriptor,
        _bytes: &mut ObjectBytes,
    ) -> Result<(), VerifierRejection> {
        Ok(())
    }
}

/// The serving runtime the fixture's scope-enforcement evidence is about.
pub(crate) fn kv_backend() -> Subject {
    Subject::Runtime(RuntimeSubject {
        category: ExecutionCategory::VmSandbox,
        release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
        instance: digest("yougori/test/identity/kv-backend/v1", &[b"runner"]),
    })
}

/// Scope enforcement shown by evidence a CORE-01 probe registry evaluated at
/// `observed_at`, fresh for `fresh_for`. CORE-01 has no KV-scope capability yet, so a
/// guest report of a runtime capability on [`kv_backend`] stands in for it.
pub(crate) fn scope_enforcement(
    observed_at: MonotonicTime,
    fresh_for: Duration,
) -> ScopeEnforcement {
    let clock = Arc::new(ManualClock::new(observed_at));
    let mut registry = ProbeRegistry::new(clock);
    let subject = kv_backend();
    let configuration =
        ConfigurationFingerprint::from_settings([("kv-scope", "enforced")]).unwrap();
    let probe = FakeProbe::guest_report(Capability::IoUring);
    probe.respond(
        &subject,
        Observation::supported(configuration, fresh_for, SupportDetail::Plain),
    );
    registry.register(Box::new(probe)).unwrap();
    registry.refresh(Capability::IoUring, &subject).unwrap();
    let evidence = registry
        .evaluate(&Requirement::new(
            Capability::IoUring,
            subject,
            SourceClass::GuestReport,
            fresh_for,
            configuration,
        ))
        .unwrap();
    ScopeEnforcement::Verified { evidence }
}
