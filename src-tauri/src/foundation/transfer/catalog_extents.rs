//! The verified-extents port over the CORE-02 catalog (T05).
//!
//! What a transfer may count as already verified at a local recipient is what the
//! catalog holds verified in the transfer's own tenant scope under the adapter's artifact
//! class: a published, healthy object whole, read as the owner's content facts; otherwise
//! the extents the tenant's pending import of the same content has verified so far, if
//! the transfer's parent execution is the one importing it (G9; S2 CORE-05, INT-08: a
//! retry reuses verified extents). Equal content in another scope or class, and another
//! execution's import, are never reused (S3.3). A cancelled or failed import reports
//! nothing; a resumed one verifies its staging again. A remote recipient's verified
//! ranges are not the local catalog's to report, so none are.

use std::sync::{Arc, Mutex, PoisonError};

use super::endpoint::Endpoint;
use super::ports::VerifiedExtentsPort;
use super::range::{ByteRange, RangeSet};
use crate::foundation::catalog::{ArtifactClass, Catalog, ObjectId, Scope};
use crate::foundation::ids::{ContentKey, ExecutionId, TenantId};

/// [`VerifiedExtentsPort`] over the host's [`Catalog`], shared with its importers.
///
/// Catalog objects are keyed by scope, artifact class and content key, and a transfer
/// envelope names only the content key, so the class is the adapter's configuration:
/// one adapter per class of transfer, such as model weights.
pub struct CatalogExtents {
    catalog: Arc<Mutex<Catalog>>,
    class: ArtifactClass,
}

impl CatalogExtents {
    pub fn new(catalog: Arc<Mutex<Catalog>>, class: ArtifactClass) -> Self {
        Self { catalog, class }
    }

    /// The artifact class this adapter looks objects up under.
    pub fn class(&self) -> ArtifactClass {
        self.class
    }
}

impl VerifiedExtentsPort for CatalogExtents {
    fn verified(
        &self,
        tenant: &TenantId,
        parent: &ExecutionId,
        recipient: &Endpoint,
        object: &ContentKey,
    ) -> RangeSet {
        if !recipient.is_local() {
            return RangeSet::new();
        }
        let scope = Scope::tenant(tenant.clone());
        let id = ObjectId::new(&scope, self.class, *object);
        let catalog = self.catalog.lock().unwrap_or_else(PoisonError::into_inner);
        match catalog.object_view(&scope, parent, id) {
            Ok(view) if view.content_key == *object => ByteRange::new(0, view.length_bytes)
                .map(RangeSet::single)
                .unwrap_or_default(),
            _ => staged(&catalog, &scope, parent, self.class, object),
        }
    }
}

/// The extents the tenant's pending import of `object` by `parent` has verified, within
/// the object's true length. A span that is empty or runs past the largest offset is not
/// reported.
fn staged(
    catalog: &Catalog,
    scope: &Scope,
    parent: &ExecutionId,
    class: ArtifactClass,
    object: &ContentKey,
) -> RangeSet {
    let Some(staged) = catalog.staged_extents(scope, parent, class, *object) else {
        return RangeSet::new();
    };
    let Ok(whole) = ByteRange::new(0, staged.true_length_bytes) else {
        return RangeSet::new();
    };
    if staged.content_key != *object {
        return RangeSet::new();
    }
    RangeSet::from_ranges(
        staged
            .verified
            .iter()
            .filter_map(|span| ByteRange::starting_at(span.offset_bytes, span.length_bytes).ok()),
    )
    .intersection(&RangeSet::single(whole))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;
    use std::num::NonZeroU64;
    use std::path::Path;
    use std::time::Duration;

    use super::*;
    use crate::foundation::catalog::{
        ArtifactVerifier, CancelOutcome, CatalogConfig, Checkpoint, ContentDescriptor,
        ImportControl, ImportManifest, ImportRequest, ImportSource, ImportStart, ImportStatus,
        ImportTicket, ObjectBytes, ObjectMetadata, ObjectRole, Proceed, PublisherId, SourceError,
        SourceIdentity, TrustClaim, TrustPolicy, Uninterrupted, VerifierRegistry,
        VerifierRejection,
    };
    use crate::foundation::transfer::fakes::{
        download_connection, download_fields, operation, parent, range, route, tenant, test_key,
        World, SESSION,
    };
    use crate::foundation::transfer::{
        ObjectGrant, TransferGate, TransferPorts, TransferRefusal, TransferScope, TransferStatus,
    };

    /// Bytes held in memory, served in bounded reads.
    struct MemorySource {
        bytes: Vec<u8>,
    }

    impl ImportSource for MemorySource {
        fn identity(&self) -> SourceIdentity {
            SourceIdentity::describe("test-memory", "weights")
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

    /// The responsible verifier for user-selected model weights: no publisher is trusted,
    /// and the structure check accepts any bytes.
    struct UserWeights;

    impl ArtifactVerifier for UserWeights {
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

    /// Committed catalog files are read-only; make them writable so the temporary root
    /// can be removed.
    fn make_writable(path: &Path) {
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                make_writable(&entry.path());
            }
        }
        if let Ok(metadata) = fs::metadata(path) {
            let mut permissions = metadata.permissions();
            if permissions.readonly() {
                permissions.set_readonly(false);
                let _ = fs::set_permissions(path, permissions);
            }
        }
    }

    /// Interrupts an import before the extent it names.
    struct StopBefore(u32);

    impl ImportControl for StopBefore {
        fn proceed(&mut self, at: Checkpoint) -> Proceed {
            match at {
                Checkpoint::Extent { extent } if extent >= self.0 => Proceed::Interrupt,
                _ => Proceed::Continue,
            }
        }
    }

    /// An empty catalog in `root` where tenant-a may import 4 KiB of its own model weights.
    fn open_catalog(root: &Path, world: &World) -> Catalog {
        let config = CatalogConfig::new(Duration::from_secs(60))
            .with_quota(Scope::tenant(tenant()), 4096)
            .with_trust(
                ArtifactClass::ModelWeights,
                TrustPolicy::new().accept_user_selected(),
            );
        let mut verifiers = VerifierRegistry::new();
        verifiers.register(Box::new(UserWeights)).unwrap();
        Catalog::open(root, config, verifiers, world.clock.clone())
            .unwrap()
            .0
    }

    /// Begins, or attaches to, tenant-a's import of `bytes` as model weights in 32-byte
    /// extents by the parent execution, and drives it under `control`.
    fn import(
        catalog: &mut Catalog,
        bytes: &[u8],
        control: &mut dyn ImportControl,
    ) -> (ImportTicket, ImportStatus) {
        let request = ImportRequest {
            operation: operation("op-import"),
            execution: parent(),
            scope: Scope::tenant(tenant()),
            class: ArtifactClass::ModelWeights,
            role: ObjectRole::Original,
            manifest: ImportManifest::describe(bytes, NonZeroU64::new(32).unwrap()),
            trust: TrustClaim::UserSelected,
            depends_on: BTreeSet::new(),
            metadata: ObjectMetadata::new(),
        };
        let mut source = MemorySource {
            bytes: bytes.to_vec(),
        };
        let ticket = match catalog.begin_import(request, source.identity()).unwrap() {
            ImportStart::Started(ticket) | ImportStart::Attached(ticket) => ticket,
            other => panic!("expected an import in flight, got {other:?}"),
        };
        let status = catalog.drive_import(&ticket, &mut source, control).unwrap();
        (ticket, status)
    }

    fn lock(catalog: &Mutex<Catalog>) -> std::sync::MutexGuard<'_, Catalog> {
        catalog.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A catalog in `root` with `bytes` published as tenant-a's original.
    fn catalog_with(root: &Path, world: &World, bytes: &[u8]) -> Arc<Mutex<Catalog>> {
        let mut catalog = open_catalog(root, world);
        let (_, status) = import(&mut catalog, bytes, &mut Uninterrupted);
        assert!(
            matches!(status, ImportStatus::Published { .. }),
            "{status:?}"
        );
        Arc::new(Mutex::new(catalog))
    }

    /// The real catalog answers for objects published in the transfer's own scope and
    /// class, whole; a transfer of such an object reuses it and moves nothing.
    #[test]
    fn published_objects_in_the_transfer_scope_count_as_verified() {
        let world = World::new();
        let dir = tempfile::tempdir().unwrap();
        let bytes: Vec<u8> = (0u8..100).collect();
        let key = ContentKey::of(&bytes);
        let catalog = catalog_with(dir.path(), &world, &bytes);
        let extents = Arc::new(CatalogExtents::new(
            catalog.clone(),
            ArtifactClass::ModelWeights,
        ));
        let whole = RangeSet::single(range(0, 100));
        assert_eq!(
            extents.verified(&tenant(), &parent(), &Endpoint::HostCatalog, &key),
            whole
        );
        let execution = Endpoint::Execution {
            execution: parent(),
        };
        assert_eq!(
            extents.verified(&tenant(), &parent(), &execution, &key),
            whole
        );
        let other_tenant = TenantId::new("tenant-b").unwrap();
        assert!(extents
            .verified(&other_tenant, &parent(), &Endpoint::HostCatalog, &key)
            .is_empty());
        let sidecars = CatalogExtents::new(catalog.clone(), ArtifactClass::ModelSidecar);
        assert!(sidecars
            .verified(&tenant(), &parent(), &Endpoint::HostCatalog, &key)
            .is_empty());
        assert!(extents
            .verified(&tenant(), &parent(), &route("partner-registry"), &key)
            .is_empty());
        assert!(extents
            .verified(
                &tenant(),
                &parent(),
                &Endpoint::HostCatalog,
                &ContentKey::of(b"absent")
            )
            .is_empty());

        let gate = TransferGate::new(
            test_key(),
            TransferPorts {
                clock: world.clock.clone(),
                clock_session: SESSION,
                authority: world.authority.clone(),
                budget: world.ledger.clone(),
                extents,
                progress: world.progress.clone(),
            },
        );
        let mut fields = download_fields();
        fields.scope = TransferScope::single(key, ObjectGrant::whole(100).unwrap());
        let mut session = gate
            .open(&world.seal(fields), &download_connection())
            .unwrap();
        assert_eq!(session.verified_bytes(), 100);
        assert!(session.missing().is_empty());
        assert!(matches!(
            session.admit(&key, range(0, 10)),
            Err(TransferRefusal::AlreadyCovered { .. })
        ));
        session.finish().unwrap();
        assert_eq!(session.status(), &TransferStatus::Completed);
        assert_eq!(session.used_bytes(), 0);

        let mut absent = download_fields();
        absent.operation = operation("op-absent");
        absent.scope =
            TransferScope::single(ContentKey::of(b"absent"), ObjectGrant::whole(6).unwrap());
        let session = gate
            .open(&world.seal(absent), &download_connection())
            .unwrap();
        assert_eq!(session.verified_bytes(), 0);

        drop(session);
        drop(gate);
        drop(catalog);
        make_writable(dir.path());
    }

    /// G9 (S2 CORE-05, INT-08): the extents the tenant's own pending import of the same
    /// content verified count as verified, for the execution that imports it; another
    /// execution's, tenant's or class's staged bytes never do (S3.3). A retry moves, and
    /// charges, only the rest, and the transfer completes once the import publishes.
    #[test]
    fn staged_extents_of_the_same_execution_count_as_verified() {
        let world = World::new();
        let dir = tempfile::tempdir().unwrap();
        let bytes: Vec<u8> = (0u8..128).collect();
        let key = ContentKey::of(&bytes);
        let mut catalog = open_catalog(dir.path(), &world);
        let (ticket, status) = import(&mut catalog, &bytes, &mut StopBefore(2));
        assert!(matches!(status, ImportStatus::Pending { .. }), "{status:?}");
        let catalog = Arc::new(Mutex::new(catalog));
        let extents = Arc::new(CatalogExtents::new(
            catalog.clone(),
            ArtifactClass::ModelWeights,
        ));

        let staged = RangeSet::single(range(0, 64));
        assert_eq!(
            extents.verified(&tenant(), &parent(), &Endpoint::HostCatalog, &key),
            staged
        );
        let execution = Endpoint::Execution {
            execution: parent(),
        };
        assert_eq!(
            extents.verified(&tenant(), &parent(), &execution, &key),
            staged
        );
        let neighbour = ExecutionId::new("exe-neighbour").unwrap();
        assert!(extents
            .verified(&tenant(), &neighbour, &Endpoint::HostCatalog, &key)
            .is_empty());
        let other_tenant = TenantId::new("tenant-b").unwrap();
        assert!(extents
            .verified(&other_tenant, &parent(), &Endpoint::HostCatalog, &key)
            .is_empty());
        let sidecars = CatalogExtents::new(catalog.clone(), ArtifactClass::ModelSidecar);
        assert!(sidecars
            .verified(&tenant(), &parent(), &Endpoint::HostCatalog, &key)
            .is_empty());
        assert!(extents
            .verified(&tenant(), &parent(), &route("partner-registry"), &key)
            .is_empty());

        let gate = TransferGate::new(
            test_key(),
            TransferPorts {
                clock: world.clock.clone(),
                clock_session: SESSION,
                authority: world.authority.clone(),
                budget: world.ledger.clone(),
                extents,
                progress: world.progress.clone(),
            },
        );
        let mut fields = download_fields();
        fields.scope = TransferScope::single(key, ObjectGrant::whole(128).unwrap());
        let mut session = gate
            .open(&world.seal(fields), &download_connection())
            .unwrap();
        assert_eq!(session.verified_bytes(), 64);
        assert!(matches!(
            session.admit(&key, range(0, 32)),
            Err(TransferRefusal::AlreadyCovered { .. })
        ));
        for (start, end) in [(64, 96), (96, 128)] {
            let permit = session.admit(&key, range(start, end)).unwrap();
            session.deliver(permit).unwrap();
        }
        assert_eq!(session.used_bytes(), 64);
        assert_eq!(
            session.finish(),
            Err(TransferRefusal::Incomplete { missing_bytes: 64 })
        );

        let (_, status) = import(&mut lock(&catalog), &bytes, &mut Uninterrupted);
        assert!(
            matches!(status, ImportStatus::Published { .. }),
            "{status:?}"
        );
        session.finish().unwrap();
        assert_eq!(session.status(), &TransferStatus::Completed);
        assert_eq!(session.used_bytes(), 64);
        drop(ticket);

        drop(session);
        drop(gate);
        drop(catalog);
        make_writable(dir.path());
    }

    /// A cancelled import's staged bytes are no longer reported: the catalog keeps them
    /// only for a resumed import, which verifies them again.
    #[test]
    fn a_cancelled_import_reports_nothing() {
        let world = World::new();
        let dir = tempfile::tempdir().unwrap();
        let bytes: Vec<u8> = (0u8..128).collect();
        let key = ContentKey::of(&bytes);
        let mut catalog = open_catalog(dir.path(), &world);
        let (ticket, _) = import(&mut catalog, &bytes, &mut StopBefore(3));
        let catalog = Arc::new(Mutex::new(catalog));
        let extents = CatalogExtents::new(catalog.clone(), ArtifactClass::ModelWeights);
        assert_eq!(
            extents.verified(&tenant(), &parent(), &Endpoint::HostCatalog, &key),
            RangeSet::single(range(0, 96))
        );
        assert_eq!(
            lock(&catalog).cancel_import(ticket),
            CancelOutcome::Cancelled
        );
        assert!(extents
            .verified(&tenant(), &parent(), &Endpoint::HostCatalog, &key)
            .is_empty());
        drop(extents);
        drop(catalog);
        make_writable(dir.path());
    }
}
