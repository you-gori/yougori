//! The cache step over a real representation store, local storage tier, catalog and GPU
//! tier, on the real ledger: an original is never offered, the prepared form that GPU
//! weights need to drop clean is kept while they are resident, and the prepared form of
//! least value is evicted through the catalog and forgotten by the store.

use std::collections::BTreeSet;
use std::num::NonZeroU64;

use tempfile::TempDir;

use super::*;
use crate::foundation::catalog::{
    ArtifactClass, ArtifactVerifier, Catalog, CatalogConfig, CatalogLimits, ContentDescriptor,
    ImportAmortization, ImportManifest, ImportRequest, ImportSource, ImportStart, ImportStatus,
    ObjectBytes, ObjectMetadata, ObjectRole, ObjectStatus, PublisherId, Scope, SourceError,
    SourceIdentity, TrustClaim, TrustPolicy, Uninterrupted, VerifierRegistry, VerifierRejection,
};
use crate::model_memory::tiers::{
    DerivedKind, GpuTier, LocalStorageTier, ModelKey, ObjectRef, PoolId, PoolPresence,
    PoolSelection, RepresentationKind, RepresentationProposal, RepresentationStore, SpaceBudget,
    StoragePool, Tier,
};

pub(super) const STORAGE: ResourceKey = ResourceKey::Host(HostResource::StorageQuota);

/// Accepts every structure; the catalog still checks every byte against its content key.
struct AcceptingVerifier;

impl ArtifactVerifier for AcceptingVerifier {
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

/// Bytes in memory, read in bounded ranges.
struct BytesSource {
    identity: SourceIdentity,
    bytes: Vec<u8>,
}

impl ImportSource for BytesSource {
    fn identity(&self) -> SourceIdentity {
        self.identity
    }

    fn length_bytes(&mut self) -> Result<u64, SourceError> {
        Ok(self.bytes.len() as u64)
    }

    fn read_at(&mut self, offset_bytes: u64, buffer: &mut [u8]) -> Result<usize, SourceError> {
        let start = usize::try_from(offset_bytes).unwrap();
        let available = self.bytes.get(start..).unwrap_or(&[]);
        let count = available.len().min(buffer.len());
        buffer[..count].copy_from_slice(&available[..count]);
        Ok(count)
    }
}

/// A real catalog under `root` in which the tenant's user-selected model weights are
/// trusted.
pub(super) fn open_catalog(root: &TempDir, clock: Arc<ManualClock>) -> Catalog {
    let config = CatalogConfig::new(Duration::from_secs(60))
        .with_limits(CatalogLimits {
            max_object_bytes: 1 << 20,
            max_extent_bytes: 64,
            ..CatalogLimits::default()
        })
        .with_trust(
            ArtifactClass::ModelWeights,
            TrustPolicy::new().accept_user_selected(),
        )
        .with_quota(Scope::tenant(tenant()), 1 << 20);
    let mut verifiers = VerifierRegistry::new();
    verifiers.register(Box::new(AcceptingVerifier)).unwrap();
    let clock: Arc<dyn Clock> = clock;
    Catalog::open(root.path(), config, verifiers, clock)
        .unwrap()
        .0
}

pub(super) fn alice() -> Consumer {
    Consumer {
        tenant: tenant(),
        execution: ExecutionId::new("exe-alice").unwrap(),
        trust: TrustScope::named(ExecutionCategory::SharedKernelGpuRuntime, "alpha"),
    }
}

pub(super) fn pool() -> PoolId {
    PoolId::new("pool-c").unwrap()
}

/// Imports `bytes` with `role` into the pool: storage is reserved, the catalog's
/// importer publishes the object, and local storage records the publication.
pub(super) fn import<C: Clock>(
    local: &mut LocalStorageTier,
    catalog: &mut Catalog,
    ledger: &mut Ledger<C>,
    bytes: &[u8],
    role: ObjectRole,
) -> ObjectRef {
    let owner = alice();
    let manifest = ImportManifest::describe(bytes, NonZeroU64::new(64).unwrap());
    let object = ObjectRef {
        scope: owner.scope(),
        class: ArtifactClass::ModelWeights,
        content: manifest.content_key,
    };
    let charge = LedgerCharge {
        operation: OperationId::new("op-import").unwrap(),
        priority: Priority::Foreground,
        retry_number: 0,
    };
    let reservation = local
        .reserve_import(
            &pool(),
            object.clone(),
            bytes.len() as u64,
            &owner.execution,
            &charge,
            ledger,
        )
        .unwrap();
    let mut source = BytesSource {
        identity: SourceIdentity::describe("test", &object.content.to_string()),
        bytes: bytes.to_vec(),
    };
    let request = ImportRequest {
        operation: OperationId::new("op-import").unwrap(),
        execution: owner.execution.clone(),
        scope: object.scope.clone(),
        class: object.class,
        role,
        manifest,
        trust: TrustClaim::UserSelected,
        depends_on: BTreeSet::new(),
        metadata: ObjectMetadata::new(),
    };
    let ImportStart::Started(ticket) = catalog.begin_import(request, source.identity()).unwrap()
    else {
        panic!("a new import starts");
    };
    let status = catalog
        .drive_import(&ticket, &mut source, &mut Uninterrupted)
        .unwrap();
    assert!(matches!(status, ImportStatus::Published { .. }));
    local.record_published(reservation, catalog).unwrap();
    object
}

pub(super) fn forecast() -> ImportAmortization {
    ImportAmortization {
        expected_uses: 21.0,
        per_use_saving_seconds: 8.0,
        preparation_cost_seconds: 120.0,
        retention_penalty_seconds: 40.0,
    }
}

/// What the last survey found, by representation kind.
fn holds(step: &DropLowValueCaches<CacheEntry>) -> Vec<(RepresentationKind, Hold)> {
    step.candidates()
        .iter()
        .map(|candidate| (candidate.work.kind, candidate.hold))
        .collect()
}

#[test]
fn the_cache_step_keeps_originals_and_needed_copies_of_a_real_store() {
    let clock = start();
    let root = TempDir::new().unwrap();
    let mut catalog = open_catalog(&root, Arc::clone(&clock));
    let mut host = Ledger::new(
        Arc::clone(&clock),
        HostSubject { machine: machine() },
        config(),
    );
    declare(&mut host, STORAGE, 10_000);
    declare(&mut host, gpu(), 64 * GIB);
    let mut local = LocalStorageTier::new();
    local
        .add_pool(StoragePool {
            id: pool(),
            selection: PoolSelection::UserSelected,
            presence: PoolPresence::Present,
        })
        .unwrap();
    let original = import(
        &mut local,
        &mut catalog,
        &mut host,
        &[1u8; 3_000],
        ObjectRole::Original,
    );
    let derived = || ObjectRole::Prepared {
        derived_from: BTreeSet::from([original.id()]),
    };
    let raw = import(
        &mut local,
        &mut catalog,
        &mut host,
        &[2u8; 2_000],
        derived(),
    );
    let compressed = import(
        &mut local,
        &mut catalog,
        &mut host,
        &[3u8; 1_000],
        derived(),
    );
    let model = ModelKey {
        scope: alice().scope(),
        model: digest("yougori/test/reclaim/model/v1", &[b"llama-8b"]),
    };
    let mut store =
        RepresentationStore::new(SpaceBudget::Explicit { max_bytes: 10_000 }, 86_400.0).unwrap();
    store
        .admit(
            RepresentationProposal::Original {
                model: model.clone(),
                object: original.clone(),
                bytes: 3_000,
            },
            clock.as_ref(),
        )
        .unwrap();
    for (object, kind, bytes) in [
        (&raw, DerivedKind::RawPrepared, 2_000),
        (&compressed, DerivedKind::CompressedPrepared, 1_000),
    ] {
        store
            .admit(
                RepresentationProposal::Derived {
                    model: model.clone(),
                    object: object.clone(),
                    kind,
                    tier: Tier::LocalStorage,
                    bytes,
                    forecast: forecast(),
                },
                clock.as_ref(),
            )
            .unwrap();
    }
    // The raw form is used often; the compressed one never.
    clock.advance(Duration::from_secs(3_600));
    for _ in 0..4 {
        store
            .record_use(
                &model,
                RepresentationKind::RawPrepared,
                30.0,
                clock.as_ref(),
            )
            .unwrap();
    }
    // The GPU holds clean weights loaded from the raw form, which only its stored copy
    // can rebuild.
    let mut gpu_tier = GpuTier::new(
        GpuDeviceKey {
            machine: machine(),
            device: digest("yougori/test/gpu/v1", &[&[0]]),
        },
        None,
    );
    let weights = {
        let owner = alice();
        let lease = catalog
            .acquire_lease(
                &owner.scope(),
                &owner.execution,
                raw.id(),
                Duration::from_secs(600),
            )
            .unwrap();
        let handle = catalog
            .open_read(&owner.scope(), &owner.execution, lease)
            .unwrap();
        let charge = LedgerCharge {
            operation: OperationId::new("op-load").unwrap(),
            priority: Priority::Foreground,
            retry_number: 0,
        };
        let weights = gpu_tier
            .load_weights(&owner, &raw, &handle, &catalog, GIB, &charge, &mut host)
            .unwrap();
        drop(handle);
        catalog
            .release_lease(&owner.scope(), &owner.execution, lease)
            .unwrap();
        weights
    };
    let compressed_reservation = local.reservation_of(compressed.id()).unwrap();
    let ledger = Arc::new(Mutex::new(host));

    let mut caches = DropLowValueCaches::new(Requester::ModelPlacement);
    caches
        .prepare(
            &mut TierCaches::new(
                &mut store,
                &mut catalog,
                clock.as_ref(),
                Arc::clone(&ledger),
            )
            .with_local(&mut local, pool())
            .with_gpu(&gpu_tier),
        )
        .unwrap();
    assert_eq!(
        holds(&caches),
        [
            (RepresentationKind::CompressedPrepared, Hold::Free),
            (
                RepresentationKind::RawPrepared,
                Hold::Pinned(PinnedBy::CanonicalCopyNeeded)
            ),
            (
                RepresentationKind::Original,
                Hold::Pinned(PinnedBy::Original)
            ),
        ]
    );

    // An import of 4,500 bytes finds 4,000 free: the compressed form goes.
    let request = ReservationRequest::new(
        provenance(Requester::ModelPlacement, "import-next"),
        Priority::Foreground,
        Amounts::new().with(STORAGE, 4_500),
    );
    let admission = {
        let mut ladder = ReclaimLadder::new();
        register_model_reclaimers(&mut ladder, [&mut caches as &mut dyn ModelReclaimer]);
        ledger
            .lock()
            .unwrap()
            .reserve_reclaiming(request, &mut ladder)
    };
    let settlement = caches
        .settle(
            &admission.report,
            &mut TierCaches::new(
                &mut store,
                &mut catalog,
                clock.as_ref(),
                Arc::clone(&ledger),
            )
            .with_local(&mut local, pool())
            .with_gpu(&gpu_tier),
        )
        .unwrap();
    assert!(
        admission.admission.is_err(),
        "its storage counts until freed"
    );
    assert_eq!(settlement.stopped.len(), 1, "{settlement:?}");
    assert_eq!(settlement.awaiting_release(), [compressed_reservation]);
    assert_eq!(
        catalog.status(&compressed.scope, compressed.id()),
        ObjectStatus::Absent
    );
    for kept in [&original, &raw] {
        assert_eq!(
            catalog.status(&kept.scope, kept.id()),
            ObjectStatus::Published
        );
    }
    let kinds: Vec<RepresentationKind> = store
        .representations()
        .into_iter()
        .map(|held| held.kind)
        .collect();
    assert_eq!(
        kinds,
        [
            RepresentationKind::Original,
            RepresentationKind::RawPrepared
        ]
    );
    assert_eq!(
        state(&ledger.lock().unwrap(), compressed_reservation),
        Some(ReservationState::Releasing)
    );

    // Once the GPU weights are freed, the raw form is a cache like any other; the
    // original never is.
    gpu_tier.free(weights, &mut ledger.lock().unwrap()).unwrap();
    caches
        .prepare(
            &mut TierCaches::new(
                &mut store,
                &mut catalog,
                clock.as_ref(),
                Arc::clone(&ledger),
            )
            .with_local(&mut local, pool())
            .with_gpu(&gpu_tier),
        )
        .unwrap();
    assert_eq!(
        holds(&caches),
        [
            (RepresentationKind::RawPrepared, Hold::Free),
            (
                RepresentationKind::Original,
                Hold::Pinned(PinnedBy::Original)
            ),
        ]
    );
}
