//! A clean drop needs a verified canonical copy of exactly the artifact's content, and that
//! proof comes only from a real check: the CORE-02 catalog or the residency rule of clean
//! eviction (Appendix E step 5; GPU-W05; §1.1 line 307). A catalog proof holds a catalog
//! lease until the artifact is refilled.

use std::collections::BTreeSet;
use std::fs;
use std::num::NonZeroU64;
use std::path::Path;

use tempfile::TempDir;

use super::*;
use crate::foundation::catalog::{
    ArtifactClass, ArtifactVerifier, Catalog, CatalogConfig, ContentDescriptor, ImportManifest,
    ImportRequest, ImportSource, ImportStart, ImportStatus, LeaseId, ObjectBytes, ObjectId,
    ObjectMetadata, ObjectRole, PublisherId, ReadRefusal, Scope, SourceError, SourceIdentity,
    TrustClaim, TrustPolicy, Uninterrupted, VerifierRegistry, VerifierRejection,
};
use crate::foundation::ids::{ExecutionId, OperationId, TenantId};

/// The bytes of the test weights in the catalog; their content key is what a VMM plan of
/// them declares.
const WEIGHTS: &[u8] = b"weights of model a, imported and verified by the catalog";

fn tenant(name: &str) -> Scope {
    Scope::tenant(TenantId::new(name).unwrap())
}

/// The execution the runner's park belongs to.
fn runner() -> ExecutionId {
    ExecutionId::new("exe-runner").unwrap()
}

/// Accepts the structure of every model-weights object; the catalog itself checks every
/// byte against the content key before it publishes.
struct AcceptWeights;

impl ArtifactVerifier for AcceptWeights {
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

/// The weights, read from memory.
struct Source(&'static [u8]);

impl ImportSource for Source {
    fn identity(&self) -> SourceIdentity {
        SourceIdentity::describe("test", "weights-a")
    }

    fn length_bytes(&mut self) -> Result<u64, SourceError> {
        Ok(self.0.len() as u64)
    }

    fn read_at(&mut self, offset_bytes: u64, buffer: &mut [u8]) -> Result<usize, SourceError> {
        let available = usize::try_from(offset_bytes)
            .ok()
            .and_then(|offset| self.0.get(offset..))
            .unwrap_or(&[]);
        let count = available.len().min(buffer.len());
        buffer[..count].copy_from_slice(&available[..count]);
        Ok(count)
    }
}

/// A catalog in a temporary root, where tenant "a" chose the weights as its own original.
struct Store {
    dir: TempDir,
    catalog: Catalog,
    object: ObjectId,
}

impl Store {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let config = CatalogConfig::new(MINUTE)
            .with_quota(tenant("a"), 1 << 20)
            .with_quota(tenant("b"), 1 << 20)
            .with_trust(
                ArtifactClass::ModelWeights,
                TrustPolicy::new().accept_user_selected(),
            );
        let mut verifiers = VerifierRegistry::new();
        verifiers.register(Box::new(AcceptWeights)).unwrap();
        let clock: Arc<dyn crate::foundation::ids::Clock> =
            Arc::new(ManualClock::new(MonotonicTime::ZERO));
        let (mut catalog, _) = Catalog::open(dir.path(), config, verifiers, clock).unwrap();
        let request = ImportRequest {
            operation: OperationId::new("op-import").unwrap(),
            execution: ExecutionId::new("exe-import").unwrap(),
            scope: tenant("a"),
            class: ArtifactClass::ModelWeights,
            role: ObjectRole::Original,
            manifest: ImportManifest::describe(WEIGHTS, NonZeroU64::new(16).unwrap()),
            trust: TrustClaim::UserSelected,
            depends_on: BTreeSet::new(),
            metadata: ObjectMetadata::new(),
        };
        let mut source = Source(WEIGHTS);
        let ImportStart::Started(ticket) =
            catalog.begin_import(request, source.identity()).unwrap()
        else {
            panic!("a new import starts");
        };
        let ImportStatus::Published { object, .. } = catalog
            .drive_import(&ticket, &mut source, &mut Uninterrupted)
            .unwrap()
        else {
            panic!("the import publishes");
        };
        Self {
            dir,
            catalog,
            object,
        }
    }

    /// A catalog proof of the weights for tenant "a", leased for an hour.
    fn proof(&mut self) -> VerifiedCanonicalCopy {
        VerifiedCanonicalCopy::in_catalog(
            &mut self.catalog,
            &tenant("a"),
            &runner(),
            ArtifactClass::ModelWeights,
            ContentKey::of(WEIGHTS),
            HOUR,
        )
        .unwrap()
    }

    /// Whether `lease` still lets tenant "a" read the weights.
    fn leased(&self, lease: LeaseId) -> bool {
        self.catalog
            .open_read(&tenant("a"), &runner(), lease)
            .is_ok()
    }

    /// Flips a byte of the stored object and has the catalog re-verify it, which
    /// quarantines it and revokes its leases.
    fn corrupt(&mut self) {
        let data = self
            .dir
            .path()
            .join("objects")
            .join(self.object.to_string())
            .join("data");
        make_writable(&data);
        let mut bytes = fs::read(&data).unwrap();
        bytes[0] ^= 0xff;
        fs::write(&data, bytes).unwrap();
        assert!(self
            .catalog
            .verify_object(&tenant("a"), self.object)
            .is_err());
    }
}

impl Drop for Store {
    /// Committed files are read-only; make them writable so the temporary root goes.
    fn drop(&mut self) {
        make_tree_writable(self.dir.path());
    }
}

/// Clears the read-only flag the catalog sets on what it committed under the test's
/// temporary root, so the test can corrupt it and Windows can remove the root.
#[allow(clippy::permissions_set_readonly_false)]
fn make_writable(path: &Path) {
    if let Ok(metadata) = fs::metadata(path) {
        let mut permissions = metadata.permissions();
        if permissions.readonly() {
            permissions.set_readonly(false);
            let _ = fs::set_permissions(path, permissions);
        }
    }
}

fn make_tree_writable(path: &Path) {
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            make_tree_writable(&entry.path());
        }
    }
    make_writable(path);
}

/// P1 maps artifact "a" in batches of `lengths`, its bytes declared to be the weights.
fn load_weights(world: &mut World, lengths: &[u64]) -> MappingKey {
    world.probe(P1, private());
    let planned = ArtifactLayout {
        content: ContentKey::of(WEIGHTS),
        ..layout("a", lengths)
    };
    let key = world
        .plan(P1, &planned, private(), VmmOrigin::Create)
        .unwrap();
    world.fill(key, "a", u32::try_from(lengths.len()).unwrap());
    key
}

#[test]
fn a_catalog_copy_must_be_published_healthy_and_in_the_readers_scope() {
    let content = ContentKey::of(WEIGHTS);
    let class = ArtifactClass::ModelWeights;
    let mut store = Store::new();
    let proof = store.proof();
    assert_eq!(proof.content(), content);
    assert_eq!(
        proof.source(),
        CanonicalSource::Catalog {
            object: store.object
        }
    );
    let lease = proof.lease().unwrap();
    assert!(store.leased(lease), "the proof holds a catalog lease");

    let in_scope = |catalog: &mut Catalog, scope: &Scope, class, content| {
        VerifiedCanonicalCopy::in_catalog(catalog, scope, &runner(), class, content, HOUR)
    };
    assert_eq!(
        in_scope(&mut store.catalog, &tenant("b"), class, content),
        Err(CanonicalCopyRefusal::NotInCatalog {
            scope: tenant("b"),
            class,
            content,
        }),
        "equal content in another scope is never permission"
    );
    assert!(matches!(
        in_scope(
            &mut store.catalog,
            &tenant("a"),
            ArtifactClass::ModelSidecar,
            content
        ),
        Err(CanonicalCopyRefusal::NotInCatalog { .. })
    ));
    assert!(
        matches!(
            in_scope(
                &mut store.catalog,
                &tenant("a"),
                class,
                content_of("never imported")
            ),
            Err(CanonicalCopyRefusal::NotInCatalog { .. })
        ),
        "naming content does not make a copy of it"
    );
    assert_eq!(
        VerifiedCanonicalCopy::in_catalog(
            &mut store.catalog,
            &tenant("a"),
            &runner(),
            class,
            content,
            Duration::ZERO,
        ),
        Err(CanonicalCopyRefusal::LeaseRefused {
            object: store.object,
            reason: ReadRefusal::ZeroDuration,
        }),
        "a copy the catalog will not lease could vanish while the GPU copy is dropped"
    );

    store.corrupt();
    let refusal = in_scope(&mut store.catalog, &tenant("a"), class, content).unwrap_err();
    assert!(
        matches!(refusal, CanonicalCopyRefusal::NotInCatalog { .. }),
        "a quarantined object is no canonical copy"
    );
    assert!(refusal.to_string().contains("no published, healthy"));
    assert!(!store.leased(lease), "quarantine revoked the lease");
    assert_eq!(
        proof.release(&mut store.catalog),
        Ok(()),
        "a revoked lease counts as released"
    );
}

#[test]
fn a_catalog_proof_holds_its_lease_until_the_artifact_is_refilled() {
    let mut store = Store::new();
    let mut world = World::new();
    let key = load_weights(&mut world, &[4 * MIB]);
    assert_eq!(
        world.model.artifact_content(key),
        Some(ContentKey::of(WEIGHTS))
    );
    let proof = store.proof();
    let lease = proof.lease().unwrap();
    let report = world
        .park(key, ParkSource::CleanDrop { copy: proof })
        .unwrap();
    assert_eq!(report.device_to_host_bytes, 0);
    assert_eq!(report.released_bytes, 4 * MIB);
    assert_eq!(
        world
            .model
            .canonical_copy(key)
            .and_then(|copy| copy.lease()),
        Some(lease),
        "the artifact keeps the proof, and its lease, while it is parked"
    );
    let not_refilled = Err(VmmError::NotRefilled { key });
    assert_eq!(
        world.model.release_canonical_copy(&mut store.catalog, key),
        not_refilled
    );
    assert!(world
        .model
        .renew_canonical_copy(&mut store.catalog, key, HOUR)
        .is_ok());

    world.model.wake(key).unwrap();
    assert_eq!(
        world.model.release_canonical_copy(&mut store.catalog, key),
        not_refilled,
        "woken but not refilled: the copy may still be the refill's source"
    );
    world.back(key, 0).unwrap();
    let event = world.populate(key, 0).unwrap();
    assert_eq!(
        world.model.release_canonical_copy(&mut store.catalog, key),
        not_refilled
    );
    assert!(store.leased(lease));

    world.driver.complete(event);
    world.publish(key, 0, batch_digest("a", 0)).unwrap();
    world
        .model
        .release_canonical_copy(&mut store.catalog, key)
        .unwrap();
    assert!(!store.leased(lease), "refilled: the lease is released");
    assert!(world.model.canonical_copy(key).is_none());
    assert_eq!(
        world.model.release_canonical_copy(&mut store.catalog, key),
        Err(VmmError::NoCanonicalCopy { key })
    );
    assert_eq!(
        world
            .model
            .renew_canonical_copy(&mut store.catalog, key, HOUR),
        Err(VmmError::NoCanonicalCopy { key })
    );
    world.assert_no_refusals();
}

#[test]
fn a_held_copy_serves_a_later_park_before_the_refill() {
    let mut store = Store::new();
    let mut world = World::new();
    let key = load_weights(&mut world, &[4 * MIB, 4 * MIB]);
    let first = store.proof();
    let held = first.lease().unwrap();
    world
        .park(key, ParkSource::CleanDrop { copy: first })
        .unwrap();
    world.model.wake(key).unwrap();
    world.back(key, 0).unwrap();
    let event = world.populate(key, 0).unwrap();
    world.driver.complete(event);
    world.publish(key, 0, batch_digest("a", 0)).unwrap();

    let second = store.proof();
    let lapsing = second.lease().unwrap();
    assert_eq!(
        world.model.begin_park(
            &mut world.driver,
            key,
            ParkSource::CleanDrop { copy: second }
        ),
        Err(VmmError::CanonicalCopyHeld { key }),
        "one artifact holds one catalog proof"
    );
    assert!(
        store.leased(lapsing),
        "a refused proof's lease lapses only when it expires"
    );
    let report = world.park(key, ParkSource::HeldCopy).unwrap();
    assert_eq!(report.device_to_host_bytes, 0);
    assert_eq!(report.unmapped_bytes, 4 * MIB, "batch 0 was refilled");
    assert_eq!(
        world
            .model
            .canonical_copy(key)
            .and_then(|copy| copy.lease()),
        Some(held)
    );

    world.model.wake(key).unwrap();
    world.fill(key, "a", 2);
    world
        .model
        .release_canonical_copy(&mut store.catalog, key)
        .unwrap();
    assert!(!store.leased(held));
    assert_eq!(
        world.park(key, ParkSource::HeldCopy),
        Err(VmmError::NoCanonicalCopy { key })
    );
    world.assert_no_refusals();
}

#[test]
fn a_proof_of_other_content_never_drops_the_artifact() {
    let mut store = Store::new();
    let mut world = World::new();
    let key = world.load(P1, "a", &[4 * MIB], private());
    assert_eq!(
        world.model.begin_park(
            &mut world.driver,
            key,
            ParkSource::CleanDrop {
                copy: store.proof()
            }
        ),
        Err(VmmError::CanonicalCopyMismatch {
            expected: content_of("a"),
            copy: ContentKey::of(WEIGHTS),
        })
    );
    assert_eq!(world.model.lifecycle(key), Some(Lifecycle::Active));
    assert!(world.model.canonical_copy(key).is_none());
    assert_eq!(world.count_calls("cuMemUnmap"), 0);
}

#[test]
fn a_residency_proof_holds_no_lease_and_is_not_kept() {
    let mut store = Store::new();
    let mut world = World::new();
    let key = world.load(P1, "a", &[4 * MIB], private());
    let proof =
        VerifiedCanonicalCopy::reconstructing(&verified_copy(content_of("a")), content_of("a"))
            .unwrap();
    assert_eq!(proof.lease(), None);
    assert!(matches!(
        proof.renew(&mut store.catalog, HOUR),
        Err(CanonicalCopyRefusal::LeaseUnchanged { .. })
    ));
    world
        .park(key, ParkSource::CleanDrop { copy: proof })
        .unwrap();
    assert!(world.model.canonical_copy(key).is_none());
    assert_eq!(
        world.park(key, ParkSource::HeldCopy),
        Err(VmmError::NotInLifecycle {
            key,
            expected: Lifecycle::Active,
            found: Lifecycle::Parked,
        })
    );
    world.model.wake(key).unwrap();
    assert_eq!(
        world.park(key, ParkSource::HeldCopy),
        Err(VmmError::NoCanonicalCopy { key })
    );
    let unused =
        VerifiedCanonicalCopy::reconstructing(&verified_copy(content_of("a")), content_of("a"))
            .unwrap();
    assert_eq!(unused.release(&mut store.catalog), Ok(()));
}

#[test]
fn a_reconstructible_copy_must_be_verified_for_these_weights_and_stay_available() {
    let content = content_of("a");
    for tier in [CopyTier::LocalStorage, CopyTier::PinnedHost] {
        let proof = VerifiedCanonicalCopy::reconstructing(
            &ReconstructibleCopy {
                tier,
                verification: Verification::Verified {
                    content: Content::Immutable(content),
                },
            },
            content,
        )
        .unwrap();
        assert_eq!(proof.source(), CanonicalSource::Reconstructible { tier });
        assert_eq!(proof.content(), content);
    }

    let unverified = ReconstructibleCopy {
        tier: CopyTier::LocalStorage,
        verification: Verification::Unverified,
    };
    assert_eq!(
        VerifiedCanonicalCopy::reconstructing(&unverified, content),
        Err(CanonicalCopyRefusal::Unverified {
            tier: CopyTier::LocalStorage
        })
    );

    let other = Content::Immutable(content_of("b"));
    let state = Content::SessionState(*content.digest());
    for verified in [other, state] {
        let copy = ReconstructibleCopy {
            tier: CopyTier::LocalStorage,
            verification: Verification::Verified { content: verified },
        };
        assert_eq!(
            VerifiedCanonicalCopy::reconstructing(&copy, content),
            Err(CanonicalCopyRefusal::OtherContent {
                tier: CopyTier::LocalStorage,
                verified,
            }),
            "a copy verified for other content, or a session state, never stands in"
        );
    }

    for tier in [
        CopyTier::ReclaimableHost,
        CopyTier::AuthorizedPeer,
        CopyTier::RemoteSource,
    ] {
        let refusal = VerifiedCanonicalCopy::reconstructing(
            &ReconstructibleCopy {
                tier,
                verification: Verification::Verified {
                    content: Content::Immutable(content),
                },
            },
            content,
        )
        .unwrap_err();
        assert_eq!(refusal, CanonicalCopyRefusal::MayVanish { tier });
        assert!(!refusal.to_string().is_empty());
    }
}

/// Fails to compile when `T` implements the marker trait `M`: the second impl then also
/// applies, and the inferred parameter becomes ambiguous.
trait AmbiguousIf<M, A> {
    fn check() {}
}

impl<M, T: ?Sized> AmbiguousIf<M, ()> for T {}

enum Implemented {}

/// Marks deserializable types.
enum Deserializes {}

impl<T: for<'de> serde::Deserialize<'de>> AmbiguousIf<Deserializes, Implemented> for T {}

#[test]
fn a_clone_never_carries_the_catalog_lease() {
    let mut store = Store::new();
    let mut world = World::new();
    let key = load_weights(&mut world, &[4 * MIB]);
    let original = store.proof();
    let clone = original.clone();
    assert_eq!(clone.content(), original.content());
    assert_eq!(clone.source(), original.source());
    assert_eq!(clone.lease(), None, "the lease keeps one holder");
    assert_eq!(
        world.park(key, ParkSource::CleanDrop { copy: clone }),
        Err(VmmError::DetachedCanonicalCopy { key }),
        "a clone of a catalog proof cannot keep the copy while the GPU copy is dropped"
    );
    assert_eq!(world.model.lifecycle(key), Some(Lifecycle::Active));
    world
        .park(key, ParkSource::CleanDrop { copy: original })
        .unwrap();

    let residency =
        VerifiedCanonicalCopy::reconstructing(&verified_copy(content_of("a")), content_of("a"))
            .unwrap();
    assert_eq!(
        residency.clone(),
        residency,
        "a residency proof holds no lease to lose"
    );
    let key = world.load(P1, "b-artifact", &[4 * MIB], private());
    let other = VerifiedCanonicalCopy::reconstructing(
        &verified_copy(content_of("b-artifact")),
        content_of("b-artifact"),
    )
    .unwrap();
    let source = ParkSource::CleanDrop { copy: other };
    assert!(world.park(key, source.clone()).is_ok());
}

#[test]
fn the_authorizing_types_are_never_read_back_from_json() {
    <VerifiedCanonicalCopy as AmbiguousIf<Deserializes, _>>::check();
    <ParkSource as AmbiguousIf<Deserializes, _>>::check();

    let proof =
        VerifiedCanonicalCopy::reconstructing(&verified_copy(content_of("a")), content_of("a"))
            .unwrap();
    let json = serde_json::to_value(ParkSource::CleanDrop { copy: proof }).unwrap();
    assert_eq!(json["kind"], "clean_drop");
    assert_eq!(json["copy"]["content"], content_of("a").to_string());
    assert_eq!(json["copy"]["source"]["source"], "reconstructible");
    assert!(json["copy"].get("hold").is_none());

    let mut store = Store::new();
    let leased = serde_json::to_value(store.proof()).unwrap();
    assert_eq!(leased["source"]["source"], "catalog");
    assert_eq!(leased["hold"]["execution"], "exe-runner");
    assert!(
        leased["hold"].get("lease").is_none(),
        "a lease id is local to its catalog and never serialized"
    );
    assert_eq!(
        serde_json::to_value(ParkSource::HeldCopy).unwrap()["kind"],
        "held_copy"
    );
}
