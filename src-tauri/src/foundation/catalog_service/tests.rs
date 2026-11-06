//! Tests for the engine catalog service: open and recovery, per-class trust registration
//! through the trust-root service, quotas, lease-aware garbage collection, trust after a
//! reload, and the status. A real catalog in a temporary directory, a real trust-root file
//! with Ed25519 keys, a manual clock and a fixed calendar.

use std::collections::BTreeSet;
use std::fs;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};

use super::*;
use crate::foundation::catalog::{
    ArtifactClass, ArtifactVerifier, Catalog, Checkpoint, ContentDescriptor, ImportControl,
    ImportManifest, ImportRefusal, ImportRequest, ImportSource, ImportStage, ImportStart,
    ImportStatus, IntegrityFailure, ObjectBytes, ObjectId, ObjectMetadata, ObjectRole,
    ObjectStatus, Proceed, PublisherId, QuotaRefusal, Scope, SourceError, SourceIdentity,
    TrustClaim, TrustRefusal, Uninterrupted, VerifierRejection,
};
use crate::foundation::ids::{ExecutionId, ManualClock, MonotonicTime, OperationId, TenantId};
use crate::foundation::signing::{
    content_statement, ClassRefusal, ClassVerification, Ed25519PublicKey, ReloadOutcome,
    StatementBinding, StructureValidator, TrustCalendar, TrustRootLocation, TrustRootService,
};

const SETTING: &str = "YOUGORI_TEST_CATALOG_TRUST_ROOTS";
const GRACE: Duration = Duration::from_secs(60);

fn pair(seed: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
}

fn public(seed: u8) -> Ed25519PublicKey {
    Ed25519PublicKey::from_bytes(pair(seed).public_key().as_ref()).unwrap()
}

fn publisher(seed: u8) -> PublisherId {
    public(seed).publisher_id()
}

/// Key `seed` named `name`, signing `classes` through 2027.
fn key(name: &str, seed: u8, classes: &[&str]) -> Value {
    json!({
        "id": name,
        "algorithm": "ed25519",
        "public_key": public(seed).to_hex(),
        "classes": classes,
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2028-01-01T00:00:00Z",
    })
}

fn revoked(mut listed: Value) -> Value {
    listed["revoked"] = json!({ "reason": "key-compromise" });
    listed
}

struct FixedCalendar(DateTime<Utc>);

impl TrustCalendar for FixedCalendar {
    fn now(&self) -> DateTime<Utc> {
        self.0
    }
}

fn calendar() -> Arc<FixedCalendar> {
    Arc::new(FixedCalendar("2026-10-29T12:00:00Z".parse().unwrap()))
}

/// Accepts every structure: these tests are about trust, quotas and lifecycle.
struct AnyStructure;

impl StructureValidator for AnyStructure {
    fn validate(
        &self,
        _content: &ContentDescriptor,
        _bytes: &mut ObjectBytes,
    ) -> Result<(), VerifierRejection> {
        Ok(())
    }
}

/// A local verifier that authenticates no publisher, as the sidecar's does.
struct LocalVerifier(ArtifactClass);

impl ArtifactVerifier for LocalVerifier {
    fn class(&self) -> ArtifactClass {
        self.0
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

fn signed(class: ArtifactClass) -> OfferedClass {
    OfferedClass::Signed(ClassVerification {
        class,
        binding: StatementBinding::Content,
        structure: Box::new(AnyStructure),
    })
}

fn tenant() -> Scope {
    Scope::tenant(TenantId::new("owner").unwrap())
}

fn execution() -> ExecutionId {
    ExecutionId::new("exe-catalog-service").unwrap()
}

/// Bytes in memory as a catalog import source.
struct Bytes {
    identity: SourceIdentity,
    bytes: Vec<u8>,
}

impl Bytes {
    fn new(locator: &str, bytes: &[u8]) -> Self {
        Self {
            identity: SourceIdentity::describe("test", locator),
            bytes: bytes.to_vec(),
        }
    }
}

impl ImportSource for Bytes {
    fn identity(&self) -> SourceIdentity {
        self.identity
    }

    fn length_bytes(&mut self) -> Result<u64, SourceError> {
        Ok(self.bytes.len() as u64)
    }

    fn read_at(&mut self, offset_bytes: u64, buffer: &mut [u8]) -> Result<usize, SourceError> {
        let rest = &self.bytes[offset_bytes as usize..];
        let read = rest.len().min(buffer.len());
        buffer[..read].copy_from_slice(&rest[..read]);
        Ok(read)
    }
}

/// Interrupts at one checkpoint.
struct StopAt(Checkpoint);

impl ImportControl for StopAt {
    fn proceed(&mut self, at: Checkpoint) -> Proceed {
        if at == self.0 {
            Proceed::Interrupt
        } else {
            Proceed::Continue
        }
    }
}

fn request(scope: &Scope, class: ArtifactClass, bytes: &[u8], trust: TrustClaim) -> ImportRequest {
    ImportRequest {
        operation: OperationId::new("op-catalog-service").unwrap(),
        execution: execution(),
        scope: scope.clone(),
        class,
        role: ObjectRole::Original,
        manifest: ImportManifest::describe(bytes, NonZeroU64::new(4).unwrap()),
        trust,
        depends_on: BTreeSet::new(),
        metadata: ObjectMetadata::new(),
    }
}

/// A publisher claim signed by key `seed` over the content statement of `bytes`.
fn signed_by(seed: u8, class: ArtifactClass, bytes: &[u8]) -> TrustClaim {
    let manifest = ImportManifest::describe(bytes, NonZeroU64::new(4).unwrap());
    let statement = content_statement(
        &publisher(seed),
        class,
        &manifest.content_key,
        manifest.true_length_bytes,
    );
    TrustClaim::Publisher {
        publisher: publisher(seed),
        attestation: pair(seed).sign(statement.as_bytes()).as_ref().to_vec(),
    }
}

/// Starts and drives one import to its end under `control`, then detaches.
fn import(
    catalog: &mut Catalog,
    request: ImportRequest,
    source: &mut Bytes,
    control: &mut dyn ImportControl,
) -> Result<ImportStatus, ImportRefusal> {
    match catalog.begin_import(request, source.identity)? {
        ImportStart::Started(ticket) | ImportStart::Attached(ticket) => {
            let status = catalog.drive_import(&ticket, source, control).unwrap();
            catalog.cancel_import(ticket);
            Ok(status)
        }
        ImportStart::AlreadyPublished(object) => Ok(ImportStatus::Published {
            object,
            progress: Default::default(),
        }),
    }
}

fn published(status: Result<ImportStatus, ImportRefusal>) -> ObjectId {
    match status {
        Ok(ImportStatus::Published { object, .. }) => object,
        other => panic!("not published: {other:?}"),
    }
}

/// A catalog root, a trust-root file and a manual clock, in temporary directories.
struct Fixture {
    dir: tempfile::TempDir,
    clock: Arc<ManualClock>,
}

impl Fixture {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
            clock: Arc::new(ManualClock::new(MonotonicTime::from_nanos(1))),
        }
    }

    fn root(&self) -> PathBuf {
        self.dir.path().join("catalog")
    }

    fn roots_file(&self) -> PathBuf {
        self.dir.path().join("trust-roots.json")
    }

    /// A trust-root service over a file listing `keys`, or over no file at all.
    fn trust(&self, keys: Option<Vec<Value>>) -> TrustRootService {
        let location = match keys {
            None => TrustRootLocation::from_setting(SETTING, None),
            Some(keys) => {
                self.write_roots(keys);
                TrustRootLocation::from_setting(SETTING, Some(self.roots_file().as_os_str()))
            }
        };
        TrustRootService::open(location, calendar())
    }

    fn write_roots(&self, keys: Vec<Value>) {
        fs::write(
            self.roots_file(),
            json!({ "format": 1, "keys": keys }).to_string(),
        )
        .unwrap();
    }

    fn open(
        &self,
        config: CatalogServiceConfig,
        offered: Vec<OfferedClass>,
        trust: &mut TrustRootService,
    ) -> CatalogService {
        CatalogService::open(
            &self.root(),
            config,
            offered,
            trust,
            self.clock.clone(),
            calendar(),
            Mutex::new,
        )
        .unwrap()
        .0
    }
}

fn config() -> CatalogServiceConfig {
    CatalogServiceConfig::new(GRACE)
        .with_quota(tenant(), 1 << 20)
        .with_quota(Scope::Host, 1 << 20)
        .accept_user_selected(ArtifactClass::ModelWeights)
}

#[test]
fn opening_creates_the_root_and_reports_a_clean_recovery() {
    let fixture = Fixture::new();
    let mut trust = fixture.trust(None);
    let service = fixture.open(config(), Vec::new(), &mut trust);
    for dir in ["staging", "objects", "records", "roots"] {
        assert!(fixture.root().join(dir).is_dir(), "{dir}");
    }
    let recovery = service.recovery();
    assert_eq!(recovery.published, 0);
    assert!(recovery.quarantined.is_empty() && recovery.unpublished.is_empty());
    assert_eq!(recovery.interrupted_imports, 0);
    assert_eq!(recovery.opened_at, calendar().now());
    assert_eq!(service.root(), fixture.root());
    let status = service.status();
    assert_eq!(status.classes.len(), ArtifactClass::ALL.len());
    assert!(status
        .classes
        .iter()
        .all(|class| class.verifier == ClassVerifier::NotOffered && !class.policy));

    // A relative root would depend on the working directory: refused, nothing created.
    let refused = CatalogService::open(
        Path::new("relative-catalog"),
        config(),
        Vec::new(),
        &mut trust,
        fixture.clock.clone(),
        calendar(),
        Mutex::new,
    )
    .unwrap_err();
    assert_eq!(
        refused,
        OpenRefusal::NotAbsolute {
            root: "relative-catalog".to_owned()
        }
    );
    assert!(!Path::new("relative-catalog").exists());
}

#[test]
fn classes_with_keys_get_signed_verifiers_and_classes_without_keys_keep_refusing() {
    let fixture = Fixture::new();
    let mut trust = fixture.trust(Some(vec![key("updates", 1, &["runtime_update"])]));
    let service = fixture.open(
        config().accept_user_selected(ArtifactClass::ModelSidecar),
        vec![
            signed(ArtifactClass::RuntimeUpdate),
            signed(ArtifactClass::GuestImage),
            signed(ArtifactClass::ModelWeights),
            OfferedClass::Local(Box::new(LocalVerifier(ArtifactClass::ModelSidecar))),
            signed(ArtifactClass::RuntimeUpdate),
        ],
        &mut trust,
    );
    assert_eq!(
        service.verifier(ArtifactClass::RuntimeUpdate),
        &ClassVerifier::Signed
    );
    assert_eq!(
        service.verifier(ArtifactClass::GuestImage),
        &ClassVerifier::Refused {
            refusal: ClassRefusal::NoKeys {
                class: ArtifactClass::GuestImage
            }
        }
    );
    assert_eq!(
        service.verifier(ArtifactClass::ModelWeights),
        &ClassVerifier::UserSelectedOnly {
            publishers: ClassRefusal::NoKeys {
                class: ArtifactClass::ModelWeights
            }
        }
    );
    assert_eq!(
        service.verifier(ArtifactClass::ModelSidecar),
        &ClassVerifier::Local
    );
    assert_eq!(
        service.verifier(ArtifactClass::OciLayer),
        &ClassVerifier::NotOffered
    );

    let mut catalog = service.catalog();
    // The class with keys publishes what its publisher signed, and only that.
    let update = b"runtime update v2";
    published(import(
        &mut catalog,
        request(
            &Scope::Host,
            ArtifactClass::RuntimeUpdate,
            update,
            signed_by(1, ArtifactClass::RuntimeUpdate, update),
        ),
        &mut Bytes::new("update", update),
        &mut Uninterrupted,
    ));
    let forged = import(
        &mut catalog,
        request(
            &Scope::Host,
            ArtifactClass::RuntimeUpdate,
            b"other update",
            signed_by(1, ArtifactClass::RuntimeUpdate, update),
        ),
        &mut Bytes::new("forged", b"other update"),
        &mut Uninterrupted,
    );
    assert!(
        matches!(
            forged,
            Err(ImportRefusal::Trust {
                refusal: TrustRefusal::AttestationRejected { .. }
            })
        ),
        "{forged:?}"
    );
    // A class without keys refuses every publication with a typed reason, even one
    // signed by a key the roots trust for another class.
    for class in [ArtifactClass::GuestImage, ArtifactClass::OciLayer] {
        let refused = import(
            &mut catalog,
            request(&Scope::Host, class, b"image", signed_by(1, class, b"image")),
            &mut Bytes::new("image", b"image"),
            &mut Uninterrupted,
        );
        assert_eq!(
            refused,
            Err(ImportRefusal::Trust {
                refusal: TrustRefusal::NoVerifier { class }
            })
        );
    }
    // The user-selected class takes the tenant's own originals and trusts no publisher.
    let weights = b"model weights";
    published(import(
        &mut catalog,
        request(
            &tenant(),
            ArtifactClass::ModelWeights,
            weights,
            TrustClaim::UserSelected,
        ),
        &mut Bytes::new("weights", weights),
        &mut Uninterrupted,
    ));
    let claimed = import(
        &mut catalog,
        request(
            &tenant(),
            ArtifactClass::ModelWeights,
            b"published weights",
            signed_by(1, ArtifactClass::ModelWeights, b"published weights"),
        ),
        &mut Bytes::new("claimed", b"published weights"),
        &mut Uninterrupted,
    );
    assert!(
        matches!(
            claimed,
            Err(ImportRefusal::Trust {
                refusal: TrustRefusal::PublisherNotTrusted { .. }
            })
        ),
        "{claimed:?}"
    );
    drop(catalog);

    let status = service.status();
    assert_eq!(
        status.refused_offers,
        vec![ClassRefusal::AlreadyRegistered {
            class: ArtifactClass::RuntimeUpdate
        }]
    );
    let json = serde_json::to_value(&status).unwrap();
    let class = |tag: &str| {
        json["classes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|class| class["class"] == tag)
            .cloned()
            .unwrap()
    };
    assert_eq!(class("runtime_update")["verifier"], "signed");
    assert_eq!(class("runtime_update")["accepts_user_selected"], false);
    assert_eq!(class("guest_image")["verifier"], "refused");
    assert_eq!(class("guest_image")["refusal"]["refusal"], "no_keys");
    assert_eq!(class("model_weights")["verifier"], "user_selected_only");
    assert_eq!(class("model_weights")["accepts_user_selected"], true);
    assert_eq!(class("model_sidecar")["verifier"], "local");
    assert_eq!(class("model_sidecar")["accepts_user_selected"], true);
    assert_eq!(class("oci_layer")["verifier"], "not_offered");
    assert_eq!(class("oci_layer")["policy"], false);
}

#[test]
fn without_trust_roots_signed_classes_refuse_and_user_selected_classes_take_originals_only() {
    let fixture = Fixture::new();
    let mut trust = fixture.trust(None);
    let service = fixture.open(
        config(),
        vec![
            signed(ArtifactClass::ModelHelper),
            signed(ArtifactClass::ModelWeights),
        ],
        &mut trust,
    );
    assert_eq!(
        service.verifier(ArtifactClass::ModelHelper),
        &ClassVerifier::Refused {
            refusal: ClassRefusal::NoTrustRoots {
                class: ArtifactClass::ModelHelper
            }
        }
    );
    assert_eq!(
        service.verifier(ArtifactClass::ModelWeights),
        &ClassVerifier::UserSelectedOnly {
            publishers: ClassRefusal::NoTrustRoots {
                class: ArtifactClass::ModelWeights
            }
        }
    );
    let mut catalog = service.catalog();
    let helper = import(
        &mut catalog,
        request(
            &Scope::Host,
            ArtifactClass::ModelHelper,
            b"helper",
            signed_by(1, ArtifactClass::ModelHelper, b"helper"),
        ),
        &mut Bytes::new("helper", b"helper"),
        &mut Uninterrupted,
    );
    assert_eq!(
        helper,
        Err(ImportRefusal::Trust {
            refusal: TrustRefusal::NoVerifier {
                class: ArtifactClass::ModelHelper
            }
        })
    );
    // A checksum is never trust, and a user selection stays in the tenant's own scope.
    let checksum = import(
        &mut catalog,
        request(
            &tenant(),
            ArtifactClass::ModelWeights,
            b"weights",
            TrustClaim::ChecksumOnly,
        ),
        &mut Bytes::new("weights", b"weights"),
        &mut Uninterrupted,
    );
    assert!(matches!(
        checksum,
        Err(ImportRefusal::Trust {
            refusal: TrustRefusal::ChecksumIsNotTrust { .. }
        })
    ));
    let host = import(
        &mut catalog,
        request(
            &Scope::Host,
            ArtifactClass::ModelWeights,
            b"weights",
            TrustClaim::UserSelected,
        ),
        &mut Bytes::new("weights", b"weights"),
        &mut Uninterrupted,
    );
    assert!(matches!(
        host,
        Err(ImportRefusal::Trust {
            refusal: TrustRefusal::UserSelectionOutsideTenantScope { .. }
        })
    ));
}

#[test]
fn an_import_over_the_scope_budget_is_refused_and_nothing_is_evicted() {
    let fixture = Fixture::new();
    let mut trust = fixture.trust(None);
    let service = fixture.open(
        CatalogServiceConfig::new(GRACE)
            .with_quota(tenant(), 20)
            .accept_user_selected(ArtifactClass::ModelWeights),
        vec![signed(ArtifactClass::ModelWeights)],
        &mut trust,
    );
    let mut catalog = service.catalog();
    let first = published(import(
        &mut catalog,
        request(
            &tenant(),
            ArtifactClass::ModelWeights,
            b"twelve bytes",
            TrustClaim::UserSelected,
        ),
        &mut Bytes::new("first", b"twelve bytes"),
        &mut Uninterrupted,
    ));
    let over = import(
        &mut catalog,
        request(
            &tenant(),
            ArtifactClass::ModelWeights,
            b"twelve again",
            TrustClaim::UserSelected,
        ),
        &mut Bytes::new("second", b"twelve again"),
        &mut Uninterrupted,
    );
    assert_eq!(
        over,
        Err(ImportRefusal::Quota {
            refusal: QuotaRefusal::Exceeded {
                scope: tenant(),
                limit_bytes: 20,
                charged_bytes: 12,
                requested_bytes: 12,
                evictable_bytes: 0,
            }
        })
    );
    // A scope without a budget stores nothing.
    let other = Scope::tenant(TenantId::new("guest").unwrap());
    assert_eq!(
        import(
            &mut catalog,
            request(
                &other,
                ArtifactClass::ModelWeights,
                b"weights",
                TrustClaim::UserSelected,
            ),
            &mut Bytes::new("guest", b"weights"),
            &mut Uninterrupted,
        ),
        Err(ImportRefusal::Quota {
            refusal: QuotaRefusal::NoBudget { scope: other }
        })
    );
    assert_eq!(catalog.status(&tenant(), first), ObjectStatus::Published);
    drop(catalog);
    let status = service.status();
    let scope = &status.catalog.scopes[0];
    assert_eq!(scope.scope, tenant());
    assert_eq!(scope.quota.limit_bytes, Some(20));
    assert_eq!(scope.quota.charged_bytes, 12);
    assert!(!scope.quota.over_budget);
}

/// The data file of a committed object, made writable so a test can damage it.
fn data_file(root: &Path, object: ObjectId) -> PathBuf {
    let path = root.join("objects").join(object.to_string()).join("data");
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    permissions.set_readonly(false);
    fs::set_permissions(&path, permissions).unwrap();
    path
}

#[test]
fn reopening_recovers_interrupted_imports_and_publications_and_quarantines_damage() {
    let fixture = Fixture::new();
    let mut trust = fixture.trust(None);
    let offered = || vec![signed(ArtifactClass::ModelWeights)];
    let weights = |name: &str| format!("{name} weights, sixteen+ bytes").into_bytes();
    let (whole, partial, committed) = (weights("whole"), weights("partial"), weights("committed"));
    let user = |bytes: &[u8]| {
        request(
            &tenant(),
            ArtifactClass::ModelWeights,
            bytes,
            TrustClaim::UserSelected,
        )
    };
    let (damaged, committed_object) = {
        let service = fixture.open(config(), offered(), &mut trust);
        let mut catalog = service.catalog();
        let damaged = published(import(
            &mut catalog,
            user(&whole),
            &mut Bytes::new("whole", &whole),
            &mut Uninterrupted,
        ));
        // Interrupted while copying: two extents are verified and staged.
        let status = import(
            &mut catalog,
            user(&partial),
            &mut Bytes::new("partial", &partial),
            &mut StopAt(Checkpoint::Extent { extent: 2 }),
        );
        assert!(
            matches!(status, Ok(ImportStatus::Pending { .. })),
            "{status:?}"
        );
        // Interrupted after the durable commit, before publication.
        let status = import(
            &mut catalog,
            user(&committed),
            &mut Bytes::new("committed", &committed),
            &mut StopAt(Checkpoint::Stage {
                stage: ImportStage::CatalogPublication,
            }),
        );
        assert!(
            matches!(status, Ok(ImportStatus::Pending { .. })),
            "{status:?}"
        );
        let committed_object = ObjectId::new(
            &tenant(),
            ArtifactClass::ModelWeights,
            user(&committed).manifest.content_key,
        );
        (damaged, committed_object)
    };
    // The published copy of the first object loses its tail while the engine is down.
    let path = data_file(&fixture.root(), damaged);
    fs::write(&path, &whole[..4]).unwrap();

    let service = fixture.open(config(), offered(), &mut trust);
    let recovery = service.recovery().clone();
    assert_eq!(
        recovery.quarantined,
        vec![QuarantinedObject {
            object: damaged,
            reason: IntegrityFailure::LengthMismatch {
                expected_bytes: whole.len() as u64,
                found_bytes: 4,
            },
        }]
    );
    assert_eq!(recovery.unpublished, vec![committed_object]);
    // Both interrupted imports left their staging: the copy's extents, and the committed
    // one's declaration and journal.
    assert_eq!(recovery.interrupted_imports, 2);
    assert_eq!(recovery.published, 0);

    let mut catalog = service.catalog();
    // The interrupted copy resumes from its verified extents.
    match import(
        &mut catalog,
        user(&partial),
        &mut Bytes::new("partial", &partial),
        &mut Uninterrupted,
    ) {
        Ok(ImportStatus::Published { progress, .. }) => {
            assert_eq!(progress.reused_extents, 2, "{progress:?}");
        }
        other => panic!("{other:?}"),
    }
    // The committed copy is validated and published without fetching a byte.
    match import(
        &mut catalog,
        user(&committed),
        &mut Bytes::new("committed", &committed),
        &mut Uninterrupted,
    ) {
        Ok(ImportStatus::Published { object, progress }) => {
            assert_eq!(object, committed_object);
            assert_eq!(progress.fetched_bytes, 0, "{progress:?}");
        }
        other => panic!("{other:?}"),
    }
    // A verified import of the same content replaces the quarantined copy.
    assert!(matches!(
        catalog.status(&tenant(), damaged),
        ObjectStatus::Quarantined { .. }
    ));
    published(import(
        &mut catalog,
        user(&whole),
        &mut Bytes::new("whole", &whole),
        &mut Uninterrupted,
    ));
    assert_eq!(catalog.status(&tenant(), damaged), ObjectStatus::Published);
}

#[test]
fn garbage_collection_keeps_leased_objects_and_originals_and_touches_nothing_outside() {
    let fixture = Fixture::new();
    let mut trust = fixture.trust(None);
    let service = fixture.open(
        config(),
        vec![signed(ArtifactClass::ModelWeights)],
        &mut trust,
    );
    // The user's original file lives outside the catalog.
    let user_file = fixture.dir.path().join("model.safetensors");
    let original_bytes = b"the user's original model file".to_vec();
    fs::write(&user_file, &original_bytes).unwrap();

    let (original, prepared) = {
        let mut catalog = service.catalog();
        let original = published(import(
            &mut catalog,
            request(
                &tenant(),
                ArtifactClass::ModelWeights,
                &original_bytes,
                TrustClaim::UserSelected,
            ),
            &mut Bytes::new("user-file", &original_bytes),
            &mut Uninterrupted,
        ));
        let converted = b"a prepared representation".to_vec();
        let mut prepared_request = request(
            &tenant(),
            ArtifactClass::ModelWeights,
            &converted,
            TrustClaim::UserSelected,
        );
        prepared_request.role = ObjectRole::Prepared {
            derived_from: BTreeSet::from([original]),
        };
        let prepared = published(import(
            &mut catalog,
            prepared_request,
            &mut Bytes::new("prepared", &converted),
            &mut Uninterrupted,
        ));
        (original, prepared)
    };
    let lease = service
        .catalog()
        .acquire_lease(&tenant(), &execution(), prepared, GRACE * 10)
        .unwrap();
    fixture.clock.advance(GRACE * 2);

    // Unreachable and past the grace period, but leased: kept, and the original too.
    let record = service.collect_garbage();
    assert_eq!(record.at, calendar().now());
    assert_eq!(
        record.outcome,
        GcOutcome::Collected {
            removed: Vec::new(),
            removed_bytes: 0,
            removed_unpublished: Vec::new(),
            removed_staging: 0,
            kept_leased: vec![prepared],
            kept_originals: 1,
            kept_quarantined: 0,
            kept_in_grace: 0,
        }
    );
    service
        .catalog()
        .release_lease(&tenant(), &execution(), lease)
        .unwrap();
    // The grace period restarts when the lease ends.
    let record = service.collect_garbage();
    assert!(
        matches!(&record.outcome, GcOutcome::Collected { kept_in_grace: 1, removed, .. } if removed.is_empty()),
        "{record:?}"
    );
    fixture.clock.advance(GRACE * 2);
    let record = service.collect_garbage();
    assert!(
        matches!(&record.outcome, GcOutcome::Collected { removed, kept_originals: 1, .. } if *removed == vec![prepared]),
        "{record:?}"
    );
    let catalog = service.catalog();
    assert_eq!(catalog.status(&tenant(), prepared), ObjectStatus::Absent);
    assert_eq!(catalog.status(&tenant(), original), ObjectStatus::Published);
    drop(catalog);
    // Nothing outside the catalog root was touched.
    assert_eq!(fs::read(&user_file).unwrap(), original_bytes);
    assert_eq!(service.status().last_gc, Some(record));
}

#[test]
fn reloaded_roots_quarantine_a_revoked_publishers_objects_and_keep_user_selections() {
    let fixture = Fixture::new();
    let classes = &["runtime_update", "model_weights"];
    let mut trust = fixture.trust(Some(vec![key("release", 1, classes)]));
    let service = fixture.open(
        config(),
        vec![
            signed(ArtifactClass::RuntimeUpdate),
            signed(ArtifactClass::ModelWeights),
            signed(ArtifactClass::GuestImage),
        ],
        &mut trust,
    );
    assert_eq!(
        service.verifier(ArtifactClass::ModelWeights),
        &ClassVerifier::Signed
    );
    let update = b"runtime update".to_vec();
    let weights = b"the owner's own weights".to_vec();
    let (update_object, weights_object, lease) = {
        let mut catalog = service.catalog();
        let update_object = published(import(
            &mut catalog,
            request(
                &Scope::Host,
                ArtifactClass::RuntimeUpdate,
                &update,
                signed_by(1, ArtifactClass::RuntimeUpdate, &update),
            ),
            &mut Bytes::new("update", &update),
            &mut Uninterrupted,
        ));
        let weights_object = published(import(
            &mut catalog,
            request(
                &tenant(),
                ArtifactClass::ModelWeights,
                &weights,
                TrustClaim::UserSelected,
            ),
            &mut Bytes::new("weights", &weights),
            &mut Uninterrupted,
        ));
        let lease = catalog
            .acquire_lease(&tenant(), &execution(), weights_object, GRACE)
            .unwrap();
        (update_object, weights_object, lease)
    };

    // The owner revokes the release key and adds a key for guest images.
    fixture.write_roots(vec![
        revoked(key("release", 1, classes)),
        key("images", 2, &["guest_image"]),
    ]);
    assert!(matches!(trust.reload(), ReloadOutcome::Applied { .. }));
    let applied = service.apply_trust_roots(&trust);
    assert_eq!(applied.generation, Some(2));
    let runtime = applied
        .classes
        .iter()
        .find(|class| class.class == ArtifactClass::RuntimeUpdate)
        .unwrap();
    assert_eq!(runtime.quarantined, vec![update_object]);
    let model = applied
        .classes
        .iter()
        .find(|class| class.class == ArtifactClass::ModelWeights)
        .unwrap();
    assert!(model.quarantined.is_empty(), "{model:?}");
    assert_eq!(applied.needs_reopen, vec![ArtifactClass::GuestImage]);

    let catalog = service.catalog();
    assert!(matches!(
        catalog.status(&Scope::Host, update_object),
        ObjectStatus::Quarantined {
            reason: IntegrityFailure::TrustWithdrawn { .. }
        }
    ));
    // The tenant's own original stays published and its lease live.
    assert_eq!(
        catalog.status(&tenant(), weights_object),
        ObjectStatus::Published
    );
    assert_eq!(
        catalog
            .lease_object(&tenant(), &execution(), lease)
            .unwrap()
            .0,
        weights_object
    );
    drop(catalog);
    assert_eq!(service.status().last_trust, Some(applied));
}

#[test]
fn the_status_counts_objects_by_class_and_state_with_quota_leases_recovery_and_gc() {
    let fixture = Fixture::new();
    let mut trust = fixture.trust(None);
    let service = fixture.open(
        config(),
        vec![signed(ArtifactClass::ModelWeights)],
        &mut trust,
    );
    {
        let mut catalog = service.catalog();
        let object = published(import(
            &mut catalog,
            request(
                &tenant(),
                ArtifactClass::ModelWeights,
                b"eleven byte",
                TrustClaim::UserSelected,
            ),
            &mut Bytes::new("weights", b"eleven byte"),
            &mut Uninterrupted,
        ));
        catalog
            .acquire_lease(&tenant(), &execution(), object, GRACE)
            .unwrap();
    }
    assert!(service.status().last_gc.is_none());
    service.collect_garbage();
    let status = service.status();
    assert_eq!(status.root, fixture.root().display().to_string());
    assert_eq!(status.catalog.live_leases, 1);
    let scope = status
        .catalog
        .scopes
        .iter()
        .find(|scope| scope.scope == tenant())
        .unwrap();
    assert_eq!(scope.leased_objects, 1);
    assert_eq!(scope.classes.len(), 1);
    assert_eq!(scope.classes[0].published.objects, 1);
    assert_eq!(scope.classes[0].published.bytes, 11);
    assert_eq!(scope.classes[0].originals.objects, 1);
    assert_eq!(scope.quota.published_bytes, 11);
    let json = serde_json::to_value(&status).unwrap();
    assert_eq!(json["recovery"]["published"], 0);
    assert_eq!(json["last_gc"]["outcome"], "collected");
    assert_eq!(json["last_gc"]["kept_originals"], 1);
    assert!(json["last_trust"].is_null());
    assert_eq!(
        json["catalog"]["scopes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|scope| scope["scope"]["tenant"] == "owner")
            .unwrap()["classes"][0]["published"],
        json!({"objects": 1, "bytes": 11})
    );
}

#[test]
fn a_location_is_configured_only_as_an_absolute_directory() {
    assert_eq!(
        CatalogLocation::from_setting(SETTING, None),
        CatalogLocation::NotConfigured { setting: SETTING }
    );
    assert_eq!(
        CatalogLocation::from_setting(SETTING, Some(std::ffi::OsStr::new(""))),
        CatalogLocation::NotConfigured { setting: SETTING }
    );
    let relative = CatalogLocation::from_setting(SETTING, Some(std::ffi::OsStr::new("catalog")));
    assert_eq!(
        relative,
        CatalogLocation::Invalid {
            setting: SETTING,
            problem: LocationProblem::NotAbsolute
        }
    );
    assert!(relative.remedy().unwrap().contains(SETTING));
    let dir = tempfile::tempdir().unwrap();
    let absolute = CatalogLocation::from_setting(SETTING, Some(dir.path().as_os_str()));
    assert_eq!(
        absolute,
        CatalogLocation::Directory {
            setting: SETTING,
            path: dir.path().to_path_buf()
        }
    );
    assert_eq!(absolute.remedy(), None);
    assert!(CatalogLocation::from_setting(SETTING, None)
        .remedy()
        .unwrap()
        .contains("none is built in"));
}

/// A local verifier that authenticates publishers its own way: here, an attestation
/// reading `vouched`. Which publishers it may admit is the policy's call.
struct OwnWayVerifier(ArtifactClass);

impl ArtifactVerifier for OwnWayVerifier {
    fn class(&self) -> ArtifactClass {
        self.0
    }

    fn authenticate(
        &self,
        _content: &ContentDescriptor,
        _publisher: &PublisherId,
        attestation: &[u8],
    ) -> Result<(), VerifierRejection> {
        if attestation == b"vouched" {
            Ok(())
        } else {
            Err(VerifierRejection::AttestationInvalid)
        }
    }

    fn validate(
        &self,
        _content: &ContentDescriptor,
        _bytes: &mut ObjectBytes,
    ) -> Result<(), VerifierRejection> {
        Ok(())
    }
}

/// `class` with its own verifier and its policy from the trust roots' keys for it.
fn sourced(class: ArtifactClass) -> OfferedClass {
    OfferedClass::LocalWithPolicy {
        verifier: Box::new(OwnWayVerifier(class)),
        policy: Box::new(move |trust: &TrustRootService| trust.policy(class).unwrap_or_default()),
    }
}

fn vouched(seed: u8) -> TrustClaim {
    TrustClaim::Publisher {
        publisher: publisher(seed),
        attestation: b"vouched".to_vec(),
    }
}

#[test]
fn a_local_class_with_a_policy_source_keeps_its_objects_across_a_reopen() {
    let fixture = Fixture::new();
    let mut trust = fixture.trust(Some(vec![key("oci-publisher", 21, &["oci_layer"])]));
    let class = ArtifactClass::OciLayer;
    let service = fixture.open(config(), vec![sourced(class)], &mut trust);
    let object = published(import(
        &mut service.catalog(),
        request(&Scope::Host, class, b"a layer", vouched(21)),
        &mut Bytes::new("layer", b"a layer"),
        &mut Uninterrupted,
    ));
    // A publisher the roots do not list is refused by the same policy.
    assert_eq!(
        import(
            &mut service.catalog(),
            request(&Scope::Host, class, b"another layer", vouched(22)),
            &mut Bytes::new("another", b"another layer"),
            &mut Uninterrupted,
        ),
        Err(ImportRefusal::Trust {
            refusal: TrustRefusal::PublisherNotTrusted {
                class,
                publisher: publisher(22),
            }
        })
    );
    drop(service);

    // Reopened with its policy source, recovery quarantines nothing.
    let service = fixture.open(config(), vec![sourced(class)], &mut trust);
    assert!(service.recovery().quarantined.is_empty());
    assert_eq!(service.recovery().published, 1);
    assert_eq!(
        service.catalog().status(&Scope::Host, object),
        ObjectStatus::Published
    );
    drop(service);

    // Offered without one, the class has no policy and recovery quarantines the object.
    let service = fixture.open(
        config(),
        vec![OfferedClass::Local(Box::new(OwnWayVerifier(class)))],
        &mut trust,
    );
    assert_eq!(
        service.recovery().quarantined,
        vec![QuarantinedObject {
            object,
            reason: IntegrityFailure::TrustWithdrawn {
                refusal: TrustRefusal::NoPolicy { class }
            },
        }]
    );
}

#[test]
fn a_reload_that_removes_a_local_class_keys_refuses_its_objects_by_policy() {
    let fixture = Fixture::new();
    let publisher_key = key("oci-publisher", 21, &["oci_layer"]);
    let other_key = key("helper-publisher", 23, &["model_helper"]);
    let mut trust = fixture.trust(Some(vec![publisher_key.clone(), other_key.clone()]));
    let class = ArtifactClass::OciLayer;
    let service = fixture.open(config(), vec![sourced(class)], &mut trust);
    let object = published(import(
        &mut service.catalog(),
        request(&Scope::Host, class, b"a layer", vouched(21)),
        &mut Bytes::new("layer", b"a layer"),
        &mut Uninterrupted,
    ));

    // The owner drops the class's only key: its objects lose their trust, not kept
    // silently, and nothing new is admitted.
    fixture.write_roots(vec![other_key.clone()]);
    assert!(matches!(trust.reload(), ReloadOutcome::Applied { .. }));
    let applied = service.apply_trust_roots(&trust);
    let revised = applied
        .classes
        .iter()
        .find(|applied| applied.class == class)
        .unwrap();
    assert_eq!(revised.quarantined, vec![object]);
    assert_eq!(
        service.catalog().status(&Scope::Host, object),
        ObjectStatus::Quarantined {
            reason: IntegrityFailure::TrustWithdrawn {
                refusal: TrustRefusal::PublisherNotTrusted {
                    class,
                    publisher: publisher(21),
                }
            }
        }
    );
    assert_eq!(
        import(
            &mut service.catalog(),
            request(&Scope::Host, class, b"a second layer", vouched(21)),
            &mut Bytes::new("second", b"a second layer"),
            &mut Uninterrupted,
        ),
        Err(ImportRefusal::Trust {
            refusal: TrustRefusal::PublisherNotTrusted {
                class,
                publisher: publisher(21),
            }
        })
    );

    // The key comes back: the source reads it again and the object is restored.
    fixture.write_roots(vec![publisher_key, other_key]);
    assert!(matches!(trust.reload(), ReloadOutcome::Applied { .. }));
    let applied = service.apply_trust_roots(&trust);
    let revised = applied
        .classes
        .iter()
        .find(|applied| applied.class == class)
        .unwrap();
    assert_eq!(revised.restored, vec![object]);
    assert_eq!(
        service.catalog().status(&Scope::Host, object),
        ObjectStatus::Published
    );
}

#[test]
fn the_status_and_last_trust_list_a_local_class_with_a_policy_source() {
    let fixture = Fixture::new();
    let mut trust = fixture.trust(Some(vec![key("oci-publisher", 21, &["oci_layer"])]));
    let service = fixture.open(
        config().accept_user_selected(ArtifactClass::GuestImage),
        vec![
            sourced(ArtifactClass::OciLayer),
            sourced(ArtifactClass::GuestImage),
            OfferedClass::Local(Box::new(LocalVerifier(ArtifactClass::ModelSidecar))),
        ],
        &mut trust,
    );
    let admission = |status: &CatalogServiceStatus, class: ArtifactClass| {
        status
            .classes
            .iter()
            .find(|admission| admission.class == class)
            .cloned()
            .unwrap()
    };
    let status = service.status();
    for class in [ArtifactClass::OciLayer, ArtifactClass::GuestImage] {
        assert_eq!(admission(&status, class).verifier, ClassVerifier::Local);
        assert!(admission(&status, class).policy, "{class}");
    }
    assert!(!admission(&status, ArtifactClass::OciLayer).accepts_user_selected);
    // A source's policy keeps the tenants' own originals where the engine accepts them.
    assert!(admission(&status, ArtifactClass::GuestImage).accepts_user_selected);
    // The sidecar's local class has no source and no policy, as before.
    assert!(!admission(&status, ArtifactClass::ModelSidecar).policy);
    assert!(status.last_trust.is_none());
    assert!(format!("{:?}", sourced(ArtifactClass::OciLayer)).contains("LocalWithPolicy"));

    let applied = service.apply_trust_roots(&trust);
    let listed: Vec<ArtifactClass> = applied
        .classes
        .iter()
        .map(|applied| applied.class)
        .collect();
    assert_eq!(
        listed,
        vec![ArtifactClass::OciLayer, ArtifactClass::GuestImage]
    );
    let status = service.status();
    assert_eq!(status.last_trust, Some(applied));
    assert!(admission(&status, ArtifactClass::GuestImage).accepts_user_selected);
    assert!(service.catalog().config().trust[&ArtifactClass::OciLayer].trusts(&publisher(21)));
}
