//! M18F's registrations against a real catalog service in a temporary directory: a real
//! trust-root file, Ed25519 keys from fixed seeds (test keys, never release keys), a
//! manual clock and a fixed calendar. The fixtures here are shared with `tests_oci`,
//! `tests_guest` and `tests_update`; the tests here cover the registration itself, the
//! classes that stay refused, and keys and statements that never cross classes (VM-W48,
//! line 2671: "Keep artifact-class trust policies distinct").

use std::collections::BTreeSet;
use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};

use super::publish::{publish, MemorySource, Published};
use super::*;
use crate::foundation::catalog::{
    ArtifactClass, Catalog, ImportManifest, ImportRefusal, ImportRequest, ImportSource, ObjectId,
    ObjectMetadata, ObjectRole, ObjectStatus, PublisherId, ReadRefusal, Scope, SourceError,
    SourceIdentity, TrustClaim, TrustRefusal, Uninterrupted,
};
use crate::foundation::catalog_service::{CatalogService, CatalogServiceConfig, ClassVerifier};
use crate::foundation::ids::{
    ContentKey, ExecutionId, ManualClock, MonotonicTime, OperationId, TenantId,
};
use crate::foundation::signing::{
    content_statement, Ed25519PublicKey, TrustCalendar, TrustRootLocation, TrustRootService,
};
use crate::sandbox::trust::UnixSeconds;
use crate::sandbox_contract::oci::ImportLimits;

const SETTING: &str = "YOUGORI_TEST_M18F_TRUST_ROOTS";

/// The OCI publisher's key: `oci_layer` only.
pub(super) const OCI: u8 = 31;
/// The guest image release key: `guest_image` only.
pub(super) const GUEST: u8 = 32;
/// The update root key: `runtime_update` only.
pub(super) const UPDATE_ROOT: u8 = 33;
/// A key in no trust-root file.
pub(super) const ROGUE: u8 = 34;
/// A key allowed every class of this module, revoked.
pub(super) const REVOKED: u8 = 35;

pub(super) fn pair(seed: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
}

pub(super) fn public(seed: u8) -> Ed25519PublicKey {
    Ed25519PublicKey::from_bytes(pair(seed).public_key().as_ref()).unwrap()
}

pub(super) fn publisher(seed: u8) -> PublisherId {
    public(seed).publisher_id()
}

/// Key `seed` named `name`, signing `classes` through 2027.
pub(super) fn key(name: &str, seed: u8, classes: &[&str]) -> Value {
    json!({
        "id": name,
        "algorithm": "ed25519",
        "public_key": public(seed).to_hex(),
        "classes": classes,
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2028-01-01T00:00:00Z",
    })
}

pub(super) fn revoked(mut listed: Value) -> Value {
    listed["revoked"] = json!({ "reason": "key-compromise" });
    listed
}

/// The owner's trust roots: one key per class and a revoked key allowed all three.
pub(super) fn keys() -> Vec<Value> {
    vec![
        key("oci-publisher", OCI, &["oci_layer"]),
        key("guest-release", GUEST, &["guest_image"]),
        key("update-root", UPDATE_ROOT, &["runtime_update"]),
        revoked(key(
            "revoked-everything",
            REVOKED,
            &["oci_layer", "guest_image", "runtime_update"],
        )),
    ]
}

/// [`keys`] with the key named `id` revoked.
pub(super) fn keys_revoking(id: &str) -> Vec<Value> {
    keys()
        .into_iter()
        .map(|listed| {
            if listed["id"] == id && listed.get("revoked").is_none() {
                revoked(listed)
            } else {
                listed
            }
        })
        .collect()
}

pub(super) struct FixedCalendar(DateTime<Utc>);

impl TrustCalendar for FixedCalendar {
    fn now(&self) -> DateTime<Utc> {
        self.0
    }
}

pub(super) fn calendar() -> Arc<FixedCalendar> {
    Arc::new(FixedCalendar("2026-10-29T12:00:00Z".parse().unwrap()))
}

/// The calendar's time as the trust client's Unix seconds.
pub(super) fn now() -> UnixSeconds {
    UnixSeconds::new(u64::try_from(calendar().now().timestamp()).unwrap())
}

pub(super) fn tenant(name: &str) -> Scope {
    Scope::tenant(TenantId::new(name).unwrap())
}

pub(super) fn execution(name: &str) -> ExecutionId {
    ExecutionId::new(name).unwrap()
}

pub(super) fn operation() -> OperationId {
    OperationId::new("op-m18f").unwrap()
}

/// Bytes in memory as a catalog import source, as a local file would be.
pub(super) struct Bytes {
    pub identity: SourceIdentity,
    pub bytes: Vec<u8>,
}

impl Bytes {
    pub(super) fn new(locator: &str, bytes: &[u8]) -> Self {
        Self {
            identity: SourceIdentity::describe("m18f-test", locator),
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
        let rest = &self.bytes[(offset_bytes as usize).min(self.bytes.len())..];
        let read = rest.len().min(buffer.len());
        buffer[..read].copy_from_slice(&rest[..read]);
        Ok(read)
    }
}

/// Publishes `bytes` as `class` in `scope` under `trust`, bypassing every import entry,
/// as a caller holding the catalog could.
pub(super) fn raw_import(
    catalog: &mut Catalog,
    scope: &Scope,
    class: ArtifactClass,
    bytes: &[u8],
    trust: TrustClaim,
) -> Result<Published, PublishFailure> {
    let request = ImportRequest {
        operation: operation(),
        execution: execution("exe-raw"),
        scope: scope.clone(),
        class,
        role: ObjectRole::Original,
        manifest: ImportManifest::describe(bytes, NonZeroU64::new(1024).unwrap()),
        trust,
        depends_on: BTreeSet::new(),
        metadata: ObjectMetadata::new(),
    };
    let mut source = MemorySource {
        identity: SourceIdentity::describe("m18f-raw", &ContentKey::of(bytes).to_string()),
        bytes,
    };
    publish(catalog, request, &mut source, &mut Uninterrupted)
}

/// The trust refusal of a failed publication.
pub(super) fn trust_refusal(result: Result<Published, PublishFailure>) -> TrustRefusal {
    match result {
        Err(PublishFailure::Refused {
            refusal: ImportRefusal::Trust { refusal },
        }) => refusal,
        other => panic!("not a trust refusal: {other:?}"),
    }
}

/// A claim signed by `seed` over the catalog's content statement about `bytes` as
/// `class`: a plain publisher signature.
pub(super) fn content_signed(seed: u8, class: ArtifactClass, bytes: &[u8]) -> TrustClaim {
    let statement = content_statement(
        &publisher(seed),
        class,
        &ContentKey::of(bytes),
        bytes.len() as u64,
    );
    TrustClaim::Publisher {
        publisher: publisher(seed),
        attestation: pair(seed).sign(statement.as_bytes()).as_ref().to_vec(),
    }
}

/// That `object` of `class` with `bytes` is neither published in `scope` nor readable
/// there.
pub(super) fn assert_absent(
    catalog: &mut Catalog,
    scope: &Scope,
    class: ArtifactClass,
    bytes: &[u8],
) {
    let object = ObjectId::new(scope, class, ContentKey::of(bytes));
    assert_eq!(catalog.status(scope, object), ObjectStatus::Absent);
    assert_eq!(
        catalog.acquire_lease(
            scope,
            &execution("exe-reader"),
            object,
            Duration::from_secs(60)
        ),
        Err(ReadRefusal::NotGranted { object })
    );
}

/// Committed catalog files are read-only; make them writable for a test's edit and for
/// the temporary root's removal.
#[allow(clippy::permissions_set_readonly_false)]
pub(super) fn make_tree_writable(path: &Path) {
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            make_tree_writable(&entry.path());
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

/// A catalog root, a trust-root file and a manual clock, in a temporary directory.
pub(super) struct Fixture {
    pub dir: tempfile::TempDir,
    pub clock: Arc<ManualClock>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        make_tree_writable(self.dir.path());
    }
}

/// The opened service and the classes registered in it.
pub(super) struct Opened {
    pub service: CatalogService,
    pub classes: PolicyClasses,
}

pub(super) fn config() -> CatalogServiceConfig {
    CatalogServiceConfig::new(Duration::from_secs(60))
        .with_quota(Scope::Host, 1 << 30)
        .with_quota(tenant("a"), 1 << 30)
        .with_quota(tenant("b"), 1 << 30)
}

impl Fixture {
    pub(super) fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
            clock: Arc::new(ManualClock::new(MonotonicTime::from_nanos(1))),
        }
    }

    pub(super) fn root(&self) -> PathBuf {
        self.dir.path().join("catalog")
    }

    pub(super) fn roots_file(&self) -> PathBuf {
        self.dir.path().join("trust-roots.json")
    }

    pub(super) fn write_roots(&self, keys: Vec<Value>) {
        fs::write(
            self.roots_file(),
            json!({ "format": 1, "keys": keys }).to_string(),
        )
        .unwrap();
    }

    /// A trust-root service over the configured file, written with `keys` when given.
    pub(super) fn trust(&self, keys: Option<Vec<Value>>) -> TrustRootService {
        if let Some(keys) = keys {
            self.write_roots(keys);
        }
        TrustRootService::open(
            TrustRootLocation::from_setting(SETTING, Some(self.roots_file().as_os_str())),
            calendar(),
        )
    }

    /// Opens the catalog service with `offered`.
    pub(super) fn service(
        &self,
        offered: Vec<crate::foundation::catalog_service::OfferedClass>,
        trust: &mut TrustRootService,
    ) -> CatalogService {
        CatalogService::open(
            &self.root(),
            config(),
            offered,
            trust,
            self.clock.clone(),
            calendar(),
            Mutex::new,
        )
        .unwrap()
        .0
    }

    /// Opens the catalog service with this module's classes, as the engine would; their
    /// policies come from the trust roots before the catalog opens.
    pub(super) fn open(&self, trust: &mut TrustRootService) -> Opened {
        let classes = PolicyClasses::new(trust, calendar(), ImportLimits::default()).unwrap();
        let service = self.service(classes.offered(), trust);
        Opened { service, classes }
    }

    /// Reloads `trust` from `keys` and sets the policies again through the service, as the
    /// engine does after a reload; returns what each class's re-check quarantined.
    pub(super) fn reload(
        &self,
        opened: &Opened,
        trust: &mut TrustRootService,
        keys: Vec<Value>,
    ) -> Vec<crate::foundation::signing::PolicyApplied> {
        self.write_roots(keys);
        assert!(matches!(
            trust.reload(),
            crate::foundation::signing::ReloadOutcome::Applied { .. }
        ));
        let applied = opened.service.apply_trust_roots(trust);
        for class in POLICY_CLASSES {
            assert!(applied.classes.iter().any(|applied| applied.class == class));
        }
        applied.classes
    }

    /// The data file of `object`.
    pub(super) fn data(&self, object: ObjectId) -> PathBuf {
        self.root()
            .join("objects")
            .join(object.to_string())
            .join("data")
    }

    /// Flips one byte of `object`'s stored bytes at `offset`, as a disk or another
    /// process would.
    pub(super) fn corrupt(&self, object: ObjectId, offset: u64) {
        let path = self.data(object);
        make_tree_writable(&path);
        let mut byte = [0u8; 1];
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.seek(SeekFrom::Start(offset)).unwrap();
        std::io::Read::read_exact(&mut file, &mut byte).unwrap();
        byte[0] ^= 0x5a;
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(&byte).unwrap();
    }
}

#[test]
fn each_class_with_a_committed_verifier_is_registered_with_its_own_policy() {
    let fixture = Fixture::new();
    let mut trust = fixture.trust(Some(keys()));
    let opened = fixture.open(&mut trust);
    let status = opened.service.status();
    for class in POLICY_CLASSES {
        let admission = status
            .classes
            .iter()
            .find(|admission| admission.class == class)
            .unwrap();
        assert_eq!(admission.verifier, ClassVerifier::Local, "{class}");
        assert!(admission.policy, "{class}");
        assert!(!admission.accepts_user_selected, "{class}");
    }
    assert!(status.refused_offers.is_empty());

    // Each policy trusts exactly the keys allowed its class, never a revoked one.
    let catalog = opened.service.catalog();
    let trusted =
        |class: ArtifactClass, seed: u8| catalog.config().trust[&class].trusts(&publisher(seed));
    for (class, own) in [
        (ArtifactClass::OciLayer, OCI),
        (ArtifactClass::GuestImage, GUEST),
        (ArtifactClass::RuntimeUpdate, UPDATE_ROOT),
    ] {
        for seed in [OCI, GUEST, UPDATE_ROOT, ROGUE, REVOKED] {
            assert_eq!(trusted(class, seed), seed == own, "{class} and key {seed}");
        }
    }
    drop(catalog);

    // The engine's existing classes are untouched.
    for class in [
        ArtifactClass::ModelWeights,
        ArtifactClass::ModelSidecar,
        ArtifactClass::ModelHelper,
    ] {
        assert_eq!(*opened.service.verifier(class), ClassVerifier::NotOffered);
    }
    assert!(awaiting_reopen(&opened.service, &trust).is_empty());
    assert!(format!("{:?}", opened.classes).contains("PolicyClasses"));
}

#[test]
fn document_manifests_and_dependency_packages_stay_refused() {
    let fixture = Fixture::new();
    let mut trust = fixture.trust(Some(keys()));
    let opened = fixture.open(&mut trust);
    assert_eq!(
        STILL_REFUSED.map(|refused| (refused.class, refused.owner)),
        [
            (ArtifactClass::DocumentManifest, "O04"),
            (ArtifactClass::DependencyPackage, "O04"),
        ]
    );
    let mut catalog = opened.service.catalog();
    for StillRefused { class, .. } in STILL_REFUSED {
        assert_eq!(*opened.service.verifier(class), ClassVerifier::NotOffered);
        assert!(!POLICY_CLASSES.contains(&class));
        // Whoever signs it, and even when the owner selects it, nothing is admitted.
        for claim in [
            content_signed(OCI, class, b"a package"),
            content_signed(UPDATE_ROOT, class, b"a package"),
            TrustClaim::UserSelected,
        ] {
            assert_eq!(
                trust_refusal(raw_import(
                    &mut catalog,
                    &tenant("a"),
                    class,
                    b"a package",
                    claim
                )),
                TrustRefusal::NoVerifier { class }
            );
        }
        assert_absent(&mut catalog, &tenant("a"), class, b"a package");
    }
}

#[test]
fn without_trust_roots_nothing_is_offered_until_the_catalog_reopens() {
    let fixture = Fixture::new();
    // A configured location with no file yet: no roots are in force.
    let mut trust = fixture.trust(None);
    assert!(trust.shared().is_none());
    assert_eq!(
        PolicyClasses::new(&trust, calendar(), ImportLimits::default()).map(drop),
        Err(PolicyClassesRefusal::NoTrustRoots)
    );
    let service = fixture.service(Vec::new(), &mut trust);
    for class in POLICY_CLASSES {
        assert_eq!(*service.verifier(class), ClassVerifier::NotOffered);
    }
    assert!(awaiting_reopen(&service, &trust).is_empty());
    {
        let mut catalog = service.catalog();
        // Without roots no source reads a publisher, and the class has no policy.
        assert!((roots_policy(ArtifactClass::OciLayer))(&trust) == Default::default());
        assert!(!catalog
            .config()
            .trust
            .contains_key(&ArtifactClass::OciLayer));
        assert_eq!(
            trust_refusal(raw_import(
                &mut catalog,
                &Scope::Host,
                ArtifactClass::GuestImage,
                b"kernel",
                content_signed(GUEST, ArtifactClass::GuestImage, b"kernel"),
            )),
            TrustRefusal::NoVerifier {
                class: ArtifactClass::GuestImage
            }
        );
    }

    // The owner places the file and reloads: the classes wait for a reopen.
    fixture.write_roots(keys());
    assert!(matches!(
        trust.reload(),
        crate::foundation::signing::ReloadOutcome::Applied { .. }
    ));
    assert_eq!(awaiting_reopen(&service, &trust), POLICY_CLASSES.to_vec());
    drop(service);
    let opened = fixture.open(&mut trust);
    for class in POLICY_CLASSES {
        assert_eq!(*opened.service.verifier(class), ClassVerifier::Local);
    }
    assert!(awaiting_reopen(&opened.service, &trust).is_empty());

    // Unenforceable OCI limits are refused, not weakened.
    let limits = ImportLimits {
        extent_bytes: 0,
        ..ImportLimits::default()
    };
    assert!(matches!(
        PolicyClasses::new(&trust, calendar(), limits).map(drop),
        Err(PolicyClassesRefusal::Limits { .. })
    ));
}

#[test]
fn keys_and_statements_never_cross_classes() {
    use super::tests_guest::{release_signed_by, KERNEL};
    use super::tests_oci::{image, publish_request, Registry};
    use super::tests_update::{UpdateRepository, KERNEL_TARGET, RUNTIME};

    let fixture = Fixture::new();
    let mut trust = fixture.trust(Some(keys()));
    let opened = fixture.open(&mut trust);

    // An OCI manifest signed by the guest image key: the OCI policy does not trust it,
    // and V10's port would not accept the key for OCI layers either.
    let fx = image(b"app");
    let mut registry = Registry::serving(&fx);
    let (pin, mut request) = publish_request(&fx, tenant("a"), OCI);
    request.trust = super::tests_oci::signed_trust(&fx, GUEST);
    let refused = import_pinned(
        opened.classes.oci(),
        &mut opened.service.catalog(),
        &mut registry,
        &pin,
        &request,
    )
    .unwrap_err();
    assert!(
        format!("{refused:?}").contains("PublisherNotTrusted"),
        "{refused:?}"
    );
    assert!(opened.service.catalog().objects(&tenant("a")).is_empty());

    // A guest release signed by the OCI key: the key may not sign guest images.
    let (release, files) = release_signed_by(OCI);
    let refused = opened.classes.guest().verify(&release).unwrap_err();
    assert!(
        format!("{refused:?}").contains("ClassNotAllowed"),
        "{refused:?}"
    );

    // A genuine guest release attestation, offered for another class: as an OCI layer it
    // is not V10's attestation, as a runtime update it is not a ticket, and its key is
    // trusted for neither.
    let (release, _) = release_signed_by(GUEST);
    let genuine = release.trust_claim();
    let TrustClaim::Publisher { attestation, .. } = &genuine else {
        unreachable!()
    };
    let mut catalog = opened.service.catalog();
    for (class, scope) in [
        (ArtifactClass::OciLayer, tenant("a")),
        (ArtifactClass::RuntimeUpdate, Scope::Host),
    ] {
        assert_eq!(
            trust_refusal(raw_import(
                &mut catalog,
                &scope,
                class,
                KERNEL,
                genuine.clone()
            )),
            TrustRefusal::PublisherNotTrusted {
                class,
                publisher: publisher(GUEST)
            }
        );
        let own = if class == ArtifactClass::OciLayer {
            OCI
        } else {
            UPDATE_ROOT
        };
        let claim = TrustClaim::Publisher {
            publisher: publisher(own),
            attestation: attestation.clone(),
        };
        assert!(matches!(
            trust_refusal(raw_import(&mut catalog, &scope, class, KERNEL, claim)),
            TrustRefusal::AttestationRejected { publisher: rejected, .. } if rejected == publisher(own)
        ));
        assert_absent(&mut catalog, &scope, class, KERNEL);
    }
    // The same attestation with the guest key admits the kernel as a guest image only.
    assert!(raw_import(
        &mut catalog,
        &Scope::Host,
        ArtifactClass::GuestImage,
        KERNEL,
        genuine
    )
    .is_ok());

    // A plain content signature by each class's own key is no attestation for its class:
    // none of the three admits a bare signature.
    for (class, seed, scope) in [
        (ArtifactClass::OciLayer, OCI, tenant("a")),
        (ArtifactClass::GuestImage, GUEST, Scope::Host),
        (ArtifactClass::RuntimeUpdate, UPDATE_ROOT, Scope::Host),
    ] {
        assert!(matches!(
            trust_refusal(raw_import(
                &mut catalog,
                &scope,
                class,
                RUNTIME,
                content_signed(seed, class, RUNTIME)
            )),
            TrustRefusal::AttestationRejected { .. }
        ));
        assert_absent(&mut catalog, &scope, class, RUNTIME);
    }
    drop(catalog);
    drop(files);

    // A guest kernel the update client verified is a guest image target, never a
    // runtime update.
    let repository = UpdateRepository::new();
    let client = repository.client();
    let kernel = repository.opened(&client, KERNEL_TARGET);
    let refused = opened
        .classes
        .updates()
        .import(
            &mut opened.service.catalog(),
            &client,
            super::tests_update::import_of(&kernel),
            &mut Uninterrupted,
        )
        .unwrap_err();
    assert_eq!(
        refused,
        UpdateImportError::WrongClass {
            class: ArtifactClass::GuestImage
        }
    );
    assert_eq!(opened.classes.updates().pending(), 0);
}

/// The lines proposed for the engine's `catalog_service.rs`
/// (work/engine-catalog_service.diff), run as written against the service: `open` offers
/// the classes when roots are in force; `on_trust_roots_reloaded` adds the classes that
/// wait for a reopen to the service's own report.
#[test]
fn the_proposed_engine_lines_register_the_classes_and_follow_reloads() {
    fn shared_by_the_engine<T: Send + Sync>() {}
    shared_by_the_engine::<PolicyClasses>();

    let fixture = Fixture::new();
    let mut trust = fixture.trust(Some(keys()));
    let calendar: Arc<dyn TrustCalendar> = calendar();
    // `open`, with the engine's own classes left out.
    let trust_ref = &mut trust;
    let policy = PolicyClasses::new(trust_ref, Arc::clone(&calendar), ImportLimits::default()).ok();
    let mut offered = Vec::new();
    offered.extend(policy.iter().flat_map(PolicyClasses::offered));
    let (service, _) = CatalogService::open(
        &fixture.root(),
        config(),
        offered,
        trust_ref,
        fixture.clock.clone(),
        Arc::clone(&calendar),
        Mutex::new,
    )
    .unwrap();
    assert!(policy.is_some());
    for class in POLICY_CLASSES {
        assert_eq!(*service.verifier(class), ClassVerifier::Local);
    }

    // `on_trust_roots_reloaded`, after the owner revokes the guest image key.
    fixture.write_roots(keys_revoking("guest-release"));
    assert!(matches!(
        trust.reload(),
        crate::foundation::signing::ReloadOutcome::Applied { .. }
    ));
    let trust = &trust;
    let mut applied = service.apply_trust_roots(trust);
    applied
        .needs_reopen
        .extend(awaiting_reopen(&service, trust));
    assert_eq!(
        applied
            .classes
            .iter()
            .map(|applied| applied.class)
            .collect::<Vec<_>>(),
        POLICY_CLASSES.to_vec()
    );
    assert!(applied.needs_reopen.is_empty());
    assert!(
        !service.catalog().config().trust[&ArtifactClass::GuestImage].trusts(&publisher(GUEST))
    );
    // The service keeps that report for its status.
    assert_eq!(
        service.status().last_trust.map(|last| last.classes),
        Some(applied.classes)
    );
}

/// The catalog service reads these classes' policies before the catalog opens, so a
/// reopen finds their objects trusted and quarantines none.
#[test]
fn a_reopened_catalog_keeps_the_classes_objects_published() {
    use super::tests_guest::release_signed_by;

    let fixture = Fixture::new();
    let mut trust = fixture.trust(Some(keys()));
    let opened = fixture.open(&mut trust);
    let (release, mut files) = release_signed_by(GUEST);
    let installed = opened
        .classes
        .guest()
        .install(
            &mut opened.service.catalog(),
            GuestInstall {
                operation: operation(),
                execution: execution("guest-installer"),
                release: &release,
            },
            &mut files,
            &mut Uninterrupted,
        )
        .unwrap();
    let mut objects: Vec<ObjectId> = installed.artifacts.values().copied().collect();
    objects.extend([installed.manifest, installed.record]);
    objects.sort();
    drop(opened);

    let reopened = fixture.open(&mut trust);
    assert!(reopened.service.recovery().quarantined.is_empty());
    assert_eq!(reopened.service.recovery().published, objects.len());
    let catalog = reopened.service.catalog();
    for object in objects {
        assert_eq!(
            catalog.status(&Scope::Host, object),
            ObjectStatus::Published
        );
    }
}

/// Every file under `path`, read as text, concatenated.
fn everything_under(path: &Path) -> String {
    let mut text = String::new();
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                text.push_str(&everything_under(&path));
            } else {
                text.push_str(&String::from_utf8_lossy(&fs::read(&path).unwrap()));
            }
        }
    }
    text
}

/// The guest release attestation and the update admission ticket carry no signature of
/// their own: the catalog records the publisher alone, its records, status and failure
/// log never hold either, and the one signature evidence an install keeps is the CORE-08
/// `SignedComponent` over the manifest's own content statement.
#[test]
fn neither_the_attestation_nor_the_ticket_is_recorded_or_shown_as_evidence() {
    use super::tests_guest::release_signed_by;
    use super::tests_update::{import_of, UpdateRepository, RUNTIME_TARGET};
    use crate::sandbox::guest_image::{signing_statement, ArtifactRole, MANIFEST_CLASS};

    let fixture = Fixture::new();
    let mut trust = fixture.trust(Some(keys()));
    let opened = fixture.open(&mut trust);
    let (release, mut files) = release_signed_by(GUEST);
    let installed = opened
        .classes
        .guest()
        .install(
            &mut opened.service.catalog(),
            GuestInstall {
                operation: operation(),
                execution: execution("guest-installer"),
                release: &release,
            },
            &mut files,
            &mut Uninterrupted,
        )
        .unwrap();
    let repository = UpdateRepository::new();
    let client = repository.client();
    let runtime = repository.opened(&client, RUNTIME_TARGET);
    let update = opened
        .classes
        .updates()
        .import(
            &mut opened.service.catalog(),
            &client,
            import_of(&runtime),
            &mut Uninterrupted,
        )
        .unwrap();
    // A forged ticket is refused, so the failure log holds a trust refusal too.
    let forged = serde_json::to_vec(&json!({"format": UPDATE_TICKET_FORMAT, "ticket": 7})).unwrap();
    assert!(raw_import(
        &mut opened.service.catalog(),
        &Scope::Host,
        ArtifactClass::RuntimeUpdate,
        b"forged",
        TrustClaim::Publisher {
            publisher: publisher(UPDATE_ROOT),
            attestation: forged,
        },
    )
    .is_err());

    // The signature evidence names the manifest's content statement, never the container.
    let component = installed.image.component();
    assert!(component.is_verified());
    assert_eq!(component.class(), MANIFEST_CLASS);
    assert_eq!(
        *component.statement(),
        signing_statement(&publisher(GUEST), &release.manifest)
    );

    // The catalog records publishers only.
    let catalog = opened.service.catalog();
    for (object, seed) in [
        (installed.artifacts[&ArtifactRole::Kernel], GUEST),
        (installed.manifest, GUEST),
        (update.object, UPDATE_ROOT),
    ] {
        assert_eq!(
            catalog
                .private_metadata(&Scope::Host, object)
                .unwrap()
                .trust,
            crate::foundation::catalog::TrustBasis::Publisher {
                publisher: publisher(seed)
            }
        );
    }
    let failures = serde_json::to_string(&catalog.failures().collect::<Vec<_>>()).unwrap();
    drop(catalog);
    let status = serde_json::to_string(&opened.service.status()).unwrap();
    let on_disk = everything_under(&fixture.root());
    let signature = hex::encode(release.signature.signature.as_bytes());
    for shown in [&on_disk, &status, &failures] {
        for needle in [GUEST_ATTESTATION_FORMAT, UPDATE_TICKET_FORMAT, &signature] {
            assert!(!shown.contains(needle), "{needle}");
        }
    }
    assert!(failures.contains("attestation_rejected"), "{failures}");
}
