//! Tests for the trust-root service: no default, loading and atomic reloads, revocations
//! a reload cannot withdraw, verifiers and policies per class through the catalog's own
//! registration, and the status listing.

use std::collections::BTreeSet;
use std::ffi::OsStr;
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
    ArtifactClass, Catalog, CatalogConfig, ContentDescriptor, ImportManifest, ImportRefusal,
    ImportRequest, ImportSource, ImportStart, ImportStatus, ObjectBytes, ObjectMetadata,
    ObjectRole, ObjectStatus, PublisherId, Scope, SourceError, SourceIdentity, TrustClaim,
    TrustPolicy, TrustRefusal, Uninterrupted, VerifierRegistry, VerifierRejection,
};
use crate::foundation::ids::{ContentKey, ExecutionId, ManualClock, MonotonicTime, OperationId};
use crate::foundation::report::Label;

pub(super) const SETTING: &str = "YOUGORI_TEST_TRUST_ROOTS";
pub(super) const UPDATES: &[&str] = &["runtime_update", "guest_image"];

pub(super) fn pair(seed: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
}

pub(super) fn public(seed: u8) -> Ed25519PublicKey {
    Ed25519PublicKey::from_bytes(pair(seed).public_key().as_ref()).unwrap()
}

pub(super) fn publisher(seed: u8) -> PublisherId {
    public(seed).publisher_id()
}

pub(super) fn sign(seed: u8, message: &[u8]) -> Vec<u8> {
    pair(seed).sign(message).as_ref().to_vec()
}

pub(super) fn at(text: &str) -> DateTime<Utc> {
    text.parse().unwrap()
}

pub(super) fn id(text: &str) -> RootKeyId {
    RootKeyId::new(text).unwrap()
}

/// One listed key, signing `classes`, valid from `from` until `until` (dates).
pub(super) fn key(name: &str, seed: u8, classes: &[&str], from: &str, until: &str) -> Value {
    json!({
        "id": name,
        "algorithm": "ed25519",
        "public_key": public(seed).to_hex(),
        "classes": classes,
        "valid_from": format!("{from}T00:00:00Z"),
        "valid_until": format!("{until}T00:00:00Z"),
    })
}

pub(super) fn revoked(mut listed: Value, reason: &str) -> Value {
    listed["revoked"] = json!({ "reason": reason });
    listed
}

pub(super) fn document(keys: Vec<Value>) -> String {
    json!({ "format": 1, "keys": keys }).to_string()
}

/// Release key 1 (2026) with its rotation key 2 (from December 2026), model-weights key 3
/// and revoked update key 4.
pub(super) fn standard_keys() -> Vec<Value> {
    let mut rotated = key("release-2027", 2, UPDATES, "2026-12-01", "2028-01-01");
    rotated["replaces"] = json!("release-2026");
    vec![
        key("release-2026", 1, UPDATES, "2026-01-01", "2027-01-01"),
        rotated,
        key("models", 3, &["model_weights"], "2026-01-01", "2027-01-01"),
        revoked(
            key(
                "compromised",
                4,
                &["runtime_update"],
                "2026-01-01",
                "2027-01-01",
            ),
            "key-compromise",
        ),
    ]
}

pub(super) struct FixedCalendar(Mutex<DateTime<Utc>>);

impl FixedCalendar {
    pub(super) fn at(text: &str) -> Arc<Self> {
        Arc::new(Self(Mutex::new(at(text))))
    }

    pub(super) fn set(&self, text: &str) {
        *self.0.lock().unwrap() = at(text);
    }
}

impl TrustCalendar for FixedCalendar {
    fn now(&self) -> DateTime<Utc> {
        *self.0.lock().unwrap()
    }
}

/// A trust-root file in a temporary directory, rewritten by each test step.
pub(super) struct RootsFile {
    dir: tempfile::TempDir,
}

impl RootsFile {
    pub(super) fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    pub(super) fn path(&self) -> PathBuf {
        self.dir.path().join("trust-roots.json")
    }

    pub(super) fn write(&self, text: &str) {
        fs::write(self.path(), text).unwrap();
    }

    pub(super) fn location(&self) -> TrustRootLocation {
        TrustRootLocation::from_setting(SETTING, Some(self.path().as_os_str()))
    }

    /// A service over this file, written with `keys` first, at `when`.
    pub(super) fn service(
        &self,
        keys: Vec<Value>,
        when: &str,
    ) -> (TrustRootService, Arc<FixedCalendar>) {
        self.write(&document(keys));
        let calendar = FixedCalendar::at(when);
        let service = TrustRootService::open(self.location(), calendar.clone());
        (service, calendar)
    }
}

fn descriptor(class: ArtifactClass, bytes: &[u8]) -> ContentDescriptor {
    let manifest = ImportManifest::describe(bytes, NonZeroU64::new(8).unwrap());
    ContentDescriptor {
        scope: Scope::Host,
        class,
        content_key: manifest.content_key,
        length_bytes: manifest.true_length_bytes,
        manifest_digest: manifest.digest(),
    }
}

/// `seed`'s attestation for `bytes` as content of `class`.
fn attestation(seed: u8, class: ArtifactClass, bytes: &[u8]) -> Vec<u8> {
    let content = descriptor(class, bytes);
    let statement = content_statement(
        &publisher(seed),
        class,
        &content.content_key,
        content.length_bytes,
    );
    sign(seed, statement.as_bytes())
}

/// A structure check that accepts every object.
struct AcceptAll;

impl StructureValidator for AcceptAll {
    fn validate(
        &self,
        _content: &ContentDescriptor,
        _bytes: &mut ObjectBytes,
    ) -> Result<(), VerifierRejection> {
        Ok(())
    }
}

fn offer(class: ArtifactClass) -> ClassVerification {
    ClassVerification {
        class,
        binding: StatementBinding::Content,
        structure: Box::new(AcceptAll),
    }
}

// No default.

#[test]
fn with_no_location_nothing_is_trusted_and_the_status_says_how_to_configure_it() {
    for value in [None, Some(OsStr::new(""))] {
        let location = TrustRootLocation::from_setting(SETTING, value);
        assert_eq!(
            location,
            TrustRootLocation::NotConfigured { setting: SETTING }
        );
        let calendar = FixedCalendar::at("2026-06-01T00:00:00Z");
        let mut service = TrustRootService::open(location, calendar);
        assert_eq!(service.generation(), None);
        assert!(service.shared().is_none());

        let status = service.status();
        let RootsState::NotConfigured { setting, remedy } = &status.roots else {
            panic!("expected not configured, got {:?}", status.roots);
        };
        assert_eq!(*setting, SETTING);
        assert!(remedy.contains(SETTING), "{remedy}");
        assert!(remedy.contains("no key is built in"), "{remedy}");
        assert_eq!(status.last_refusal, None);
        assert_eq!(status.classes.len(), ArtifactClass::ALL.len());
        assert!(status
            .classes
            .iter()
            .all(|class| class.trust == ClassTrust::NoTrustRoots));

        // Every class refuses, typed; nothing passes silently.
        for class in ArtifactClass::ALL {
            assert_eq!(
                service.policy(class),
                Err(ClassRefusal::NoTrustRoots { class })
            );
            assert_eq!(
                service
                    .verifier(class, StatementBinding::Content, Box::new(AcceptAll))
                    .unwrap_err(),
                ClassRefusal::NoTrustRoots { class }
            );
        }
        let mut registry = VerifierRegistry::new();
        let (config, registration) = service.register(
            vec![offer(ArtifactClass::RuntimeUpdate)],
            &mut registry,
            CatalogConfig::new(Duration::from_secs(60)),
        );
        assert!(registration.registered.is_empty());
        assert_eq!(
            registration.refused,
            vec![ClassRefusal::NoTrustRoots {
                class: ArtifactClass::RuntimeUpdate
            }]
        );
        assert!(!registry.is_registered(ArtifactClass::RuntimeUpdate));
        assert!(config.trust.is_empty());
        let component = service.identify(
            ArtifactClass::RuntimeUpdate,
            &publisher(1),
            content_statement(
                &publisher(1),
                ArtifactClass::RuntimeUpdate,
                &ContentKey::of(b"x"),
                1,
            ),
            &sign(1, b"anything"),
        );
        assert_eq!(
            component.verification(),
            &ComponentVerification::NoTrustRoots {}
        );
        assert!(matches!(
            service.reload(),
            ReloadOutcome::NotConfigured {
                setting: SETTING,
                ..
            }
        ));
    }
}

#[test]
fn a_relative_location_is_refused_rather_than_resolved() {
    let location = TrustRootLocation::from_setting(SETTING, Some(OsStr::new("trust-roots.json")));
    assert_eq!(
        location,
        TrustRootLocation::Invalid {
            setting: SETTING,
            problem: LocationError::NotAbsolute
        }
    );
    let mut service = TrustRootService::open(location, FixedCalendar::at("2026-06-01T00:00:00Z"));
    let status = service.status();
    assert!(
        matches!(
            &status.roots,
            RootsState::InvalidLocation { problem: LocationError::NotAbsolute, remedy, .. }
                if remedy.contains(SETTING)
        ),
        "{:?}",
        status.roots
    );
    assert!(matches!(
        service.reload(),
        ReloadOutcome::InvalidLocation { .. }
    ));
    assert_eq!(
        service.policy(ArtifactClass::RuntimeUpdate),
        Err(ClassRefusal::NoTrustRoots {
            class: ArtifactClass::RuntimeUpdate
        })
    );
}

// Loading and reloading.

#[test]
fn the_configured_file_is_put_in_force_in_the_shared_roots() {
    let file = RootsFile::new();
    let (service, _) = file.service(standard_keys(), "2026-06-01T00:00:00Z");
    assert_eq!(service.generation(), Some(1));
    let shared = service.shared().unwrap();
    assert_eq!(*shared.current(), TrustRoots::load(&file.path()).unwrap());
    let status = service.status();
    assert_eq!(
        status.roots,
        RootsState::Loaded {
            location: file.path().display().to_string(),
            generation: 1,
            keys: 4
        }
    );
    assert_eq!(status.last_refusal, None);
}

#[test]
fn a_missing_or_invalid_file_trusts_nothing_and_says_why() {
    let file = RootsFile::new();
    let calendar = FixedCalendar::at("2026-06-01T00:00:00Z");
    let mut service = TrustRootService::open(file.location(), calendar);
    let status = service.status();
    assert!(
        matches!(&status.roots, RootsState::NotLoaded { location, .. } if *location == file.path().display().to_string()),
        "{:?}",
        status.roots
    );
    assert!(matches!(
        status.last_refusal,
        Some(LoadRefusal::File {
            error: TrustRootError::Unreadable { .. }
        })
    ));
    assert!(status
        .classes
        .iter()
        .all(|class| class.trust == ClassTrust::NoTrustRoots));

    // An empty key set is a refusal, not an empty trust.
    file.write(&document(Vec::new()));
    assert_eq!(
        service.reload(),
        ReloadOutcome::Refused {
            refusal: LoadRefusal::File {
                error: TrustRootError::NoKeys
            },
            kept: None
        }
    );
    assert_eq!(service.generation(), None);

    // Once a valid file is in place, a reload puts it in force.
    file.write(&document(standard_keys()));
    let ReloadOutcome::Applied {
        generation,
        changed,
        needs_reopen,
    } = service.reload()
    else {
        panic!("expected the file in force");
    };
    assert_eq!(generation, 1);
    assert_eq!(
        changed,
        vec![
            ArtifactClass::ModelWeights,
            ArtifactClass::GuestImage,
            ArtifactClass::RuntimeUpdate
        ]
    );
    assert!(needs_reopen.is_empty());
    assert_eq!(service.status().last_refusal, None);
}

#[test]
fn a_refused_reload_keeps_the_roots_in_force_and_reports_why() {
    let file = RootsFile::new();
    let (mut service, _) = file.service(standard_keys(), "2026-06-01T00:00:00Z");
    let class = ArtifactClass::RuntimeUpdate;
    let verifier = service
        .verifier(class, StatementBinding::Content, Box::new(AcceptAll))
        .unwrap();
    let bytes = b"runtime update 1.2.3";
    let content = descriptor(class, bytes);
    let in_force = service.shared().unwrap().current();

    let malformed = "{\"format\": 1, \"keys\": [";
    let unknown_field = json!({ "format": 1, "keys": standard_keys(), "extra": true }).to_string();
    let other_format = json!({ "format": 2, "keys": standard_keys() }).to_string();
    let mut bad_window = standard_keys();
    bad_window[0]["valid_until"] = json!("2025-01-01T00:00:00Z");
    for (text, expected) in [
        (malformed.to_owned(), None),
        (unknown_field, None),
        (
            other_format,
            Some(TrustRootError::UnsupportedFormat { found: 2 }),
        ),
        (
            document(bad_window),
            Some(TrustRootError::EmptyValidity {
                id: id("release-2026"),
            }),
        ),
    ] {
        file.write(&text);
        let ReloadOutcome::Refused { refusal, kept } = service.reload() else {
            panic!("expected a refusal for {text}");
        };
        assert_eq!(kept, Some(1));
        let LoadRefusal::File { error } = &refusal else {
            panic!("expected a file refusal, got {refusal:?}");
        };
        match expected {
            Some(expected) => assert_eq!(error, &expected),
            None => assert!(
                matches!(error, TrustRootError::Malformed { .. }),
                "{error:?}"
            ),
        }
        // The roots in force are untouched, and a verifier given out before still
        // verifies under them.
        assert_eq!(service.generation(), Some(1));
        assert_eq!(service.shared().unwrap().current(), in_force);
        assert_eq!(
            verifier.check(&content, &publisher(1), &attestation(1, class, bytes)),
            Ok(id("release-2026"))
        );
        let status = service.status();
        assert!(matches!(
            status.roots,
            RootsState::Loaded { generation: 1, .. }
        ));
        assert_eq!(status.last_refusal, Some(refusal.clone()));
        // The status says why, located and typed, without quoting the file.
        let shown = serde_json::to_value(&status).unwrap();
        assert_eq!(shown["last_refusal"]["refusal"], "file");
        assert!(shown["last_refusal"]["detail"].as_str().unwrap().len() > 10);
    }
    // A file that disappears is a refusal too, and the roots stay.
    fs::remove_file(file.path()).unwrap();
    assert!(matches!(
        service.reload(),
        ReloadOutcome::Refused {
            refusal: LoadRefusal::File {
                error: TrustRootError::Unreadable { .. }
            },
            kept: Some(1)
        }
    ));

    // A valid file is accepted as the next generation and clears the refusal.
    file.write(&document(standard_keys()));
    assert!(matches!(
        service.reload(),
        ReloadOutcome::Applied { generation: 2, .. }
    ));
    assert_eq!(service.status().last_refusal, None);
}

#[test]
fn a_reload_reaches_every_verifier_at_once() {
    let file = RootsFile::new();
    let (mut service, _) = file.service(standard_keys(), "2026-06-01T00:00:00Z");
    let class = ArtifactClass::RuntimeUpdate;
    let first = service
        .verifier(class, StatementBinding::Content, Box::new(AcceptAll))
        .unwrap();
    let second = service
        .verifier(
            ArtifactClass::GuestImage,
            StatementBinding::Content,
            Box::new(AcceptAll),
        )
        .unwrap();
    let update = b"runtime update";
    let image = b"guest image";
    let update_content = descriptor(class, update);
    let image_content = descriptor(ArtifactClass::GuestImage, image);
    assert!(first
        .check(
            &update_content,
            &publisher(1),
            &attestation(1, class, update)
        )
        .is_ok());

    // The owner revokes release-2026: both verifiers refuse it at once, and the reload
    // names the classes whose policy changed.
    let mut keys = standard_keys();
    keys[0] = revoked(keys[0].clone(), "key-compromise");
    file.write(&document(keys));
    let ReloadOutcome::Applied {
        generation,
        changed,
        ..
    } = service.reload()
    else {
        panic!("expected the revocation in force");
    };
    assert_eq!(generation, 2);
    assert_eq!(
        changed,
        vec![ArtifactClass::GuestImage, ArtifactClass::RuntimeUpdate]
    );
    let revoked_refusal = KeyRefusal::Revoked {
        key: id("release-2026"),
        reason: Label::new("key-compromise").unwrap(),
    };
    assert_eq!(
        first.check(
            &update_content,
            &publisher(1),
            &attestation(1, class, update)
        ),
        Err(revoked_refusal.clone())
    );
    assert_eq!(
        second.check(
            &image_content,
            &publisher(1),
            &attestation(1, ArtifactClass::GuestImage, image)
        ),
        Err(revoked_refusal)
    );
    assert!(!service.policy(class).unwrap().trusts(&publisher(1)));
}

// Emergency revocation.

#[test]
fn a_reload_never_withdraws_a_revocation() {
    let file = RootsFile::new();
    let (mut service, _) = file.service(standard_keys(), "2026-06-01T00:00:00Z");
    let in_force = service.shared().unwrap().current();

    // The revoked key 4 listed again unrevoked, under its own id or another, is refused.
    let mut unrevoked = standard_keys();
    unrevoked[3] = key(
        "compromised",
        4,
        &["runtime_update"],
        "2026-01-01",
        "2027-01-01",
    );
    let mut renamed = standard_keys();
    renamed[3] = key(
        "fresh-name",
        4,
        &["guest_image"],
        "2026-01-01",
        "2027-01-01",
    );
    for (keys, listed_as) in [(unrevoked, "compromised"), (renamed, "fresh-name")] {
        file.write(&document(keys));
        let outcome = service.reload();
        assert_eq!(
            outcome,
            ReloadOutcome::Refused {
                refusal: LoadRefusal::RevocationWithdrawn {
                    key: id(listed_as),
                    publisher: publisher(4),
                    revoked_as: id("compromised"),
                },
                kept: Some(1)
            }
        );
        assert_eq!(service.shared().unwrap().current(), in_force);
        let shown = serde_json::to_value(&outcome).unwrap();
        assert_eq!(shown["refusal"]["refusal"], "revocation_withdrawn");
        assert_eq!(shown["refusal"]["key"], listed_as);
        assert!(shown["refusal"]["detail"]
            .as_str()
            .unwrap()
            .contains("while the engine is stopped"));
    }

    // Dropping the revoked key altogether is accepted: it is trusted no longer either way.
    let mut dropped = standard_keys();
    dropped.pop();
    file.write(&document(dropped.clone()));
    assert!(matches!(
        service.reload(),
        ReloadOutcome::Applied { generation: 2, .. }
    ));
    assert_eq!(
        service.shared().unwrap().current().key_for(&publisher(4)),
        None
    );
    // And it cannot come back unrevoked later either.
    dropped.push(key(
        "compromised",
        4,
        &["runtime_update"],
        "2026-01-01",
        "2027-01-01",
    ));
    file.write(&document(dropped));
    assert!(matches!(
        service.reload(),
        ReloadOutcome::Refused {
            refusal: LoadRefusal::RevocationWithdrawn { .. },
            kept: Some(2)
        }
    ));
    // A newly revoked key is remembered from the reload that revoked it.
    let mut keys = standard_keys();
    keys[2] = revoked(keys[2].clone(), "retired");
    file.write(&document(keys));
    assert!(matches!(
        service.reload(),
        ReloadOutcome::Applied { generation: 3, .. }
    ));
    file.write(&document(standard_keys()));
    assert!(matches!(
        service.reload(),
        ReloadOutcome::Refused {
            refusal: LoadRefusal::RevocationWithdrawn { .. },
            kept: Some(3)
        }
    ));
}

// Per class.

#[test]
fn each_class_with_keys_gets_its_verifier_and_policy_and_every_other_class_refuses() {
    let file = RootsFile::new();
    let (service, _) = file.service(standard_keys(), "2026-06-01T00:00:00Z");
    let roots = service.shared().unwrap().current();
    for class in ArtifactClass::ALL {
        let has_keys = matches!(
            class,
            ArtifactClass::RuntimeUpdate | ArtifactClass::GuestImage | ArtifactClass::ModelWeights
        );
        let verifier = service.verifier(class, StatementBinding::Content, Box::new(AcceptAll));
        if has_keys {
            assert_eq!(service.policy(class), Ok(roots.policy_for(class)));
            assert_eq!(
                crate::foundation::catalog::ArtifactVerifier::class(&verifier.unwrap()),
                class
            );
        } else {
            assert_eq!(service.policy(class), Err(ClassRefusal::NoKeys { class }));
            assert_eq!(verifier.unwrap_err(), ClassRefusal::NoKeys { class });
        }
    }
    // Each class's policy is its own: the model-weights key is not an update publisher.
    let updates = service.policy(ArtifactClass::RuntimeUpdate).unwrap();
    assert!(updates.trusts(&publisher(1)) && updates.trusts(&publisher(2)));
    assert!(!updates.trusts(&publisher(3)));
    assert!(
        !updates.trusts(&publisher(4)),
        "a revoked key is not trusted"
    );
    assert!(service
        .policy(ArtifactClass::ModelWeights)
        .unwrap()
        .trusts(&publisher(3)));

    // A class whose only key is revoked has keys, but its policy trusts nobody.
    let only_revoked = RootsFile::new();
    let (service, _) = only_revoked.service(
        vec![revoked(
            key("helpers", 5, &["model_helper"], "2026-01-01", "2027-01-01"),
            "key-compromise",
        )],
        "2026-06-01T00:00:00Z",
    );
    let policy = service.policy(ArtifactClass::ModelHelper).unwrap();
    assert!(!policy.trusts(&publisher(5)));
    assert_eq!(policy, TrustPolicy::new());
}

struct MemorySource {
    identity: SourceIdentity,
    bytes: Vec<u8>,
}

impl MemorySource {
    fn new(bytes: &[u8]) -> Self {
        Self {
            identity: SourceIdentity::describe("test", &ContentKey::of(bytes).to_string()),
            bytes: bytes.to_vec(),
        }
    }
}

impl ImportSource for MemorySource {
    fn identity(&self) -> SourceIdentity {
        self.identity
    }

    fn length_bytes(&mut self) -> Result<u64, SourceError> {
        Ok(u64::try_from(self.bytes.len()).unwrap())
    }

    fn read_at(&mut self, offset_bytes: u64, buffer: &mut [u8]) -> Result<usize, SourceError> {
        let start = usize::try_from(offset_bytes).unwrap().min(self.bytes.len());
        let available = &self.bytes[start..];
        let count = available.len().min(buffer.len());
        buffer[..count].copy_from_slice(&available[..count]);
        Ok(count)
    }
}

fn request(class: ArtifactClass, bytes: &[u8], trust: TrustClaim) -> ImportRequest {
    ImportRequest {
        operation: OperationId::new(format!("op-{}", class.tag().replace('_', "-"))).unwrap(),
        execution: ExecutionId::new("exe-1").unwrap(),
        scope: Scope::Host,
        class,
        role: ObjectRole::Original,
        manifest: ImportManifest::describe(bytes, NonZeroU64::new(8).unwrap()),
        trust,
        depends_on: BTreeSet::new(),
        metadata: ObjectMetadata::new(),
    }
}

fn signed_by(seed: u8, class: ArtifactClass, bytes: &[u8]) -> TrustClaim {
    TrustClaim::Publisher {
        publisher: publisher(seed),
        attestation: attestation(seed, class, bytes),
    }
}

fn drive(catalog: &mut Catalog, request: ImportRequest, bytes: &[u8]) -> ImportStatus {
    let mut source = MemorySource::new(bytes);
    match catalog.begin_import(request, source.identity()).unwrap() {
        ImportStart::Started(ticket) | ImportStart::Attached(ticket) => catalog
            .drive_import(&ticket, &mut source, &mut Uninterrupted)
            .unwrap(),
        other => panic!("expected a new import, got {other:?}"),
    }
}

/// Committed files are read-only; make them writable so the temporary root goes.
#[allow(clippy::permissions_set_readonly_false)]
fn make_tree_writable(path: &Path) {
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

#[test]
fn registration_goes_through_the_catalog_and_a_reload_quarantines_what_a_revoked_key_admitted() {
    let file = RootsFile::new();
    let (mut service, calendar) = file.service(standard_keys(), "2026-06-01T00:00:00Z");
    let update = ArtifactClass::RuntimeUpdate;
    let helper = ArtifactClass::ModelHelper;

    // A class the registry already has a verifier for is refused, not replaced.
    let mut registry = VerifierRegistry::new();
    registry
        .register(Box::new(
            service
                .verifier(
                    ArtifactClass::GuestImage,
                    StatementBinding::Content,
                    Box::new(AcceptAll),
                )
                .unwrap(),
        ))
        .unwrap();
    let config = CatalogConfig::new(Duration::from_secs(60)).with_quota(Scope::Host, 1 << 16);
    let (config, registration) = service.register(
        vec![
            offer(update),
            offer(helper),
            offer(ArtifactClass::GuestImage),
        ],
        &mut registry,
        config,
    );
    assert_eq!(registration.registered, vec![update]);
    assert_eq!(
        registration.refused,
        vec![
            ClassRefusal::NoKeys { class: helper },
            ClassRefusal::AlreadyRegistered {
                class: ArtifactClass::GuestImage
            }
        ]
    );
    assert!(registry.is_registered(update));
    assert!(!registry.is_registered(helper));
    assert_eq!(
        config.trust.get(&update),
        Some(&service.policy(update).unwrap())
    );
    assert!(!config.trust.contains_key(&helper));

    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(1_000_000_000)));
    let mut catalog = Catalog::open(dir.path(), config, registry, clock)
        .unwrap()
        .0;

    // A signed update is admitted; a helper is refused, typed, for want of a verifier.
    let bytes = b"runtime update 1.2.3 for every host".to_vec();
    let object = match drive(
        &mut catalog,
        request(update, &bytes, signed_by(1, update, &bytes)),
        &bytes,
    ) {
        ImportStatus::Published { object, .. } => object,
        other => panic!("expected publication, got {other:?}"),
    };
    let helper_bytes = b"helper bundle".to_vec();
    assert_eq!(
        catalog
            .begin_import(
                request(helper, &helper_bytes, signed_by(1, helper, &helper_bytes)),
                MemorySource::new(&helper_bytes).identity()
            )
            .unwrap_err(),
        ImportRefusal::Trust {
            refusal: TrustRefusal::NoVerifier { class: helper }
        }
    );

    // The owner revokes release-2026 and adds a helper key: the reload names the update
    // class as changed and the helper class as needing the catalog reopened, and setting
    // the policies quarantines the update, without deleting it.
    let mut keys = standard_keys();
    keys[0] = revoked(keys[0].clone(), "key-compromise");
    keys.push(key(
        "helpers",
        5,
        &["model_helper"],
        "2026-01-01",
        "2027-01-01",
    ));
    file.write(&document(keys));
    let ReloadOutcome::Applied {
        changed,
        needs_reopen,
        ..
    } = service.reload()
    else {
        panic!("expected the new roots in force");
    };
    assert!(changed.contains(&update) && changed.contains(&helper));
    assert_eq!(needs_reopen, vec![helper]);
    let applied = service.apply_policies(&mut catalog);
    assert_eq!(
        applied,
        vec![PolicyApplied {
            class: update,
            quarantined: vec![object],
            restored: Vec::new(),
        }]
    );
    assert!(matches!(
        catalog.status(&Scope::Host, object),
        ObjectStatus::Quarantined { .. }
    ));
    let again = b"runtime update 1.2.4 for every host".to_vec();
    assert_eq!(
        catalog
            .begin_import(
                request(update, &again, signed_by(1, update, &again)),
                MemorySource::new(&again).identity()
            )
            .unwrap_err(),
        ImportRefusal::Trust {
            refusal: TrustRefusal::PublisherNotTrusted {
                class: update,
                publisher: publisher(1)
            }
        }
    );
    // The rotation key admits updates once its window opens.
    calendar.set("2026-12-15T00:00:00Z");
    let rotated = b"runtime update 1.3.0 for every host".to_vec();
    assert!(matches!(
        drive(
            &mut catalog,
            request(update, &rotated, signed_by(2, update, &rotated)),
            &rotated
        ),
        ImportStatus::Published { .. }
    ));
    drop(catalog);
    make_tree_writable(dir.path());
}

// Status.

#[test]
fn the_status_lists_every_class_with_its_keys_their_validity_and_revocations() {
    let file = RootsFile::new();
    let mut keys = standard_keys();
    keys.push(key(
        "old-images",
        6,
        &["guest_image"],
        "2025-01-01",
        "2026-01-01",
    ));
    let (mut service, calendar) = file.service(keys, "2026-06-01T00:00:00Z");
    let mut registry = VerifierRegistry::new();
    let _ = service.register(
        vec![offer(ArtifactClass::RuntimeUpdate)],
        &mut registry,
        CatalogConfig::new(Duration::from_secs(60)),
    );
    let status = service.status();
    assert_eq!(status.checked_at, at("2026-06-01T00:00:00Z"));
    assert_eq!(
        status
            .classes
            .iter()
            .map(|class| class.class)
            .collect::<Vec<_>>(),
        ArtifactClass::ALL.to_vec()
    );
    let trust_of = |status: &TrustRootStatus, class: ArtifactClass| {
        status
            .classes
            .iter()
            .find(|entry| entry.class == class)
            .unwrap()
            .trust
            .clone()
    };
    assert_eq!(
        trust_of(&status, ArtifactClass::ModelHelper),
        ClassTrust::NoKeys
    );
    let ClassTrust::Keys {
        usable_now,
        verifier_registered,
        keys,
    } = trust_of(&status, ArtifactClass::RuntimeUpdate)
    else {
        panic!("expected update keys");
    };
    assert!(verifier_registered);
    assert_eq!(usable_now, 1);
    let states: Vec<(&str, KeyState)> = keys
        .iter()
        .map(|key| (key.id.as_str(), key.state.clone()))
        .collect();
    assert_eq!(
        states,
        vec![
            (
                "compromised",
                KeyState::Revoked {
                    reason: Label::new("key-compromise").unwrap()
                }
            ),
            ("release-2026", KeyState::Valid),
            ("release-2027", KeyState::NotYetValid),
        ]
    );
    let release = &keys[1];
    assert_eq!(release.publisher, publisher(1));
    assert_eq!(release.algorithm, KeyAlgorithm::Ed25519);
    assert_eq!(release.valid_from, at("2026-01-01T00:00:00Z"));
    assert_eq!(release.valid_until, at("2027-01-01T00:00:00Z"));
    assert_eq!(release.replaces, None);
    assert_eq!(release.replaced_by, Some(id("release-2027")));
    assert_eq!(keys[2].replaces, Some(id("release-2026")));
    let ClassTrust::Keys {
        usable_now,
        verifier_registered,
        keys,
    } = trust_of(&status, ArtifactClass::GuestImage)
    else {
        panic!("expected image keys");
    };
    assert!(!verifier_registered);
    assert_eq!(usable_now, 1);
    assert_eq!(keys[0].id, id("old-images"));
    assert_eq!(keys[0].state, KeyState::Expired);

    // During the rotation overlap both release keys vouch; after it, only the new one.
    calendar.set("2026-12-15T00:00:00Z");
    let ClassTrust::Keys { usable_now, .. } =
        trust_of(&service.status(), ArtifactClass::RuntimeUpdate)
    else {
        panic!("expected update keys");
    };
    assert_eq!(usable_now, 2);
    calendar.set("2027-02-01T00:00:00Z");
    let ClassTrust::Keys {
        usable_now, keys, ..
    } = trust_of(&service.status(), ArtifactClass::RuntimeUpdate)
    else {
        panic!("expected update keys");
    };
    assert_eq!(usable_now, 1);
    assert_eq!(keys[1].state, KeyState::Expired);

    // The serialized status is tagged, and lists the remedy-free loaded state.
    let shown = serde_json::to_value(service.status()).unwrap();
    assert_eq!(shown["roots"]["state"], "loaded");
    assert_eq!(shown["roots"]["generation"], 1);
    assert_eq!(shown["last_refusal"], Value::Null);
    let update = &shown["classes"][5];
    assert_eq!(update["class"], "runtime_update");
    assert_eq!(update["trust"]["trust"], "keys");
    assert_eq!(update["trust"]["keys"][0]["state"], "revoked");
    assert_eq!(update["trust"]["keys"][0]["reason"], "key-compromise");
    assert_eq!(update["trust"]["keys"][2]["state"], "valid");
    assert_eq!(shown["classes"][7]["trust"]["trust"], "no_keys");
}
