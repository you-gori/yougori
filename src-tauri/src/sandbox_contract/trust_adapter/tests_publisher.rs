//! The OCI importer's publisher-signature port over the trust roots: Ed25519 signatures
//! made in the test with `ring` (fixed seeds) over the importer's own manifest statement
//! (VM-W48, line 2671: "wrong signatures ... provenance failures cannot execute content").

use std::sync::{Arc, Mutex};

use chrono::{DateTime, SecondsFormat, Utc};
use ring::signature::{Ed25519KeyPair, KeyPair};

use super::*;
use crate::foundation::catalog::{ArtifactClass, PublisherId};
use crate::foundation::signing::{
    Ed25519Error, Ed25519PublicKey, KeyRefusal, RootKeyId, SharedTrustRoots, TrustCalendar,
    TrustRoots,
};
use crate::sandbox::trust::{PublicKey, SchemeKind};
use crate::sandbox_contract::oci::{
    manifest_statement, ImportLimits, OciDigest, OciVerifier, PublisherSignatures, SignatureRefusal,
};

const NOW: i64 = 1_700_000_000;
const DAY: i64 = 86_400;
const MANIFEST: &[u8] =
    br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}"#;

/// A calendar the test sets.
struct TestCalendar(Mutex<DateTime<Utc>>);

impl TestCalendar {
    fn at(seconds: i64) -> Arc<Self> {
        Arc::new(Self(Mutex::new(time(seconds))))
    }

    fn set(&self, seconds: i64) {
        *self.0.lock().unwrap() = time(seconds);
    }
}

impl TrustCalendar for TestCalendar {
    fn now(&self) -> DateTime<Utc> {
        *self.0.lock().unwrap()
    }
}

fn time(seconds: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(seconds, 0).unwrap()
}

fn pair(seed: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
}

fn publisher(pair: &Ed25519KeyPair) -> PublisherId {
    Ed25519PublicKey::from_bytes(pair.public_key().as_ref())
        .unwrap()
        .publisher_id()
}

/// One key of the trust-root file, in the foundation's format 1.
fn entry(
    id: &str,
    pair: &Ed25519KeyPair,
    classes: &[&str],
    valid: (i64, i64),
    revoked: bool,
) -> serde_json::Value {
    let mut key = serde_json::json!({
        "id": id,
        "algorithm": "ed25519",
        "public_key": hex::encode(pair.public_key().as_ref()),
        "classes": classes,
        "valid_from": time(valid.0).to_rfc3339_opts(SecondsFormat::Secs, true),
        "valid_until": time(valid.1).to_rfc3339_opts(SecondsFormat::Secs, true),
    });
    if revoked {
        key["revoked"] = serde_json::json!({"reason": "key-compromise"});
    }
    key
}

fn roots(entries: Vec<serde_json::Value>) -> TrustRoots {
    TrustRoots::from_json(&serde_json::json!({"format": 1, "keys": entries}).to_string()).unwrap()
}

const WINDOW: (i64, i64) = (NOW - DAY, NOW + 30 * DAY);

/// The OCI publisher (seed 81), a runtime-update key (82), a revoked OCI key (83) and an
/// OCI key whose window starts tomorrow (85). Seed 84 is in no file.
fn trust_roots() -> TrustRoots {
    roots(vec![
        entry("oci-publisher", &pair(81), &["oci_layer"], WINDOW, false),
        entry(
            "runtime-only",
            &pair(82),
            &["runtime_update"],
            WINDOW,
            false,
        ),
        entry("oci-revoked", &pair(83), &["oci_layer"], WINDOW, true),
        entry(
            "oci-next",
            &pair(85),
            &["oci_layer"],
            (NOW + DAY, NOW + 60 * DAY),
            false,
        ),
    ])
}

fn statement(manifest: &[u8]) -> crate::foundation::ids::Digest {
    manifest_statement(&OciDigest::of(manifest))
}

fn sign(pair: &Ed25519KeyPair, manifest: &[u8]) -> Vec<u8> {
    pair.sign(statement(manifest).as_bytes()).as_ref().to_vec()
}

fn signatures(calendar: Arc<TestCalendar>) -> (SharedTrustRoots, TrustRootSignatures) {
    let shared = SharedTrustRoots::new(trust_roots());
    let signatures = TrustRootSignatures::new(shared.clone(), calendar);
    (shared, signatures)
}

#[test]
fn a_publisher_signature_over_the_manifest_statement_verifies() {
    let (_, signatures) = signatures(TestCalendar::at(NOW));
    let publisher = publisher(&pair(81));
    let signature = sign(&pair(81), MANIFEST);
    assert_eq!(
        signatures.verify(&publisher, &statement(MANIFEST), &signature),
        Ok(())
    );
    assert_eq!(
        signatures.check(&publisher, &statement(MANIFEST), &signature),
        Ok(RootKeyId::new("oci-publisher").unwrap())
    );
    // The catalog's publisher identity is the trust client's for the same key.
    assert_eq!(
        publisher,
        PublicKey::new(SchemeKind::Ed25519, pair(81).public_key().as_ref().to_vec()).publisher_id()
    );
    // It is the importer's port, and its verifier takes it.
    let port: Arc<dyn PublisherSignatures> = Arc::new(signatures.clone());
    assert_eq!(
        port.verify(&publisher, &statement(MANIFEST), &signature),
        Ok(())
    );
    assert!(OciVerifier::new(port, ImportLimits::default()).is_ok());
    assert!(format!("{signatures:?}").contains("keys: 4"));
}

#[test]
fn wrong_signatures_are_bad_signatures() {
    let (_, signatures) = signatures(TestCalendar::at(NOW));
    let publisher = publisher(&pair(81));
    let genuine = sign(&pair(81), MANIFEST);
    let key = RootKeyId::new("oci-publisher").unwrap();

    let mut flipped = genuine.clone();
    flipped[7] ^= 0x10;
    let other_manifest = sign(&pair(81), b"{\"another\":\"manifest\"}");
    let other_key = sign(&pair(84), MANIFEST);
    let raw_digest = pair(81)
        .sign(OciDigest::of(MANIFEST).as_bytes())
        .as_ref()
        .to_vec();
    for signature in [&flipped, &other_manifest, &other_key, &raw_digest] {
        assert_eq!(
            signatures.verify(&publisher, &statement(MANIFEST), signature),
            Err(SignatureRefusal::BadSignature)
        );
        assert_eq!(
            signatures.check(&publisher, &statement(MANIFEST), signature),
            Err(KeyRefusal::Signature {
                key: key.clone(),
                error: Ed25519Error::BadSignature,
            })
        );
    }
    assert_eq!(
        signatures.verify(&publisher, &statement(MANIFEST), &genuine[..63]),
        Err(SignatureRefusal::BadSignature)
    );
    assert_eq!(
        signatures.check(&publisher, &statement(MANIFEST), &genuine[..63]),
        Err(KeyRefusal::Signature {
            key,
            error: Ed25519Error::SignatureLength { found_bytes: 63 },
        })
    );
}

#[test]
fn keys_that_may_not_vouch_for_oci_layers_now_are_unknown_publishers() {
    let calendar = TestCalendar::at(NOW);
    let (_, signatures) = signatures(calendar.clone());
    let refused = |seed: u8| {
        let signature = sign(&pair(seed), MANIFEST);
        let publisher = publisher(&pair(seed));
        (
            signatures.verify(&publisher, &statement(MANIFEST), &signature),
            signatures.check(&publisher, &statement(MANIFEST), &signature),
        )
    };

    // A key in no trust-root file.
    let (verdict, reason) = refused(84);
    assert_eq!(verdict, Err(SignatureRefusal::UnknownPublisher));
    assert!(matches!(reason, Err(KeyRefusal::UnknownPublisher { .. })));
    // A key for another artifact class: classes keep distinct policies.
    let (verdict, reason) = refused(82);
    assert_eq!(verdict, Err(SignatureRefusal::UnknownPublisher));
    assert!(matches!(
        reason,
        Err(KeyRefusal::ClassNotAllowed {
            class: ArtifactClass::OciLayer,
            ..
        })
    ));
    // A revoked key, whatever its window.
    let (verdict, reason) = refused(83);
    assert_eq!(verdict, Err(SignatureRefusal::UnknownPublisher));
    assert!(matches!(reason, Err(KeyRefusal::Revoked { .. })));
    // A key before its window opens, then inside it, then after it closes.
    let (verdict, reason) = refused(85);
    assert_eq!(verdict, Err(SignatureRefusal::UnknownPublisher));
    assert!(matches!(reason, Err(KeyRefusal::NotYetValid { .. })));
    calendar.set(NOW + DAY);
    assert_eq!(refused(85).0, Ok(()));
    calendar.set(NOW + 60 * DAY);
    let (verdict, reason) = refused(85);
    assert_eq!(verdict, Err(SignatureRefusal::UnknownPublisher));
    assert!(matches!(reason, Err(KeyRefusal::Expired { .. })));
    // The publisher's own window closed too, so its genuine signature stops verifying.
    assert_eq!(refused(81).0, Err(SignatureRefusal::UnknownPublisher));
}

#[test]
fn a_reloaded_trust_root_file_applies_to_the_next_check() {
    let (shared, signatures) = signatures(TestCalendar::at(NOW));
    let copy = signatures.clone();
    let publisher = publisher(&pair(81));
    let signature = sign(&pair(81), MANIFEST);
    assert_eq!(
        copy.verify(&publisher, &statement(MANIFEST), &signature),
        Ok(())
    );
    // The owner revokes the publisher's key in the file and reloads it.
    shared.replace(roots(vec![entry(
        "oci-publisher",
        &pair(81),
        &["oci_layer"],
        WINDOW,
        true,
    )]));
    for port in [&signatures, &copy] {
        assert_eq!(
            port.verify(&publisher, &statement(MANIFEST), &signature),
            Err(SignatureRefusal::UnknownPublisher)
        );
        assert!(matches!(
            port.check(&publisher, &statement(MANIFEST), &signature),
            Err(KeyRefusal::Revoked { .. })
        ));
    }
}
