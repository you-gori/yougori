//! Tests for CORE-08 signing: the RFC 8032 vectors, every refusal of a signature, a key
//! and a trust-root file, and the catalog admitting a signed artifact and quarantining it
//! when its key is revoked.

use std::collections::BTreeSet;
use std::fs;
use std::num::NonZeroU64;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};

use super::*;
use crate::foundation::catalog::{
    ArtifactClass, ArtifactVerifier, Catalog, CatalogConfig, ContentDescriptor, ImportManifest,
    ImportRefusal, ImportRequest, ImportSource, ImportStart, ImportStatus, ObjectBytes,
    ObjectMetadata, ObjectRole, ObjectStatus, PublisherId, Scope, SourceError, SourceIdentity,
    TrustClaim, TrustRefusal, Uninterrupted, VerifierRegistry, VerifierRejection,
};
use crate::foundation::ids::{
    ContentKey, Digest, DigestBuilder, ExecutionId, IdError, ManualClock, MonotonicTime,
    OperationId,
};
use crate::foundation::report::Label;

/// RFC 8032 §7.1: TEST 1, TEST 2, TEST 3 and TEST SHA(abc), as (secret key, public key,
/// message, signature).
const RFC_8032: [(&str, &str, &str, &str); 4] = [
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
         5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
         085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac\
         18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
    (
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
         2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589\
         09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
    ),
];

/// The example trust-root file of API.md: RFC 8032 test keys, never release keys.
const EXAMPLE: &str = r#"{
  "format": 1,
  "keys": [
    {
      "id": "runtime-release-2026",
      "algorithm": "ed25519",
      "public_key": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
      "classes": ["runtime_update", "guest_image"],
      "valid_from": "2026-01-01T00:00:00Z",
      "valid_until": "2027-01-01T00:00:00Z"
    },
    {
      "id": "runtime-release-2027",
      "algorithm": "ed25519",
      "public_key": "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
      "classes": ["runtime_update", "guest_image"],
      "valid_from": "2026-12-01T00:00:00Z",
      "valid_until": "2028-01-01T00:00:00Z",
      "replaces": "runtime-release-2026"
    },
    {
      "id": "model-helpers-2026",
      "algorithm": "ed25519",
      "public_key": "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
      "classes": ["model_sidecar"],
      "valid_from": "2026-01-01T00:00:00Z",
      "valid_until": "2027-01-01T00:00:00Z",
      "revoked": { "reason": "key-compromise" }
    }
  ]
}"#;

fn pair(seed: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
}

fn public(seed: u8) -> Ed25519PublicKey {
    Ed25519PublicKey::from_bytes(pair(seed).public_key().as_ref()).unwrap()
}

fn sign(seed: u8, message: &[u8]) -> Vec<u8> {
    pair(seed).sign(message).as_ref().to_vec()
}

fn at(text: &str) -> DateTime<Utc> {
    text.parse().unwrap()
}

fn id(text: &str) -> RootKeyId {
    RootKeyId::new(text).unwrap()
}

/// One listed key, signing `classes`, valid from `from` until `until` (dates of 2026–2028).
fn key(name: &str, seed: u8, classes: &[&str], from: &str, until: &str) -> Value {
    json!({
        "id": name,
        "algorithm": "ed25519",
        "public_key": public(seed).to_hex(),
        "classes": classes,
        "valid_from": format!("{from}T00:00:00Z"),
        "valid_until": format!("{until}T00:00:00Z"),
    })
}

fn document(keys: Vec<Value>) -> String {
    json!({ "format": 1, "keys": keys }).to_string()
}

const UPDATES: &[&str] = &["runtime_update", "guest_image"];

/// Release keys 1 (2026) and 2 (its rotation, from December 2026), a model-weights key 3
/// and a revoked update key 4.
fn standard_keys() -> Vec<Value> {
    let mut rotated = key("release-2027", 2, UPDATES, "2026-12-01", "2028-01-01");
    rotated["replaces"] = json!("release-2026");
    let mut revoked = key(
        "compromised",
        4,
        &["runtime_update"],
        "2026-01-01",
        "2027-01-01",
    );
    revoked["revoked"] = json!({ "reason": "key-compromise" });
    vec![
        key("release-2026", 1, UPDATES, "2026-01-01", "2027-01-01"),
        rotated,
        key("models", 3, &["model_weights"], "2026-01-01", "2027-01-01"),
        revoked,
    ]
}

fn standard_roots() -> TrustRoots {
    TrustRoots::from_json(&document(standard_keys())).unwrap()
}

fn refusal(keys: Vec<Value>) -> TrustRootError {
    TrustRoots::from_json(&document(keys)).unwrap_err()
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

/// The content statement `seed`'s key signs for `content` as `class`.
fn signed_content(seed: u8, class: ArtifactClass, content: &ContentDescriptor) -> Vec<u8> {
    let statement = content_statement(
        &public(seed).publisher_id(),
        class,
        &content.content_key,
        content.length_bytes,
    );
    sign(seed, statement.as_bytes())
}

struct FixedCalendar(Mutex<DateTime<Utc>>);

impl FixedCalendar {
    fn at(text: &str) -> Arc<Self> {
        Arc::new(Self(Mutex::new(at(text))))
    }

    fn set(&self, text: &str) {
        *self.0.lock().unwrap() = at(text);
    }
}

impl TrustCalendar for FixedCalendar {
    fn now(&self) -> DateTime<Utc> {
        *self.0.lock().unwrap()
    }
}

/// A structure check that accepts every object, or refuses every one.
struct Structure {
    accept: bool,
}

impl StructureValidator for Structure {
    fn validate(
        &self,
        _content: &ContentDescriptor,
        _bytes: &mut ObjectBytes,
    ) -> Result<(), VerifierRejection> {
        if self.accept {
            Ok(())
        } else {
            Err(VerifierRejection::WrongFormat {
                detail: "not an update archive".to_owned(),
            })
        }
    }
}

fn verifier(
    class: ArtifactClass,
    binding: StatementBinding,
    roots: &SharedTrustRoots,
    calendar: &Arc<FixedCalendar>,
    accept: bool,
) -> SignedArtifactVerifier {
    SignedArtifactVerifier::new(
        class,
        binding,
        roots.clone(),
        calendar.clone(),
        Box::new(Structure { accept }),
    )
}

// Ed25519 (RFC 8032) and the key checks.

#[test]
fn the_rfc_8032_test_vectors_verify_and_ring_signs_them() {
    for (secret, public_key, message, signature) in RFC_8032 {
        let pair = Ed25519KeyPair::from_seed_unchecked(&hex::decode(secret).unwrap()).unwrap();
        assert_eq!(hex::encode(pair.public_key().as_ref()), public_key);
        let key = hex::decode(public_key).unwrap();
        let message = hex::decode(message).unwrap();
        let signature = hex::decode(signature).unwrap();
        assert_eq!(pair.sign(&message).as_ref(), signature.as_slice());
        assert_eq!(verify_ed25519(&key, &message, &signature), Ok(()));
        let checked = Ed25519PublicKey::from_hex(public_key).unwrap();
        assert_eq!(checked.verify(&message, &signature), Ok(()));
        assert_eq!(checked.to_hex(), public_key);

        // Any flipped bit of the signature, and any change of the message, is refused.
        for index in 0..ED25519_SIGNATURE_BYTES {
            let mut tampered = signature.clone();
            tampered[index] ^= 0x01;
            assert_eq!(
                verify_ed25519(&key, &message, &tampered),
                Err(Ed25519Error::BadSignature),
                "signature byte {index}"
            );
        }
        let mut longer = message.clone();
        longer.push(0);
        assert_eq!(
            verify_ed25519(&key, &longer, &signature),
            Err(Ed25519Error::BadSignature)
        );
        if let Some(first) = message.first() {
            let mut flipped = message.clone();
            flipped[0] = first ^ 0x80;
            assert_eq!(
                verify_ed25519(&key, &flipped, &signature),
                Err(Ed25519Error::BadSignature)
            );
        }
    }
}

#[test]
fn a_tampered_message_is_refused() {
    let message = content_statement(
        &public(1).publisher_id(),
        ArtifactClass::RuntimeUpdate,
        &ContentKey::of(b"update"),
        6,
    );
    let signature = sign(1, message.as_bytes());
    let key = public(1);
    assert_eq!(key.verify(message.as_bytes(), &signature), Ok(()));
    for index in 0..message.as_bytes().len() {
        let mut tampered = *message.as_bytes();
        tampered[index] ^= 0x01;
        assert_eq!(
            key.verify(&tampered, &signature),
            Err(Ed25519Error::BadSignature)
        );
    }
    // The same signature over another content key or length is refused too.
    for (content, length) in [(b"updatf".as_slice(), 6), (b"update".as_slice(), 7)] {
        let other = content_statement(
            &public(1).publisher_id(),
            ArtifactClass::RuntimeUpdate,
            &ContentKey::of(content),
            length,
        );
        assert_eq!(
            key.verify(other.as_bytes(), &signature),
            Err(Ed25519Error::BadSignature)
        );
    }
}

#[test]
fn a_wrong_key_is_refused() {
    let signature = sign(1, b"statement");
    assert_eq!(public(1).verify(b"statement", &signature), Ok(()));
    assert_eq!(
        public(2).verify(b"statement", &signature),
        Err(Ed25519Error::BadSignature)
    );
    assert_eq!(
        verify_ed25519(public(2).as_bytes(), b"statement", &signature),
        Err(Ed25519Error::BadSignature)
    );

    // Through the roots: key 1's signature presented as release-2027's (key 2), and as an
    // unknown publisher's.
    let roots = standard_roots();
    let statement = Digest::from_bytes([7; 32]);
    let by_one = sign(1, statement.as_bytes());
    let now = at("2026-12-15T00:00:00Z");
    let class = ArtifactClass::RuntimeUpdate;
    assert_eq!(
        roots
            .verify_statement(&public(1).publisher_id(), class, &statement, &by_one, now)
            .map(|key| key.id().clone()),
        Ok(id("release-2026"))
    );
    assert_eq!(
        roots.verify_statement(&public(2).publisher_id(), class, &statement, &by_one, now),
        Err(KeyRefusal::Signature {
            key: id("release-2027"),
            error: Ed25519Error::BadSignature
        })
    );
    let stranger = public(9).publisher_id();
    let by_stranger = sign(9, statement.as_bytes());
    assert_eq!(
        roots.verify_statement(&stranger, class, &statement, &by_stranger, now),
        Err(KeyRefusal::UnknownPublisher {
            publisher: stranger
        })
    );
}

#[test]
fn signatures_and_keys_of_the_wrong_length_are_refused() {
    let signature = sign(1, b"m");
    assert_eq!(
        public(1).verify(b"m", &signature[..63]),
        Err(Ed25519Error::SignatureLength { found_bytes: 63 })
    );
    let mut longer = signature.clone();
    longer.push(0);
    assert_eq!(
        public(1).verify(b"m", &longer),
        Err(Ed25519Error::SignatureLength { found_bytes: 65 })
    );
    assert_eq!(
        verify_ed25519(&public(1).as_bytes()[..31], b"m", &signature),
        Err(Ed25519Error::PublicKeyLength { found_bytes: 31 })
    );
    assert_eq!(
        Ed25519PublicKey::from_hex("zz"),
        Err(Ed25519Error::PublicKeyNotHex)
    );
    // The serialized form is the hexadecimal key, read back through the same checks.
    let text = serde_json::to_string(&public(1)).unwrap();
    assert_eq!(text, format!("\"{}\"", public(1).to_hex()));
    assert_eq!(
        serde_json::from_str::<Ed25519PublicKey>(&text).unwrap(),
        public(1)
    );
    assert!(serde_json::from_str::<Ed25519PublicKey>(&format!("\"{}\"", "00".repeat(32))).is_err());
}

#[test]
fn small_order_and_non_canonical_keys_are_refused() {
    // Under the identity point a fixed signature (R = identity, S = 0) verifies for every
    // message when the key is not checked first.
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let mut forged = [0u8; 64];
    forged[0] = 1;
    for message in [b"any statement".as_slice(), b"another one"] {
        assert!(
            ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, identity)
                .verify(message, &forged)
                .is_ok()
        );
        assert_eq!(
            verify_ed25519(&identity, message, &forged),
            Err(Ed25519Error::SmallOrderPublicKey)
        );
    }

    let mut field_prime = [0xffu8; 32];
    field_prime[0] = 0xed;
    field_prime[31] = 0x7f;
    // The two points of order 8 are y and p - y: they sum to p.
    let order_eight = [
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    ]
    .map(|text| hex::decode(text).unwrap());
    let mut carry = 0u16;
    for index in 0..32 {
        let sum = u16::from(order_eight[0][index]) + u16::from(order_eight[1][index]) + carry;
        assert_eq!(sum & 0xff, u16::from(field_prime[index]), "byte {index}");
        carry = sum >> 8;
    }
    let mut p_minus_one = field_prime;
    p_minus_one[0] = 0xec;
    let small = [
        vec![0u8; 32],
        identity.to_vec(),
        order_eight[0].clone(),
        order_eight[1].clone(),
        p_minus_one.to_vec(),
    ];
    for key in small {
        assert_eq!(
            Ed25519PublicKey::from_bytes(&key),
            Err(Ed25519Error::SmallOrderPublicKey)
        );
        let mut negative = key.clone();
        negative[31] |= 0x80;
        assert_eq!(
            Ed25519PublicKey::from_bytes(&negative),
            Err(Ed25519Error::SmallOrderPublicKey)
        );
    }
    let mut p_plus_one = field_prime;
    p_plus_one[0] = 0xee;
    for key in [field_prime, p_plus_one, [0xff; 32]] {
        assert_eq!(
            Ed25519PublicKey::from_bytes(&key),
            Err(Ed25519Error::NonCanonicalPublicKey)
        );
    }
}

#[test]
fn the_fingerprint_and_statements_match_independent_known_answers() {
    // Computed with Python's hashlib from the documented encoding of `ids::digest`.
    let key = Ed25519PublicKey::from_hex(RFC_8032[0].1).unwrap();
    assert_eq!(
        key.fingerprint().to_hex(),
        "b99d5a935641bf24d0293f47fb3773b5038f419ab6f93812326567bc872aab3f"
    );
    assert_eq!(
        key.publisher_id(),
        PublisherId::from_key_fingerprint(key.fingerprint())
    );
    // The sandbox's key identity hashes the same parts under the same domain.
    assert_eq!(
        key.fingerprint(),
        DigestBuilder::new("yougori/sandbox/trust/key/v1")
            .str("ed25519")
            .bytes(key.as_bytes())
            .finish()
    );
    assert_eq!(
        content_statement(
            &key.publisher_id(),
            ArtifactClass::RuntimeUpdate,
            &ContentKey::of(b"artifact"),
            8
        )
        .to_hex(),
        "f509eab5755f06b93b85b79becd5338291887ad9f9556859dff3dfe52d31dbea"
    );
    let manifest = Digest::from_bytes(std::array::from_fn(|index| u8::try_from(index).unwrap()));
    assert_eq!(
        manifest_statement(&key.publisher_id(), ArtifactClass::GuestImage, &manifest).to_hex(),
        "bc13725136429b978f821d76b857a3187bee0bce082e91d07348ddde4fc7c862"
    );
}

// Keys in the roots: windows, revocation, rotation, classes, domains.

#[test]
fn a_key_outside_its_window_is_refused() {
    let roots = standard_roots();
    let publisher = public(1).publisher_id();
    let class = ArtifactClass::RuntimeUpdate;
    let statement = Digest::from_bytes([3; 32]);
    let signature = sign(1, statement.as_bytes());
    let verify = |time: &str| {
        roots
            .verify_statement(&publisher, class, &statement, &signature, at(time))
            .map(|key| key.id().clone())
    };
    assert_eq!(
        verify("2025-12-31T23:59:59Z"),
        Err(KeyRefusal::NotYetValid {
            key: id("release-2026"),
            valid_from: at("2026-01-01T00:00:00Z")
        })
    );
    assert_eq!(verify("2026-01-01T00:00:00Z"), Ok(id("release-2026")));
    assert_eq!(verify("2026-12-31T23:59:59Z"), Ok(id("release-2026")));
    // The end of the window is exclusive.
    assert_eq!(
        verify("2027-01-01T00:00:00Z"),
        Err(KeyRefusal::Expired {
            key: id("release-2026"),
            valid_until: at("2027-01-01T00:00:00Z")
        })
    );
    // A time written with an offset is the same instant.
    assert_eq!(verify("2027-01-01T00:59:59+01:00"), Ok(id("release-2026")));
}

#[test]
fn a_revoked_key_verifies_nothing_and_leaves_the_policy() {
    let roots = standard_roots();
    let revoked = public(4).publisher_id();
    let statement = Digest::from_bytes([5; 32]);
    let signature = sign(4, statement.as_bytes());
    let reason = Label::new("key-compromise").unwrap();
    for time in ["2025-06-01", "2026-06-01", "2027-06-01"] {
        assert_eq!(
            roots.verify_statement(
                &revoked,
                ArtifactClass::RuntimeUpdate,
                &statement,
                &signature,
                at(&format!("{time}T00:00:00Z"))
            ),
            Err(KeyRefusal::Revoked {
                key: id("compromised"),
                reason: reason.clone()
            })
        );
    }
    let key = roots.key(&id("compromised")).unwrap();
    assert!(key.is_revoked());
    assert_eq!(key.revocation().unwrap().reason, reason);
    let policy = roots.policy_for(ArtifactClass::RuntimeUpdate);
    assert!(!policy.trusts(&revoked));
    assert!(policy.trusts(&public(1).publisher_id()));
    assert!(policy.trusts(&public(2).publisher_id()));
    assert!(!policy.trusts(&public(3).publisher_id()));
    assert!(!policy.accepts_user_selected());
    let weights = roots.policy_for(ArtifactClass::ModelWeights);
    assert!(weights.trusts(&public(3).publisher_id()));
    assert!(!weights.trusts(&public(1).publisher_id()));
    // Refusals are serialized for evidence records.
    let refused = KeyRefusal::Revoked {
        key: id("compromised"),
        reason,
    };
    assert_eq!(
        serde_json::to_value(&refused).unwrap(),
        json!({"refusal": "revoked", "key": "compromised", "reason": "key-compromise"})
    );
    assert!(refused.to_string().contains("revoked"));
}

#[test]
fn a_rotation_hands_over_from_the_old_key_to_the_new() {
    let roots = standard_roots();
    let new = roots.key(&id("release-2027")).unwrap();
    assert_eq!(new.replaces(), Some(&id("release-2026")));
    assert_eq!(roots.key(&id("release-2026")).unwrap().replaces(), None);
    let statement = Digest::from_bytes([1; 32]);
    let class = ArtifactClass::GuestImage;
    let verify = |seed: u8, time: &str| {
        roots
            .verify_statement(
                &public(seed).publisher_id(),
                class,
                &statement,
                &sign(seed, statement.as_bytes()),
                at(time),
            )
            .map(|key| key.id().clone())
    };
    assert!(matches!(
        verify(2, "2026-11-30T00:00:00Z"),
        Err(KeyRefusal::NotYetValid { .. })
    ));
    // Both verify during the overlap; afterwards only the new key.
    assert_eq!(verify(1, "2026-12-15T00:00:00Z"), Ok(id("release-2026")));
    assert_eq!(verify(2, "2026-12-15T00:00:00Z"), Ok(id("release-2027")));
    assert!(matches!(
        verify(1, "2027-01-01T00:00:00Z"),
        Err(KeyRefusal::Expired { .. })
    ));
    assert_eq!(verify(2, "2027-06-01T00:00:00Z"), Ok(id("release-2027")));
    // The expired key stays in the policy, so what it admitted keeps its trust.
    assert!(roots.policy_for(class).trusts(&public(1).publisher_id()));
}

#[test]
fn a_key_signs_only_its_classes() {
    let roots = standard_roots();
    let statement = Digest::from_bytes([2; 32]);
    assert_eq!(
        roots
            .verify_statement(
                &public(3).publisher_id(),
                ArtifactClass::GuestImage,
                &statement,
                &sign(3, statement.as_bytes()),
                at("2026-06-01T00:00:00Z"),
            )
            .map(|key| key.id().clone()),
        Err(KeyRefusal::ClassNotAllowed {
            key: id("models"),
            class: ArtifactClass::GuestImage
        })
    );
}

#[test]
fn a_signature_under_another_domain_or_over_raw_bytes_is_refused() {
    let roots = SharedTrustRoots::new(standard_roots());
    let calendar = FixedCalendar::at("2026-06-01T00:00:00Z");
    let class = ArtifactClass::RuntimeUpdate;
    let check = verifier(class, StatementBinding::Content, &roots, &calendar, true);
    let bytes = b"runtime update 1.2.3";
    let content = descriptor(class, bytes);
    let publisher = public(1).publisher_id();
    assert_eq!(
        check.check(&content, &publisher, &signed_content(1, class, &content)),
        Ok(id("release-2026"))
    );

    let bad_signature = || {
        Err(KeyRefusal::Signature {
            key: id("release-2026"),
            error: Ed25519Error::BadSignature,
        })
    };
    // The same fields under another domain.
    let other_domain = DigestBuilder::new("yougori/oci/manifest-statement/v1")
        .digest(&publisher.digest())
        .str(class.tag())
        .digest(content.content_key.digest())
        .u64(content.length_bytes)
        .finish();
    // The manifest statement, signed for a verifier bound to the content statement.
    let manifest = manifest_statement(&publisher, class, &content.manifest_digest);
    for message in [
        other_domain.as_bytes().as_slice(),
        manifest.as_bytes().as_slice(),
        bytes.as_slice(),
        content.content_key.digest().as_bytes().as_slice(),
    ] {
        assert_eq!(
            check.check(&content, &publisher, &sign(1, message)),
            bad_signature()
        );
        assert_eq!(
            check.authenticate(&content, &publisher, &sign(1, message)),
            Err(VerifierRejection::AttestationInvalid)
        );
    }
    // A statement for another class the same key may sign is refused too.
    let for_guest_image = signed_content(1, ArtifactClass::GuestImage, &content);
    assert_eq!(
        check.check(&content, &publisher, &for_guest_image),
        bad_signature()
    );

    // A verifier bound to the manifest accepts the manifest statement only.
    let manifest_check = verifier(class, StatementBinding::Manifest, &roots, &calendar, true);
    assert_eq!(
        manifest_check.check(&content, &publisher, &sign(1, manifest.as_bytes())),
        Ok(id("release-2026"))
    );
    assert_eq!(
        manifest_check.check(&content, &publisher, &signed_content(1, class, &content)),
        bad_signature()
    );
}

#[test]
fn the_verifier_follows_the_calendar_and_the_roots_in_force() {
    let roots = SharedTrustRoots::new(standard_roots());
    let calendar = FixedCalendar::at("2026-06-01T00:00:00Z");
    let class = ArtifactClass::RuntimeUpdate;
    let check = verifier(class, StatementBinding::Content, &roots, &calendar, true);
    assert_eq!(check.class(), class);
    let content = descriptor(class, b"update");
    let new_key = public(5).publisher_id();
    let attestation = signed_content(5, class, &content);
    assert_eq!(
        check.check(&content, &new_key, &attestation),
        Err(KeyRefusal::UnknownPublisher { publisher: new_key })
    );

    // The owner adds a key and reloads: the registered verifier sees it at once.
    let mut keys = standard_keys();
    keys.push(key(
        "hotfix",
        5,
        &["runtime_update"],
        "2026-05-01",
        "2026-07-01",
    ));
    let previous = roots.replace(TrustRoots::from_json(&document(keys)).unwrap());
    assert_eq!(previous.keys().count(), 4);
    assert_eq!(roots.current().keys().count(), 5);
    assert_eq!(
        check.check(&content, &new_key, &attestation),
        Ok(id("hotfix"))
    );
    assert_eq!(check.authenticate(&content, &new_key, &attestation), Ok(()));
    calendar.set("2026-07-01T00:00:00Z");
    assert!(matches!(
        check.check(&content, &new_key, &attestation),
        Err(KeyRefusal::Expired { .. })
    ));
    assert_eq!(
        check.authenticate(&content, &new_key, &attestation),
        Err(VerifierRejection::AttestationInvalid)
    );

    // A descriptor of another class is not this verifier's to authenticate.
    calendar.set("2026-06-01T00:00:00Z");
    let mut other = content.clone();
    other.class = ArtifactClass::GuestImage;
    assert_eq!(
        check.authenticate(&other, &new_key, &attestation),
        Err(VerifierRejection::AttestationInvalid)
    );
}

// The trust-root file.

#[test]
fn the_example_file_loads() {
    let roots = TrustRoots::from_json(EXAMPLE).unwrap();
    let ids: Vec<&str> = roots.keys().map(|key| key.id().as_str()).collect();
    assert_eq!(
        ids,
        [
            "model-helpers-2026",
            "runtime-release-2026",
            "runtime-release-2027"
        ]
    );
    let rotated = roots.key(&id("runtime-release-2027")).unwrap();
    assert_eq!(rotated.algorithm(), KeyAlgorithm::Ed25519);
    assert_eq!(rotated.public_key().to_hex(), RFC_8032[1].1);
    assert_eq!(
        rotated.classes(),
        &BTreeSet::from([ArtifactClass::RuntimeUpdate, ArtifactClass::GuestImage])
    );
    assert_eq!(rotated.valid_from(), at("2026-12-01T00:00:00Z"));
    assert_eq!(rotated.valid_until(), at("2028-01-01T00:00:00Z"));
    assert_eq!(rotated.replaces(), Some(&id("runtime-release-2026")));
    assert!(roots.key(&id("model-helpers-2026")).unwrap().is_revoked());
    assert_eq!(
        roots.key_for(&rotated.publisher_id()).map(TrustedKey::id),
        Some(&id("runtime-release-2027"))
    );
    // RFC 8032 TEST 2's signature verifies under the rotated key's entry.
    let message = hex::decode(RFC_8032[1].2).unwrap();
    let signature = hex::decode(RFC_8032[1].3).unwrap();
    assert_eq!(rotated.public_key().verify(&message, &signature), Ok(()));
}

#[test]
fn the_file_is_read_from_a_path_with_bounds() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("trust-roots.json");
    fs::write(&path, EXAMPLE).unwrap();
    assert_eq!(
        TrustRoots::load(&path).unwrap(),
        TrustRoots::from_json(EXAMPLE).unwrap()
    );
    assert!(matches!(
        TrustRoots::load(&dir.path().join("missing.json")),
        Err(TrustRootError::Unreadable { .. })
    ));
    let large = dir.path().join("large.json");
    let padding = " ".repeat(usize::try_from(MAX_TRUST_ROOTS_BYTES).unwrap());
    fs::write(&large, format!("{padding}{EXAMPLE}")).unwrap();
    assert_eq!(
        TrustRoots::load(&large),
        Err(TrustRootError::TooLarge {
            max_bytes: MAX_TRUST_ROOTS_BYTES
        })
    );
}

#[test]
fn an_empty_or_oversized_set_and_other_formats_are_refused() {
    assert_eq!(refusal(Vec::new()), TrustRootError::NoKeys);
    let one = key("a", 1, UPDATES, "2026-01-01", "2027-01-01");
    assert_eq!(
        refusal(vec![one.clone(); MAX_TRUST_ROOT_KEYS + 1]),
        TrustRootError::TooManyKeys {
            max: MAX_TRUST_ROOT_KEYS
        }
    );
    let mut next = json!({ "format": 2, "keys": [one.clone()] });
    assert_eq!(
        TrustRoots::from_json(&next.to_string()),
        Err(TrustRootError::UnsupportedFormat { found: 2 })
    );
    // Another version is refused for its version, whatever its contents.
    assert_eq!(
        TrustRoots::from_json(&json!({ "format": 0, "roots": "elsewhere" }).to_string()),
        Err(TrustRootError::UnsupportedFormat { found: 0 })
    );
    next["format"] = json!(1);
    next["comment"] = json!("an unknown field");
    for text in [
        next.to_string(),
        json!({ "keys": [one.clone()] }).to_string(),
        "not json".to_owned(),
        json!({ "format": 1, "keys": [one.clone()], "threshold": 1 }).to_string(),
    ] {
        assert!(
            matches!(
                TrustRoots::from_json(&text),
                Err(TrustRootError::Malformed { .. })
            ),
            "{text}"
        );
    }
}

#[test]
fn duplicate_ids_and_keys_are_refused() {
    let a = key("a", 1, UPDATES, "2026-01-01", "2027-01-01");
    assert_eq!(
        refusal(vec![a.clone(), a.clone()]),
        TrustRootError::DuplicateKeyId { id: id("a") }
    );
    let mut same_key = a.clone();
    same_key["id"] = json!("b");
    assert_eq!(
        refusal(vec![a.clone(), same_key]),
        TrustRootError::DuplicatePublicKey {
            id: id("b"),
            same_as: id("a")
        }
    );
    let mut bad_id = a.clone();
    bad_id["id"] = json!("-a");
    assert_eq!(
        refusal(vec![a, bad_id]),
        TrustRootError::InvalidKeyId {
            index: 1,
            error: IdError::InvalidStart
        }
    );
}

#[test]
fn malformed_keys_and_unknown_algorithms_are_refused() {
    let base = key("a", 1, UPDATES, "2026-01-01", "2027-01-01");
    let with = |field: &str, value: Value| {
        let mut changed = base.clone();
        changed[field] = value;
        refusal(vec![changed])
    };
    let malformed = |error| TrustRootError::MalformedPublicKey { id: id("a"), error };
    assert_eq!(
        with("public_key", json!("not hex")),
        malformed(Ed25519Error::PublicKeyNotHex)
    );
    assert_eq!(
        with("public_key", json!(public(1).to_hex()[..62].to_owned())),
        malformed(Ed25519Error::PublicKeyLength { found_bytes: 31 })
    );
    assert_eq!(
        with("public_key", json!(format!("01{}", "00".repeat(31)))),
        malformed(Ed25519Error::SmallOrderPublicKey)
    );
    assert_eq!(
        with("public_key", json!(format!("ed{}7f", "ff".repeat(30)))),
        malformed(Ed25519Error::NonCanonicalPublicKey)
    );
    for algorithm in ["rsa", "ed448", "Ed25519", "hmac_sha256_test", ""] {
        assert_eq!(
            with("algorithm", json!(algorithm)),
            TrustRootError::UnknownAlgorithm { id: id("a") },
            "{algorithm}"
        );
    }
    let mut extra = base.clone();
    extra["threshold"] = json!(2);
    assert!(matches!(
        refusal(vec![extra]),
        TrustRootError::Malformed { .. }
    ));
}

#[test]
fn classes_and_windows_are_checked() {
    let base = key("a", 1, UPDATES, "2026-01-01", "2027-01-01");
    let with = |field: &str, value: Value| {
        let mut changed = base.clone();
        changed[field] = value;
        TrustRoots::from_json(&document(vec![changed]))
    };
    assert_eq!(
        with("classes", json!([])),
        Err(TrustRootError::NoClasses { id: id("a") })
    );
    assert_eq!(
        with("classes", json!(["guest_image", "guest_image"])),
        Err(TrustRootError::DuplicateClass {
            id: id("a"),
            class: ArtifactClass::GuestImage
        })
    );
    assert_eq!(
        with("valid_until", json!("2026-01-01T00:00:00Z")),
        Err(TrustRootError::EmptyValidity { id: id("a") })
    );
    assert_eq!(
        with("valid_until", json!("2025-01-01T00:00:00Z")),
        Err(TrustRootError::EmptyValidity { id: id("a") })
    );
    for (field, value) in [
        ("classes", json!(["firmware"])),
        ("valid_from", json!("2026-01-01")),
        ("valid_until", json!(1767225600)),
        ("revoked", json!({ "reason": "a key leaked" })),
        (
            "revoked",
            json!({ "reason": "leak", "on": "2026-01-01T00:00:00Z" }),
        ),
    ] {
        assert!(
            matches!(with(field, value), Err(TrustRootError::Malformed { .. })),
            "{field}"
        );
    }
    // Missing windows are refused: no key is permanent.
    let mut permanent = base.clone();
    permanent.as_object_mut().unwrap().remove("valid_until");
    assert!(matches!(
        refusal(vec![permanent]),
        TrustRootError::Malformed { .. }
    ));
}

#[test]
fn rotations_must_name_a_listed_key_once_without_cycles_or_gaps() {
    let replacing = |name: &str, seed: u8, replaces: &str, from: &str, until: &str| {
        let mut entry = key(name, seed, UPDATES, from, until);
        entry["replaces"] = json!(replaces);
        entry
    };
    let old = key("old", 1, UPDATES, "2026-01-01", "2027-01-01");
    assert_eq!(
        refusal(vec![
            old.clone(),
            replacing("new", 2, "missing", "2026-12-01", "2028-01-01")
        ]),
        TrustRootError::UnknownPredecessor { id: id("new") }
    );
    assert_eq!(
        refusal(vec![
            old.clone(),
            replacing("new", 2, "not an id", "2026-12-01", "2028-01-01")
        ]),
        TrustRootError::UnknownPredecessor { id: id("new") }
    );
    assert_eq!(
        refusal(vec![
            old.clone(),
            replacing("new-a", 2, "old", "2026-12-01", "2028-01-01"),
            replacing("new-b", 3, "old", "2026-12-01", "2028-01-01"),
        ]),
        TrustRootError::ForkedRotation {
            replaced: id("old"),
            first: id("new-a"),
            second: id("new-b")
        }
    );
    assert_eq!(
        refusal(vec![replacing(
            "self",
            1,
            "self",
            "2026-01-01",
            "2027-01-01"
        )]),
        TrustRootError::RotationCycle { id: id("self") }
    );
    assert_eq!(
        refusal(vec![
            replacing("a", 1, "b", "2026-01-01", "2027-01-01"),
            replacing("b", 2, "a", "2026-12-01", "2028-01-01"),
        ]),
        TrustRootError::RotationCycle { id: id("a") }
    );
    // A gap, a successor starting first, and one ending first are refused.
    for (from, until) in [
        ("2027-01-02", "2028-01-01"),
        ("2026-01-01", "2028-01-01"),
        ("2025-06-01", "2028-01-01"),
        ("2026-06-01", "2026-12-01"),
    ] {
        assert_eq!(
            refusal(vec![old.clone(), replacing("new", 2, "old", from, until)]),
            TrustRootError::RotationWindow {
                id: id("new"),
                replaces: id("old")
            },
            "{from} {until}"
        );
    }
    // Touching windows are continuous, and a chain of rotations is accepted.
    let roots = TrustRoots::from_json(&document(vec![
        old,
        replacing("new", 2, "old", "2027-01-01", "2028-01-01"),
        replacing("newer", 3, "new", "2027-12-01", "2029-01-01"),
    ]))
    .unwrap();
    assert_eq!(
        roots.key(&id("newer")).unwrap().replaces(),
        Some(&id("new"))
    );
    let errors = [
        TrustRootError::RotationCycle { id: id("a") },
        TrustRootError::UnsupportedFormat { found: 2 },
        TrustRootError::MalformedPublicKey {
            id: id("a"),
            error: Ed25519Error::SmallOrderPublicKey,
        },
    ];
    for error in errors {
        assert!(!error.to_string().is_empty());
    }
}

// The catalog, end to end.

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

fn update_request(bytes: &[u8], trust: TrustClaim) -> ImportRequest {
    ImportRequest {
        operation: OperationId::new("op-signed-update").unwrap(),
        execution: ExecutionId::new("exe-1").unwrap(),
        scope: Scope::Host,
        class: ArtifactClass::RuntimeUpdate,
        role: ObjectRole::Original,
        manifest: ImportManifest::describe(bytes, NonZeroU64::new(8).unwrap()),
        trust,
        depends_on: BTreeSet::new(),
        metadata: ObjectMetadata::new(),
    }
}

/// `seed`'s attestation for `bytes` as a runtime update.
fn attestation_for(seed: u8, bytes: &[u8]) -> Vec<u8> {
    let class = ArtifactClass::RuntimeUpdate;
    signed_content(seed, class, &descriptor(class, bytes))
}

fn claim(seed: u8, attestation: Vec<u8>) -> TrustClaim {
    TrustClaim::Publisher {
        publisher: public(seed).publisher_id(),
        attestation,
    }
}

fn signed_by(seed: u8, bytes: &[u8]) -> TrustClaim {
    claim(seed, attestation_for(seed, bytes))
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

fn open_catalog(
    root: &Path,
    roots: &SharedTrustRoots,
    calendar: &Arc<FixedCalendar>,
    accept_structure: bool,
) -> Catalog {
    let class = ArtifactClass::RuntimeUpdate;
    let mut verifiers = VerifierRegistry::new();
    verifiers
        .register(Box::new(verifier(
            class,
            StatementBinding::Content,
            roots,
            calendar,
            accept_structure,
        )))
        .unwrap();
    let config = CatalogConfig::new(Duration::from_secs(60))
        .with_quota(Scope::Host, 1 << 16)
        .with_trust(class, roots.current().policy_for(class));
    let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(1_000_000_000)));
    Catalog::open(root, config, verifiers, clock).unwrap().0
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
fn the_catalog_admits_a_signed_update_and_quarantines_it_when_its_key_is_revoked() {
    let dir = tempfile::tempdir().unwrap();
    let roots = SharedTrustRoots::new(standard_roots());
    let calendar = FixedCalendar::at("2026-06-01T00:00:00Z");
    let mut catalog = open_catalog(dir.path(), &roots, &calendar, true);
    let class = ArtifactClass::RuntimeUpdate;
    let bytes = b"runtime update 1.2.3 for every host".to_vec();
    let refused_for = |status: Result<ImportStart, ImportRefusal>| match status {
        Err(ImportRefusal::Trust { refusal }) => refusal,
        other => panic!("expected a trust refusal, got {other:?}"),
    };

    // A checksum alone, a tampered signature and a signature for other bytes are refused
    // before anything is written.
    let source = MemorySource::new(&bytes).identity();
    assert_eq!(
        refused_for(catalog.begin_import(update_request(&bytes, TrustClaim::ChecksumOnly), source)),
        TrustRefusal::ChecksumIsNotTrust { class }
    );
    let publisher = public(1).publisher_id();
    let mut tampered = attestation_for(1, &bytes);
    tampered[10] ^= 0x01;
    for trust in [
        claim(1, tampered),
        claim(1, attestation_for(1, b"another update")),
    ] {
        assert_eq!(
            refused_for(catalog.begin_import(update_request(&bytes, trust), source)),
            TrustRefusal::AttestationRejected {
                class,
                publisher,
                rejection: VerifierRejection::AttestationInvalid
            }
        );
    }
    // A publisher outside the roots is not trusted by the class policy.
    let stranger = signed_by(9, &bytes);
    assert_eq!(
        refused_for(catalog.begin_import(update_request(&bytes, stranger), source)),
        TrustRefusal::PublisherNotTrusted {
            class,
            publisher: public(9).publisher_id()
        }
    );

    // The real signature is admitted and the object published.
    let object = match drive(
        &mut catalog,
        update_request(&bytes, signed_by(1, &bytes)),
        &bytes,
    ) {
        ImportStatus::Published { object, .. } => object,
        other => panic!("expected publication, got {other:?}"),
    };
    assert_eq!(
        catalog.status(&Scope::Host, object),
        ObjectStatus::Published
    );

    // The owner revokes the key: the reloaded roots withdraw it from the class policy,
    // and the catalog quarantines what it admitted, without deleting it.
    let mut keys = standard_keys();
    keys[0]["revoked"] = json!({ "reason": "key-compromise" });
    roots.replace(TrustRoots::from_json(&document(keys)).unwrap());
    let revision = catalog.set_trust_policy(class, roots.current().policy_for(class));
    assert_eq!(revision.quarantined, vec![object]);
    assert!(matches!(
        catalog.status(&Scope::Host, object),
        ObjectStatus::Quarantined { .. }
    ));
    let again = b"runtime update 1.2.4 for every host".to_vec();
    assert_eq!(
        refused_for(catalog.begin_import(
            update_request(&again, signed_by(1, &again)),
            MemorySource::new(&again).identity()
        )),
        TrustRefusal::PublisherNotTrusted { class, publisher }
    );
    drop(catalog);
    make_tree_writable(dir.path());
}

#[test]
fn the_catalog_runs_the_class_structure_check() {
    let dir = tempfile::tempdir().unwrap();
    let roots = SharedTrustRoots::new(standard_roots());
    let calendar = FixedCalendar::at("2026-06-01T00:00:00Z");
    let mut catalog = open_catalog(dir.path(), &roots, &calendar, false);
    let bytes = b"not an archive".to_vec();
    let status = drive(
        &mut catalog,
        update_request(&bytes, signed_by(1, &bytes)),
        &bytes,
    );
    assert!(
        !matches!(status, ImportStatus::Published { .. }),
        "{status:?}"
    );
    drop(catalog);
    make_tree_writable(dir.path());
}
