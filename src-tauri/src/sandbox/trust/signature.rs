//! Signature verification behind a port (VM-W45, line 2493; S2 CORE-08, line 45:
//! "signed component identity ... an unauthenticated checksum is not a release trust
//! root").
//!
//! The update client never verifies a signature itself: it asks a [`SignatureScheme`]
//! registered for the key's [`SchemeKind`]. A key whose scheme is not registered is an
//! explicit refusal, never a key that silently fails or passes. The engine's Ed25519
//! adapter is wired by the lead over the existing `ring` dependency (§19, line 3042);
//! until then the only scheme here is [`HmacSha256TestScheme`], which is not production
//! grade and which the production profile refuses.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::foundation::catalog::PublisherId;
use crate::foundation::ids::{Digest, DigestBuilder};
use crate::foundation::transfer::{hmac_sha256, tags_equal, HMAC_SHA256_TAG_BYTES};

/// Domain of [`KeyId`].
pub const KEY_DOMAIN: &str = "yougori/sandbox/trust/key/v1";

/// A signature scheme a key belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemeKind {
    /// Ed25519 (RFC 8032); the production scheme, verified by an adapter over `ring`.
    Ed25519,
    /// HMAC-SHA256 with the "public" key as the shared secret: whoever can verify can
    /// also forge, so it is a test scheme only and never production grade.
    HmacSha256Test,
}

impl SchemeKind {
    pub const ALL: [Self; 2] = [Self::Ed25519, Self::HmacSha256Test];

    /// The stable tag hashed into key identities.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::HmacSha256Test => "hmac-sha256-test",
        }
    }

    /// Whether the production assurance profile accepts keys of this scheme (line 2282:
    /// unsigned or test-signed builds are outside the production profile).
    pub const fn production_grade(self) -> bool {
        matches!(self, Self::Ed25519)
    }
}

impl fmt::Display for SchemeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.tag())
    }
}

/// Bytes written as lowercase hexadecimal in JSON.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HexBytes(Vec<u8>);

impl HexBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for HexBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HexBytes({})", hex::encode(&self.0))
    }
}

impl Serialize for HexBytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for HexBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        hex::decode(text)
            .map(Self)
            .map_err(|_| serde::de::Error::custom("bytes must be hexadecimal"))
    }
}

/// The identity of one key: the digest of its scheme and material. It is also the
/// publisher identity the catalog knows the key by ([`PublicKey::publisher_id`]).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyId(Digest);

impl KeyId {
    pub const fn digest(self) -> Digest {
        self.0
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyId({})", self.0.to_hex())
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.to_hex())
    }
}

/// A verification key as root metadata lists it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicKey {
    pub scheme: SchemeKind,
    pub material: HexBytes,
}

impl PublicKey {
    pub fn new(scheme: SchemeKind, material: Vec<u8>) -> Self {
        Self {
            scheme,
            material: HexBytes::new(material),
        }
    }

    /// The key's identity, recomputed from its scheme and material so a listed id that
    /// does not match is caught.
    pub fn key_id(&self) -> KeyId {
        KeyId(
            DigestBuilder::new(KEY_DOMAIN)
                .str(self.scheme.tag())
                .bytes(self.material.as_bytes())
                .finish(),
        )
    }

    /// The catalog's publisher identity for this key (S2 CORE-08 "signed component
    /// identity"): the same fingerprint, so one key is one publisher everywhere.
    pub fn publisher_id(&self) -> PublisherId {
        PublisherId::from_key_fingerprint(self.key_id().digest())
    }
}

/// One signature over a metadata file, by the key it names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    pub key_id: KeyId,
    pub signature: HexBytes,
}

/// Why one signature was not accepted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "rejection", rename_all = "snake_case")]
pub enum SignatureRejection {
    /// No scheme is registered for the key's kind; an explicit refusal, not a pass.
    SchemeUnavailable { scheme: SchemeKind },
    WrongLength {
        expected_bytes: usize,
        found_bytes: usize,
    },
    /// The signature does not verify under the key.
    Invalid,
}

impl fmt::Display for SignatureRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SchemeUnavailable { scheme } => {
                write!(f, "no verifier is registered for the {scheme} scheme")
            }
            Self::WrongLength {
                expected_bytes,
                found_bytes,
            } => write!(
                f,
                "the signature is {found_bytes} bytes, not {expected_bytes}"
            ),
            Self::Invalid => f.write_str("the signature does not verify under the key"),
        }
    }
}

impl std::error::Error for SignatureRejection {}

/// The port: verifies signatures of one scheme. Adapters over real libraries implement
/// it; the registry refuses a scheme nobody implements.
pub trait SignatureScheme: Send + Sync {
    /// The one scheme this verifier handles.
    fn kind(&self) -> SchemeKind;

    /// Whether `signature` is `public_key`'s signature over `message`.
    fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), SignatureRejection>;
}

/// A second verifier was offered for a scheme.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DuplicateScheme {
    pub scheme: SchemeKind,
}

impl fmt::Display for DuplicateScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a verifier for {} is already registered", self.scheme)
    }
}

impl std::error::Error for DuplicateScheme {}

/// At most one verifier per scheme; a scheme with none is refused explicitly.
#[derive(Default)]
pub struct SchemeRegistry {
    schemes: BTreeMap<SchemeKind, Box<dyn SignatureScheme>>,
}

impl SchemeRegistry {
    /// An empty registry: every key is refused until its scheme is registered.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, scheme: Box<dyn SignatureScheme>) -> Result<(), DuplicateScheme> {
        let kind = scheme.kind();
        if self.schemes.contains_key(&kind) {
            return Err(DuplicateScheme { scheme: kind });
        }
        self.schemes.insert(kind, scheme);
        Ok(())
    }

    pub fn is_registered(&self, scheme: SchemeKind) -> bool {
        self.schemes.contains_key(&scheme)
    }

    /// Verifies `signature` as `key`'s signature over `message` with the key's scheme.
    pub fn verify(
        &self,
        key: &PublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), SignatureRejection> {
        let scheme = self
            .schemes
            .get(&key.scheme)
            .filter(|scheme| scheme.kind() == key.scheme)
            .ok_or(SignatureRejection::SchemeUnavailable { scheme: key.scheme })?;
        scheme.verify(key.material.as_bytes(), message, signature)
    }
}

impl fmt::Debug for SchemeRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.schemes.keys()).finish()
    }
}

/// HMAC-SHA256 as a signature scheme for tests, over the shared construction in
/// `foundation::transfer`. The key material is the shared secret, so a verifier can
/// forge: [`SchemeKind::HmacSha256Test`] is never production grade.
#[derive(Clone, Copy, Debug, Default)]
pub struct HmacSha256TestScheme;

impl HmacSha256TestScheme {
    /// The signature of `message` under `secret`.
    pub fn sign(secret: &[u8], message: &[u8]) -> Vec<u8> {
        hmac_sha256(secret, message).to_vec()
    }
}

impl SignatureScheme for HmacSha256TestScheme {
    fn kind(&self) -> SchemeKind {
        SchemeKind::HmacSha256Test
    }

    fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), SignatureRejection> {
        let offered: [u8; HMAC_SHA256_TAG_BYTES] =
            signature
                .try_into()
                .map_err(|_| SignatureRejection::WrongLength {
                    expected_bytes: HMAC_SHA256_TAG_BYTES,
                    found_bytes: signature.len(),
                })?;
        let expected = hmac_sha256(public_key, message);
        if tags_equal(&expected, &offered) {
            Ok(())
        } else {
            Err(SignatureRejection::Invalid)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key(secret: &[u8]) -> PublicKey {
        PublicKey::new(SchemeKind::HmacSha256Test, secret.to_vec())
    }

    #[test]
    fn hex_bytes_round_trip_and_refuse_non_hex() {
        let bytes = HexBytes::new(vec![0x00, 0xab, 0xff]);
        let json = serde_json::to_string(&bytes).unwrap();
        assert_eq!(json, "\"00abff\"");
        assert_eq!(serde_json::from_str::<HexBytes>(&json).unwrap(), bytes);
        assert!(serde_json::from_str::<HexBytes>("\"zz\"").is_err());
        assert_eq!(format!("{bytes:?}"), "HexBytes(00abff)");
    }

    #[test]
    fn key_ids_bind_scheme_and_material() {
        let a = test_key(b"secret");
        let b = PublicKey::new(SchemeKind::Ed25519, b"secret".to_vec());
        assert_ne!(a.key_id(), b.key_id());
        assert_eq!(a.key_id(), test_key(b"secret").key_id());
        assert_eq!(
            a.publisher_id(),
            PublisherId::from_key_fingerprint(a.key_id().digest())
        );
        let json = serde_json::to_value(&a).unwrap();
        assert_eq!(json["scheme"], "hmac_sha256_test");
        assert_eq!(serde_json::from_value::<PublicKey>(json).unwrap(), a);
        assert!(serde_json::from_str::<PublicKey>(
            "{\"scheme\":\"ed25519\",\"material\":\"00\",\"extra\":1}"
        )
        .is_err());
    }

    #[test]
    fn only_ed25519_is_production_grade() {
        assert!(SchemeKind::Ed25519.production_grade());
        assert!(!SchemeKind::HmacSha256Test.production_grade());
        for kind in SchemeKind::ALL {
            assert_eq!(
                serde_json::to_value(kind).unwrap(),
                serde_json::json!(kind.tag().replace('-', "_"))
            );
        }
    }

    #[test]
    fn the_test_scheme_verifies_its_own_signatures_and_nothing_else() {
        let mut registry = SchemeRegistry::new();
        registry.register(Box::new(HmacSha256TestScheme)).unwrap();
        assert_eq!(
            registry.register(Box::new(HmacSha256TestScheme)),
            Err(DuplicateScheme {
                scheme: SchemeKind::HmacSha256Test
            })
        );
        let key = test_key(b"secret");
        let signature = HmacSha256TestScheme::sign(b"secret", b"message");
        assert_eq!(registry.verify(&key, b"message", &signature), Ok(()));
        assert_eq!(
            registry.verify(&key, b"messagf", &signature),
            Err(SignatureRejection::Invalid)
        );
        assert_eq!(
            registry.verify(&test_key(b"other"), b"message", &signature),
            Err(SignatureRejection::Invalid)
        );
        assert_eq!(
            registry.verify(&key, b"message", &signature[..31]),
            Err(SignatureRejection::WrongLength {
                expected_bytes: 32,
                found_bytes: 31
            })
        );
        // RFC 4231 test case 2 pins the construction.
        assert_eq!(
            hex::encode(HmacSha256TestScheme::sign(
                b"Jefe",
                b"what do ya want for nothing?"
            )),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn an_unregistered_scheme_is_an_explicit_refusal() {
        let registry = SchemeRegistry::new();
        assert!(!registry.is_registered(SchemeKind::Ed25519));
        let key = PublicKey::new(SchemeKind::Ed25519, vec![7; 32]);
        assert_eq!(
            registry.verify(&key, b"m", &[0; 64]),
            Err(SignatureRejection::SchemeUnavailable {
                scheme: SchemeKind::Ed25519
            })
        );
        assert_eq!(format!("{registry:?}"), "{}");
    }
}
