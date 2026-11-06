//! Ed25519 verification over `ring` (RFC 8032; S2 CORE-08, line 206: "signed component
//! identity").
//!
//! This verifies exactly the message it is given. Callers sign and verify a
//! domain-separated statement about an artifact, never the artifact's raw bytes: the
//! catalog's [`content_statement`](super::content_statement) and
//! [`manifest_statement`](super::manifest_statement), or the sandbox update client's
//! metadata digests behind its `SignatureScheme` port.
//!
//! A public key is checked before it is used. Besides its length, a key whose encoding is
//! non-canonical or names a point of small order is refused: under the identity point,
//! for one, a fixed signature verifies for every message, so such a key would make any
//! statement look signed.

use std::fmt;

use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::foundation::catalog::PublisherId;
use crate::foundation::ids::{Digest, DigestBuilder};

/// Length of an Ed25519 public key (RFC 8032 §5.1.5).
pub const ED25519_PUBLIC_KEY_BYTES: usize = 32;

/// Length of an Ed25519 signature (RFC 8032 §5.1.6).
pub const ED25519_SIGNATURE_BYTES: usize = 64;

/// Domain of [`Ed25519PublicKey::fingerprint`]. It is the sandbox update client's key
/// domain (`sandbox::trust::KEY_DOMAIN`), and the fingerprint hashes the same parts in the
/// same order (the scheme tag, then the key bytes), so one key is one publisher in the
/// catalog and in the sandbox. A known-answer test pins the result.
pub const KEY_FINGERPRINT_DOMAIN: &str = "yougori/sandbox/trust/key/v1";

/// The scheme tag hashed into fingerprints, as the sandbox writes it.
pub const ED25519_TAG: &str = "ed25519";

/// The field prime p = 2^255 - 19, little-endian: encodings at or above it are
/// non-canonical (RFC 8032 §5.1.3).
const FIELD_PRIME: [u8; 32] = {
    let mut bytes = [0xff; 32];
    bytes[0] = 0xed;
    bytes[31] = 0x7f;
    bytes
};

/// The canonical encodings, sign bit cleared, of the points of small order on the curve
/// (the blocklist libsodium applies): y = 0 (order 4), y = 1 (the identity), the two
/// points of order 8, and y = p - 1 (order 2).
const SMALL_ORDER: [[u8; 32]; 5] = [
    [0; 32],
    {
        let mut bytes = [0; 32];
        bytes[0] = 1;
        bytes
    },
    [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98,
        0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53,
        0xfc, 0x05,
    ],
    [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0x7a,
    ],
    {
        let mut bytes = [0xff; 32];
        bytes[0] = 0xec;
        bytes[31] = 0x7f;
        bytes
    },
];

/// Why an Ed25519 key or signature was not accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum Ed25519Error {
    /// The public key is not [`ED25519_PUBLIC_KEY_BYTES`] long.
    PublicKeyLength { found_bytes: usize },
    /// The public key's text form is not hexadecimal.
    PublicKeyNotHex,
    /// The public key's y-coordinate is not reduced modulo p.
    NonCanonicalPublicKey,
    /// The public key is a point of small order, under which signatures can be forged.
    SmallOrderPublicKey,
    /// The signature is not [`ED25519_SIGNATURE_BYTES`] long.
    SignatureLength { found_bytes: usize },
    /// The signature does not verify for this message under this key.
    BadSignature,
}

impl fmt::Display for Ed25519Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublicKeyLength { found_bytes } => write!(
                f,
                "an Ed25519 public key is {ED25519_PUBLIC_KEY_BYTES} bytes, not {found_bytes}"
            ),
            Self::PublicKeyNotHex => f.write_str("the Ed25519 public key is not hexadecimal"),
            Self::NonCanonicalPublicKey => {
                f.write_str("the Ed25519 public key is not canonically encoded")
            }
            Self::SmallOrderPublicKey => {
                f.write_str("the Ed25519 public key is a point of small order")
            }
            Self::SignatureLength { found_bytes } => write!(
                f,
                "an Ed25519 signature is {ED25519_SIGNATURE_BYTES} bytes, not {found_bytes}"
            ),
            Self::BadSignature => f.write_str("the signature does not verify under the key"),
        }
    }
}

impl std::error::Error for Ed25519Error {}

/// A checked Ed25519 public key: the right length, canonically encoded and not of small
/// order. It is written as lowercase hexadecimal.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ed25519PublicKey([u8; ED25519_PUBLIC_KEY_BYTES]);

impl Ed25519PublicKey {
    /// Checks `bytes` as an Ed25519 public key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Ed25519Error> {
        let key: [u8; ED25519_PUBLIC_KEY_BYTES] =
            bytes
                .try_into()
                .map_err(|_| Ed25519Error::PublicKeyLength {
                    found_bytes: bytes.len(),
                })?;
        let mut y = key;
        y[31] &= 0x7f;
        if !below_field_prime(&y) {
            return Err(Ed25519Error::NonCanonicalPublicKey);
        }
        if SMALL_ORDER.contains(&y) {
            return Err(Ed25519Error::SmallOrderPublicKey);
        }
        Ok(Self(key))
    }

    /// Checks hexadecimal `text`, in either case, as an Ed25519 public key.
    pub fn from_hex(text: &str) -> Result<Self, Ed25519Error> {
        let bytes = hex::decode(text).map_err(|_| Ed25519Error::PublicKeyNotHex)?;
        Self::from_bytes(&bytes)
    }

    /// The key's 32 bytes.
    pub const fn as_bytes(&self) -> &[u8; ED25519_PUBLIC_KEY_BYTES] {
        &self.0
    }

    /// Lowercase hexadecimal, the canonical text form.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// The key's fingerprint under [`KEY_FINGERPRINT_DOMAIN`].
    pub fn fingerprint(&self) -> Digest {
        DigestBuilder::new(KEY_FINGERPRINT_DOMAIN)
            .str(ED25519_TAG)
            .bytes(&self.0)
            .finish()
    }

    /// The catalog's publisher identity for this key: its fingerprint (S2 CORE-08
    /// "signed component identity").
    pub fn publisher_id(&self) -> PublisherId {
        PublisherId::from_key_fingerprint(self.fingerprint())
    }

    /// Whether `signature` is this key's Ed25519 signature over `message`. `ring` refuses
    /// a signature whose scalar is not reduced, so a valid signature cannot be altered
    /// into a second valid one.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Ed25519Error> {
        if signature.len() != ED25519_SIGNATURE_BYTES {
            return Err(Ed25519Error::SignatureLength {
                found_bytes: signature.len(),
            });
        }
        UnparsedPublicKey::new(&ED25519, &self.0)
            .verify(message, signature)
            .map_err(|_| Ed25519Error::BadSignature)
    }
}

impl fmt::Debug for Ed25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ed25519PublicKey({})", self.to_hex())
    }
}

impl fmt::Display for Ed25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for Ed25519PublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Ed25519PublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::from_hex(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Whether `signature` is the Ed25519 signature of `public_key` over `message`: the
/// primitive a signature-scheme port wraps. The key is checked as
/// [`Ed25519PublicKey::from_bytes`] checks it. `message` should be a domain-separated
/// statement, never an artifact's raw bytes.
pub fn verify_ed25519(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), Ed25519Error> {
    Ed25519PublicKey::from_bytes(public_key)?.verify(message, signature)
}

/// Whether the little-endian 255-bit value `y` (sign bit cleared) is below p.
fn below_field_prime(y: &[u8; 32]) -> bool {
    y.iter().rev().cmp(FIELD_PRIME.iter().rev()) == std::cmp::Ordering::Less
}
