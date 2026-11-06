//! The Ed25519 adapter against RFC 8032 (§7.1 test vectors, copied from the RFC text as
//! byte literals), single-bit corruption, exact lengths and arbitrary input.

use ring::signature::{Ed25519KeyPair, KeyPair};
use sha2::Digest as _;

use super::*;
use crate::foundation::signing::Ed25519PublicKey;
use crate::sandbox::trust::{
    HmacSha256TestScheme, PublicKey, SchemeKind, SchemeRegistry, SignatureRejection,
    SignatureScheme,
};

/// One RFC 8032 §7.1 test vector.
struct Vector {
    secret_key: &'static [u8],
    public_key: &'static [u8],
    message: &'static [u8],
    signature: &'static [u8],
}

/// RFC 8032 §7.1, TEST 1: the empty message.
const TEST_1: Vector = Vector {
    secret_key: &[
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ],
    public_key: &[
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ],
    message: &[],
    signature: &[
        0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82,
        0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49,
        0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c,
        0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43,
        0x8e, 0x7a, 0x10, 0x0b,
    ],
};

/// RFC 8032 §7.1, TEST 2: one byte.
const TEST_2: Vector = Vector {
    secret_key: &[
        0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e,
        0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8,
        0xa6, 0xfb,
    ],
    public_key: &[
        0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e,
        0xbc, 0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4,
        0x66, 0x0c,
    ],
    message: &[0x72],
    signature: &[
        0x92, 0xa0, 0x09, 0xa9, 0xf0, 0xd4, 0xca, 0xb8, 0x72, 0x0e, 0x82, 0x0b, 0x5f, 0x64, 0x25,
        0x40, 0xa2, 0xb2, 0x7b, 0x54, 0x16, 0x50, 0x3f, 0x8f, 0xb3, 0x76, 0x22, 0x23, 0xeb, 0xdb,
        0x69, 0xda, 0x08, 0x5a, 0xc1, 0xe4, 0x3e, 0x15, 0x99, 0x6e, 0x45, 0x8f, 0x36, 0x13, 0xd0,
        0xf1, 0x1d, 0x8c, 0x38, 0x7b, 0x2e, 0xae, 0xb4, 0x30, 0x2a, 0xee, 0xb0, 0x0d, 0x29, 0x16,
        0x12, 0xbb, 0x0c, 0x00,
    ],
};

/// RFC 8032 §7.1, TEST 3: two bytes.
const TEST_3: Vector = Vector {
    secret_key: &[
        0xc5, 0xaa, 0x8d, 0xf4, 0x3f, 0x9f, 0x83, 0x7b, 0xed, 0xb7, 0x44, 0x2f, 0x31, 0xdc, 0xb7,
        0xb1, 0x66, 0xd3, 0x85, 0x35, 0x07, 0x6f, 0x09, 0x4b, 0x85, 0xce, 0x3a, 0x2e, 0x0b, 0x44,
        0x58, 0xf7,
    ],
    public_key: &[
        0xfc, 0x51, 0xcd, 0x8e, 0x62, 0x18, 0xa1, 0xa3, 0x8d, 0xa4, 0x7e, 0xd0, 0x02, 0x30, 0xf0,
        0x58, 0x08, 0x16, 0xed, 0x13, 0xba, 0x33, 0x03, 0xac, 0x5d, 0xeb, 0x91, 0x15, 0x48, 0x90,
        0x80, 0x25,
    ],
    message: &[0xaf, 0x82],
    signature: &[
        0x62, 0x91, 0xd6, 0x57, 0xde, 0xec, 0x24, 0x02, 0x48, 0x27, 0xe6, 0x9c, 0x3a, 0xbe, 0x01,
        0xa3, 0x0c, 0xe5, 0x48, 0xa2, 0x84, 0x74, 0x3a, 0x44, 0x5e, 0x36, 0x80, 0xd7, 0xdb, 0x5a,
        0xc3, 0xac, 0x18, 0xff, 0x9b, 0x53, 0x8d, 0x16, 0xf2, 0x90, 0xae, 0x67, 0xf7, 0x60, 0x98,
        0x4d, 0xc6, 0x59, 0x4a, 0x7c, 0x15, 0xe9, 0x71, 0x6e, 0xd2, 0x8d, 0xc0, 0x27, 0xbe, 0xce,
        0xea, 0x1e, 0xc4, 0x0a,
    ],
};

/// RFC 8032 §7.1, TEST SHA(abc): the message is SHA-512 of "abc".
const TEST_SHA_ABC: Vector = Vector {
    secret_key: &[
        0x83, 0x3f, 0xe6, 0x24, 0x09, 0x23, 0x7b, 0x9d, 0x62, 0xec, 0x77, 0x58, 0x75, 0x20, 0x91,
        0x1e, 0x9a, 0x75, 0x9c, 0xec, 0x1d, 0x19, 0x75, 0x5b, 0x7d, 0xa9, 0x01, 0xb9, 0x6d, 0xca,
        0x3d, 0x42,
    ],
    public_key: &[
        0xec, 0x17, 0x2b, 0x93, 0xad, 0x5e, 0x56, 0x3b, 0xf4, 0x93, 0x2c, 0x70, 0xe1, 0x24, 0x50,
        0x34, 0xc3, 0x54, 0x67, 0xef, 0x2e, 0xfd, 0x4d, 0x64, 0xeb, 0xf8, 0x19, 0x68, 0x34, 0x67,
        0xe2, 0xbf,
    ],
    message: &[
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41,
        0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55,
        0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3,
        0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f,
        0xa5, 0x4c, 0xa4, 0x9f,
    ],
    signature: &[
        0xdc, 0x2a, 0x44, 0x59, 0xe7, 0x36, 0x96, 0x33, 0xa5, 0x2b, 0x1b, 0xf2, 0x77, 0x83, 0x9a,
        0x00, 0x20, 0x10, 0x09, 0xa3, 0xef, 0xbf, 0x3e, 0xcb, 0x69, 0xbe, 0xa2, 0x18, 0x6c, 0x26,
        0xb5, 0x89, 0x09, 0x35, 0x1f, 0xc9, 0xac, 0x90, 0xb3, 0xec, 0xfd, 0xfb, 0xc7, 0xc6, 0x64,
        0x31, 0xe0, 0x30, 0x3d, 0xca, 0x17, 0x9c, 0x13, 0x8a, 0xc1, 0x7a, 0xd9, 0xbe, 0xf1, 0x17,
        0x73, 0x31, 0xa7, 0x04,
    ],
};

const VECTORS: [&Vector; 4] = [&TEST_1, &TEST_2, &TEST_3, &TEST_SHA_ABC];

fn flipped(bytes: &[u8], bit: usize) -> Vec<u8> {
    let mut copy = bytes.to_vec();
    copy[bit / 8] ^= 1 << (bit % 8);
    copy
}

#[test]
fn rfc8032_vectors_verify() {
    for vector in VECTORS {
        assert_eq!(
            Ed25519Scheme.verify(vector.public_key, vector.message, vector.signature),
            Ok(())
        );
    }
}

#[test]
fn the_vector_literals_are_consistent_with_their_secret_keys() {
    // Ed25519 signing is deterministic: each secret key yields the vector's public key
    // and signature byte for byte, which pins the literals above.
    for vector in VECTORS {
        let pair = Ed25519KeyPair::from_seed_unchecked(vector.secret_key).unwrap();
        assert_eq!(pair.public_key().as_ref(), vector.public_key);
        assert_eq!(pair.sign(vector.message).as_ref(), vector.signature);
    }
    assert_eq!(
        sha2::Sha512::digest(b"abc").as_slice(),
        TEST_SHA_ABC.message
    );
}

#[test]
fn one_flipped_bit_in_the_message_signature_or_key_fails() {
    for vector in VECTORS {
        for bit in 0..vector.signature.len() * 8 {
            assert_eq!(
                Ed25519Scheme.verify(
                    vector.public_key,
                    vector.message,
                    &flipped(vector.signature, bit)
                ),
                Err(SignatureRejection::Invalid),
                "signature bit {bit}"
            );
        }
        for bit in 0..vector.public_key.len() * 8 {
            assert_eq!(
                Ed25519Scheme.verify(
                    &flipped(vector.public_key, bit),
                    vector.message,
                    vector.signature
                ),
                Err(SignatureRejection::Invalid),
                "key bit {bit}"
            );
        }
        for bit in 0..vector.message.len() * 8 {
            assert_eq!(
                Ed25519Scheme.verify(
                    vector.public_key,
                    &flipped(vector.message, bit),
                    vector.signature
                ),
                Err(SignatureRejection::Invalid),
                "message bit {bit}"
            );
        }
        // A longer or shorter message is another message.
        let mut longer = vector.message.to_vec();
        longer.push(0);
        assert_eq!(
            Ed25519Scheme.verify(vector.public_key, &longer, vector.signature),
            Err(SignatureRejection::Invalid)
        );
    }
    // Another vector's signature or key does not verify this message.
    assert_eq!(
        Ed25519Scheme.verify(TEST_2.public_key, TEST_2.message, TEST_3.signature),
        Err(SignatureRejection::Invalid)
    );
    assert_eq!(
        Ed25519Scheme.verify(TEST_3.public_key, TEST_2.message, TEST_2.signature),
        Err(SignatureRejection::Invalid)
    );
}

#[test]
fn wrong_lengths_are_refused_first_with_the_ports_rejection() {
    let vector = &TEST_2;
    for length in [0, 1, 31, 33, 64] {
        let key = vec![0x3d; length];
        assert_eq!(
            Ed25519Scheme.verify(&key, vector.message, vector.signature),
            Err(SignatureRejection::WrongLength {
                expected_bytes: 32,
                found_bytes: length,
            })
        );
    }
    for length in [0, 1, 32, 63, 65, 128] {
        let signature = vec![0x92; length];
        assert_eq!(
            Ed25519Scheme.verify(vector.public_key, vector.message, &signature),
            Err(SignatureRejection::WrongLength {
                expected_bytes: 64,
                found_bytes: length,
            })
        );
    }
    // The signature's length is compared first, so it is the one reported when both are
    // wrong; a wrong-length signature under a malformed key is still a length rejection.
    assert_eq!(
        Ed25519Scheme.verify(
            &vector.public_key[..31],
            vector.message,
            &vector.signature[..63]
        ),
        Err(SignatureRejection::WrongLength {
            expected_bytes: 64,
            found_bytes: 63,
        })
    );
    assert_eq!(
        Ed25519Scheme.verify(&[0xff; 32], vector.message, &vector.signature[..63]),
        Err(SignatureRejection::WrongLength {
            expected_bytes: 64,
            found_bytes: 63,
        })
    );
    // A valid signature with a trailing byte, or the key with one, is refused too.
    let mut padded = vector.signature.to_vec();
    padded.push(0);
    assert!(matches!(
        Ed25519Scheme.verify(vector.public_key, vector.message, &padded),
        Err(SignatureRejection::WrongLength {
            found_bytes: 65,
            ..
        })
    ));
    let mut padded_key = vector.public_key.to_vec();
    padded_key.push(0);
    assert!(matches!(
        Ed25519Scheme.verify(&padded_key, vector.message, vector.signature),
        Err(SignatureRejection::WrongLength {
            found_bytes: 33,
            ..
        })
    ));
}

#[test]
fn arbitrary_input_is_refused_without_panicking() {
    // Every length pair around the exact ones, in several fills: a wrong length is the
    // length rejection, an exact one reaches the verifier, and nothing panics.
    for fill in [0x00u8, 0x01, 0x7f, 0x80, 0xff] {
        for key_length in 0..=40 {
            for signature_length in [0, 1, 32, 63, 64, 65, 100] {
                let key = vec![fill; key_length];
                let signature = vec![fill; signature_length];
                let outcome = Ed25519Scheme.verify(&key, b"payload", &signature);
                if key_length == 32 && signature_length == 64 {
                    assert!(matches!(outcome, Ok(()) | Err(SignatureRejection::Invalid)));
                } else {
                    assert!(matches!(
                        outcome,
                        Err(SignatureRejection::WrongLength { .. })
                    ));
                }
            }
        }
    }
    // Keys that are not canonical curve points, and a signature whose scalar is not
    // reduced, are refused as invalid.
    let not_canonical = [0xff; 32];
    let unreduced_scalar = {
        let mut signature = TEST_1.signature.to_vec();
        signature[32..].fill(0xff);
        signature
    };
    assert_eq!(
        Ed25519Scheme.verify(&not_canonical, TEST_1.message, TEST_1.signature),
        Err(SignatureRejection::Invalid)
    );
    assert_eq!(
        Ed25519Scheme.verify(TEST_1.public_key, TEST_1.message, &unreduced_scalar),
        Err(SignatureRejection::Invalid)
    );
    // A long message is only a message.
    let long = vec![0x5a; 1 << 16];
    assert_eq!(
        Ed25519Scheme.verify(TEST_1.public_key, &long, TEST_1.signature),
        Err(SignatureRejection::Invalid)
    );
}

#[test]
fn the_adapter_is_the_ed25519_verifier_and_nothing_else() {
    assert_eq!(Ed25519Scheme.kind(), SchemeKind::Ed25519);
    let mut registry = SchemeRegistry::new();
    registry.register(Box::new(Ed25519Scheme)).unwrap();
    let key = PublicKey::new(SchemeKind::Ed25519, TEST_3.public_key.to_vec());
    assert_eq!(
        registry.verify(&key, TEST_3.message, TEST_3.signature),
        Ok(())
    );
    // An HMAC key and tag are not Ed25519, even with Ed25519 lengths.
    let secret = [7u8; 32];
    let tag = HmacSha256TestScheme::sign(&secret, b"m");
    let hmac_key = PublicKey::new(SchemeKind::HmacSha256Test, secret.to_vec());
    assert_eq!(
        registry.verify(&hmac_key, b"m", &tag),
        Err(SignatureRejection::SchemeUnavailable {
            scheme: SchemeKind::HmacSha256Test
        })
    );
    let mut doubled = tag.clone();
    doubled.extend_from_slice(&tag);
    assert_eq!(
        Ed25519Scheme.verify(&secret, b"m", &doubled),
        Err(SignatureRejection::Invalid)
    );
}

#[test]
fn the_client_key_identity_is_the_foundation_fingerprint() {
    // The foundation's known answer for the RFC 8032 TEST 1 key under its
    // key-fingerprint domain: the trust client's key id hashes the same parts, so one
    // key is one publisher in the catalog and in the sandbox.
    let key = PublicKey::new(SchemeKind::Ed25519, TEST_1.public_key.to_vec());
    assert_eq!(
        key.key_id().to_string(),
        "b99d5a935641bf24d0293f47fb3773b5038f419ab6f93812326567bc872aab3f"
    );
    for vector in VECTORS {
        let key = PublicKey::new(SchemeKind::Ed25519, vector.public_key.to_vec());
        let foundation = Ed25519PublicKey::from_bytes(vector.public_key).unwrap();
        assert_eq!(key.key_id().digest(), foundation.fingerprint());
        assert_eq!(key.publisher_id(), foundation.publisher_id());
    }
}

#[test]
fn weak_keys_are_refused_even_with_a_matching_signature() {
    // Under the identity point, R = identity and S = 0 satisfy the verification
    // equation for every message; the foundation refuses such keys, so the port does.
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let mut forged = [0u8; 64];
    forged[0] = 1;
    for message in [&b""[..], b"any statement", TEST_SHA_ABC.message] {
        assert_eq!(
            Ed25519Scheme.verify(&identity, message, &forged),
            Err(SignatureRejection::Invalid)
        );
    }
    // Every small-order encoding, either sign bit, and non-canonical encodings.
    let mut order_two = [0xff; 32];
    order_two[0] = 0xec;
    order_two[31] = 0x7f;
    let mut not_canonical = [0xff; 32];
    not_canonical[31] = 0x7f;
    for key in [[0u8; 32], identity, order_two, not_canonical] {
        let mut negated = key;
        negated[31] |= 0x80;
        for key in [key, negated] {
            assert_eq!(
                Ed25519Scheme.verify(&key, TEST_1.message, TEST_1.signature),
                Err(SignatureRejection::Invalid)
            );
        }
    }
}
