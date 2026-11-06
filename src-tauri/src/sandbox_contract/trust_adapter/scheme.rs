//! Ed25519 behind the trust client's signature port (VM-W45, plan line 2668: "trust
//! roots, key rotation"; §8.3, line 2453: "verify signed artifact metadata before
//! execution"; §19, line 3217: `ring` is an approved dependency the plan reuses).
//!
//! [`Ed25519Scheme`] is the [`SignatureScheme`] the update client asks for keys of
//! [`SchemeKind::Ed25519`]. It delegates to the foundation's one Ed25519 verification,
//! [`verify_ed25519`], and maps each [`Ed25519Error`] onto the port's own
//! [`SignatureRejection`]: a key or signature of the wrong length is
//! [`SignatureRejection::WrongLength`], and a key that is not canonically encoded or
//! names a point of small order, like a signature that does not verify, is
//! [`SignatureRejection::Invalid`]. This module calls no cryptographic library itself.
//!
//! The port puts lengths before verification. The foundation checks the key first (its
//! length, then its encoding) and the signature's length after, so a wrong-length
//! signature under a malformed key would come back as a refused key; the adapter
//! therefore compares the signature's length itself, first, and leaves the key's length
//! to the foundation. When both lengths are wrong, the signature's is reported.
//!
//! The port has one length rejection, worded for signatures; a key of the wrong length
//! is told apart by `expected_bytes` ([`ED25519_PUBLIC_KEY_BYTES`] rather than
//! [`ED25519_SIGNATURE_BYTES`]).

use crate::foundation::signing::{
    verify_ed25519, Ed25519Error, ED25519_PUBLIC_KEY_BYTES, ED25519_SIGNATURE_BYTES,
};
use crate::sandbox::trust::{SchemeKind, SignatureRejection, SignatureScheme};

/// Ed25519 (RFC 8032) for the update client: the production scheme. It verifies; it
/// holds no key and signs nothing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ed25519Scheme;

impl SignatureScheme for Ed25519Scheme {
    fn kind(&self) -> SchemeKind {
        SchemeKind::Ed25519
    }

    fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), SignatureRejection> {
        if signature.len() != ED25519_SIGNATURE_BYTES {
            return Err(rejection(Ed25519Error::SignatureLength {
                found_bytes: signature.len(),
            }));
        }
        verify_ed25519(public_key, message, signature).map_err(rejection)
    }
}

/// The port's rejection for a foundation Ed25519 error.
fn rejection(error: Ed25519Error) -> SignatureRejection {
    match error {
        Ed25519Error::PublicKeyLength { found_bytes } => SignatureRejection::WrongLength {
            expected_bytes: ED25519_PUBLIC_KEY_BYTES,
            found_bytes,
        },
        Ed25519Error::SignatureLength { found_bytes } => SignatureRejection::WrongLength {
            expected_bytes: ED25519_SIGNATURE_BYTES,
            found_bytes,
        },
        // The port has no rejection for a refused key: it is not a key any signature
        // verifies under. `PublicKeyNotHex` arises only from text, never from bytes.
        Ed25519Error::PublicKeyNotHex
        | Ed25519Error::NonCanonicalPublicKey
        | Ed25519Error::SmallOrderPublicKey
        | Ed25519Error::BadSignature => SignatureRejection::Invalid,
    }
}
