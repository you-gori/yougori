//! SSH wire-format public keys, the base64 of a `known_hosts` line and OpenSSH's SHA256
//! fingerprint (RFC 4253 §6.6, RFC 5656 §3.1, RFC 8709 §4, RFC 4251 §5, RFC 4648 §4).
//!
//! The checks are structural: a blob must be exactly one public key of the declared
//! algorithm, with nothing before or after it, so the rendered line is one OpenSSH can
//! read and the parser can recognise exactly. They do not check that an ECDSA point lies
//! on its curve or that an RSA modulus is a product of two primes; OpenSSH validates the
//! key itself when it loads the line. Base64 is the engine's `base64` crate: padded
//! `STANDARD` for the key, whose decoder takes canonical padding only and refuses
//! non-zero bits after the last byte, and unpadded `STANDARD_NO_PAD` for fingerprints.

use std::fmt;

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine as _;
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::sandbox_contract::remote::HostKeyAlgorithm;

/// The shortest RSA host-key modulus accepted, in bits.
pub const MIN_RSA_MODULUS_BITS: u64 = 2_048;

/// Why a public key blob was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum KeyBlobProblem {
    /// A length field runs past the end of the blob.
    Truncated,
    /// Bytes follow the key.
    TrailingBytes,
    /// The blob names another key type than the algorithm's.
    KeyTypeMismatch,
    /// An ECDSA blob names another curve than its key type.
    CurveMismatch,
    /// The public value has the wrong form: 32 bytes for Ed25519, an uncompressed point
    /// of the curve's size for ECDSA.
    PublicValue,
    /// An RSA integer is zero, negative or not minimally encoded.
    RsaInteger,
    /// The RSA modulus is shorter than [`MIN_RSA_MODULUS_BITS`].
    RsaModulusTooShort { bits: u64, min_bits: u64 },
}

impl fmt::Display for KeyBlobProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("the public key blob is truncated"),
            Self::TrailingBytes => f.write_str("bytes follow the public key"),
            Self::KeyTypeMismatch => {
                f.write_str("the public key blob names another key type than its algorithm")
            }
            Self::CurveMismatch => f.write_str("the ECDSA key names another curve"),
            Self::PublicValue => f.write_str("the public key value has the wrong form"),
            Self::RsaInteger => f.write_str("an RSA integer is not a minimal positive mpint"),
            Self::RsaModulusTooShort { bits, min_bits } => write!(
                f,
                "the RSA modulus has {bits} bits; at least {min_bits} are required"
            ),
        }
    }
}

impl std::error::Error for KeyBlobProblem {}

/// The key type OpenSSH writes in a `known_hosts` line and as the first string of the
/// key blob. For RSA this is the key format `ssh-rsa`; `rsa-sha2-512` (V12's
/// [`HostKeyAlgorithm::tag`]) is the signature algorithm that goes into
/// `HostKeyAlgorithms`.
pub const fn known_hosts_key_type(algorithm: HostKeyAlgorithm) -> &'static str {
    match algorithm {
        HostKeyAlgorithm::Ed25519 => "ssh-ed25519",
        HostKeyAlgorithm::EcdsaNistp256 => "ecdsa-sha2-nistp256",
        HostKeyAlgorithm::EcdsaNistp384 => "ecdsa-sha2-nistp384",
        HostKeyAlgorithm::RsaSha2_512 => "ssh-rsa",
    }
}

/// The algorithm whose `known_hosts` key type is `name`.
pub(super) fn algorithm_for_key_type(name: &str) -> Option<HostKeyAlgorithm> {
    [
        HostKeyAlgorithm::Ed25519,
        HostKeyAlgorithm::EcdsaNistp256,
        HostKeyAlgorithm::EcdsaNistp384,
        HostKeyAlgorithm::RsaSha2_512,
    ]
    .into_iter()
    .find(|algorithm| known_hosts_key_type(*algorithm) == name)
}

struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    /// One RFC 4251 `string`: a big-endian u32 length and that many bytes.
    fn string(&mut self) -> Result<&'a [u8], KeyBlobProblem> {
        let (length, rest) = self
            .rest
            .split_first_chunk::<4>()
            .ok_or(KeyBlobProblem::Truncated)?;
        let length =
            usize::try_from(u32::from_be_bytes(*length)).map_err(|_| KeyBlobProblem::Truncated)?;
        if rest.len() < length {
            return Err(KeyBlobProblem::Truncated);
        }
        let (value, rest) = rest.split_at(length);
        self.rest = rest;
        Ok(value)
    }

    fn finish(self) -> Result<(), KeyBlobProblem> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(KeyBlobProblem::TrailingBytes)
        }
    }
}

/// The bit length of a positive, minimally encoded `mpint` (RFC 4251 §5).
fn positive_mpint_bits(value: &[u8]) -> Result<u64, KeyBlobProblem> {
    let (&first, rest) = value.split_first().ok_or(KeyBlobProblem::RsaInteger)?;
    if first & 0x80 != 0 {
        return Err(KeyBlobProblem::RsaInteger);
    }
    let magnitude = if first == 0 {
        // A leading zero byte is allowed only to keep a set high bit positive.
        match rest.first() {
            Some(&next) if next & 0x80 != 0 => rest,
            _ => return Err(KeyBlobProblem::RsaInteger),
        }
    } else {
        value
    };
    let leading = magnitude
        .first()
        .map_or(8, |byte| u64::from(byte.leading_zeros()));
    let bytes = u64::try_from(magnitude.len()).map_err(|_| KeyBlobProblem::RsaInteger)?;
    Ok(bytes.saturating_mul(8).saturating_sub(leading))
}

/// Checks that `blob` is one public key of `algorithm` in SSH wire form.
pub(super) fn check_blob(algorithm: HostKeyAlgorithm, blob: &[u8]) -> Result<(), KeyBlobProblem> {
    let mut reader = Reader { rest: blob };
    if reader.string()? != known_hosts_key_type(algorithm).as_bytes() {
        return Err(KeyBlobProblem::KeyTypeMismatch);
    }
    match algorithm {
        HostKeyAlgorithm::Ed25519 => {
            if reader.string()?.len() != 32 {
                return Err(KeyBlobProblem::PublicValue);
            }
        }
        HostKeyAlgorithm::EcdsaNistp256 | HostKeyAlgorithm::EcdsaNistp384 => {
            let (curve, point_bytes) = if algorithm == HostKeyAlgorithm::EcdsaNistp256 {
                ("nistp256", 65)
            } else {
                ("nistp384", 97)
            };
            if reader.string()? != curve.as_bytes() {
                return Err(KeyBlobProblem::CurveMismatch);
            }
            let point = reader.string()?;
            if point.len() != point_bytes || point.first() != Some(&0x04) {
                return Err(KeyBlobProblem::PublicValue);
            }
        }
        HostKeyAlgorithm::RsaSha2_512 => {
            positive_mpint_bits(reader.string()?)?;
            let bits = positive_mpint_bits(reader.string()?)?;
            if bits < MIN_RSA_MODULUS_BITS {
                return Err(KeyBlobProblem::RsaModulusTooShort {
                    bits,
                    min_bits: MIN_RSA_MODULUS_BITS,
                });
            }
        }
    }
    reader.finish()
}

/// The length of an unpadded base64 SHA-256 digest.
const SHA256_BASE64_CHARS: usize = 43;

/// Standard base64 with padding (RFC 4648 §4), as OpenSSH writes a key in `known_hosts`.
pub(super) fn base64_encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// Decodes canonical padded base64 only: whole groups of four, padding only at the end,
/// and zero bits after the last byte, so exactly one text decodes to each byte string.
/// The empty text is refused, since no key is empty.
pub(super) fn base64_decode(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() {
        return None;
    }
    STANDARD.decode(text).ok()
}

/// OpenSSH's fingerprint of a key blob: `SHA256:` and the unpadded base64 of its SHA-256,
/// as `ssh-keygen -l` and the client's host-key warnings print it.
pub(super) fn openssh_sha256(blob: &[u8]) -> String {
    format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(blob)))
}

/// Whether `text` has the form of an OpenSSH SHA256 fingerprint: the canonical unpadded
/// base64 of 32 bytes after `SHA256:`.
///
/// Stricter than the character check it replaced: 43 symbols carry 258 bits, and a text
/// whose last symbol sets either of the 2 bits past the 256th is refused, since it is the
/// encoding of no digest and OpenSSH never prints one. A warning carrying such a text is
/// still read as a changed key, without a `reported` fingerprint.
pub(super) fn is_openssh_sha256(text: &str) -> bool {
    text.strip_prefix("SHA256:").is_some_and(|encoded| {
        encoded.len() == SHA256_BASE64_CHARS
            && STANDARD_NO_PAD
                .decode(encoded)
                .is_ok_and(|digest| digest.len() == 32)
    })
}
