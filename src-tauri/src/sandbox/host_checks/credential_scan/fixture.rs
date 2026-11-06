//! The fixture credential VM-CP-12 looks for and the forms it is searched in (§17,
//! line 3162: "a fixture credential is stored in the vault; ... the launch specification,
//! the relay's inputs and logs, the audit and the fake provider's echoed response contain
//! no fixture value; the executor's outbound request contains it").
//!
//! A [`FixtureCredential`] is a test value of [`MIN_FIXTURE_BYTES`] to
//! [`MAX_FIXTURE_BYTES`] visible ASCII bytes. It is never printed, serialized or copied
//! into a report, so a report written into one of the scanned locations cannot itself
//! make a finding. Its searched forms ([`FixtureCredential::forms`]) are its exact bytes
//! and the common encodings of [`Encoding`]:
//!
//! - base64 in the standard and the URL-safe alphabet: the credential may start at any of
//!   the three byte positions of a 3-byte group of the encoded data (as inside
//!   `Basic base64(user:password)`), so each alphabet gives three forms, each holding
//!   only the characters that the credential's own bits decide, without padding;
//! - hexadecimal in lowercase and in uppercase digits;
//! - percent-encoding (RFC 3986): every byte outside the unreserved set as `%XX`, in
//!   uppercase and in lowercase digits.
//!
//! A form equal to an earlier one (the percent-encoding of a credential of unreserved
//! characters only is its exact bytes) is searched once, under the earlier encoding.
//! Nothing else is searched: no other alphabet, case or escape, no line-wrapped base64,
//! no compressed, encrypted or split copy.

use std::fmt;

use serde::Serialize;

/// The shortest fixture accepted: long enough that every searched form, base64's
/// shortest included, is at least 20 characters.
pub const MIN_FIXTURE_BYTES: usize = 16;

/// The longest fixture accepted.
pub const MAX_FIXTURE_BYTES: usize = 1024;

/// A form the fixture credential is searched in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Encoding {
    /// The credential's own bytes.
    Exact,
    /// Base64, standard alphabet (RFC 4648 section 4), at any 3-byte alignment.
    Base64,
    /// Base64, URL-safe alphabet (RFC 4648 section 5), at any 3-byte alignment.
    Base64Url,
    /// Two lowercase hexadecimal digits per byte.
    HexLowercase,
    /// Two uppercase hexadecimal digits per byte.
    HexUppercase,
    /// RFC 3986 percent-encoding of every byte outside the unreserved set, uppercase
    /// digits.
    PercentUppercase,
    /// The same with lowercase digits.
    PercentLowercase,
}

impl Encoding {
    /// Every encoding searched, in the order a shared form is attributed.
    pub const ALL: [Self; 7] = [
        Self::Exact,
        Self::Base64,
        Self::Base64Url,
        Self::HexLowercase,
        Self::HexUppercase,
        Self::PercentUppercase,
        Self::PercentLowercase,
    ];

    /// The position of the encoding in [`Self::ALL`].
    pub const fn index(self) -> usize {
        match self {
            Self::Exact => 0,
            Self::Base64 => 1,
            Self::Base64Url => 2,
            Self::HexLowercase => 3,
            Self::HexUppercase => 4,
            Self::PercentUppercase => 5,
            Self::PercentLowercase => 6,
        }
    }
}

impl fmt::Display for Encoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Exact => "the exact bytes",
            Self::Base64 => "base64",
            Self::Base64Url => "URL-safe base64",
            Self::HexLowercase => "lowercase hexadecimal",
            Self::HexUppercase => "uppercase hexadecimal",
            Self::PercentUppercase => "percent-encoding with uppercase digits",
            Self::PercentLowercase => "percent-encoding with lowercase digits",
        })
    }
}

/// Why a fixture credential was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "fixture", rename_all = "snake_case")]
pub enum FixtureError {
    /// Fewer than [`MIN_FIXTURE_BYTES`] bytes.
    TooShort { minimum: usize },
    /// More than [`MAX_FIXTURE_BYTES`] bytes.
    TooLong { maximum: usize },
    /// A byte that is not visible ASCII (`!` to `~`), at this offset.
    NotVisibleAscii { offset: usize },
}

impl fmt::Display for FixtureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { minimum } => {
                write!(f, "a fixture credential has at least {minimum} bytes")
            }
            Self::TooLong { maximum } => {
                write!(f, "a fixture credential has at most {maximum} bytes")
            }
            Self::NotVisibleAscii { offset } => write!(
                f,
                "a fixture credential is visible ASCII; byte {offset} is not"
            ),
        }
    }
}

impl std::error::Error for FixtureError {}

/// The fixture credential of one VM-CP-12 run. Its bytes are never printed or
/// serialized.
#[derive(Clone, PartialEq, Eq)]
pub struct FixtureCredential(Vec<u8>);

impl FixtureCredential {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, FixtureError> {
        let bytes = bytes.into();
        if bytes.len() < MIN_FIXTURE_BYTES {
            return Err(FixtureError::TooShort {
                minimum: MIN_FIXTURE_BYTES,
            });
        }
        if bytes.len() > MAX_FIXTURE_BYTES {
            return Err(FixtureError::TooLong {
                maximum: MAX_FIXTURE_BYTES,
            });
        }
        if let Some(offset) = bytes.iter().position(|byte| !byte.is_ascii_graphic()) {
            return Err(FixtureError::NotVisibleAscii { offset });
        }
        Ok(Self(bytes))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Always false: a fixture has at least [`MIN_FIXTURE_BYTES`] bytes.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Every searched form with the encoding it is attributed to, in [`Encoding::ALL`]
    /// order; a form equal to an earlier one is left out.
    pub fn forms(&self) -> Vec<(Encoding, Vec<u8>)> {
        let mut forms: Vec<(Encoding, Vec<u8>)> = Vec::new();
        let mut add = |encoding: Encoding, form: Vec<u8>| {
            if !forms.iter().any(|(_, earlier)| *earlier == form) {
                forms.push((encoding, form));
            }
        };
        add(Encoding::Exact, self.0.clone());
        for alignment in 0..3 {
            add(
                Encoding::Base64,
                base64_fragment(&self.0, alignment, STANDARD),
            );
        }
        for alignment in 0..3 {
            add(
                Encoding::Base64Url,
                base64_fragment(&self.0, alignment, URL_SAFE),
            );
        }
        add(Encoding::HexLowercase, hex(&self.0, LOWER_DIGITS));
        add(Encoding::HexUppercase, hex(&self.0, UPPER_DIGITS));
        add(Encoding::PercentUppercase, percent(&self.0, UPPER_DIGITS));
        add(Encoding::PercentLowercase, percent(&self.0, LOWER_DIGITS));
        forms
    }
}

impl fmt::Debug for FixtureCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FixtureCredential({} bytes, withheld)", self.0.len())
    }
}

/// The base64 alphabets of RFC 4648 sections 4 and 5.
pub(super) const STANDARD: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
pub(super) const URL_SAFE: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const LOWER_DIGITS: &[u8; 16] = b"0123456789abcdef";
const UPPER_DIGITS: &[u8; 16] = b"0123456789ABCDEF";

/// `bytes` in base64 with `alphabet`, without padding: one character per 6 bits, the
/// last one filled with zero bits.
pub(super) fn base64(bytes: &[u8], alphabet: &[u8; 64]) -> Vec<u8> {
    let bits = bytes.len() * 8;
    (0..bits.div_ceil(6))
        .map(|index| alphabet[usize::from(sextet(bytes, index))])
        .collect()
}

/// The 6 bits of character `index` of `bytes` in base64, zero past the end.
fn sextet(bytes: &[u8], index: usize) -> u8 {
    let start = index * 6;
    let mut value = 0u8;
    for bit in start..start + 6 {
        let byte = bytes.get(bit / 8).copied().unwrap_or(0);
        let set = (byte >> (7 - bit % 8)) & 1;
        value = (value << 1) | set;
    }
    value
}

/// The base64 characters of `credential` that its own bits decide when it starts
/// `alignment` bytes into a 3-byte group: character `i` of the encoded data covers bits
/// `6i..6i + 6`, and only characters wholly inside the credential's bits are kept.
fn base64_fragment(credential: &[u8], alignment: usize, alphabet: &[u8; 64]) -> Vec<u8> {
    let mut data = vec![0u8; alignment];
    data.extend_from_slice(credential);
    let first = (alignment * 8).div_ceil(6);
    let end = data.len() * 8 / 6;
    let encoded = base64(&data, alphabet);
    encoded
        .get(first..end)
        .map(<[u8]>::to_vec)
        .unwrap_or_default()
}

fn hex(bytes: &[u8], digits: &[u8; 16]) -> Vec<u8> {
    bytes
        .iter()
        .flat_map(|byte| {
            [
                digits[usize::from(byte >> 4)],
                digits[usize::from(byte & 0xf)],
            ]
        })
        .collect()
}

/// RFC 3986 section 2.3's unreserved characters, which percent-encoding keeps.
const fn unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

fn percent(bytes: &[u8], digits: &[u8; 16]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(bytes.len() * 3);
    for byte in bytes {
        if unreserved(*byte) {
            encoded.push(*byte);
        } else {
            encoded.extend_from_slice(&[
                b'%',
                digits[usize::from(byte >> 4)],
                digits[usize::from(byte & 0xf)],
            ]);
        }
    }
    encoded
}
