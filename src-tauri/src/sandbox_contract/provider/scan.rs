//! Secret-reflection scanning (VM part §4.5 line 2008; VM-P12).
//!
//! Response-header stripping alone does not stop an endpoint from reflecting a
//! credential in its body, so every response header and the body are scanned for the
//! credential the vault holds, the authorization value composed from it and every known
//! fixture secret or canary. The scan has limited coverage, stated in [`SCAN_COVERAGE`];
//! passing it is not proof that nothing leaked.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::sandbox_contract::effects::CanaryToken;

/// Shortest secret the scanner accepts; shorter needles would match by chance and are
/// too short for the base64 forms.
pub const MIN_SCANNED_SECRET_BYTES: usize = 8;

/// What the scan detects and what it cannot (VM-P12: state the scan's limited coverage).
pub const SCAN_COVERAGE: &str = "Detects a secret of at least 8 bytes verbatim, ASCII \
case-insensitively, as hexadecimal, as standard or URL-safe base64 at any byte alignment, \
fully percent-encoded, and with a JSON-escaped solidus, in each response header name, each \
header value and the body, and in the request the executor builds. It does not detect \
shorter secrets, partial or split reflections (across headers, fields or chunks), other \
encodings (double encoding, base32, quoted-printable, unicode escapes of letters, \
compression, encryption, hashing, reversal), information carried by timing, sizes or \
status codes, or copies outside the bytes scanned (TLS libraries, OS buffers, crash dumps, \
swap). Tier 0 tests run it against fakes only.";

/// The encoding a secret was found in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanEncoding {
    Verbatim,
    AsciiCaseInsensitive,
    Hexadecimal,
    Base64Standard,
    Base64UrlSafe,
    PercentEncoded,
    JsonEscaped,
}

const STANDARD_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_SAFE_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Base64 of whole three-byte groups only, without padding.
fn base64_groups(bytes: &[u8], alphabet: &[u8; 64]) -> Vec<u8> {
    let mut out = Vec::new();
    for group in bytes.chunks_exact(3) {
        let &[a, b, c] = group else {
            continue;
        };
        let indices = [
            a >> 2,
            ((a & 0b11) << 4) | (b >> 4),
            ((b & 0b1111) << 2) | (c >> 6),
            c & 0b11_1111,
        ];
        for index in indices {
            if let Some(&symbol) = alphabet.get(usize::from(index)) {
                out.push(symbol);
            }
        }
    }
    out
}

/// The base64 runs that any encoding of a text containing `secret` must contain: for
/// each of the three alignments, the groups made only of secret bytes.
fn base64_needles(secret: &[u8], alphabet: &[u8; 64]) -> Vec<Vec<u8>> {
    (0..3)
        .filter_map(|shift| {
            let rest = secret.get(shift..)?;
            let whole = rest.len() - rest.len() % 3;
            let groups = rest.get(..whole)?;
            (groups.len() >= 3).then(|| base64_groups(groups, alphabet))
        })
        .collect()
}

fn percent_encode_all(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for &byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte);
        } else {
            out.extend(format!("%{byte:02X}").bytes());
        }
    }
    out
}

fn json_escape_solidus(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for &byte in bytes {
        match byte {
            b'/' => out.extend_from_slice(b"\\/"),
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            _ => out.push(byte),
        }
    }
    out
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn contains_folded(haystack_folded: &[u8], needle: &[u8]) -> bool {
    contains(haystack_folded, &needle.to_ascii_lowercase())
}

/// The first encoding in which `secret` appears in `haystack`, if any. Secrets shorter
/// than [`MIN_SCANNED_SECRET_BYTES`] are not scanned for and never match.
pub fn find_encoded(haystack: &[u8], secret: &[u8]) -> Option<ScanEncoding> {
    if secret.len() < MIN_SCANNED_SECRET_BYTES {
        return None;
    }
    if contains(haystack, secret) {
        return Some(ScanEncoding::Verbatim);
    }
    let folded = haystack.to_ascii_lowercase();
    if contains_folded(&folded, secret) {
        return Some(ScanEncoding::AsciiCaseInsensitive);
    }
    if contains_folded(&folded, hex::encode(secret).as_bytes()) {
        return Some(ScanEncoding::Hexadecimal);
    }
    for (alphabet, encoding) in [
        (STANDARD_ALPHABET, ScanEncoding::Base64Standard),
        (URL_SAFE_ALPHABET, ScanEncoding::Base64UrlSafe),
    ] {
        if base64_needles(secret, alphabet)
            .iter()
            .any(|needle| contains(haystack, needle))
        {
            return Some(encoding);
        }
    }
    if contains_folded(&folded, &percent_encode_all(secret)) {
        return Some(ScanEncoding::PercentEncoded);
    }
    let escaped = json_escape_solidus(secret);
    if escaped != secret && contains(haystack, &escaped) {
        return Some(ScanEncoding::JsonEscaped);
    }
    None
}

strict_provider_enum! {
    /// Where a secret was found. Header positions are indices: a header name that
    /// carries a secret must not be echoed.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum LeakLocation tag "location" {
        RequestLine,
        RequestHeader { index: u32 },
        RequestBody,
        ResponseHeaderName { index: u32 },
        ResponseHeaderValue { index: u32 },
        ResponseBody,
    }
}

/// What was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeakSource {
    /// The credential the vault holds for the operation's scope, or the authorization
    /// value composed from it.
    VaultCredential,
    /// A known fixture secret.
    FixtureSecret,
    Canary,
    /// A response header named like a request credential header, which reflects one.
    CredentialHeaderName,
}

/// One finding; it records where and how, never the secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeakFinding {
    pub location: LeakLocation,
    pub source: LeakSource,
    pub encoding: ScanEncoding,
}

/// The findings of one scan, in a stable order.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeakReport {
    pub findings: Vec<LeakFinding>,
}

impl LeakReport {
    /// Whether nothing was found.
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    pub(super) fn push(&mut self, finding: LeakFinding) {
        if !self.findings.contains(&finding) {
            self.findings.push(finding);
            self.findings.sort();
        }
    }
}

strict_provider_enum! {
    /// Why a secret was not registered for scanning.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ScanRefusal tag "refusal" {
        TooShort { min_bytes: u64 },
    }
}

impl fmt::Display for ScanRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { min_bytes } => {
                write!(f, "a scanned secret needs at least {min_bytes} bytes")
            }
        }
    }
}

impl std::error::Error for ScanRefusal {}

/// Known fixture secrets and canaries every scan also looks for. It is never serialized,
/// and its `Debug` output shows only counts.
#[derive(Clone, Default)]
pub struct KnownSecrets {
    fixtures: Vec<Vec<u8>>,
    canaries: Vec<CanaryToken>,
}

impl fmt::Debug for KnownSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KnownSecrets {{ fixtures: {}, canaries: {} }}",
            self.fixtures.len(),
            self.canaries.len()
        )
    }
}

impl KnownSecrets {
    /// No known secrets yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a fixture secret of at least [`MIN_SCANNED_SECRET_BYTES`] bytes.
    pub fn with_fixture(mut self, secret: &[u8]) -> Result<Self, ScanRefusal> {
        if secret.len() < MIN_SCANNED_SECRET_BYTES {
            return Err(ScanRefusal::TooShort {
                min_bytes: u64::try_from(MIN_SCANNED_SECRET_BYTES).unwrap_or(u64::MAX),
            });
        }
        self.fixtures.push(secret.to_vec());
        Ok(self)
    }

    /// Adds a canary; its marker is scanned for in text form.
    pub fn with_canary(mut self, canary: CanaryToken) -> Self {
        self.canaries.push(canary);
        self
    }

    /// The first known secret found in `haystack`.
    pub fn find(&self, haystack: &[u8]) -> Option<(LeakSource, ScanEncoding)> {
        for fixture in &self.fixtures {
            if let Some(encoding) = find_encoded(haystack, fixture) {
                return Some((LeakSource::FixtureSecret, encoding));
            }
        }
        for canary in &self.canaries {
            if let Some(encoding) = find_encoded(haystack, canary.marker.to_hex().as_bytes()) {
                return Some((LeakSource::Canary, encoding));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::digest;

    const SECRET: &[u8] = b"sk-fixture/Secret+Value=42";

    fn standard_base64(bytes: &[u8]) -> String {
        // Full base64 with padding, for building test haystacks.
        let mut padded = bytes.to_vec();
        let pad = (3 - bytes.len() % 3) % 3;
        padded.extend(std::iter::repeat(0).take(pad));
        let mut text = String::from_utf8(base64_groups(&padded, STANDARD_ALPHABET)).unwrap();
        for _ in 0..pad {
            text.pop();
        }
        text.push_str(&"=".repeat(pad));
        text
    }

    #[test]
    fn each_covered_encoding_is_detected() {
        let cases: Vec<(Vec<u8>, ScanEncoding)> = vec![
            (
                [b"x ".as_slice(), SECRET, b" y"].concat(),
                ScanEncoding::Verbatim,
            ),
            (
                SECRET.to_ascii_uppercase(),
                ScanEncoding::AsciiCaseInsensitive,
            ),
            (
                hex::encode_upper(SECRET).into_bytes(),
                ScanEncoding::Hexadecimal,
            ),
            (
                percent_encode_all(SECRET).to_ascii_lowercase(),
                ScanEncoding::PercentEncoded,
            ),
            (json_escape_solidus(SECRET), ScanEncoding::JsonEscaped),
        ];
        for (haystack, expected) in cases {
            assert_eq!(find_encoded(&haystack, SECRET), Some(expected));
        }
    }

    #[test]
    fn base64_is_detected_at_every_alignment_and_in_both_alphabets() {
        for prefix in ["", "a", "ab", "abc", "Basic dXNlcjo"] {
            let text = [prefix.as_bytes(), SECRET].concat();
            let encoded = standard_base64(&text);
            assert_eq!(
                find_encoded(encoded.as_bytes(), SECRET),
                Some(ScanEncoding::Base64Standard),
                "prefix {prefix:?}"
            );
            let url_safe = encoded.replace('+', "-").replace('/', "_");
            assert!(find_encoded(url_safe.as_bytes(), SECRET).is_some());
        }
    }

    #[test]
    fn limits_of_coverage_are_real() {
        // Too short to scan for.
        assert_eq!(find_encoded(b"abc1234", b"abc1234"), None);
        // Split across two places, or reversed: not detected, as SCAN_COVERAGE says.
        assert_eq!(
            find_encoded(b"sk-fixture/Se ... cret+Value=42", SECRET),
            None
        );
        let reversed: Vec<u8> = SECRET.iter().rev().copied().collect();
        assert_eq!(find_encoded(&reversed, SECRET), None);
        assert!(SCAN_COVERAGE.contains("does not detect"));
    }

    #[test]
    fn known_secrets_find_fixtures_and_canaries_without_showing_them() {
        let canary = CanaryToken {
            marker: digest("yougori/test/canary/v1", &[b"c"]),
        };
        let known = KnownSecrets::new()
            .with_fixture(SECRET)
            .unwrap()
            .with_canary(canary);
        assert_eq!(
            known.find(SECRET),
            Some((LeakSource::FixtureSecret, ScanEncoding::Verbatim))
        );
        assert_eq!(
            known.find(canary.marker.to_hex().as_bytes()),
            Some((LeakSource::Canary, ScanEncoding::Verbatim))
        );
        assert_eq!(known.find(b"nothing secret here"), None);
        let debug = format!("{known:?}");
        assert_eq!(debug, "KnownSecrets { fixtures: 1, canaries: 1 }");
        assert_eq!(
            KnownSecrets::new().with_fixture(b"short").err(),
            Some(ScanRefusal::TooShort { min_bytes: 8 })
        );
    }

    #[test]
    fn leak_reports_hold_locations_never_secrets() {
        let mut report = LeakReport::default();
        report.push(LeakFinding {
            location: LeakLocation::ResponseHeaderValue { index: 2 },
            source: LeakSource::VaultCredential,
            encoding: ScanEncoding::Verbatim,
        });
        report.push(LeakFinding {
            location: LeakLocation::ResponseBody,
            source: LeakSource::FixtureSecret,
            encoding: ScanEncoding::Base64Standard,
        });
        let json = serde_json::to_string(&report).unwrap();
        assert_eq!(serde_json::from_str::<LeakReport>(&json).unwrap(), report);
        assert!(!report.is_clean());
        assert!(
            serde_json::from_str::<LeakLocation>(r#"{"location":"response_body","extra":1}"#)
                .is_err()
        );
    }
}
