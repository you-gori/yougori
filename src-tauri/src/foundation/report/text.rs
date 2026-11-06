//! Redaction-safe text for the measurement contract (S8: "Redact credentials, prompts and
//! private paths").
//!
//! Records hold short labels, public source URLs, commit hashes and fixture references.
//! There is no free-text field, so a prompt, credential or private path has nowhere to go;
//! content that must be identified is stored as a digest with a disclosure level.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::error::{ReportError, UrlProblem};
use crate::foundation::ids::{digest, Digest};

/// Longest accepted [`Label`].
pub const MAX_LABEL_LEN: usize = 64;

/// Longest accepted [`PublicUrl`].
pub const MAX_URL_LEN: usize = 256;

/// Domain of [`FixtureRef::digesting`].
pub const FIXTURE_DIGEST_DOMAIN: &str = "yougori/report/fixture/v1";

/// An alphanumeric run at least this long that contains a digit reads as an opaque token.
const OPAQUE_RUN_LEN: usize = 24;

/// After a credential prefix, an alphanumeric run at least this long reads as a secret.
const CREDENTIAL_RUN_LEN: usize = 16;

/// Prefixes of common API keys and tokens, compared case-insensitively.
const CREDENTIAL_PREFIXES: &[&str] = &[
    "sk-",
    "sk_",
    "rk_",
    "pk_",
    "hf_",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "glpat-",
    "xoxa-",
    "xoxb-",
    "xoxp-",
    "xoxr-",
    "xoxs-",
    "akia",
    "asia",
    "aiza",
    "ya29.",
    "eyj",
    "npm_",
    "pypi-",
];

/// Host names and top-level labels that never name a public source.
const PRIVATE_HOST_LABELS: &[&str] = &[
    "localhost",
    "local",
    "internal",
    "lan",
    "home",
    "corp",
    "intranet",
    "private",
    "test",
    "invalid",
    "example",
    "arpa",
];

fn alphanumeric_runs(text: &str) -> impl Iterator<Item = &str> {
    text.split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|run| !run.is_empty())
}

fn has_digit(run: &str) -> bool {
    run.bytes().any(|byte| byte.is_ascii_digit())
}

fn looks_like_credential(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let prefixed = CREDENTIAL_PREFIXES
        .iter()
        .any(|prefix| lower.starts_with(prefix));
    alphanumeric_runs(text).any(|run| {
        (run.len() >= OPAQUE_RUN_LEN && has_digit(run))
            || (prefixed && run.len() >= CREDENTIAL_RUN_LEN)
    })
}

fn check_label(value: &str) -> Result<(), ReportError> {
    let first = value.chars().next().ok_or(ReportError::EmptyLabel)?;
    if value
        .chars()
        .any(|character| matches!(character, '/' | '\\' | '~'))
    {
        return Err(ReportError::LooksLikePath);
    }
    if let Some(character) = value.chars().find(|character| {
        !(character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-' | '+' | ':'))
    }) {
        return Err(ReportError::InvalidLabelCharacter { character });
    }
    if value.len() > MAX_LABEL_LEN {
        return Err(ReportError::LabelTooLong { max: MAX_LABEL_LEN });
    }
    if !first.is_ascii_alphanumeric() {
        return Err(ReportError::LabelInvalidStart);
    }
    if first.is_ascii_alphabetic() && value.as_bytes().get(1) == Some(&b':') {
        return Err(ReportError::LooksLikePath);
    }
    if looks_like_credential(value) {
        return Err(ReportError::LooksLikeCredential);
    }
    Ok(())
}

/// A short public label such as an engine name, version, GPU model or region (S8 raw run
/// record). At most 64 ASCII letters, digits, '.', '_', '-', '+' or ':', starting with a
/// letter or digit.
///
/// Redaction by construction (S8): spaces and line breaks are refused, so a prompt cannot
/// be stored; '/', '\\', '~' and drive prefixes such as `C:` are refused, so a path cannot
/// be stored; and credential-shaped values (known key prefixes, long opaque runs with
/// digits) are refused. Digests belong in [`Digest`], never in a label.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Label(String);

impl Label {
    /// Checks `value` against the redaction rules above.
    pub fn new(value: impl Into<String>) -> Result<Self, ReportError> {
        let value = value.into();
        check_label(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Label {
    type Error = ReportError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Label> for String {
    fn from(label: Label) -> Self {
        label.0
    }
}

impl fmt::Debug for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Label({})", self.0)
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn check_host(host: &str) -> Result<(), UrlProblem> {
    if host.is_empty() {
        return Err(UrlProblem::InvalidHost);
    }
    if host == "localhost" {
        return Err(UrlProblem::PrivateHost);
    }
    if host.chars().any(|character| {
        !(character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || matches!(character, '.' | '-'))
    }) {
        return Err(UrlProblem::InvalidHost);
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2
        || labels
            .iter()
            .any(|label| label.is_empty() || label.starts_with('-') || label.ends_with('-'))
    {
        return Err(UrlProblem::InvalidHost);
    }
    let top = labels.last().copied().unwrap_or_default();
    if !top.bytes().any(|byte| byte.is_ascii_lowercase()) {
        return Err(UrlProblem::PrivateHost);
    }
    if PRIVATE_HOST_LABELS.contains(&top) {
        return Err(UrlProblem::PrivateHost);
    }
    Ok(())
}

fn check_public_url(value: &str) -> Result<(), UrlProblem> {
    if value.len() > MAX_URL_LEN {
        return Err(UrlProblem::TooLong);
    }
    let rest = value.strip_prefix("https://").ok_or(UrlProblem::NotHttps)?;
    if rest.contains(['?', '#']) {
        return Err(UrlProblem::QueryOrFragment);
    }
    if rest.contains('@') {
        return Err(UrlProblem::Credentials);
    }
    let (host, path) = match rest.find('/') {
        Some(index) => rest.split_at(index),
        None => (rest, ""),
    };
    check_host(host)?;
    if path.chars().any(|character| {
        !(character.is_ascii_alphanumeric()
            || matches!(character, '-' | '.' | '_' | '~' | '/' | '%'))
    }) {
        return Err(UrlProblem::InvalidCharacter);
    }
    if alphanumeric_runs(path).any(|run| {
        run.len() >= OPAQUE_RUN_LEN
            && has_digit(run)
            && run.bytes().any(|byte| byte.is_ascii_uppercase())
            && run.bytes().any(|byte| byte.is_ascii_lowercase())
    }) {
        return Err(UrlProblem::OpaqueSegment);
    }
    Ok(())
}

/// The public source of a third-party claim or a price list (S7 "Public comparison",
/// BENCH-13 source/date).
///
/// Only `https` URLs to a public host name with a plain path: no user information, query
/// string, fragment, port, IP address, private host or token-shaped path segment, since
/// those are where credentials and private locations travel.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PublicUrl(String);

impl PublicUrl {
    /// Checks `value` against the rules above.
    pub fn new(value: impl Into<String>) -> Result<Self, ReportError> {
        let value = value.into();
        check_public_url(&value).map_err(|problem| ReportError::InvalidPublicUrl { problem })?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for PublicUrl {
    type Error = ReportError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<PublicUrl> for String {
    fn from(url: PublicUrl) -> Self {
        url.0
    }
}

impl fmt::Debug for PublicUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicUrl({})", self.0)
    }
}

impl fmt::Display for PublicUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A source-control commit of a model revision (S8 "model revision"): 40 or 64 lowercase
/// hexadecimal characters.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CommitHash(String);

impl CommitHash {
    /// Accepts 40 or 64 lowercase hexadecimal characters.
    pub fn new(value: impl Into<String>) -> Result<Self, ReportError> {
        let value = value.into();
        let hex = value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if !(hex && matches!(value.len(), 40 | 64)) {
            return Err(ReportError::InvalidCommitHash);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for CommitHash {
    type Error = ReportError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<CommitHash> for String {
    fn from(hash: CommitHash) -> Self {
        hash.0
    }
}

impl fmt::Debug for CommitHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CommitHash({})", self.0)
    }
}

/// Who may see a fixture (S8: "Public artifacts use permitted synthetic or approved
/// fixtures").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Disclosure {
    /// Private content: only its digest is recorded and it never appears in a public
    /// artifact.
    Private,
    /// A fixture approved for publication.
    ApprovedFixture,
    /// Synthetic content generated for testing and permitted for publication.
    PermittedSynthetic,
}

impl Disclosure {
    /// Whether a public artifact may reference the fixture (S8, S12 BENCH-13 review).
    pub const fn is_publishable(self) -> bool {
        !matches!(self, Self::Private)
    }
}

/// A prompt, tool schema or task fixture, identified by id and content digest instead of
/// its text (S8 redaction).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureRef {
    pub id: Label,
    pub digest: Digest,
    pub disclosure: Disclosure,
}

impl FixtureRef {
    /// A fixture whose content digest was computed elsewhere.
    pub fn new(id: Label, digest: Digest, disclosure: Disclosure) -> Self {
        Self {
            id,
            digest,
            disclosure,
        }
    }

    /// Identifies `content` by its digest under [`FIXTURE_DIGEST_DOMAIN`]; the content
    /// itself is not kept.
    pub fn digesting(id: Label, content: &[u8], disclosure: Disclosure) -> Self {
        Self::new(id, digest(FIXTURE_DIGEST_DOMAIN, &[content]), disclosure)
    }
}

/// Names one monotonic clock, such as the host clock or a guest clock (S8 "Use distinct
/// clocks", §2.1 "Use monotonic timestamps"). Times from different clocks are never
/// subtracted from each other.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ClockId(Label);

impl ClockId {
    /// Names a clock, such as `host-monotonic`.
    pub fn new(label: Label) -> Self {
        Self(label)
    }

    pub fn label(&self) -> &Label {
        &self.0
    }
}

impl fmt::Display for ClockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_labels_are_accepted() {
        for value in [
            "vllm",
            "0.29.0",
            "nvidia-rtx-4090",
            "Q4_K_M",
            "us-east-1",
            "llama3:8b",
            "1.2.3+cu124",
            "Apache-2.0",
            "asia-pacific-south-1",
            "sk-hynix-ddr5",
            "internationalization",
        ] {
            assert_eq!(Label::new(value).unwrap().as_str(), value);
        }
    }

    #[test]
    fn paths_cannot_be_labels() {
        for value in [
            "C:\\Users\\Argon\\models\\llama.safetensors",
            "/home/user/.ssh/id_rsa",
            "~/secrets",
            "models/llama",
            "C:model",
            "D:",
        ] {
            assert_eq!(
                Label::new(value),
                Err(ReportError::LooksLikePath),
                "{value}"
            );
        }
    }

    #[test]
    fn prompts_cannot_be_labels() {
        assert_eq!(
            Label::new("Write a poem about the sea"),
            Err(ReportError::InvalidLabelCharacter { character: ' ' })
        );
        assert_eq!(
            Label::new("line1\nline2"),
            Err(ReportError::InvalidLabelCharacter { character: '\n' })
        );
        assert_eq!(
            Label::new("x".repeat(MAX_LABEL_LEN + 1)),
            Err(ReportError::LabelTooLong { max: MAX_LABEL_LEN })
        );
        assert_eq!(Label::new(""), Err(ReportError::EmptyLabel));
        assert_eq!(Label::new("-x"), Err(ReportError::LabelInvalidStart));
    }

    #[test]
    fn credentials_cannot_be_labels() {
        for value in [
            "sk-proj-abcdefghijklmnop1234",
            "hf_AbCdEfGhIjKlMnOpQrStUvWxYz012345",
            "ghp_0123456789abcdefghijABCDEFGHIJ012345",
            "AKIAIOSFODNN7EXAMPLE",
            "eyJhbGciOiJIUzI1NiJ9",
            "x9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4",
        ] {
            assert_eq!(
                Label::new(value),
                Err(ReportError::LooksLikeCredential),
                "{value}"
            );
        }
    }

    #[test]
    fn deserialization_applies_the_same_rules() {
        assert!(serde_json::from_str::<Label>("\"a prompt with spaces\"").is_err());
        assert!(serde_json::from_str::<Label>("\"/etc/passwd\"").is_err());
        assert!(serde_json::from_str::<Label>("\"hf_AbCdEfGhIjKlMnOpQrStUvWxYz012345\"").is_err());
        let label: Label = serde_json::from_str("\"vllm\"").unwrap();
        assert_eq!(serde_json::to_string(&label).unwrap(), "\"vllm\"");
    }

    #[test]
    fn public_urls_are_plain_https_sources() {
        for value in [
            "https://github.com/runloopai/computesdk-benchmarks/blob/master/METHODOLOGY.md",
            "https://docs.vllm.ai/en/v0.31.0/features/sleep_mode/",
            "https://arxiv.org/abs/2607.05147",
            "https://github.com/org/repo/blob/0123456789abcdef0123456789abcdef01234567/README.md",
        ] {
            assert_eq!(PublicUrl::new(value).unwrap().as_str(), value);
        }
        let refused = [
            ("http://example.org/x", UrlProblem::NotHttps),
            ("file:///C:/Users/argon/report.json", UrlProblem::NotHttps),
            ("https://user:token@example.org/x", UrlProblem::Credentials),
            (
                "https://example.org/x?token=abc",
                UrlProblem::QueryOrFragment,
            ),
            (
                "https://example.org/x#access_token=abc",
                UrlProblem::QueryOrFragment,
            ),
            ("https://localhost/x", UrlProblem::PrivateHost),
            ("https://10.0.0.1/x", UrlProblem::PrivateHost),
            ("https://models.internal/x", UrlProblem::PrivateHost),
            ("https://example.org:8443/x", UrlProblem::InvalidHost),
            ("https://Example.org/x", UrlProblem::InvalidHost),
            ("https://example.org/a b", UrlProblem::InvalidCharacter),
            (
                "https://example.org/dl/AbCdEfGhIjKlMnOpQrStUvWx1234",
                UrlProblem::OpaqueSegment,
            ),
        ];
        for (value, problem) in refused {
            assert_eq!(
                PublicUrl::new(value),
                Err(ReportError::InvalidPublicUrl { problem }),
                "{value}"
            );
        }
        assert!(serde_json::from_str::<PublicUrl>("\"https://localhost/x\"").is_err());
    }

    #[test]
    fn fixtures_keep_only_a_digest() {
        let prompt = b"Summarise the attached contract for the board";
        let fixture = FixtureRef::digesting(
            Label::new("contract-summary").unwrap(),
            prompt,
            Disclosure::Private,
        );
        assert_eq!(fixture.digest, digest(FIXTURE_DIGEST_DOMAIN, &[prompt]));
        let json = serde_json::to_string(&fixture).unwrap();
        assert!(!json.contains("contract for the board"));
        assert!(!fixture.disclosure.is_publishable());
        assert!(Disclosure::ApprovedFixture.is_publishable());
        assert!(Disclosure::PermittedSynthetic.is_publishable());
    }

    #[test]
    fn commit_hashes_are_checked() {
        let hash = "0123456789abcdef0123456789abcdef01234567";
        assert_eq!(CommitHash::new(hash).unwrap().as_str(), hash);
        assert!(CommitHash::new(hash.to_uppercase()).is_err());
        assert!(CommitHash::new(&hash[..39]).is_err());
        assert!(CommitHash::new("g".repeat(40)).is_err());
    }
}
