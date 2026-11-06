//! Redaction applied before an event leaves its producer (CORE-06 redaction policy).
//!
//! Metadata is logged by default. Credentials, authorization headers, prompts, hidden
//! model reasoning and private paths never leave the producer. Text an untrusted party
//! controls is withheld unless a policy keeps it, and kept text is scanned and bounded
//! (VM part §8.2; GPU part §3.10; S8 "redact credentials, prompts and private paths").

use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::envelope::{check_name, ConfigError, EmitError};
use crate::foundation::ids::{Digest, MonotonicTime};
use crate::foundation::text::is_hazardous;

/// Replaces a credential-like span in kept text.
pub const REDACTED: &str = "[redacted]";
/// Replaces a path-like token in kept text.
pub const REDACTED_PATH: &str = "[redacted-path]";

/// What a field holds, declared by the code that builds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldClass {
    /// Metadata the producer's own code chose: identifiers, counts, fixed labels. Logged
    /// by default (VM part §8.2 "log metadata by default").
    Metadata,
    /// Text a guest, user, model or remote peer controls. Withheld unless the policy keeps
    /// it; kept text is scanned and bounded (§8.2 "bound attacker-controlled log fields").
    Untrusted,
    /// A password, key, token or other secret.
    Credential,
    /// An authorization header of any scheme.
    AuthorizationHeader,
    /// A raw prompt.
    Prompt,
    /// Hidden model reasoning.
    ModelReasoning,
    /// A private filesystem path or name.
    PrivatePath,
}

impl FieldClass {
    /// Whether values of this class never leave their producer (§8.2; §3.10; S8).
    pub const fn is_sensitive(self) -> bool {
        !matches!(self, Self::Metadata | Self::Untrusted)
    }
}

/// A field's value before redaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FieldValue {
    Text(String),
    Unsigned(u64),
    Signed(i64),
    Flag(bool),
    Digest(Digest),
}

impl From<&str> for FieldValue {
    fn from(value: &str) -> Self {
        Self::Text(value.to_owned())
    }
}

impl From<String> for FieldValue {
    fn from(value: String) -> Self {
        Self::Text(value)
    }
}

impl From<u64> for FieldValue {
    fn from(value: u64) -> Self {
        Self::Unsigned(value)
    }
}

impl From<i64> for FieldValue {
    fn from(value: i64) -> Self {
        Self::Signed(value)
    }
}

impl From<bool> for FieldValue {
    fn from(value: bool) -> Self {
        Self::Flag(value)
    }
}

impl From<Digest> for FieldValue {
    fn from(value: Digest) -> Self {
        Self::Digest(value)
    }
}

/// One named field before redaction. Names are compile-time constants, so an attacker
/// never chooses a field name. Its `Debug` output shows only metadata values, so printing
/// a draft cannot leak what redaction would remove.
#[derive(Clone, PartialEq, Eq)]
pub struct Field {
    name: &'static str,
    class: FieldClass,
    value: FieldValue,
}

impl fmt::Debug for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("Field");
        debug.field("name", &self.name).field("class", &self.class);
        if self.class == FieldClass::Metadata {
            debug.field("value", &self.value);
        } else {
            debug.field("value", &"<withheld>");
        }
        debug.finish()
    }
}

impl Field {
    pub fn new(name: &'static str, class: FieldClass, value: impl Into<FieldValue>) -> Self {
        Self {
            name,
            class,
            value: value.into(),
        }
    }

    pub fn metadata(name: &'static str, value: impl Into<FieldValue>) -> Self {
        Self::new(name, FieldClass::Metadata, value)
    }

    pub fn untrusted(name: &'static str, value: impl Into<FieldValue>) -> Self {
        Self::new(name, FieldClass::Untrusted, value)
    }

    pub fn name(&self) -> &'static str {
        self.name
    }

    pub fn class(&self) -> FieldClass {
        self.class
    }
}

strict_tagged_enum! {
    /// A field's value as it leaves the producer.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum RedactedValue (tag = "kind", wire = RedactedValueWire, wire_name = "RedactedValueWire") {
        /// Scanned text, cut to the policy's bound; `full_bytes` is the scanned length
        /// before the cut.
        Text { text: String, full_bytes: u64 },
        Unsigned { value: u64 },
        Signed { value: i64 },
        Flag { value: bool },
        Digest { digest: Digest },
        /// Untrusted content withheld under a metadata-only policy; only its size is kept.
        Withheld { bytes: u64 },
        /// A sensitive value; nothing about it is kept but its class.
        Removed { class: FieldClass },
    }
}

impl RedactedValue {
    /// Whether kept text was cut to the policy's bound.
    pub fn is_truncated(&self) -> bool {
        matches!(self, Self::Text { text, full_bytes } if byte_len(text) < *full_bytes)
    }
}

/// One field as it leaves the producer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedField {
    name: String,
    value: RedactedValue,
}

impl RedactedField {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn value(&self) -> &RedactedValue {
        &self.value
    }
}

/// The fields of one event after redaction, with the number cut by the field bound.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedFields {
    fields: Vec<RedactedField>,
    omitted_fields: u64,
}

impl RedactedFields {
    pub fn fields(&self) -> &[RedactedField] {
        &self.fields
    }

    /// Fields beyond the policy's bound, counted rather than dropped silently.
    pub fn omitted_fields(&self) -> u64 {
        self.omitted_fields
    }

    pub fn get(&self, name: &str) -> Option<&RedactedValue> {
        self.fields
            .iter()
            .find(|field| field.name == name)
            .map(|field| &field.value)
    }
}

/// What a policy does with untrusted content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UntrustedText {
    /// Keep only its size (VM part §8.2 "log metadata by default").
    Withhold,
    /// Keep it scanned and cut to the policy's text bound.
    KeepBounded,
}

/// How a producer redacts fields before they leave it (CORE-06 redaction policy).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RedactionPolicy {
    untrusted_text: UntrustedText,
    max_text_bytes: usize,
    max_fields: usize,
}

impl RedactionPolicy {
    /// Default bound on kept text per field (VM part §8.2 "bound attacker-controlled log
    /// fields").
    pub const DEFAULT_MAX_TEXT_BYTES: usize = 256;
    /// Default bound on fields per event; more are counted, not kept.
    pub const DEFAULT_MAX_FIELDS: usize = 32;

    /// Metadata only: untrusted content is withheld and sensitive classes removed.
    pub const fn metadata_only() -> Self {
        Self {
            untrusted_text: UntrustedText::Withhold,
            max_text_bytes: Self::DEFAULT_MAX_TEXT_BYTES,
            max_fields: Self::DEFAULT_MAX_FIELDS,
        }
    }

    /// Also keeps untrusted text, scanned and bounded.
    pub const fn keeping_untrusted_text(mut self) -> Self {
        self.untrusted_text = UntrustedText::KeepBounded;
        self
    }

    pub const fn with_max_text_bytes(mut self, max_text_bytes: usize) -> Self {
        self.max_text_bytes = max_text_bytes;
        self
    }

    pub const fn with_max_fields(mut self, max_fields: usize) -> Self {
        self.max_fields = max_fields;
        self
    }

    pub const fn untrusted_text(&self) -> UntrustedText {
        self.untrusted_text
    }

    /// Redacts `fields`. Every name must fit the identifier grammar and appear once;
    /// fields past the bound are counted in [`RedactedFields::omitted_fields`].
    pub fn redact(&self, fields: Vec<Field>) -> Result<RedactedFields, EmitError> {
        let mut names = BTreeSet::new();
        for field in &fields {
            check_name(field.name).map_err(|error| EmitError::InvalidName {
                name: field.name,
                error,
            })?;
            if !names.insert(field.name) {
                return Err(EmitError::DuplicateField { name: field.name });
            }
        }
        let total = fields.len();
        let kept: Vec<RedactedField> = fields
            .into_iter()
            .take(self.max_fields)
            .map(|field| self.redact_field(field))
            .collect();
        Ok(RedactedFields {
            omitted_fields: u64::try_from(total.saturating_sub(kept.len())).unwrap_or(u64::MAX),
            fields: kept,
        })
    }

    /// Redacts fields that came from a guest or other untrusted party: whatever class they
    /// were declared with, nothing in them is treated as the producer's own metadata.
    pub(super) fn redact_untrusted(&self, fields: Vec<Field>) -> Result<RedactedFields, EmitError> {
        self.redact(
            fields
                .into_iter()
                .map(|field| match field.class {
                    FieldClass::Metadata => Field {
                        class: FieldClass::Untrusted,
                        ..field
                    },
                    _ => field,
                })
                .collect(),
        )
    }

    fn redact_field(&self, field: Field) -> RedactedField {
        let untrusted = field.class == FieldClass::Untrusted;
        let withhold = untrusted && self.untrusted_text == UntrustedText::Withhold;
        let value = match field.value {
            _ if field.class.is_sensitive() => RedactedValue::Removed { class: field.class },
            FieldValue::Unsigned(value) => RedactedValue::Unsigned { value },
            FieldValue::Signed(value) => RedactedValue::Signed { value },
            FieldValue::Flag(value) => RedactedValue::Flag { value },
            FieldValue::Digest(_) if withhold => RedactedValue::Withheld { bytes: 32 },
            FieldValue::Digest(digest) => RedactedValue::Digest { digest },
            FieldValue::Text(text) if withhold => RedactedValue::Withheld {
                bytes: byte_len(&text),
            },
            FieldValue::Text(text) => {
                let scanned = scrub(&text);
                RedactedValue::Text {
                    text: cut(&scanned, self.max_text_bytes).to_owned(),
                    full_bytes: byte_len(&scanned),
                }
            }
        };
        RedactedField {
            name: field.name.to_owned(),
            value,
        }
    }
}

impl Default for RedactionPolicy {
    fn default() -> Self {
        Self::metadata_only()
    }
}

/// At most `max_events` events per `window` from one producer (VM part §8.2 "bound
/// attacker-controlled log fields and emission rate"). Read back only through
/// [`EmissionLimit::new`]'s checks, so a stored limit is never zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "EmissionLimitRecord", into = "EmissionLimitRecord")]
pub struct EmissionLimit {
    max_events: u32,
    window: Duration,
}

/// The stored form of an [`EmissionLimit`].
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmissionLimitRecord {
    max_events: u32,
    window: Duration,
}

impl TryFrom<EmissionLimitRecord> for EmissionLimit {
    type Error = ConfigError;

    fn try_from(record: EmissionLimitRecord) -> Result<Self, Self::Error> {
        Self::new(record.max_events, record.window)
    }
}

impl From<EmissionLimit> for EmissionLimitRecord {
    fn from(limit: EmissionLimit) -> Self {
        Self {
            max_events: limit.max_events,
            window: limit.window,
        }
    }
}

impl EmissionLimit {
    pub fn new(max_events: u32, window: Duration) -> Result<Self, ConfigError> {
        if max_events == 0 {
            return Err(ConfigError::Zero {
                setting: "max_events",
            });
        }
        if window.is_zero() {
            return Err(ConfigError::Zero { setting: "window" });
        }
        Ok(Self { max_events, window })
    }

    pub fn max_events(&self) -> u32 {
        self.max_events
    }

    pub fn window(&self) -> Duration {
        self.window
    }
}

/// Counts events in fixed windows of an [`EmissionLimit`] on the producer's clock. Public
/// so other bounded emitters apply the same rule instead of copying it.
#[derive(Clone, Copy, Debug)]
pub struct RateLimiter {
    limit: EmissionLimit,
    window_start: Option<MonotonicTime>,
    used: u32,
}

impl RateLimiter {
    pub fn new(limit: EmissionLimit) -> Self {
        Self {
            limit,
            window_start: None,
            used: 0,
        }
    }

    /// Admits one event at `now`, or says how long until the window ends.
    pub fn admit(&mut self, now: MonotonicTime) -> Result<(), Duration> {
        if let Some(start) = self.window_start {
            let elapsed = now.saturating_duration_since(start);
            if elapsed < self.limit.window {
                if self.used < self.limit.max_events {
                    self.used += 1;
                    return Ok(());
                }
                return Err(self.limit.window.saturating_sub(elapsed));
            }
        }
        self.window_start = Some(now);
        self.used = 1;
        Ok(())
    }
}

fn byte_len(text: &str) -> u64 {
    u64::try_from(text.len()).unwrap_or(u64::MAX)
}

/// The longest prefix of `text` of at most `max_bytes` that ends on a character boundary.
fn cut(text: &str, max_bytes: usize) -> &str {
    let mut end = max_bytes.min(text.len());
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text.get(..end).unwrap_or("")
}

/// Key names whose values are secrets, matched as suffixes after lowercasing and mapping
/// '-' to '_'. Any key that is `key` or ends in `_key` also matches.
const CREDENTIAL_KEY_SUFFIXES: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "apikey",
    "credential",
    "credentials",
    "authorization",
    "auth",
    "cookie",
    "session",
    "sessionid",
    "session_id",
    "signature",
];

/// Prefixes of well-known credential formats.
const SECRET_PREFIXES: &[&str] = &[
    "sk-",
    "sk_",
    "ghp_",
    "gho_",
    "ghs_",
    "ghu_",
    "github_pat_",
    "hf_",
    "xoxb-",
    "xoxp-",
    "glpat-",
    "akia",
];

/// Scans text a policy keeps. Hazardous characters go, lines are joined with spaces, and
/// credential-like spans and path-like tokens become markers. This is a second line of
/// defence: declared classes and the default withholding of untrusted text come first.
fn scrub(text: &str) -> String {
    let visible: String = text
        .chars()
        .filter(|&character| !is_dropped(character))
        .collect();
    let mut tokens = Vec::new();
    for line in visible.split(['\n', '\r']) {
        scrub_line(line, &mut tokens);
    }
    tokens.join(" ")
}

/// What the scan drops: every character `foundation::text` judges hazardous (controls,
/// bidirectional, zero-width and other invisible characters, private-use and unprintable
/// ones), except line breaks, tabs and the other non-control spacing the scan splits lines
/// and tokens on (VM part §8.2 line 2371: "bound attacker-controlled log fields").
fn is_dropped(character: char) -> bool {
    let separator = matches!(character, '\n' | '\r' | '\t')
        || (character.is_whitespace() && !character.is_control());
    !separator && is_hazardous(character)
}

enum Scrubbed {
    Keep(String),
    /// Keep this token and replace the next one.
    KeepThenNext(String),
    /// Keep this token and replace the rest of the line.
    KeepThenRest(String),
}

fn scrub_line(line: &str, out: &mut Vec<String>) {
    let mut tokens = line.split_whitespace();
    while let Some(token) = tokens.next() {
        match scrub_token(token) {
            Scrubbed::Keep(kept) => out.push(kept),
            Scrubbed::KeepThenNext(kept) => {
                out.push(kept);
                if tokens.next().is_some() {
                    out.push(REDACTED.to_owned());
                }
            }
            Scrubbed::KeepThenRest(kept) => {
                let marked = kept.ends_with(REDACTED);
                out.push(kept);
                if !marked && tokens.next().is_some() {
                    out.push(REDACTED.to_owned());
                }
                return;
            }
        }
    }
}

fn scrub_token(token: &str) -> Scrubbed {
    let lowered = token.to_ascii_lowercase();
    if matches!(
        lowered.as_str(),
        "bearer" | "basic" | "digest" | "negotiate"
    ) {
        return Scrubbed::KeepThenNext(token.to_owned());
    }
    if let Some(scheme_end) = token.find("://") {
        return Scrubbed::Keep(scrub_url(token, scheme_end));
    }
    if let Some((key, rest)) = token
        .find(['=', ':'])
        .and_then(|separator| token.split_at_checked(separator))
    {
        let key_name = normalize_key(key);
        if is_credential_key(&key_name) {
            let separator = rest.get(..1).unwrap_or("");
            let value = rest.get(1..).unwrap_or("");
            let kept = format!("{key}{separator}");
            // A header value runs to the end of the line, whatever its spacing.
            let header = key_name.ends_with("authorization") || key_name.ends_with("cookie");
            return if value.is_empty() {
                Scrubbed::KeepThenRest(kept)
            } else if header {
                Scrubbed::KeepThenRest(format!("{kept}{REDACTED}"))
            } else {
                Scrubbed::Keep(format!("{kept}{REDACTED}"))
            };
        }
    }
    let core = token.trim_matches(|character: char| {
        matches!(
            character,
            '"' | '\'' | '`' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>' | ',' | ';'
        )
    });
    if looks_like_path(core) {
        return Scrubbed::Keep(REDACTED_PATH.to_owned());
    }
    if looks_like_secret(core) {
        return Scrubbed::Keep(REDACTED.to_owned());
    }
    Scrubbed::Keep(token.to_owned())
}

/// A key without surrounding quotes or brackets, lowercased, with '-' mapped to '_'.
fn normalize_key(key: &str) -> String {
    key.trim_matches(|character: char| {
        !character.is_ascii_alphanumeric() && character != '_' && character != '-'
    })
    .chars()
    .map(|character| {
        if character == '-' {
            '_'
        } else {
            character.to_ascii_lowercase()
        }
    })
    .collect()
}

fn is_credential_key(normalized: &str) -> bool {
    !normalized.is_empty()
        && (normalized == "key"
            || normalized.ends_with("_key")
            || CREDENTIAL_KEY_SUFFIXES
                .iter()
                .any(|suffix| normalized.ends_with(suffix)))
}

/// Keeps a URL's scheme and host only: user information becomes a marker, and any path,
/// query or fragment is replaced, since either can carry tokens or private names. A
/// `file:` URL is a path.
fn scrub_url(token: &str, scheme_end: usize) -> String {
    let (scheme, rest) = token.split_at_checked(scheme_end).unwrap_or((token, ""));
    if scheme
        .trim_start_matches(|character: char| !character.is_ascii_alphanumeric())
        .eq_ignore_ascii_case("file")
    {
        return REDACTED_PATH.to_owned();
    }
    let rest = rest.get(3..).unwrap_or("");
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at_checked(authority_end).unwrap_or((rest, ""));
    let mut out = format!("{scheme}://");
    match authority.rfind('@') {
        Some(at) => {
            out.push_str(REDACTED);
            out.push('@');
            out.push_str(authority.get(at + 1..).unwrap_or(""));
        }
        None => out.push_str(authority),
    }
    let tail = tail.trim_end_matches(|character: char| {
        matches!(
            character,
            '/' | '"' | '\'' | ')' | ']' | '>' | ',' | ';' | '.'
        )
    });
    if !tail.is_empty() {
        out.push('/');
        out.push_str(REDACTED);
    }
    out
}

fn looks_like_path(token: &str) -> bool {
    let drive = matches!(
        token.as_bytes(),
        [letter, b':', b'\\' | b'/', ..] if letter.is_ascii_alphabetic()
    );
    drive || token.starts_with('~') || token.contains('/') || token.contains('\\')
}

fn looks_like_secret(token: &str) -> bool {
    let lowered = token.to_ascii_lowercase();
    if token.len() >= 20
        && SECRET_PREFIXES
            .iter()
            .any(|prefix| lowered.starts_with(prefix))
    {
        return true;
    }
    token.len() >= 32
        && token.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '+' | '=' | '.')
        })
        && token.chars().any(|character| character.is_ascii_digit())
        && token
            .chars()
            .any(|character| character.is_ascii_alphabetic())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::{digest, IdError};

    fn text(value: &RedactedValue) -> &str {
        match value {
            RedactedValue::Text { text, .. } => text,
            other => panic!("expected text, found {other:?}"),
        }
    }

    #[test]
    fn metadata_is_kept_and_untrusted_text_is_withheld_by_default() {
        let policy = RedactionPolicy::default();
        assert_eq!(policy, RedactionPolicy::metadata_only());
        let artifact = digest("yougori/test/artifact/v1", &[b"weights"]);
        let fields = policy
            .redact(vec![
                Field::metadata("loader", "safetensors"),
                Field::metadata("bytes", 4_096u64),
                Field::metadata("delta", -3i64),
                Field::metadata("warm", true),
                Field::metadata("artifact", artifact),
                Field::untrusted("guest_stdout", "ready after 3s"),
                Field::untrusted("guest_count", 7u64),
                Field::untrusted("guest_digest", artifact),
            ])
            .unwrap();
        assert_eq!(text(fields.get("loader").unwrap()), "safetensors");
        assert_eq!(
            fields.get("bytes"),
            Some(&RedactedValue::Unsigned { value: 4_096 })
        );
        assert_eq!(
            fields.get("delta"),
            Some(&RedactedValue::Signed { value: -3 })
        );
        assert_eq!(
            fields.get("warm"),
            Some(&RedactedValue::Flag { value: true })
        );
        assert_eq!(
            fields.get("artifact"),
            Some(&RedactedValue::Digest { digest: artifact })
        );
        assert_eq!(
            fields.get("guest_stdout"),
            Some(&RedactedValue::Withheld { bytes: 14 })
        );
        assert_eq!(
            fields.get("guest_count"),
            Some(&RedactedValue::Unsigned { value: 7 })
        );
        assert_eq!(
            fields.get("guest_digest"),
            Some(&RedactedValue::Withheld { bytes: 32 })
        );
    }

    #[test]
    fn sensitive_classes_never_leave_the_producer() {
        let secrets = [
            (FieldClass::Credential, "hunter2-password"),
            (FieldClass::AuthorizationHeader, "Bearer abc.def.ghi"),
            (FieldClass::Prompt, "summarise my medical history"),
            (FieldClass::ModelReasoning, "the user seems to be lying"),
            (FieldClass::PrivatePath, "C:\\Users\\alice\\secret-model"),
        ];
        // Even a policy that keeps untrusted text removes every sensitive class.
        let policy = RedactionPolicy::metadata_only().keeping_untrusted_text();
        let names = ["credential", "authorization", "prompt", "reasoning", "path"];
        let fields = policy
            .redact(
                secrets
                    .iter()
                    .zip(names)
                    .map(|((class, value), name)| Field::new(name, *class, *value))
                    .collect(),
            )
            .unwrap();
        let json = serde_json::to_string(&fields).unwrap();
        for ((class, value), name) in secrets.iter().zip(names) {
            assert_eq!(
                fields.get(name),
                Some(&RedactedValue::Removed { class: *class })
            );
            assert!(!json.contains(value), "{value} leaked into {json}");
        }
        assert!(!json.contains("hunter2"));
        // A sensitive number is removed too.
        let pin = policy
            .redact(vec![Field::new("pin", FieldClass::Credential, 1234u64)])
            .unwrap();
        assert_eq!(
            pin.get("pin"),
            Some(&RedactedValue::Removed {
                class: FieldClass::Credential
            })
        );
    }

    #[test]
    fn kept_text_loses_credentials() {
        let cases = [
            ("password=hunter2 ok", "password=[redacted] ok"),
            ("db_password: hunter2", "db_password: [redacted]"),
            ("Authorization: Bearer abc def", "Authorization: [redacted]"),
            ("Authorization:Bearer abc def", "Authorization:[redacted]"),
            ("set-cookie:sid=1 theme=dark", "set-cookie:[redacted]"),
            ("Cookie: sid=1; theme=dark", "Cookie: [redacted]"),
            ("X-Api-Key: k1 k2", "X-Api-Key: [redacted]"),
            ("using Bearer abc123 then", "using Bearer [redacted] then"),
            ("{\"api_key\":\"zzz\"}", "{\"api_key\":[redacted]"),
            (
                "AWS_SECRET_ACCESS_KEY=abc",
                "AWS_SECRET_ACCESS_KEY=[redacted]",
            ),
            ("refresh_token=r1&x=2", "refresh_token=[redacted]"),
            (
                "fetch https://user:pw@example.com/a/b?token=1",
                "fetch https://[redacted]@example.com/[redacted]",
            ),
            ("see https://example.com/", "see https://example.com"),
            ("key ghp_abcdefghijklmnopqrstuvwxyz", "key [redacted]"),
            (
                "id 0123456789abcdef0123456789abcdef01234567",
                "id [redacted]",
            ),
            ("tokenizer=llama count=5", "tokenizer=llama count=5"),
        ];
        for (input, expected) in cases {
            assert_eq!(scrub(input), expected, "input {input:?}");
        }
    }

    #[test]
    fn kept_text_loses_private_paths() {
        let cases = [
            "C:\\Users\\alice\\model.bin",
            "c:/models/x",
            "/home/alice/.cache",
            "~/models",
            "\\\\server\\share",
            "projects/acme/weights",
            "\"/Users/bob/key.pem\"",
        ];
        for input in cases {
            assert_eq!(scrub(input), REDACTED_PATH, "input {input:?}");
        }
        assert_eq!(
            scrub("open file:///etc/passwd now"),
            "open [redacted-path] now"
        );
    }

    #[test]
    fn attacker_controlled_fields_are_bounded() {
        let policy = RedactionPolicy::metadata_only()
            .keeping_untrusted_text()
            .with_max_text_bytes(8)
            .with_max_fields(2);
        let fields = policy
            .redact(vec![
                Field::untrusted("a", "ééééé"),
                Field::untrusted("b", "line\nbreak\u{202E}\u{200B}\u{1b}[31m"),
                Field::untrusted("c", "dropped"),
            ])
            .unwrap();
        // 'é' is two bytes, so the cut lands on a character boundary at 8 bytes.
        let a = fields.get("a").unwrap();
        assert_eq!(text(a), "éééé");
        assert!(a.is_truncated());
        // Line breaks join, and control, bidirectional and zero-width characters go.
        assert_eq!(
            scrub("line\nbreak\u{202E}\u{200B}\u{1b}[31m"),
            "line break[31m"
        );
        assert_eq!(text(fields.get("b").unwrap()), "line bre");
        // The third field is past the bound and counted, not dropped silently.
        assert_eq!(fields.fields().len(), 2);
        assert_eq!(fields.omitted_fields(), 1);
        assert!(fields.get("c").is_none());
        assert_eq!(cut("abc", 0), "");
        // A zero-width character cannot split a marker to hide it.
        assert_eq!(scrub("pass\u{200B}word=x"), "password=[redacted]");
    }

    #[test]
    fn printing_a_draft_shows_no_value_redaction_would_remove() {
        let secret = format!(
            "{:?}",
            Field::new("token", FieldClass::Credential, "hunter2")
        );
        assert!(!secret.contains("hunter2"), "{secret}");
        let guest = format!("{:?}", Field::untrusted("stdout", "my prompt"));
        assert!(!guest.contains("my prompt"), "{guest}");
        let metadata = format!("{:?}", Field::metadata("loader", "safetensors"));
        assert!(metadata.contains("safetensors"), "{metadata}");
    }

    #[test]
    fn untrusted_fields_cannot_pose_as_metadata() {
        let fields = RedactionPolicy::metadata_only()
            .redact_untrusted(vec![Field::metadata("claimed", "I am metadata")])
            .unwrap();
        assert_eq!(
            fields.get("claimed"),
            Some(&RedactedValue::Withheld { bytes: 13 })
        );
    }

    #[test]
    fn field_names_are_checked_and_unique() {
        let policy = RedactionPolicy::metadata_only();
        assert_eq!(
            policy.redact(vec![Field::metadata("bad name", 1u64)]),
            Err(EmitError::InvalidName {
                name: "bad name",
                error: IdError::InvalidCharacter { character: ' ' }
            })
        );
        assert_eq!(
            policy.redact(vec![Field::metadata("x", 1u64), Field::metadata("x", 2u64)]),
            Err(EmitError::DuplicateField { name: "x" })
        );
    }

    #[test]
    fn redacted_values_refuse_unknown_fields() {
        let value: RedactedValue =
            serde_json::from_str(r#"{"kind":"withheld","bytes":3}"#).unwrap();
        assert_eq!(value, RedactedValue::Withheld { bytes: 3 });
        assert!(serde_json::from_str::<RedactedValue>(
            r#"{"kind":"withheld","bytes":3,"text":"x"}"#
        )
        .is_err());
        assert_eq!(
            serde_json::to_value(RedactedValue::Removed {
                class: FieldClass::Prompt
            })
            .unwrap(),
            serde_json::json!({"kind": "removed", "class": "prompt"})
        );
    }

    #[test]
    fn emission_rate_is_bounded_per_window() {
        assert_eq!(
            EmissionLimit::new(0, Duration::from_secs(1)),
            Err(ConfigError::Zero {
                setting: "max_events"
            })
        );
        assert_eq!(
            EmissionLimit::new(1, Duration::ZERO),
            Err(ConfigError::Zero { setting: "window" })
        );
        let limit = EmissionLimit::new(3, Duration::from_secs(1)).unwrap();
        let mut limiter = RateLimiter::new(limit);
        let start = MonotonicTime::from_nanos(1_000);
        for _ in 0..3 {
            assert_eq!(limiter.admit(start), Ok(()));
        }
        let later = start.saturating_add(Duration::from_millis(400));
        assert_eq!(limiter.admit(later), Err(Duration::from_millis(600)));
        let next_window = start.saturating_add(Duration::from_secs(1));
        assert_eq!(limiter.admit(next_window), Ok(()));
    }

    #[test]
    fn a_stored_emission_limit_reads_back_only_through_its_checks() {
        let limit = EmissionLimit::new(5, Duration::from_millis(250)).unwrap();
        let stored = serde_json::to_value(limit).unwrap();
        assert_eq!(
            stored,
            serde_json::json!({
                "max_events": 5,
                "window": { "secs": 0, "nanos": 250_000_000 }
            })
        );
        let read: EmissionLimit = serde_json::from_value(stored).unwrap();
        assert_eq!(read, limit);
        let zero = serde_json::json!({
            "max_events": 0,
            "window": { "secs": 1, "nanos": 0 }
        });
        assert!(serde_json::from_value::<EmissionLimit>(zero).is_err());
        let extra = serde_json::json!({
            "max_events": 5,
            "window": { "secs": 1, "nanos": 0 },
            "burst": 9
        });
        assert!(serde_json::from_value::<EmissionLimit>(extra).is_err());
    }
}
