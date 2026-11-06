//! Destination names, ports and authorities under one parser (VM §4.2 steps 1–2).
//!
//! Every hostname the broker sees — a requested destination, a TLS server name, an HTTP
//! authority, a redirect target and a policy grant — goes through [`CanonicalName::parse`]
//! or [`Authority::parse`], so review, authorization and outbound use cannot disagree
//! about which name is meant (VM §4.3: no parser disagreement).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::punycode;

/// Longest accepted name in bytes, without a trailing dot (RFC 1035).
pub const MAX_NAME_BYTES: usize = 253;
/// Longest accepted label in bytes (RFC 1035).
pub const MAX_LABEL_BYTES: usize = 63;
/// Fewest labels in a destination name. A single label is what a guest resolver would
/// complete with its search suffixes, so it is never accepted (VM §4.2 step 3).
pub const MIN_LABELS: usize = 2;

/// Which IP-literal spelling was found where a name or address was expected (VM §4.2
/// step 2: unsupported IP literals are rejected).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IpLiteralForm {
    /// A canonical dotted quad in a name position. As an authority it is an address and
    /// needs an exact endpoint grant.
    DottedQuadAsName,
    /// Fewer than four parts, such as `127.1`.
    ShortIpv4,
    /// A part with a leading zero, which `inet_aton` and URL parsers read as octal.
    OctalIpv4,
    /// A part written in hexadecimal, such as `0x7f.0.0.1`.
    HexIpv4,
    /// One decimal integer, such as `2130706433`.
    DecimalIntegerIpv4,
    /// Four decimal parts with one above 255, or more than four numeric parts.
    MalformedIpv4,
    /// A name whose last label is numeric, which URL parsers try to read as IPv4.
    NumericFinalLabel,
    /// An IPv6 address without brackets.
    UnbracketedIpv6,
    /// An IPv6 address not in the RFC 5952 canonical text form.
    NonCanonicalIpv6,
    /// An IPv6 address with a zone identifier, which names a host interface.
    Ipv6ZoneId,
}

impl IpLiteralForm {
    const fn describe(self) -> &'static str {
        match self {
            Self::DottedQuadAsName => "an IPv4 address where a name is required",
            Self::ShortIpv4 => "a short IPv4 form",
            Self::OctalIpv4 => "an IPv4 part with a leading zero (read as octal elsewhere)",
            Self::HexIpv4 => "a hexadecimal IPv4 form",
            Self::DecimalIntegerIpv4 => "an IPv4 address written as one integer",
            Self::MalformedIpv4 => "a malformed IPv4 form",
            Self::NumericFinalLabel => "a numeric last label",
            Self::UnbracketedIpv6 => "an IPv6 address without brackets",
            Self::NonCanonicalIpv6 => "an IPv6 address not in RFC 5952 form",
            Self::Ipv6ZoneId => "an IPv6 zone identifier",
        }
    }
}

/// Why an A-label (`xn--`) was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ALabelProblem {
    /// Nothing follows `xn--`.
    Empty,
    /// The Punycode does not decode.
    Undecodable,
    /// It decodes to ASCII only, which must be written as plain ASCII.
    AsciiOnly,
    /// It decodes to a control, format, space, dot-like, bidirectional or zero-width
    /// character, an uppercase letter or an invalid code point.
    DisallowedCodePoint,
    /// Re-encoding the decoded label gives a different spelling, so two A-labels could
    /// name one U-label.
    NotCanonical,
}

/// Why a name, port or authority was refused (VM §4.2 step 2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NameError {
    Empty,
    TooLong {
        bytes: usize,
    },
    EmptyLabel,
    LabelTooLong {
        bytes: usize,
    },
    /// One label only; a resolver would expand it with guest search suffixes.
    SingleLabel,
    /// A trailing dot spells the same DNS name differently for TLS and HTTP.
    TrailingDot,
    HyphenAtLabelEdge {
        label: String,
    },
    /// Hyphens in the third and fourth positions are reserved for A-labels.
    ReservedHyphenLabel {
        label: String,
    },
    InvalidCharacter {
        character: char,
    },
    /// A non-ASCII name: U-labels cannot be validated without IDNA tables, so only
    /// A-labels are accepted.
    NonAscii,
    /// Percent-encoding inside a host is an ambiguous spelling.
    AmbiguousEncoding,
    /// `user@host` or `user:password@host`.
    Userinfo,
    IpLiteral {
        form: IpLiteralForm,
    },
    InvalidALabel {
        label: String,
        problem: ALabelProblem,
    },
    /// Not a decimal port 1–65535 without sign or leading zeros.
    InvalidPort {
        text: String,
    },
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("the destination name is empty"),
            Self::TooLong { bytes } => write!(
                f,
                "the name is {bytes} bytes long; at most {MAX_NAME_BYTES} are allowed"
            ),
            Self::EmptyLabel => f.write_str("the name has an empty label"),
            Self::LabelTooLong { bytes } => write!(
                f,
                "a label is {bytes} bytes long; at most {MAX_LABEL_BYTES} are allowed"
            ),
            Self::SingleLabel => f.write_str(
                "a single-label name would be completed with guest search suffixes; give the \
                 full name",
            ),
            Self::TrailingDot => f.write_str("remove the trailing dot; names are always absolute"),
            Self::HyphenAtLabelEdge { label } => {
                write!(f, "the label {label:?} starts or ends with a hyphen")
            }
            Self::ReservedHyphenLabel { label } => write!(
                f,
                "the label {label:?} has hyphens in positions 3 and 4, reserved for A-labels"
            ),
            Self::InvalidCharacter { character } => {
                write!(f, "the destination contains {character:?}")
            }
            Self::NonAscii => f.write_str(
                "internationalized names must be given as A-labels (xn--); U-labels are not \
                 validated",
            ),
            Self::AmbiguousEncoding => f.write_str("percent-encoding is not allowed in a host"),
            Self::Userinfo => f.write_str("user information before '@' is not allowed"),
            Self::IpLiteral { form } => write!(f, "unsupported IP literal: {}", form.describe()),
            Self::InvalidALabel { label, problem } => {
                write!(f, "the A-label {label:?} is invalid ({problem:?})")
            }
            Self::InvalidPort { text } => write!(
                f,
                "{text:?} is not a port; use a decimal number 1-65535 without leading zeros"
            ),
        }
    }
}

impl std::error::Error for NameError {}

/// A destination hostname in its one canonical form (VM §4.2 step 1): lowercase ASCII
/// letter-digit-hyphen labels, A-labels for internationalized names, at least
/// [`MIN_LABELS`] labels, no trailing dot and no IP-literal spelling.
///
/// ASCII case is folded because DNS, TLS name matching and HTTP hosts are all
/// case-insensitive for ASCII (RFC 4343); a mixed-case request therefore names exactly
/// one canonical name. Non-ASCII case cannot be folded without Unicode tables, so
/// non-ASCII input is refused.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalName(String);

impl CanonicalName {
    /// Parses and canonicalizes a hostname, refusing every form listed in [`NameError`].
    pub fn parse(text: &str) -> Result<Self, NameError> {
        if text.is_empty() {
            return Err(NameError::Empty);
        }
        check_host_characters(text)?;
        if text.ends_with('.') {
            return Err(NameError::TrailingDot);
        }
        if text.len() > MAX_NAME_BYTES {
            return Err(NameError::TooLong { bytes: text.len() });
        }
        let lower = text.to_ascii_lowercase();
        if let Some(form) = ipv4_literal_form(&lower) {
            return Err(NameError::IpLiteral {
                form: match form {
                    Ipv4Literal::Canonical(_) => IpLiteralForm::DottedQuadAsName,
                    Ipv4Literal::Other(form) => form,
                },
            });
        }
        let mut labels = 0usize;
        for label in lower.split('.') {
            check_label(label)?;
            labels += 1;
        }
        if labels < MIN_LABELS {
            return Err(NameError::SingleLabel);
        }
        Ok(Self(lower))
    }

    /// The canonical text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The labels from left to right.
    pub fn labels(&self) -> impl Iterator<Item = &str> {
        self.0.split('.')
    }

    pub fn label_count(&self) -> usize {
        self.labels().count()
    }

    /// True when this name lies strictly below `zone` (never equal to it).
    pub fn is_below(&self, zone: &CanonicalName) -> bool {
        self.0.len() > zone.0.len()
            && self.0.ends_with(zone.as_str())
            && self.0.as_bytes()[self.0.len() - zone.0.len() - 1] == b'.'
    }

    /// True when this name is exactly one label below `zone`.
    pub fn is_one_label_below(&self, zone: &CanonicalName) -> bool {
        self.is_below(zone) && self.label_count() == zone.label_count() + 1
    }

    /// Length of the name in DNS wire form (RFC 1035 QNAME): one length byte per label,
    /// the label bytes and the root byte. DNS queries count as released bytes (VM §2.5).
    pub fn wire_length_bytes(&self) -> u64 {
        self.labels()
            .map(|label| label.len() as u64 + 1)
            .sum::<u64>()
            + 1
    }

    /// The special-use or private suffix this name falls under, if any (RFC 6761, RFC
    /// 8375, ICANN's `.internal`). Such names never resolve through public DNS to a
    /// public service; a destination there needs an exact endpoint grant (VM §4.2).
    pub fn special_use_suffix(&self) -> Option<&'static str> {
        SPECIAL_USE_SUFFIXES.iter().copied().find(|suffix| {
            self.0 == *suffix
                || (self.0.len() > suffix.len()
                    && self.0.ends_with(suffix)
                    && self.0.as_bytes()[self.0.len() - suffix.len() - 1] == b'.')
        })
    }
}

/// Suffixes that are special-use, private-use or locally scoped; names under them are
/// refused as resolution-based grants.
const SPECIAL_USE_SUFFIXES: &[&str] = &[
    "localhost",
    "local",
    "internal",
    "home.arpa",
    "in-addr.arpa",
    "ip6.arpa",
    "onion",
    "invalid",
    "test",
    "example",
    "alt",
    "localdomain",
    "home",
    "lan",
    "corp",
    "intranet",
    "private",
    "metadata.goog",
];

impl fmt::Debug for CanonicalName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CanonicalName({})", self.0)
    }
}

impl fmt::Display for CanonicalName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for CanonicalName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for CanonicalName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let name = Self::parse(&text).map_err(serde::de::Error::custom)?;
        if name.0 != text {
            return Err(serde::de::Error::custom(
                "a stored name must already be canonical (lowercase)",
            ));
        }
        Ok(name)
    }
}

/// Refuses characters no host spelling may contain, before any other check.
fn check_host_characters(text: &str) -> Result<(), NameError> {
    if !text.is_ascii() {
        return Err(NameError::NonAscii);
    }
    if text.contains('@') {
        return Err(NameError::Userinfo);
    }
    if text.contains('%') {
        return Err(NameError::AmbiguousEncoding);
    }
    if let Some(character) = text
        .chars()
        .find(|character| !(character.is_ascii_alphanumeric() || matches!(character, '.' | '-')))
    {
        return Err(NameError::InvalidCharacter { character });
    }
    Ok(())
}

fn check_label(label: &str) -> Result<(), NameError> {
    if label.is_empty() {
        return Err(NameError::EmptyLabel);
    }
    if label.len() > MAX_LABEL_BYTES {
        return Err(NameError::LabelTooLong { bytes: label.len() });
    }
    if label.starts_with('-') || label.ends_with('-') {
        return Err(NameError::HyphenAtLabelEdge {
            label: label.to_owned(),
        });
    }
    if label.len() >= 4 && &label[2..4] == "--" {
        return match label.strip_prefix("xn--") {
            Some(encoded) => check_a_label(label, encoded),
            None => Err(NameError::ReservedHyphenLabel {
                label: label.to_owned(),
            }),
        };
    }
    Ok(())
}

fn check_a_label(label: &str, encoded: &str) -> Result<(), NameError> {
    let refuse = |problem| NameError::InvalidALabel {
        label: label.to_owned(),
        problem,
    };
    if encoded.is_empty() {
        return Err(refuse(ALabelProblem::Empty));
    }
    let points = punycode::decode(encoded).ok_or_else(|| refuse(ALabelProblem::Undecodable))?;
    if points.iter().all(|&point| point < 0x80) {
        return Err(refuse(ALabelProblem::AsciiOnly));
    }
    if !points.iter().all(|&point| allowed_u_label_point(point)) {
        return Err(refuse(ALabelProblem::DisallowedCodePoint));
    }
    if punycode::encode(&points).as_deref() != Some(encoded) {
        return Err(refuse(ALabelProblem::NotCanonical));
    }
    Ok(())
}

/// The partial U-label check this crate can make without IDNA tables: ASCII must be
/// lowercase letter-digit-hyphen, and no control, format, space, dot-like, bidirectional,
/// zero-width or uppercase character may appear.
fn allowed_u_label_point(point: u32) -> bool {
    let Some(character) = char::from_u32(point) else {
        return false;
    };
    if point < 0x80 {
        return character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-';
    }
    let forbidden = matches!(
        point,
        0x00AD | 0x034F | 0x061C | 0x115F | 0x1160 | 0x17B4 | 0x17B5 | 0x180B..=0x180F
            | 0x200B..=0x200F | 0x2028..=0x202E | 0x2060..=0x206F | 0x3002 | 0x3164
            | 0xFE00..=0xFE0F | 0xFEFF | 0xFF0E | 0xFF61 | 0xFFA0 | 0xFFF0..=0xFFFF
    );
    !(forbidden || character.is_control() || character.is_whitespace() || character.is_uppercase())
}

enum Ipv4Literal {
    Canonical(Ipv4Addr),
    Other(IpLiteralForm),
}

fn is_decimal(part: &str) -> bool {
    !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())
}

fn is_hex(part: &str) -> bool {
    part.strip_prefix("0x")
        .is_some_and(|digits| digits.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

/// Recognizes every IPv4 spelling URL parsers and `inet_aton` accept (lowercase input).
fn ipv4_literal_form(host: &str) -> Option<Ipv4Literal> {
    let parts: Vec<&str> = host.split('.').collect();
    let numeric = |part: &str| is_decimal(part) || is_hex(part);
    let last = parts.last()?;
    if !numeric(last) {
        return None;
    }
    if !parts.iter().all(|part| numeric(part)) {
        return Some(Ipv4Literal::Other(IpLiteralForm::NumericFinalLabel));
    }
    let form = if parts.len() > 4 {
        IpLiteralForm::MalformedIpv4
    } else if parts.iter().any(|part| is_hex(part)) {
        IpLiteralForm::HexIpv4
    } else if parts
        .iter()
        .any(|part| part.len() > 1 && part.starts_with('0'))
    {
        IpLiteralForm::OctalIpv4
    } else if parts.len() == 1 {
        IpLiteralForm::DecimalIntegerIpv4
    } else if parts.len() < 4 {
        IpLiteralForm::ShortIpv4
    } else {
        let mut octets = [0u8; 4];
        for (octet, part) in octets.iter_mut().zip(&parts) {
            match part.parse::<u8>() {
                Ok(value) => *octet = value,
                Err(_) => return Some(Ipv4Literal::Other(IpLiteralForm::MalformedIpv4)),
            }
        }
        return Some(Ipv4Literal::Canonical(Ipv4Addr::from(octets)));
    };
    Some(Ipv4Literal::Other(form))
}

/// A destination port, 1–65535.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct DestinationPort(u16);

impl DestinationPort {
    /// HTTPS, the default port of an authority without one.
    pub const HTTPS: Self = Self(443);

    /// Refuses port 0.
    pub fn new(port: u16) -> Result<Self, NameError> {
        if port == 0 {
            return Err(NameError::InvalidPort {
                text: "0".to_owned(),
            });
        }
        Ok(Self(port))
    }

    /// Parses decimal text without sign, spaces or leading zeros.
    pub fn parse(text: &str) -> Result<Self, NameError> {
        let invalid = || NameError::InvalidPort {
            text: text.to_owned(),
        };
        if !is_decimal(text) || (text.len() > 1 && text.starts_with('0')) {
            return Err(invalid());
        }
        let port = text.parse::<u16>().map_err(|_| invalid())?;
        Self::new(port).map_err(|_| invalid())
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

impl fmt::Display for DestinationPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<'de> Deserialize<'de> for DestinationPort {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(u16::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// The host part of an authority: a canonical name, or an address written in its one
/// canonical literal form. An address is usable only under an exact endpoint grant.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DestinationHost {
    Name(CanonicalName),
    Address(IpAddr),
}

impl DestinationHost {
    /// The name, when the host is a name.
    pub fn name(&self) -> Option<&CanonicalName> {
        match self {
            Self::Name(name) => Some(name),
            Self::Address(_) => None,
        }
    }
}

impl fmt::Display for DestinationHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(name) => fmt::Display::fmt(name, f),
            Self::Address(IpAddr::V4(address)) => fmt::Display::fmt(address, f),
            Self::Address(IpAddr::V6(address)) => write!(f, "[{address}]"),
        }
    }
}

/// A canonical host and port (VM §4.2 step 1): the identity a route, a TLS server name
/// and an HTTP authority are compared on.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Authority {
    pub host: DestinationHost,
    pub port: DestinationPort,
}

impl Authority {
    /// Parses `host`, `host:port`, `a.b.c.d[:port]` or `[ipv6][:port]` with the one
    /// destination parser. Userinfo, paths, percent-encoding, non-canonical IP literals
    /// and every [`CanonicalName::parse`] refusal are rejected. A missing port means
    /// `default_port`.
    pub fn parse(text: &str, default_port: DestinationPort) -> Result<Self, NameError> {
        if text.is_empty() {
            return Err(NameError::Empty);
        }
        if !text.is_ascii() {
            return Err(NameError::NonAscii);
        }
        if text.contains('@') {
            return Err(NameError::Userinfo);
        }
        if let Some(rest) = text.strip_prefix('[') {
            return Self::parse_bracketed(rest, default_port);
        }
        if text.contains('%') {
            return Err(NameError::AmbiguousEncoding);
        }
        if text.matches(':').count() > 1 {
            return Err(NameError::IpLiteral {
                form: IpLiteralForm::UnbracketedIpv6,
            });
        }
        let (host, port) = match text.split_once(':') {
            Some((host, port)) => (host, DestinationPort::parse(port)?),
            None => (text, default_port),
        };
        check_host_characters(host)?;
        if host.ends_with('.') {
            return Err(NameError::TrailingDot);
        }
        let lower = host.to_ascii_lowercase();
        let host = match ipv4_literal_form(&lower) {
            Some(Ipv4Literal::Canonical(address)) => DestinationHost::Address(IpAddr::V4(address)),
            Some(Ipv4Literal::Other(form)) => return Err(NameError::IpLiteral { form }),
            None => DestinationHost::Name(CanonicalName::parse(host)?),
        };
        Ok(Self { host, port })
    }

    fn parse_bracketed(rest: &str, default_port: DestinationPort) -> Result<Self, NameError> {
        let Some((inside, after)) = rest.split_once(']') else {
            return Err(NameError::InvalidCharacter { character: '[' });
        };
        if inside.contains('%') {
            return Err(NameError::IpLiteral {
                form: IpLiteralForm::Ipv6ZoneId,
            });
        }
        let address: Ipv6Addr = inside.parse().map_err(|_| NameError::IpLiteral {
            form: IpLiteralForm::NonCanonicalIpv6,
        })?;
        if address.to_string() != inside {
            return Err(NameError::IpLiteral {
                form: IpLiteralForm::NonCanonicalIpv6,
            });
        }
        let port = match after {
            "" => default_port,
            _ => match after.strip_prefix(':') {
                Some(port) => DestinationPort::parse(port)?,
                None => {
                    return Err(NameError::InvalidCharacter {
                        character: after.chars().next().unwrap_or(']'),
                    })
                }
            },
        };
        Ok(Self {
            host: DestinationHost::Address(IpAddr::V6(address)),
            port,
        })
    }
}

impl fmt::Display for Authority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

/// The canonical route reference of a destination: `host:port`, with the host in its one
/// canonical form (a lowercase A-label name, a dotted IPv4 address or a bracketed RFC 5952
/// IPv6 address) and the port always written, 443 included (VM §4.2 step 1; VM-W03).
///
/// This is the one spelling every module uses to name the route to a destination: V01
/// route resources ([`ResourceRef::route`](crate::sandbox_contract::policy::ResourceRef::route)),
/// V08 declarations and, by the same text, V07's provider route references. Two
/// spellings that [`Authority::parse`] accepts as one authority, such as
/// `API.Example.com` and `api.example.com:443`, give one reference. A reference names a
/// route; it grants nothing.
pub fn route_reference(authority: &Authority) -> String {
    format!("{}:{}", authority.host, authority.port)
}
