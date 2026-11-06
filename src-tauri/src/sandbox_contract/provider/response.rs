//! Response policy (VM part §4.5 lines 2004 and 2008).
//!
//! Every response is scanned first: any header name, header value or body that reflects
//! the credential, an authorization value or a known fixture secret makes the whole
//! response untrusted, so it is refused and nothing of it is returned. A typed response
//! is then schema-validated and reduced to its declared fields. A credentialed
//! passthrough returns the body after the same scan, without a schema: a weaker profile
//! that is never labelled zero-exposure. The status decides what the outcome can be: a
//! redirect is never followed, a client error is a certain rejection, and a server error
//! or timeout leaves the outcome unknown.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::scan::{LeakFinding, LeakLocation, LeakReport, LeakSource, ScanEncoding};
use super::vault::UpstreamReply;
use crate::foundation::ids::{digest, Digest};
use crate::sandbox_contract::destinations::RESERVED_CREDENTIAL_HEADERS;
use crate::sandbox_contract::effects::{ParamName, RawParameters, RawValue, ScalarKind};

/// The one field a passthrough response returns.
pub const PASSTHROUGH_BODY_FIELD: &str = "body";

const REDIRECT_TARGET_DOMAIN: &str = "yougori/sandbox/provider-redirect-target/v1";

/// One declared response field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldSchema {
    pub kind: ScalarKind,
    pub required: bool,
}

/// A typed response body: a JSON object whose declared fields are scalars.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseSchema {
    pub fields: BTreeMap<ParamName, FieldSchema>,
    pub max_body_bytes: u64,
}

strict_provider_enum! {
    /// How much of a response may return (§4.5 line 2008).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum ResponseProfile tag "profile" {
        Typed { schema: ResponseSchema },
        /// The weaker passthrough profile: the scanned body as text.
        CredentialedPassthrough { max_body_bytes: u64 },
    }
}

strict_provider_enum! {
    /// Where the provider reports what a call cost, if anywhere.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum CostReport tag "report" {
        NotReported,
        Header { name: String },
        BodyField { name: ParamName },
    }
}

/// An operation's response policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponsePolicy {
    pub profile: ResponseProfile,
    pub cost_report: CostReport,
}

strict_provider_enum! {
    /// Why a response was not accepted, leaving the outcome unknown.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum ResponseRefusal tag "refusal" {
        /// The response reflects a secret; it is refused and redacted whole.
        Leak { report: LeakReport },
        TooLarge { max_bytes: u64 },
        NotUtf8,
        NotJsonObject,
        MissingField { name: ParamName },
        WrongKind { name: ParamName },
        ServerError { status: u16 },
        Timeout,
        UnexpectedStatus { status: u16 },
    }
}

impl ResponseRefusal {
    /// A stable short name.
    pub const fn tag(&self) -> &'static str {
        match self {
            Self::Leak { .. } => "leak",
            Self::TooLarge { .. } => "too_large",
            Self::NotUtf8 => "not_utf8",
            Self::NotJsonObject => "not_json_object",
            Self::MissingField { .. } => "missing_field",
            Self::WrongKind { .. } => "wrong_kind",
            Self::ServerError { .. } => "server_error",
            Self::Timeout => "timeout",
            Self::UnexpectedStatus { .. } => "unexpected_status",
        }
    }
}

impl fmt::Display for ResponseRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Leak { report } => write!(
                f,
                "the response reflects a secret in {} place(s); it was refused and redacted",
                report.findings.len()
            ),
            Self::TooLarge { max_bytes } => write!(f, "the response is above {max_bytes} bytes"),
            Self::NotUtf8 => f.write_str("the response body is not UTF-8"),
            Self::NotJsonObject => f.write_str("the response body is not a strict JSON object"),
            Self::MissingField { name } => write!(f, "the response lacks required field {name}"),
            Self::WrongKind { name } => write!(f, "response field {name} has the wrong kind"),
            Self::ServerError { status } => write!(f, "the provider answered {status}"),
            Self::Timeout => f.write_str("the provider reported a request timeout"),
            Self::UnexpectedStatus { status } => write!(f, "unexpected status {status}"),
        }
    }
}

impl std::error::Error for ResponseRefusal {}

/// What a response comes to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResponseVerdict {
    /// Accepted: only the permitted representation is kept.
    Accepted {
        representation: BTreeMap<String, String>,
        reported_spend_microunits: Option<u64>,
    },
    /// A client error: the provider certainly did not commit.
    Rejected {
        status: u16,
        reported_spend_microunits: Option<u64>,
    },
    PreconditionFailed,
    /// Never followed; the target is kept only as a digest.
    Redirect {
        target: Digest,
    },
    /// Some of the operation committed; nothing is returned.
    PartialSuccess {
        reported_spend_microunits: Option<u64>,
    },
    /// The outcome is unknown.
    Uncertain {
        refusal: ResponseRefusal,
    },
}

fn scan_reply(
    reply: &UpstreamReply,
    scanner: &dyn Fn(&[u8]) -> Option<(LeakSource, ScanEncoding)>,
) -> LeakReport {
    let mut report = LeakReport::default();
    for (index, (name, value)) in reply.headers.iter().enumerate() {
        let index = u32::try_from(index).unwrap_or(u32::MAX);
        let lower = name.to_ascii_lowercase();
        if RESERVED_CREDENTIAL_HEADERS.contains(&lower.as_str()) {
            report.push(LeakFinding {
                location: LeakLocation::ResponseHeaderName { index },
                source: LeakSource::CredentialHeaderName,
                encoding: ScanEncoding::AsciiCaseInsensitive,
            });
        }
        if let Some((source, encoding)) = scanner(name.as_bytes()) {
            report.push(LeakFinding {
                location: LeakLocation::ResponseHeaderName { index },
                source,
                encoding,
            });
        }
        if let Some((source, encoding)) = scanner(value.as_bytes()) {
            report.push(LeakFinding {
                location: LeakLocation::ResponseHeaderValue { index },
                source,
                encoding,
            });
        }
    }
    if let Some((source, encoding)) = scanner(&reply.body) {
        report.push(LeakFinding {
            location: LeakLocation::ResponseBody,
            source,
            encoding,
        });
    }
    report
}

fn parse_u64_text(text: &str) -> Option<u64> {
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed.len() > 20 || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    trimmed.parse().ok()
}

fn json_object(body: &[u8]) -> Result<RawParameters, ResponseRefusal> {
    let text = std::str::from_utf8(body).map_err(|_| ResponseRefusal::NotUtf8)?;
    RawParameters::from_json(text).map_err(|_| ResponseRefusal::NotJsonObject)
}

fn reported_cost(policy: &ResponsePolicy, reply: &UpstreamReply) -> Option<u64> {
    match &policy.cost_report {
        CostReport::NotReported => None,
        CostReport::Header { name } => reply
            .headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .and_then(|(_, value)| parse_u64_text(value)),
        CostReport::BodyField { name } => json_object(&reply.body).ok().and_then(|object| {
            object
                .iter()
                .find(|(key, _)| key.as_str() == name.as_str())
                .and_then(|(_, value)| match value {
                    RawValue::Integer(value) => u64::try_from(*value).ok(),
                    _ => None,
                })
        }),
    }
}

fn field_text(
    name: &ParamName,
    kind: &ScalarKind,
    value: &RawValue,
) -> Result<String, ResponseRefusal> {
    let wrong = || ResponseRefusal::WrongKind { name: name.clone() };
    match (kind, value) {
        (ScalarKind::Text { max_bytes }, RawValue::Text(text)) => {
            if u64::try_from(text.len()).unwrap_or(u64::MAX) > u64::from(*max_bytes)
                || text.chars().any(char::is_control)
            {
                return Err(wrong());
            }
            Ok(text.clone())
        }
        (ScalarKind::Integer { min, max }, RawValue::Integer(value)) => {
            if value < min || value > max {
                return Err(wrong());
            }
            Ok(value.to_string())
        }
        (ScalarKind::Bool, RawValue::Bool(value)) => Ok(value.to_string()),
        (ScalarKind::Digest, RawValue::Text(text)) => Digest::from_hex(text)
            .map(|digest| digest.to_hex())
            .map_err(|_| wrong()),
        _ => Err(wrong()),
    }
}

fn accept(
    policy: &ResponsePolicy,
    reply: &UpstreamReply,
) -> Result<BTreeMap<String, String>, ResponseRefusal> {
    match &policy.profile {
        ResponseProfile::Typed { schema } => {
            if u64::try_from(reply.body.len()).unwrap_or(u64::MAX) > schema.max_body_bytes {
                return Err(ResponseRefusal::TooLarge {
                    max_bytes: schema.max_body_bytes,
                });
            }
            let object = json_object(&reply.body)?;
            let mut representation = BTreeMap::new();
            for (name, field) in &schema.fields {
                match object.iter().find(|(key, _)| key.as_str() == name.as_str()) {
                    Some((_, value)) => {
                        representation.insert(
                            name.as_str().to_owned(),
                            field_text(name, &field.kind, value)?,
                        );
                    }
                    None if field.required => {
                        return Err(ResponseRefusal::MissingField { name: name.clone() })
                    }
                    None => {}
                }
            }
            Ok(representation)
        }
        ResponseProfile::CredentialedPassthrough { max_body_bytes } => {
            if u64::try_from(reply.body.len()).unwrap_or(u64::MAX) > *max_body_bytes {
                return Err(ResponseRefusal::TooLarge {
                    max_bytes: *max_body_bytes,
                });
            }
            let text = std::str::from_utf8(&reply.body).map_err(|_| ResponseRefusal::NotUtf8)?;
            Ok(BTreeMap::from([(
                PASSTHROUGH_BODY_FIELD.to_owned(),
                text.to_owned(),
            )]))
        }
    }
}

/// Evaluates `reply` under `policy`. `scanner` reports the first secret it finds in a
/// byte string: the vault's credential and the known fixture secrets.
pub fn evaluate_response(
    policy: &ResponsePolicy,
    reply: &UpstreamReply,
    scanner: &dyn Fn(&[u8]) -> Option<(LeakSource, ScanEncoding)>,
) -> ResponseVerdict {
    let report = scan_reply(reply, scanner);
    if !report.is_clean() {
        return ResponseVerdict::Uncertain {
            refusal: ResponseRefusal::Leak { report },
        };
    }
    let reported_spend_microunits = reported_cost(policy, reply);
    match reply.status {
        207 => ResponseVerdict::PartialSuccess {
            reported_spend_microunits,
        },
        200..=299 => match accept(policy, reply) {
            Ok(representation) => ResponseVerdict::Accepted {
                representation,
                reported_spend_microunits,
            },
            Err(refusal) => ResponseVerdict::Uncertain { refusal },
        },
        300..=399 => {
            let location = reply
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("location"))
                .map_or("", |(_, value)| value.as_str());
            ResponseVerdict::Redirect {
                target: digest(REDIRECT_TARGET_DOMAIN, &[location.as_bytes()]),
            }
        }
        412 => ResponseVerdict::PreconditionFailed,
        408 => ResponseVerdict::Uncertain {
            refusal: ResponseRefusal::Timeout,
        },
        400..=499 => ResponseVerdict::Rejected {
            status: reply.status,
            reported_spend_microunits,
        },
        500..=599 => ResponseVerdict::Uncertain {
            refusal: ResponseRefusal::ServerError {
                status: reply.status,
            },
        },
        status => ResponseVerdict::Uncertain {
            refusal: ResponseRefusal::UnexpectedStatus { status },
        },
    }
}
