//! The upstream request, built by the executor itself (VM part §4.5 line 2004; §9.2 line
//! 2344: the executor independently reconstructs the outbound operation).
//!
//! The request is a pure function of the operation contract, the effects
//! [`OutboundRequest`] (itself built from the effect description alone) and the payload
//! bytes whose content key the description binds. Nothing the guest sends at dispatch can
//! change it. It never carries a credential header: the vault adds authorization when it
//! sends. Every byte it puts on the wire is measured, the URL and headers included (§2.5
//! line 1815; VM-P33).

use std::collections::BTreeMap;
use std::fmt;

use super::batch::{BatchDocument, BatchRefusal};
use super::operation::{BodyEncoding, OperationFamily, ProviderOperation};
use super::scan::LeakLocation;
use crate::foundation::ids::ContentKey;
use crate::sandbox_contract::destinations::{
    Authority, HttpMethod, PathSegment, METHOD_OVERRIDE_HEADERS, RESERVED_CREDENTIAL_HEADERS,
};
use crate::sandbox_contract::effects::{
    CanonicalValue, OperationKey, OutboundRequest, ParamName, Precondition,
};

/// The request the vault authenticates and sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamRequest {
    pub method: HttpMethod,
    pub authority: Authority,
    /// Path and query, percent-encoded.
    pub target: String,
    /// Lower-case names. Never a credential or method-override header.
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl UpstreamRequest {
    /// The HTTP/1.1 request line, line end included.
    pub fn request_line(&self) -> String {
        format!("{} {} HTTP/1.1\r\n", self.method.as_str(), self.target)
    }

    /// Bytes on the wire before the vault's authorization header: the request line,
    /// every header line, the blank line and the body.
    pub fn wire_bytes(&self) -> u64 {
        let headers = self.headers.iter().fold(0usize, |sum, (name, value)| {
            sum.saturating_add(name.len())
                .saturating_add(value.len())
                .saturating_add(4)
        });
        let total = self
            .request_line()
            .len()
            .saturating_add(headers)
            .saturating_add(2)
            .saturating_add(self.body.len());
        u64::try_from(total).unwrap_or(u64::MAX)
    }

    /// The parts a leak scan covers, with their locations.
    pub fn scan_parts(&self) -> Vec<(LeakLocation, Vec<u8>)> {
        let mut parts = vec![(LeakLocation::RequestLine, self.request_line().into_bytes())];
        for (index, (name, value)) in self.headers.iter().enumerate() {
            let index = u32::try_from(index).unwrap_or(u32::MAX);
            parts.push((
                LeakLocation::RequestHeader { index },
                format!("{name}: {value}").into_bytes(),
            ));
        }
        parts.push((LeakLocation::RequestBody, self.body.clone()));
        parts
    }
}

strict_provider_enum! {
    /// Why the executor could not build the request; nothing was sent.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum RequestRefusal tag "reason" {
        OperationMismatch { operation: OperationKey },
        PathParameterMissing { name: ParamName },
        /// A path value must be one segment of unreserved characters, not `.` or `..`.
        PathParameterInvalid { name: ParamName },
        QueryKeyNotOnRoute { name: ParamName },
        PayloadMissing,
        PayloadUnexpected,
        PayloadMismatch { expected: ContentKey, actual: ContentKey },
        Batch { refusal: BatchRefusal },
        ForbiddenHeader { name: String },
        Encoding,
    }
}

impl RequestRefusal {
    /// A stable short name, used in rejection codes.
    pub const fn tag(&self) -> &'static str {
        match self {
            Self::OperationMismatch { .. } => "operation_mismatch",
            Self::PathParameterMissing { .. } => "path_parameter_missing",
            Self::PathParameterInvalid { .. } => "path_parameter_invalid",
            Self::QueryKeyNotOnRoute { .. } => "query_key_not_on_route",
            Self::PayloadMissing => "payload_missing",
            Self::PayloadUnexpected => "payload_unexpected",
            Self::PayloadMismatch { .. } => "payload_mismatch",
            Self::Batch { .. } => "batch",
            Self::ForbiddenHeader { .. } => "forbidden_header",
            Self::Encoding => "encoding",
        }
    }
}

impl fmt::Display for RequestRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OperationMismatch { .. } => {
                f.write_str("the request names another operation than the executor's")
            }
            Self::PathParameterMissing { name } => write!(f, "path parameter {name} is missing"),
            Self::PathParameterInvalid { name } => {
                write!(f, "path parameter {name} is not one plain path segment")
            }
            Self::QueryKeyNotOnRoute { name } => {
                write!(f, "the route does not accept query key {name}")
            }
            Self::PayloadMissing => f.write_str("the payload bytes are missing"),
            Self::PayloadUnexpected => f.write_str("the operation carries no payload"),
            Self::PayloadMismatch { .. } => {
                f.write_str("the payload bytes differ from the described content key")
            }
            Self::Batch { refusal } => write!(f, "{refusal}"),
            Self::ForbiddenHeader { name } => {
                write!(f, "the executor never sends a {name} header itself")
            }
            Self::Encoding => f.write_str("the request could not be encoded"),
        }
    }
}

impl std::error::Error for RequestRefusal {}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

fn percent_encode(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        if is_unreserved(byte) {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn scalar_text(value: &CanonicalValue) -> Option<String> {
    match value {
        CanonicalValue::Text(text) => Some(text.clone()),
        CanonicalValue::Integer(value) => Some(value.to_string()),
        CanonicalValue::Bool(value) => Some(value.to_string()),
        CanonicalValue::Digest(digest) => Some(digest.to_hex()),
        CanonicalValue::List(_) | CanonicalValue::Set(_) => None,
    }
}

fn plain_json(value: &CanonicalValue) -> serde_json::Value {
    match value {
        CanonicalValue::Text(text) => serde_json::Value::String(text.clone()),
        CanonicalValue::Integer(value) => serde_json::Value::from(*value),
        CanonicalValue::Bool(value) => serde_json::Value::Bool(*value),
        CanonicalValue::Digest(digest) => serde_json::Value::String(digest.to_hex()),
        CanonicalValue::List(items) => {
            serde_json::Value::Array(items.iter().map(plain_json).collect())
        }
        CanonicalValue::Set(items) => {
            serde_json::Value::Array(items.iter().map(plain_json).collect())
        }
    }
}

/// Builds the upstream request for `outbound` under `operation`, with the payload bytes
/// the description binds and, for a batch, its member operations.
pub fn build_upstream(
    operation: &ProviderOperation,
    members: &BTreeMap<OperationKey, ProviderOperation>,
    outbound: &OutboundRequest,
    payload: Option<&[u8]>,
) -> Result<UpstreamRequest, RequestRefusal> {
    if &outbound.operation != operation.key() {
        return Err(RequestRefusal::OperationMismatch {
            operation: outbound.operation.clone(),
        });
    }
    let payload = match (outbound.payload, payload) {
        (None, None) => None,
        (None, Some(_)) => return Err(RequestRefusal::PayloadUnexpected),
        (Some(_), None) => return Err(RequestRefusal::PayloadMissing),
        (Some(reference), Some(bytes)) => {
            let actual = ContentKey::of(bytes);
            let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
            if actual != reference.content || length != reference.length_bytes {
                return Err(RequestRefusal::PayloadMismatch {
                    expected: reference.content,
                    actual,
                });
            }
            Some(bytes)
        }
    };
    let binding = operation.binding();
    let spec = binding.spec().ok_or(RequestRefusal::Encoding)?;
    let mut path = String::new();
    let mut path_params = binding.path_params.iter();
    for segment in spec.path.segments() {
        path.push('/');
        match segment {
            PathSegment::Literal(literal) => path.push_str(literal),
            PathSegment::Parameter => {
                let name = path_params.next().ok_or(RequestRefusal::Encoding)?;
                let value = match outbound.parameters.get(name) {
                    Some(CanonicalValue::Text(text)) => text,
                    _ => return Err(RequestRefusal::PathParameterMissing { name: name.clone() }),
                };
                if value.is_empty()
                    || value == "."
                    || value == ".."
                    || !value.bytes().all(is_unreserved)
                {
                    return Err(RequestRefusal::PathParameterInvalid { name: name.clone() });
                }
                path.push_str(value);
            }
        }
    }
    if path.is_empty() {
        path.push('/');
    }
    let rest: Vec<(&ParamName, &CanonicalValue)> = outbound
        .parameters
        .iter()
        .filter(|(name, _)| !binding.path_params.contains(name))
        .collect();
    let encoding = operation.encoding();
    let mut query = Vec::new();
    if matches!(encoding, BodyEncoding::Query | BodyEncoding::RawPayload) {
        for (name, value) in &rest {
            if !spec.query_keys.contains(name.as_str()) {
                return Err(RequestRefusal::QueryKeyNotOnRoute {
                    name: (*name).clone(),
                });
            }
            let items: Vec<String> = match value {
                CanonicalValue::List(items) => items.iter().filter_map(scalar_text).collect(),
                CanonicalValue::Set(items) => items.iter().filter_map(scalar_text).collect(),
                scalar => scalar_text(scalar).into_iter().collect(),
            };
            for item in items {
                query.push(format!(
                    "{}={}",
                    percent_encode(name.as_str()),
                    percent_encode(&item)
                ));
            }
        }
    }
    let target = if query.is_empty() {
        path
    } else {
        format!("{path}?{}", query.join("&"))
    };
    let object = |rest: &[(&ParamName, &CanonicalValue)]| {
        serde_json::Value::Object(
            rest.iter()
                .map(|(name, value)| (name.as_str().to_owned(), plain_json(value)))
                .collect(),
        )
    };
    let (body, content_type) = match encoding {
        BodyEncoding::Query => (Vec::new(), None),
        BodyEncoding::JsonParameters => (
            serde_json::to_vec(&object(&rest)).map_err(|_| RequestRefusal::Encoding)?,
            Some("application/json"),
        ),
        BodyEncoding::RawPayload => (
            payload.ok_or(RequestRefusal::PayloadMissing)?.to_vec(),
            Some("application/octet-stream"),
        ),
        BodyEncoding::GraphQlEnvelope => {
            let OperationFamily::GraphQl(graphql) = operation.family() else {
                return Err(RequestRefusal::Encoding);
            };
            let envelope = serde_json::json!({
                "operationName": graphql.name(),
                "query": graphql.document(),
                "variables": object(&rest),
            });
            (
                serde_json::to_vec(&envelope).map_err(|_| RequestRefusal::Encoding)?,
                Some("application/json"),
            )
        }
        BodyEncoding::BatchDocument => {
            let OperationFamily::Batch(spec) = operation.family() else {
                return Err(RequestRefusal::Encoding);
            };
            let bytes = payload.ok_or(RequestRefusal::PayloadMissing)?;
            BatchDocument::parse(bytes, spec, members)
                .map_err(|refusal| RequestRefusal::Batch { refusal })?;
            (bytes.to_vec(), Some("application/json"))
        }
    };
    let mut headers = BTreeMap::new();
    headers.insert("host".to_owned(), binding.authority.to_string());
    headers.insert("accept".to_owned(), "application/json".to_owned());
    if let Some(content_type) = content_type {
        headers.insert("content-type".to_owned(), content_type.to_owned());
        headers.insert("content-length".to_owned(), body.len().to_string());
    }
    if let Some(key) = outbound.idempotency_key {
        headers.insert("idempotency-key".to_owned(), key.digest().to_hex());
    }
    let mut if_match = Vec::new();
    let mut if_none_match = Vec::new();
    for precondition in &outbound.preconditions {
        match precondition {
            Precondition::MatchesVersion { version } => {
                if_match.push(format!("\"{}\"", version.to_hex()))
            }
            Precondition::Present => if_match.push("*".to_owned()),
            Precondition::Absent => if_none_match.push("*".to_owned()),
        }
    }
    if !if_match.is_empty() {
        headers.insert("if-match".to_owned(), if_match.join(", "));
    }
    if !if_none_match.is_empty() {
        headers.insert("if-none-match".to_owned(), if_none_match.join(", "));
    }
    check_headers(&headers)?;
    Ok(UpstreamRequest {
        method: spec.method,
        authority: binding.authority.clone(),
        target,
        headers,
        body,
    })
}

/// Refuses a credential or method-override header the executor must never set itself.
pub(super) fn check_headers(headers: &BTreeMap<String, String>) -> Result<(), RequestRefusal> {
    match headers.keys().find(|name| {
        RESERVED_CREDENTIAL_HEADERS.contains(&name.as_str())
            || METHOD_OVERRIDE_HEADERS.contains(&name.as_str())
    }) {
        Some(name) => Err(RequestRefusal::ForbiddenHeader { name: name.clone() }),
        None => Ok(()),
    }
}
