//! Inspected HTTP on operation routes (VM §4.3; VM-W11; VM-P10, VM-P30).
//!
//! The request arrives already parsed by a maintained HTTP library into an
//! [`InspectedRequest`]; this module never parses wire bytes. It refuses ambiguous
//! duplicate headers, conflicting framing, upgrade and tunnelling forms, method
//! overrides, non-origin-form targets and ambiguous path or query encodings; binds the
//! normalized authority, operation, path and query; reserves credential headers on
//! credentialed routes; and refuses an SNI that disagrees with the authority. The same
//! [`Authority::parse`] reads the authority, the SNI and every redirect target.

use std::collections::BTreeMap;
use std::fmt;

use super::name::{Authority, CanonicalName, DestinationHost, DestinationPort, NameError};
use super::policy::RouteId;
use super::route::{EffectClass, HttpMethod, OperationName, OperationRoute};
use crate::foundation::ids::{Digest, DigestBuilder};

/// The HTTP version the library parsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HttpVersion {
    Http11,
    Http2,
}

/// A request as a maintained HTTP library parsed it (VM §4.3: parse once with bounded,
/// maintained libraries).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InspectedRequest {
    pub version: HttpVersion,
    pub method: String,
    /// The request target (HTTP/1.1) or `:path` (HTTP/2).
    pub target: String,
    /// `:authority` (HTTP/2 only).
    pub authority: Option<String>,
    /// `:scheme` (HTTP/2 only).
    pub scheme: Option<String>,
    /// `:protocol`, extended CONNECT (HTTP/2 only).
    pub protocol: Option<String>,
    /// Header fields in received order, names as received.
    pub headers: Vec<(String, String)>,
}

/// The TLS facts of the connection the request arrived on.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TlsFacts {
    pub sni: Option<String>,
}

/// How the request body is framed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BodyFraming {
    None,
    ContentLength(u64),
    /// A streaming body; its bytes are counted as they pass.
    Chunked,
}

/// Headers an executor injects on credentialed routes; a guest may never send them there
/// (VM §4.3: reserve authorization/cookie headers on credentialed routes).
pub const RESERVED_CREDENTIAL_HEADERS: [&str; 3] =
    ["authorization", "proxy-authorization", "cookie"];

/// Headers that re-select the method behind the bound one.
pub const METHOD_OVERRIDE_HEADERS: [&str; 3] = [
    "x-http-method-override",
    "x-http-method",
    "x-method-override",
];

/// Why an inspected request or a redirect was refused (VM §4.3; VM-P10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestRefusal {
    UnknownMethod {
        method: String,
    },
    /// CONNECT or extended CONNECT: tunnelling is not an operation.
    Tunneling,
    /// HTTP/2 pseudo-headers on an HTTP/1.1 request.
    PseudoHeaderInHttp11,
    PseudoHeaderInFields {
        name: String,
    },
    SchemeNotHttps,
    InvalidHeaderName {
        name: String,
    },
    UppercaseHeaderNameInHttp2 {
        name: String,
    },
    InvalidHeaderValue {
        name: String,
    },
    /// A header appears more than once; which copy counts would be ambiguous.
    DuplicateHeader {
        name: String,
    },
    /// Content-Length together with Transfer-Encoding.
    ConflictingFraming,
    UnsupportedTransferEncoding {
        value: String,
    },
    InvalidContentLength {
        value: String,
    },
    BodyNotAllowed {
        method: HttpMethod,
    },
    /// Upgrade, h2c (HTTP2-Settings) or `Connection: upgrade`.
    Upgrade {
        header: String,
    },
    /// A hop-by-hop header or a `Connection` option that would strip other headers.
    HopByHop {
        header: String,
    },
    MethodOverride {
        header: String,
    },
    MissingAuthority,
    /// `:authority` and Host disagree.
    AuthorityConflict,
    InvalidAuthority(NameError),
    AuthorityMismatch {
        expected: Authority,
        presented: Authority,
    },
    MissingSni,
    InvalidSni(NameError),
    /// SNI does not name the request's authority; SNI never proves the HTTP authority.
    SniAuthorityMismatch {
        sni: String,
        authority: Authority,
    },
    TargetNotOriginForm,
    Fragment,
    InvalidPathCharacter {
        character: char,
    },
    InvalidPercentEncoding,
    /// An encoding of `.`, `/`, `\` or a control character, which normalizers disagree on.
    AmbiguousEncodedCharacter {
        encoded: String,
    },
    DotSegment,
    EmptySegment,
    /// `;` path parameters, which some servers strip.
    PathParameter,
    EmptyQuery,
    EmptyQueryPair,
    QueryPairWithoutValue {
        key: String,
    },
    /// `;` as a query separator.
    AmbiguousQuerySeparator,
    /// `+`, which means a space in form encoding but not in URIs.
    PlusInQuery,
    DuplicateQueryKey {
        key: String,
    },
    QueryKeyNotPermitted {
        key: String,
    },
    NoMatchingOperation,
    ReservedHeader {
        name: String,
    },
    RedirectsDisabled,
    RedirectSchemeNotHttps,
    RedirectSchemeRelative,
    InvalidRedirect,
}

impl fmt::Display for RequestRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownMethod { method } => write!(f, "method {method:?} is not supported"),
            Self::Tunneling => f.write_str("CONNECT and tunnelling are not operations"),
            Self::PseudoHeaderInHttp11 => {
                f.write_str("HTTP/2 pseudo-headers are not valid in HTTP/1.1")
            }
            Self::PseudoHeaderInFields { name } => {
                write!(f, "pseudo-header {name:?} appears among header fields")
            }
            Self::SchemeNotHttps => f.write_str("the scheme must be https"),
            Self::InvalidHeaderName { name } => write!(f, "{name:?} is not a header name"),
            Self::UppercaseHeaderNameInHttp2 { name } => {
                write!(f, "HTTP/2 header {name:?} is not lowercase")
            }
            Self::InvalidHeaderValue { name } => write!(
                f,
                "header {name:?} has control characters or surrounding whitespace"
            ),
            Self::DuplicateHeader { name } => write!(f, "header {name:?} appears more than once"),
            Self::ConflictingFraming => {
                f.write_str("Content-Length and Transfer-Encoding are both present")
            }
            Self::UnsupportedTransferEncoding { value } => {
                write!(
                    f,
                    "Transfer-Encoding {value:?} is not supported; only chunked"
                )
            }
            Self::InvalidContentLength { value } => {
                write!(f, "Content-Length {value:?} is not one decimal number")
            }
            Self::BodyNotAllowed { method } => {
                write!(f, "{} requests may not carry a body", method.as_str())
            }
            Self::Upgrade { header } => write!(f, "protocol upgrade via {header} is refused"),
            Self::HopByHop { header } => write!(f, "hop-by-hop header {header:?} is refused"),
            Self::MethodOverride { header } => {
                write!(f, "method override header {header:?} is refused")
            }
            Self::MissingAuthority => f.write_str("the request names no authority"),
            Self::AuthorityConflict => f.write_str(":authority and Host disagree"),
            Self::InvalidAuthority(error) => write!(f, "the authority is invalid: {error}"),
            Self::AuthorityMismatch {
                expected,
                presented,
            } => write!(
                f,
                "the request is for {presented}, not the authorized {expected}"
            ),
            Self::MissingSni => f.write_str("the TLS connection sent no server name"),
            Self::InvalidSni(error) => write!(f, "the TLS server name is invalid: {error}"),
            Self::SniAuthorityMismatch { sni, authority } => {
                write!(
                    f,
                    "TLS server name {sni:?} does not name the authority {authority}"
                )
            }
            Self::TargetNotOriginForm => f.write_str("the request target must be a path"),
            Self::Fragment => f.write_str("a fragment may not be sent"),
            Self::InvalidPathCharacter { character } => {
                write!(f, "the target contains {character:?}")
            }
            Self::InvalidPercentEncoding => f.write_str("a percent-encoding is malformed"),
            Self::AmbiguousEncodedCharacter { encoded } => {
                write!(f, "the encoding {encoded} is ambiguous")
            }
            Self::DotSegment => f.write_str("dot segments are refused"),
            Self::EmptySegment => f.write_str("empty path segments are refused"),
            Self::PathParameter => f.write_str("';' path parameters are refused"),
            Self::EmptyQuery => f.write_str("an empty query is refused"),
            Self::EmptyQueryPair => f.write_str("an empty query pair is refused"),
            Self::QueryPairWithoutValue { key } => {
                write!(f, "query key {key:?} has no '=' value")
            }
            Self::AmbiguousQuerySeparator => f.write_str("';' is not a query separator"),
            Self::PlusInQuery => f.write_str("'+' is ambiguous in a query; use %20 or %2B"),
            Self::DuplicateQueryKey { key } => write!(f, "query key {key:?} appears twice"),
            Self::QueryKeyNotPermitted { key } => {
                write!(f, "query key {key:?} is not part of the operation")
            }
            Self::NoMatchingOperation => f.write_str("no permitted operation matches"),
            Self::ReservedHeader { name } => write!(
                f,
                "header {name:?} is reserved for the executor on this credentialed route"
            ),
            Self::RedirectsDisabled => f.write_str("redirects are disabled on this route"),
            Self::RedirectSchemeNotHttps => f.write_str("a redirect may not leave https"),
            Self::RedirectSchemeRelative => {
                f.write_str("scheme-relative redirect targets are refused")
            }
            Self::InvalidRedirect => f.write_str("the redirect target is not a valid URL"),
        }
    }
}

impl std::error::Error for RequestRefusal {}

/// A request bound to one operation (VM §4.3: bind normalized authority, operation, path
/// and query; VM-P30: canonical equivalents bind identically).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundRequest {
    pub route: RouteId,
    pub operation: OperationName,
    pub method: HttpMethod,
    pub authority: Authority,
    /// Normalized path segments.
    pub path: Vec<String>,
    /// Normalized query pairs; keys are unique, so order carries no meaning.
    pub query: BTreeMap<String, String>,
    pub body: BodyFraming,
    pub effect: EffectClass,
}

impl BoundRequest {
    /// The digest domain of [`BoundRequest::digest`].
    pub const DIGEST_DOMAIN: &'static str = "yougori/sandbox/bound-operation/v1";

    /// The normalized path, `/` joined.
    pub fn path_text(&self) -> String {
        format!("/{}", self.path.join("/"))
    }

    /// The origin-form target the executor sends, encoded from the bound fields rather
    /// than copied from the guest's bytes, so review, authorization and outbound encoding
    /// cannot disagree (VM §4.3, line 1973). Binding it again gives the same digest.
    pub fn outbound_target(&self) -> String {
        let mut target = self.path_text();
        let mut separator = '?';
        for (key, value) in &self.query {
            target.push(separator);
            target.push_str(key);
            target.push('=');
            target.push_str(value);
            separator = '&';
        }
        target
    }

    /// A digest of every bound field, the identity an approval or effect record names.
    pub fn digest(&self) -> Digest {
        let mut builder = DigestBuilder::new(Self::DIGEST_DOMAIN)
            .str(self.route.as_str())
            .str(self.operation.as_str())
            .str(self.method.as_str())
            .str(&self.authority.to_string())
            .str(&self.path_text())
            .u64(self.query.len() as u64);
        for (key, value) in &self.query {
            builder = builder.str(key).str(value);
        }
        builder.finish()
    }
}

fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// Validates and binds one request on an operation route.
pub fn bind_request(
    route_id: &RouteId,
    route: &OperationRoute,
    authorized: &Authority,
    request: &InspectedRequest,
    tls: &TlsFacts,
) -> Result<BoundRequest, RequestRefusal> {
    if request.method == "CONNECT" || request.protocol.is_some() {
        return Err(RequestRefusal::Tunneling);
    }
    let method =
        HttpMethod::parse(&request.method).ok_or_else(|| RequestRefusal::UnknownMethod {
            method: request.method.clone(),
        })?;
    match request.version {
        HttpVersion::Http11 => {
            if request.authority.is_some() || request.scheme.is_some() {
                return Err(RequestRefusal::PseudoHeaderInHttp11);
            }
        }
        HttpVersion::Http2 => {
            if request.scheme.as_deref() != Some("https") {
                return Err(RequestRefusal::SchemeNotHttps);
            }
        }
    }
    let headers = collect_headers(request)?;
    check_connection_headers(request.version, &headers)?;
    let body = check_framing(request.version, method, &headers)?;
    if route.is_credentialed() {
        if let Some(name) = RESERVED_CREDENTIAL_HEADERS
            .iter()
            .find(|name| headers.contains_key(**name))
        {
            return Err(RequestRefusal::ReservedHeader {
                name: (*name).to_owned(),
            });
        }
    }
    let authority = request_authority(request, &headers)?;
    if authority != *authorized {
        return Err(RequestRefusal::AuthorityMismatch {
            expected: authorized.clone(),
            presented: authority,
        });
    }
    check_sni(&authority, tls)?;
    let (path, query) = normalize_target(&request.target)?;
    let operation = route
        .operations()
        .iter()
        .find(|operation| operation.method == method && operation.path.matches(&path))
        .ok_or(RequestRefusal::NoMatchingOperation)?;
    if let Some(key) = query
        .keys()
        .find(|key| !operation.query_keys.contains(*key))
    {
        return Err(RequestRefusal::QueryKeyNotPermitted { key: key.clone() });
    }
    Ok(BoundRequest {
        route: route_id.clone(),
        operation: operation.name.clone(),
        method,
        authority,
        path,
        query,
        body,
        effect: operation.effect,
    })
}

fn collect_headers(request: &InspectedRequest) -> Result<BTreeMap<String, String>, RequestRefusal> {
    let mut headers = BTreeMap::new();
    for (name, value) in &request.headers {
        if name.starts_with(':') {
            return Err(RequestRefusal::PseudoHeaderInFields { name: name.clone() });
        }
        if name.is_empty() || !name.bytes().all(is_tchar) {
            return Err(RequestRefusal::InvalidHeaderName { name: name.clone() });
        }
        if request.version == HttpVersion::Http2
            && name.bytes().any(|byte| byte.is_ascii_uppercase())
        {
            return Err(RequestRefusal::UppercaseHeaderNameInHttp2 { name: name.clone() });
        }
        let lower = name.to_ascii_lowercase();
        let bad_value = value.bytes().any(|byte| {
            byte == b'\r'
                || byte == b'\n'
                || byte == 0
                || (byte < 0x20 && byte != b'\t')
                || byte == 0x7f
        }) || value.starts_with([' ', '\t'])
            || value.ends_with([' ', '\t']);
        if bad_value {
            return Err(RequestRefusal::InvalidHeaderValue { name: lower });
        }
        if headers.insert(lower.clone(), value.clone()).is_some() {
            return Err(RequestRefusal::DuplicateHeader { name: lower });
        }
    }
    Ok(headers)
}

fn check_connection_headers(
    version: HttpVersion,
    headers: &BTreeMap<String, String>,
) -> Result<(), RequestRefusal> {
    if headers.contains_key("upgrade") {
        return Err(RequestRefusal::Upgrade {
            header: "Upgrade".to_owned(),
        });
    }
    if headers.contains_key("http2-settings") {
        return Err(RequestRefusal::Upgrade {
            header: "HTTP2-Settings (h2c)".to_owned(),
        });
    }
    if let Some(header) = METHOD_OVERRIDE_HEADERS
        .iter()
        .find(|name| headers.contains_key(**name))
    {
        return Err(RequestRefusal::MethodOverride {
            header: (*header).to_owned(),
        });
    }
    for hop in ["keep-alive", "proxy-connection"] {
        if headers.contains_key(hop) {
            return Err(RequestRefusal::HopByHop {
                header: hop.to_owned(),
            });
        }
    }
    if let Some(te) = headers.get("te") {
        if !te.eq_ignore_ascii_case("trailers") {
            return Err(RequestRefusal::HopByHop {
                header: "te".to_owned(),
            });
        }
    }
    if let Some(connection) = headers.get("connection") {
        if version == HttpVersion::Http2 {
            return Err(RequestRefusal::HopByHop {
                header: "connection".to_owned(),
            });
        }
        for option in connection
            .split(',')
            .map(|option| option.trim().to_ascii_lowercase())
        {
            match option.as_str() {
                "close" | "keep-alive" => {}
                "upgrade" | "http2-settings" => {
                    return Err(RequestRefusal::Upgrade {
                        header: format!("Connection: {option}"),
                    })
                }
                _ => return Err(RequestRefusal::HopByHop { header: option }),
            }
        }
    }
    Ok(())
}

/// The body framing of a request head, with the header faults [`bind_request`] refuses
/// before it (unknown method, duplicate or connection-specific headers), and no route: the
/// one framing rule a wire reader uses to find where the body ends.
pub(crate) fn request_framing(request: &InspectedRequest) -> Result<BodyFraming, RequestRefusal> {
    let method =
        HttpMethod::parse(&request.method).ok_or_else(|| RequestRefusal::UnknownMethod {
            method: request.method.clone(),
        })?;
    let headers = collect_headers(request)?;
    check_connection_headers(request.version, &headers)?;
    check_framing(request.version, method, &headers)
}

fn check_framing(
    version: HttpVersion,
    method: HttpMethod,
    headers: &BTreeMap<String, String>,
) -> Result<BodyFraming, RequestRefusal> {
    let length = headers.get("content-length");
    let encoding = headers.get("transfer-encoding");
    let framing = match (length, encoding) {
        (Some(_), Some(_)) => return Err(RequestRefusal::ConflictingFraming),
        (None, Some(_)) if version == HttpVersion::Http2 => {
            return Err(RequestRefusal::HopByHop {
                header: "transfer-encoding".to_owned(),
            })
        }
        (None, Some(value)) => {
            if !value.eq_ignore_ascii_case("chunked") {
                return Err(RequestRefusal::UnsupportedTransferEncoding {
                    value: value.clone(),
                });
            }
            BodyFraming::Chunked
        }
        (Some(value), None) => {
            let invalid = || RequestRefusal::InvalidContentLength {
                value: value.clone(),
            };
            if value.is_empty()
                || !value.bytes().all(|byte| byte.is_ascii_digit())
                || (value.len() > 1 && value.starts_with('0'))
            {
                return Err(invalid());
            }
            BodyFraming::ContentLength(value.parse::<u64>().map_err(|_| invalid())?)
        }
        (None, None) => BodyFraming::None,
    };
    let has_body = !matches!(framing, BodyFraming::None | BodyFraming::ContentLength(0));
    if has_body && method.forbids_body() {
        return Err(RequestRefusal::BodyNotAllowed { method });
    }
    Ok(framing)
}

fn parse_authority(text: &str) -> Result<Authority, RequestRefusal> {
    Authority::parse(text, DestinationPort::HTTPS).map_err(RequestRefusal::InvalidAuthority)
}

fn request_authority(
    request: &InspectedRequest,
    headers: &BTreeMap<String, String>,
) -> Result<Authority, RequestRefusal> {
    let host = headers
        .get("host")
        .map(|host| parse_authority(host))
        .transpose()?;
    match request.version {
        HttpVersion::Http11 => host.ok_or(RequestRefusal::MissingAuthority),
        HttpVersion::Http2 => {
            let authority = parse_authority(
                request
                    .authority
                    .as_deref()
                    .ok_or(RequestRefusal::MissingAuthority)?,
            )?;
            match host {
                Some(host) if host != authority => Err(RequestRefusal::AuthorityConflict),
                _ => Ok(authority),
            }
        }
    }
}

fn check_sni(authority: &Authority, tls: &TlsFacts) -> Result<(), RequestRefusal> {
    match (&authority.host, &tls.sni) {
        (DestinationHost::Name(_), None) => Err(RequestRefusal::MissingSni),
        (DestinationHost::Name(name), Some(sni)) => {
            let sni_name = CanonicalName::parse(sni).map_err(RequestRefusal::InvalidSni)?;
            if sni_name == *name {
                Ok(())
            } else {
                Err(RequestRefusal::SniAuthorityMismatch {
                    sni: sni.clone(),
                    authority: authority.clone(),
                })
            }
        }
        (DestinationHost::Address(_), None) => Ok(()),
        (DestinationHost::Address(_), Some(sni)) => Err(RequestRefusal::SniAuthorityMismatch {
            sni: sni.clone(),
            authority: authority.clone(),
        }),
    }
}

/// Splits an origin-form target into normalized path segments and query pairs.
pub fn normalize_target(
    target: &str,
) -> Result<(Vec<String>, BTreeMap<String, String>), RequestRefusal> {
    if !target.starts_with('/') {
        return Err(RequestRefusal::TargetNotOriginForm);
    }
    if target.contains('#') {
        return Err(RequestRefusal::Fragment);
    }
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (target, None),
    };
    let mut segments = Vec::new();
    if path != "/" {
        for raw in path[1..].split('/') {
            if raw.is_empty() {
                return Err(RequestRefusal::EmptySegment);
            }
            if raw.contains(';') {
                return Err(RequestRefusal::PathParameter);
            }
            let segment = normalize_component(raw, false)?;
            if segment == "." || segment == ".." {
                return Err(RequestRefusal::DotSegment);
            }
            segments.push(segment);
        }
    }
    let mut pairs = BTreeMap::new();
    if let Some(query) = query {
        if query.is_empty() {
            return Err(RequestRefusal::EmptyQuery);
        }
        if query.contains(';') {
            return Err(RequestRefusal::AmbiguousQuerySeparator);
        }
        if query.contains('+') {
            return Err(RequestRefusal::PlusInQuery);
        }
        for pair in query.split('&') {
            if pair.is_empty() {
                return Err(RequestRefusal::EmptyQueryPair);
            }
            let Some((key, value)) = pair.split_once('=') else {
                return Err(RequestRefusal::QueryPairWithoutValue {
                    key: pair.to_owned(),
                });
            };
            let key = normalize_component(key, true)?;
            if key.is_empty() {
                return Err(RequestRefusal::EmptyQueryPair);
            }
            let value = normalize_component(value, true)?;
            if pairs.insert(key.clone(), value).is_some() {
                return Err(RequestRefusal::DuplicateQueryKey { key });
            }
        }
    }
    Ok((segments, pairs))
}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

/// Normalizes one path segment or query part: unreserved characters decoded, other
/// percent-encodings kept with uppercase hex; ambiguous encodings refused.
fn normalize_component(raw: &str, in_query: bool) -> Result<String, RequestRefusal> {
    let bytes = raw.as_bytes();
    let mut output = String::with_capacity(raw.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            let hex = bytes
                .get(index + 1..index + 3)
                .filter(|pair| pair.iter().all(u8::is_ascii_hexdigit))
                .ok_or(RequestRefusal::InvalidPercentEncoding)?;
            let text =
                std::str::from_utf8(hex).map_err(|_| RequestRefusal::InvalidPercentEncoding)?;
            let value =
                u8::from_str_radix(text, 16).map_err(|_| RequestRefusal::InvalidPercentEncoding)?;
            if matches!(value, b'.' | b'/' | b'\\') || value < 0x20 || value == 0x7f {
                return Err(RequestRefusal::AmbiguousEncodedCharacter {
                    encoded: format!("%{}", text.to_ascii_uppercase()),
                });
            }
            if is_unreserved(value) {
                output.push(char::from(value));
            } else {
                output.push('%');
                output.push_str(&text.to_ascii_uppercase());
            }
            index += 3;
            continue;
        }
        let allowed = is_unreserved(byte)
            || matches!(
                byte,
                b'!' | b'$' | b'\'' | b'(' | b')' | b'*' | b',' | b':' | b'@'
            )
            || (in_query && matches!(byte, b'/' | b'?'))
            || (!in_query && matches!(byte, b'&' | b'=' | b'+'));
        if !allowed {
            return Err(RequestRefusal::InvalidPathCharacter {
                character: char::from(byte),
            });
        }
        output.push(char::from(byte));
        index += 1;
    }
    Ok(output)
}

/// Where a redirect points, read with the one destination parser.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedirectTarget {
    pub authority: Authority,
    /// The origin-form target (path and query) of the redirect.
    pub target: String,
}

/// Reads a `Location` value relative to `current`. Only `https` targets and
/// origin-relative paths are accepted; userinfo, fragments, scheme-relative and
/// downgraded targets are refused.
pub fn redirect_target(
    current: &Authority,
    location: &str,
) -> Result<RedirectTarget, RequestRefusal> {
    if location.starts_with("//") {
        return Err(RequestRefusal::RedirectSchemeRelative);
    }
    if location.contains('#') {
        return Err(RequestRefusal::Fragment);
    }
    if location.starts_with('/') {
        normalize_target(location)?;
        return Ok(RedirectTarget {
            authority: current.clone(),
            target: location.to_owned(),
        });
    }
    let (scheme, rest) = location
        .split_once("://")
        .ok_or(RequestRefusal::InvalidRedirect)?;
    if scheme.eq_ignore_ascii_case("http") {
        return Err(RequestRefusal::RedirectSchemeNotHttps);
    }
    if !scheme.eq_ignore_ascii_case("https") {
        return Err(RequestRefusal::InvalidRedirect);
    }
    let split = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, target) = rest.split_at(split);
    let authority = parse_authority(authority)?;
    let target = match target {
        "" => "/".to_owned(),
        target if target.starts_with('?') => format!("/{target}"),
        target => target.to_owned(),
    };
    normalize_target(&target)?;
    Ok(RedirectTarget { authority, target })
}
