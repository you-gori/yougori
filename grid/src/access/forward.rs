//! Sending a request with a company credential the agent never sees. The hub checks the URL is
//! inside one of the credential's destinations, puts the value on the request itself, follows no
//! redirects, and hides the value wherever the answer happens to echo it. Plain `http://` is
//! accepted only for private addresses such as an internal service at `http://10.0.0.8:8080`.
use super::{
    policy::{within_path, Kind},
    sigv4,
};
use crate::net;
use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, header, Request, Response, Uri};
use hyper_util::rt::TokioIo;
use serde_json::{json, Map, Value};
use std::{
    net::IpAddr,
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{
    rustls::{self, pki_types::ServerName},
    TlsConnector,
};

/// Headers an agent may not set: the hub owns authorization, routing and framing.
pub const RESERVED_HEADERS: &[&str] = &[
    "host", "authorization", "proxy-authorization", "connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade", "content-length", "expect",
    "proxy-connection", "forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-real-ip",
    // Overrides some services honour, which would make them act on another method or path than
    // the one the rules judged.
    "x-http-method-override", "x-http-method", "x-method-override", "x-original-url", "x-rewrite-url", "x-original-method",
];
/// Answer headers that never reach the agent: sessions the credential opened, and framing.
const DROPPED_ANSWER_HEADERS: &[&str] = &["set-cookie", "set-cookie2", "connection", "keep-alive", "transfer-encoding", "trailer", "upgrade", "proxy-authenticate"];
/// The largest request body an agent may send.
pub const MAX_BODY: usize = 2 * 1024 * 1024;
/// The most the hub reads of an answer.
const MAX_ANSWER: usize = 4 * 1024 * 1024;
/// The most of an answer's body the agent gets back.
pub const AGENT_BODY: usize = 256 * 1024;
const MAX_HEADERS: usize = 32;
const CONNECT: Duration = Duration::from_secs(10);
pub const TIMEOUT: Duration = Duration::from_secs(60);
const HIDDEN: &[u8] = b"[hidden by Access Grid]";

/// Where a request goes: scheme, host and port, its path, and its query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub https: bool,
    /// Lower case; an IPv6 address keeps its brackets.
    pub host: String,
    pub port: u16,
    pub path: String,
    pub query: Option<String>,
}

impl Target {
    fn default_port(&self) -> bool {
        self.port == if self.https { 443 } else { 80 }
    }
    pub fn origin(&self) -> String {
        let scheme = if self.https { "https" } else { "http" };
        if self.default_port() {
            format!("{scheme}://{}", self.host)
        } else {
            format!("{scheme}://{}:{}", self.host, self.port)
        }
    }
    /// The URL without its query, for the activity log.
    pub fn shown(&self) -> String {
        format!("{}{}", self.origin(), self.path)
    }
    fn authority(&self) -> String {
        if self.default_port() {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

fn host_ip(host: &str) -> Option<IpAddr> {
    host.trim_start_matches('[').trim_end_matches(']').parse().ok()
}

fn parse(text: &str, what: &str) -> Result<Target, String> {
    let invalid = || format!("{what} must be a full https:// address such as https://api.example.com/v1");
    let text = text.trim();
    if text.is_empty() || text.len() > 4096 || text.chars().any(|c| c.is_control() || c == ' ' || c == '\\') || text.contains('#') {
        return Err(invalid());
    }
    let uri: Uri = text.parse().map_err(|_| invalid())?;
    let https = match uri.scheme_str() {
        Some("https") => true,
        Some("http") => false,
        _ => return Err(invalid()),
    };
    let authority = uri.authority().ok_or_else(invalid)?;
    if authority.as_str().contains('@') {
        return Err(format!("{what} may not carry a username or password"));
    }
    let host = authority.host().to_ascii_lowercase();
    let ip = host_ip(&host);
    if host.starts_with('[') != ip.is_some_and(|ip| ip.is_ipv6()) || (ip.is_none() && !net::valid_hostname(&host)) {
        return Err(invalid());
    }
    if !https && !ip.is_some_and(net::private) && host != "localhost" {
        return Err(format!("{what} must use https://; plain http:// is accepted only for private addresses such as http://10.0.0.8:8080"));
    }
    let port = authority.port_u16().unwrap_or(if https { 443 } else { 80 });
    if port == 0 {
        return Err(invalid());
    }
    let path = uri.path();
    let path = if path.is_empty() { "/" } else { path };
    let lower = path.to_ascii_lowercase();
    // An encoded `;` too: a server that decodes before it drops `;parameters` reads
    // `/admin%3bx` as `/admin`, which the rules would not see. So is a segment that is only
    // parameters (`/;x/admin`, which those servers read as `/admin`), and any encoded `%`
    // (`%25`): a server that decodes twice reads `%25%32%65` as `.` and `%2561` as `a`, and no
    // spelling of that can be judged once.
    let shaped = ["%2f", "%5c", "%2e", "%3b", "%25"];
    if path.contains("//")
        || shaped.iter().any(|escape| lower.contains(escape))
        || path.split('/').any(super::policy::dot_segment)
        || path.split('/').skip(1).any(|segment| segment.starts_with(';'))
    {
        return Err(format!("{what} has an ambiguous path (.., //, a segment of only ;parameters, or encoded slashes, dots, semicolons or percent signs)"));
    }
    Ok(Target { https, host, port, path: path.to_owned(), query: uri.query().map(str::to_owned) })
}

/// The URL an agent asked for.
pub fn target(url: &str) -> Result<Target, String> {
    parse(url, "The URL")
}

/// An address the hub itself calls, such as an OAuth token endpoint or an identity provider:
/// `https://`, or plain `http://` on a private address.
pub fn token_url(text: &str) -> Result<String, String> {
    let target = parse(text, "The address")?;
    Ok(match &target.query {
        Some(query) => format!("{}{}?{query}", target.origin(), target.path),
        None => format!("{}{}", target.origin(), target.path),
    })
}

/// A destination as the hub keeps it: `https://host[:port]` and an optional path prefix.
pub fn destination(text: &str) -> Result<String, String> {
    let target = parse(text, "A destination")?;
    if target.query.is_some() {
        return Err("A destination has no ?query; give the address and an optional path prefix".into());
    }
    Ok(format!("{}{}", target.origin(), target.path.trim_end_matches('/')))
}

/// Whether `target` lies inside `destination`: same scheme, host and port, and under its path.
pub fn within(target: &Target, destination: &str) -> bool {
    parse(destination, "A destination").is_ok_and(|place| place.https == target.https && place.host == target.host && place.port == target.port && within_path(&target.path, &place.path))
}

/// The headers a credential of this kind travels in, which an agent may not set.
pub fn owned_headers(kind: Kind, field: &str) -> Vec<String> {
    match kind {
        Kind::Header => vec![field.to_ascii_lowercase()],
        Kind::Aws => vec!["x-amz-date".into(), "x-amz-security-token".into(), "x-amz-content-sha256".into()],
        _ => Vec::new(),
    }
}

/// Headers an agent asked to send: at most 32 printable single-line pairs, none the hub owns or
/// the credential itself travels in (`owned`, lower case).
pub fn agent_headers(headers: &Map<String, Value>, owned: &[String]) -> Result<Vec<(String, String)>, String> {
    if headers.len() > MAX_HEADERS {
        return Err(format!("Send at most {MAX_HEADERS} headers"));
    }
    let mut out = Vec::new();
    for (name, value) in headers {
        let value = value.as_str().ok_or_else(|| format!("Header {name} must be text"))?;
        let lower = name.to_ascii_lowercase();
        if name.is_empty() || name.len() > 64 || !name.bytes().all(|c| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c)) {
            return Err(format!("'{name}' is not a header name"));
        }
        if value.len() > 8192 || value.chars().any(|c| c.is_control() && c != '\t') {
            return Err(format!("Header {name} must be one line of at most 8192 characters"));
        }
        if RESERVED_HEADERS.contains(&lower.as_str()) || owned.contains(&lower) {
            continue;
        }
        out.push((name.clone(), value.to_owned()));
    }
    Ok(out)
}

/// One request an agent wants sent, already inside a destination and allowed by the rules.
#[derive(Clone, Debug)]
pub struct Outgoing {
    pub method: String,
    pub target: Target,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// How the credential goes on a request, once the hub holds the value or a token it made from it.
#[derive(Clone)]
pub enum Auth {
    /// A header the hub sets, such as `Authorization: Bearer …`.
    Header(String, String),
    /// A query parameter the hub adds.
    Query(String, String),
    /// AWS: the hub signs the request (SigV4) with these keys.
    Aws { keys: sigv4::Keys, region: String, service: Option<String> },
}

/// The credential ready to go on a request, with every string that must never come back.
#[derive(Clone)]
pub struct Prepared {
    pub auth: Auth,
    pub secrets: Vec<String>,
}

impl Prepared {
    /// A value sent as it is: bearer, header, basic or query.
    pub fn plain(kind: Kind, field: &str, value: &str) -> Prepared {
        let basic = base64::engine::general_purpose::STANDARD.encode(format!("{field}:{value}"));
        let auth = match kind {
            Kind::Header => Auth::Header(field.to_owned(), value.to_owned()),
            Kind::Basic => Auth::Header("authorization".into(), format!("Basic {basic}")),
            Kind::Query => Auth::Query(field.to_owned(), value.to_owned()),
            _ => Auth::Header("authorization".into(), format!("Bearer {value}")),
        };
        let mut secrets = vec![value.to_owned()];
        if kind == Kind::Basic {
            secrets.push(basic);
        }
        Prepared { auth, secrets }
    }

    /// A short-lived bearer token the hub made, with the secret it was made from.
    pub fn bearer(token: &str, secret: &str) -> Prepared {
        Prepared { auth: Auth::Header("authorization".into(), format!("Bearer {token}")), secrets: vec![token.to_owned(), secret.to_owned()] }
    }

    /// Every form the secrets could come back in, so the answer can hide them.
    fn forms(&self) -> Vec<Vec<u8>> {
        let mut forms = Vec::new();
        for secret in &self.secrets {
            forms.push(secret.as_bytes().to_vec());
            forms.push(encode(secret).into_bytes());
            if let Ok(escaped) = serde_json::to_string(secret) {
                forms.push(escaped.trim_matches('"').as_bytes().to_vec());
            }
        }
        // A short value would hide unrelated text; such values are rare and not hidden.
        forms.retain(|form| form.len() >= 4);
        // Longest first, so a value inside a longer form is hidden as a whole.
        forms.sort_by(|a, b| b.len().cmp(&a.len()).then(a.cmp(b)));
        forms.dedup();
        forms
    }
}

/// Percent-encodes everything but unreserved characters.
fn encode(text: &str) -> String {
    text.bytes().map(|byte| if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) { (byte as char).to_string() } else { format!("%{byte:02X}") }).collect()
}

fn decode_name(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 3 <= bytes.len() {
            if let Some(byte) = std::str::from_utf8(&bytes[index + 1..index + 3]).ok().and_then(|hex| u8::from_str_radix(hex, 16).ok()) {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(if bytes[index] == b'+' { b' ' } else { bytes[index] });
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The query to send: for a query credential, any parameter of the same name the agent gave is
/// dropped and the value added.
fn query_of(target: &Target, auth: &Auth) -> Option<String> {
    let mut pairs: Vec<String> = target.query.as_deref().unwrap_or_default().split('&').filter(|pair| !pair.is_empty()).map(str::to_owned).collect();
    if let Auth::Query(name, value) = auth {
        pairs.retain(|pair| decode_name(pair.split('=').next().unwrap_or_default()) != *name);
        pairs.push(format!("{}={}", encode(name), encode(value)));
    }
    (!pairs.is_empty()).then(|| pairs.join("&"))
}

fn path_and_query(target: &Target, auth: &Auth) -> String {
    match query_of(target, auth) {
        Some(query) => format!("{}?{query}", target.path),
        None => target.path.clone(),
    }
}

fn hide(bytes: &[u8], forms: &[Vec<u8>]) -> Vec<u8> {
    if forms.is_empty() {
        return bytes.to_vec();
    }
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    'scan: while index < bytes.len() {
        for form in forms {
            if bytes[index..].starts_with(form) {
                out.extend_from_slice(HIDDEN);
                index += form.len();
                continue 'scan;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    out
}

fn roots() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut store = rustls::RootCertStore::empty();
            store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("ring supports the default TLS versions")
                .with_root_certificates(store)
                .with_no_client_auth();
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            Arc::new(config)
        })
        .clone()
}

async fn exchange<S>(stream: S, request: Request<Full<Bytes>>) -> Result<Response<Incoming>, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.map_err(|error| format!("The service did not speak HTTP: {error}"))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    sender.send_request(request).await.map_err(|error| format!("The service closed the connection: {error}"))
}

/// What a service the hub itself called answered: its status, headers and up to 1 MiB of body.
pub struct Fetched {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Fetched {
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
    /// The status and a short, printable piece of the answer, for an error message.
    pub fn said(&self) -> String {
        let json = self.json();
        let message = json["error_description"].as_str().or_else(|| json["message"].as_str()).or_else(|| json["error"]["message"].as_str()).or_else(|| json["error"].as_str()).map(str::to_owned).unwrap_or_else(|| String::from_utf8_lossy(&self.body).chars().filter(|c| !c.is_control()).take(160).collect());
        format!("HTTP {}: {}", self.status, message.chars().take(200).collect::<String>())
    }
}

/// One request the hub makes for itself (a token endpoint, an identity provider), to an address
/// `token_url` accepts. No redirects; answers over 1 MiB are refused.
pub async fn fetch(method: &str, url: &str, headers: &[(&str, String)], body: Option<Vec<u8>>) -> Result<Fetched, String> {
    let target = parse(url, "The address")?;
    let mut request = Request::builder().method(method).uri(match &target.query { Some(query) => format!("{}?{query}", target.path), None => target.path.clone() }).header(header::HOST, target.authority()).header(header::USER_AGENT, "Yougori-Access-Grid");
    for (name, value) in headers {
        request = request.header(*name, value.as_str());
    }
    let request = request.body(Full::new(Bytes::from(body.unwrap_or_default()))).map_err(|_| "The request could not be built".to_owned())?;
    let work = async {
        let response = open(&target, request).await?;
        let status = response.status().as_u16();
        let headers = response.headers().iter().map(|(name, value)| (name.as_str().to_ascii_lowercase(), String::from_utf8_lossy(value.as_bytes()).into_owned())).collect();
        let body = http_body_util::Limited::new(response.into_body(), 1024 * 1024).collect().await.map_err(|_| format!("The answer from {} was too large or interrupted", target.origin()))?.to_bytes().to_vec();
        Ok(Fetched { status, headers, body })
    };
    tokio::time::timeout(Duration::from_secs(30), work).await.map_err(|_| format!("{} did not answer within 30 seconds", target.origin()))?
}

/// Sends the request with the credential and returns what the agent may see of the answer:
/// `{status, headers, body | bodyBase64, bytes, truncated}`.
pub async fn send(outgoing: &Outgoing, prepared: &Prepared) -> Result<Value, String> {
    tokio::time::timeout(TIMEOUT, send_now(outgoing, prepared)).await.map_err(|_| format!("{} did not answer within {} seconds", outgoing.target.origin(), TIMEOUT.as_secs()))?
}

/// Connects to `target` and sends one request: TLS with publicly trusted roots for `https://`.
async fn open(target: &Target, request: Request<Full<Bytes>>) -> Result<Response<Incoming>, String> {
    let unreachable = |error: std::io::Error| format!("Cannot reach {}: {error}", target.origin());
    let connect_host = target.host.trim_start_matches('[').trim_end_matches(']').to_owned();
    let socket = tokio::time::timeout(CONNECT, tokio::net::TcpStream::connect((connect_host.as_str(), target.port)))
        .await
        .map_err(|_| format!("Cannot reach {}: no answer within {} seconds", target.origin(), CONNECT.as_secs()))?
        .map_err(unreachable)?;
    if target.https {
        let name = match host_ip(&target.host) {
            Some(ip) => ServerName::IpAddress(ip.into()),
            None => ServerName::try_from(connect_host.clone()).map_err(|_| format!("{} is not a valid TLS name", target.host))?,
        };
        let stream = tokio::time::timeout(CONNECT, TlsConnector::from(roots()).connect(name, socket))
            .await
            .map_err(|_| format!("{} did not finish TLS in time", target.origin()))?
            .map_err(|error| format!("{} failed TLS verification: {error}", target.origin()))?;
        exchange(stream, request).await
    } else {
        exchange(socket, request).await
    }
}

async fn send_now(outgoing: &Outgoing, prepared: &Prepared) -> Result<Value, String> {
    let target = &outgoing.target;
    let mut request = Request::builder().method(outgoing.method.as_str()).uri(path_and_query(target, &prepared.auth)).header(header::HOST, target.authority());
    for (name, value) in &outgoing.headers {
        request = request.header(name.as_str(), value.as_str());
    }
    // Some APIs, GitHub's among them, refuse requests without one.
    if !outgoing.headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("user-agent")) {
        request = request.header(header::USER_AGENT, "Yougori-Access-Grid");
    }
    match &prepared.auth {
        Auth::Header(name, value) => request = request.header(name.as_str(), value.as_str()),
        Auth::Query(..) => {}
        Auth::Aws { keys, region, service } => {
            let service = service.clone().or_else(|| sigv4::service_of(&target.host)).ok_or("Set the AWS service for this credential: its host does not name one")?;
            let query = query_of(target, &prepared.auth);
            for (name, value) in sigv4::sign(&outgoing.method, &target.authority(), &target.path, query.as_deref(), &outgoing.body, keys, region, &service, &sigv4::amz_date(), true) {
                request = request.header(name, value);
            }
        }
    }
    let request = request.body(Full::new(Bytes::from(outgoing.body.clone()))).map_err(|_| "The request could not be built from these headers".to_owned())?;
    let response = open(target, request).await?;
    let status = response.status().as_u16();
    let forms = prepared.forms();
    let mut headers = Map::new();
    for (name, value) in response.headers() {
        let name = name.as_str().to_ascii_lowercase();
        if DROPPED_ANSWER_HEADERS.contains(&name.as_str()) {
            continue;
        }
        let value = String::from_utf8_lossy(&hide(value.as_bytes(), &forms)).into_owned();
        match headers.get_mut(&name) {
            Some(Value::String(previous)) => {
                previous.push_str(", ");
                previous.push_str(&value);
            }
            _ => {
                headers.insert(name, Value::String(value));
            }
        }
    }
    let mut body = response.into_body();
    let mut bytes = Vec::new();
    let mut truncated = false;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| format!("The answer from {} was interrupted: {error}", target.origin()))?;
        if let Ok(data) = frame.into_data() {
            bytes.extend_from_slice(&data);
            if bytes.len() > MAX_ANSWER {
                bytes.truncate(MAX_ANSWER);
                truncated = true;
                break;
            }
        }
    }
    let total = bytes.len();
    let mut shown = hide(&bytes, &forms);
    if shown.len() > AGENT_BODY {
        shown.truncate(AGENT_BODY);
        truncated = true;
    }
    let mut answer = json!({"status": status, "headers": headers, "bytes": total, "truncated": truncated});
    match String::from_utf8(shown) {
        Ok(text) => answer["body"] = json!(text),
        Err(error) if truncated && error.utf8_error().error_len().is_none() => {
            let valid = error.utf8_error().valid_up_to();
            let mut text = error.into_bytes();
            text.truncate(valid);
            answer["body"] = json!(String::from_utf8_lossy(&text));
        }
        Err(error) => answer["bodyBase64"] = json!(base64::engine::general_purpose::STANDARD.encode(error.into_bytes())),
    }
    Ok(answer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::Body;
    use hyper::StatusCode;
    use tokio::net::TcpListener;

    #[test]
    fn urls_must_stay_inside_a_destination() {
        assert_eq!(destination("https://API.GitHub.com/").unwrap(), "https://api.github.com");
        assert_eq!(destination("https://api.example.com:8443/v1/").unwrap(), "https://api.example.com:8443/v1");
        assert_eq!(destination("http://10.0.0.8:8080/api").unwrap(), "http://10.0.0.8:8080/api");
        for bad in ["http://api.example.com", "ftp://x.example", "https://user:pw@api.example.com", "https://api.example.com/?a=1", "https://api.example.com/a/../b", "api.example.com", "https://exa mple.com"] {
            assert!(destination(bad).is_err(), "{bad}");
        }
        let place = destination("https://api.example.com/v1").unwrap();
        assert!(within(&target("https://api.example.com/v1/users?page=2").unwrap(), &place));
        assert!(within(&target("https://api.example.com/v1").unwrap(), &place));
        for outside in ["https://api.example.com/v2", "https://api.example.com/v10", "https://api.example.com:444/v1", "https://evil.example.com/v1", "https://api.example.com.evil.net/v1"] {
            assert!(!within(&target(outside).unwrap(), &place), "{outside}");
        }
        for ambiguous in ["https://api.example.com/v1/../admin", "https://api.example.com/v1/%2e%2e/admin", "https://api.example.com/v1%2Fadmin", "https://api.example.com//v1", "https://api.example.com/v1/..;/admin", "https://api.example.com/admin%3bx/users", "https://api.example.com/admin%3Bx", "https://api.example.com/;/admin", "https://api.example.com/api/;x/admin", "https://api.example.com/v1%252fadmin", "https://api.example.com/v1/%252e%252e/admin", "https://api.example.com/v1/%25%32%65%25%32%65/admin", "https://api.example.com/admin%25%33%62x/users", "https://api.example.com/%2561dmin"] {
            assert!(target(ambiguous).is_err(), "{ambiguous}");
        }
        let any = destination("https://api.example.com").unwrap();
        assert!(within(&target("https://api.example.com/anything/here").unwrap(), &any));
    }

    #[test]
    fn agents_cannot_set_the_headers_the_hub_owns() {
        let headers = json!({"Accept": "application/json", "Authorization": "Bearer mine", "Host": "evil", "X-Api-Key": "guess", "Content-Length": "9"});
        let kept = agent_headers(headers.as_object().unwrap(), &owned_headers(Kind::Header, "X-Api-Key")).unwrap();
        assert_eq!(kept, [("Accept".to_owned(), "application/json".to_owned())]);
        assert!(agent_headers(json!({"Bad Name": "x"}).as_object().unwrap(), &[]).is_err());
        assert!(agent_headers(json!({"X-A": "line\r\nInjected: 1"}).as_object().unwrap(), &[]).is_err());
        let aws = agent_headers(json!({"X-Amz-Date": "19990101T000000Z", "X-Amz-Target": "DynamoDB_20120810.ListTables"}).as_object().unwrap(), &owned_headers(Kind::Aws, "")).unwrap();
        assert_eq!(aws, [("X-Amz-Target".to_owned(), "DynamoDB_20120810.ListTables".to_owned())]);
    }

    #[test]
    fn query_credentials_replace_the_agents_parameter_and_answers_hide_every_form() {
        let target = target("http://127.0.0.1:9/items?api_key=guess&page=2").unwrap();
        let secret = Prepared::plain(Kind::Query, "api_key", "k y/1");
        assert_eq!(path_and_query(&target, &secret.auth), "/items?page=2&api_key=k%20y%2F1");
        let secret = Prepared::plain(Kind::Basic, "bot", "pass\"word");
        let echoed = format!("{{\"auth\":\"Basic {}\",\"raw\":\"pass\\\"word\",\"url\":\"pass%22word\"}}", base64::engine::general_purpose::STANDARD.encode("bot:pass\"word"));
        let hidden = String::from_utf8(hide(echoed.as_bytes(), &secret.forms())).unwrap();
        assert!(!hidden.contains("pass") && !hidden.contains(&base64::engine::general_purpose::STANDARD.encode("bot:pass\"word")), "{hidden}");
        assert_eq!(hidden.matches("[hidden by Access Grid]").count(), 3);
    }

    /// A local service that echoes what it received, sets a cookie and answers large when asked.
    async fn echo() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else { return };
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(|request: Request<Incoming>| async move {
                        let (parts, body) = request.into_parts();
                        let body = body.collect().await.unwrap().to_bytes();
                        let large = parts.uri.path() == "/large";
                        let seen = json!({
                            "method": parts.method.as_str(), "uri": parts.uri.to_string(),
                            "authorization": parts.headers.get("authorization").map(|v| v.to_str().unwrap().to_owned()),
                            "accept": parts.headers.get("accept").map(|v| v.to_str().unwrap().to_owned()),
                            "body": String::from_utf8_lossy(&body),
                        });
                        let text = if large { "x".repeat(AGENT_BODY + 10) } else { seen.to_string() };
                        Ok::<_, std::convert::Infallible>(Response::builder().status(StatusCode::CREATED).header("set-cookie", "session=abc").header("x-echo", parts.headers.get("authorization").map(|v| v.to_str().unwrap().to_owned()).unwrap_or_default()).body(crate::net::full(text)).unwrap() as Response<Body>)
                    });
                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(socket), service).await;
                });
            }
        });
        address
    }

    #[tokio::test]
    async fn the_credential_goes_on_the_request_and_never_comes_back() {
        let address = echo().await;
        let outgoing = Outgoing {
            method: "POST".into(),
            target: target(&format!("http://{address}/v1/things?x=1")).unwrap(),
            headers: agent_headers(json!({"Accept": "application/json", "Authorization": "Bearer agent-guess"}).as_object().unwrap(), &[]).unwrap(),
            body: b"{\"name\":\"a\"}".to_vec(),
        };
        let secret = Prepared::plain(Kind::Bearer, "", "sk-live-0123456789");
        let answer = send(&outgoing, &secret).await.unwrap();
        assert_eq!(answer["status"], 201);
        let body = answer["body"].as_str().unwrap();
        let seen: Value = serde_json::from_str(body).unwrap();
        assert_eq!(seen["authorization"], "Bearer [hidden by Access Grid]", "the service got the hub's credential, not the agent's guess, and the echo is hidden");
        assert_eq!(seen["accept"], "application/json");
        assert_eq!(seen["uri"], "/v1/things?x=1");
        assert_eq!(seen["body"], "{\"name\":\"a\"}");
        assert!(answer["headers"].get("set-cookie").is_none());
        assert_eq!(answer["headers"]["x-echo"], "Bearer [hidden by Access Grid]");
        assert!(!answer.to_string().contains("sk-live"));

        let large = Outgoing { method: "GET".into(), target: target(&format!("http://{address}/large")).unwrap(), headers: Vec::new(), body: Vec::new() };
        let answer = send(&large, &secret).await.unwrap();
        assert_eq!((answer["truncated"].as_bool(), answer["body"].as_str().unwrap().len()), (Some(true), AGENT_BODY));
    }
}
