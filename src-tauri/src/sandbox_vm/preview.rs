//! Previews of published guest services on this computer (M14; VM part §4.7 "serve previews
//! on isolated origins, with no implicit host application session or file access"; VM-W13):
//! the transport adapter between a caller on the loopback interface and the connection gate
//! the VM service keeps (`vm_service::publish`).
//!
//! Each publication gets a listener of its own on `127.0.0.1` (never another interface), and
//! each accepted connection carries one HTTP/1.1 request:
//!
//! - The request head is read whole (at most [`MAX_REQUEST_HEAD`] bytes) and checked: an
//!   origin-form target, no obsolete line folding, one `Host`, at most one `Content-Length`,
//!   no `Transfer-Encoding` (a chunked body is not forwarded). Its `Host` must name this
//!   listener's port on `127.0.0.1`, `localhost` or a `*.localhost` name, so a page of
//!   another site whose name a DNS rebinding pointed here is refused.
//! - An owner's publication authenticates its caller with the publication's bearer token:
//!   the first label of a `<token>.localhost` host (the address the publish answer gives,
//!   which a browser sends with every request of the page, needing no cookie) or an
//!   `Authorization: Bearer` header (for tools). A public publication, chosen as such,
//!   admits anyone who reaches the listener. The gate decides ([`PreviewHost::admit`]); a
//!   refused caller is told 401 for its authentication and 404 for anything else, never why.
//! - Forwarded to the guest: the request line, the headers without the caller's
//!   credentials (`Authorization`, `Proxy-Authorization`, `Cookie`) and hop-by-hop fields,
//!   `Host: localhost:<guest port>` and `Connection: close`, then exactly the declared body.
//! - Answered to the caller: the guest's status line and headers without its cookies
//!   (`Set-Cookie`), hop-by-hop fields or own copies of the preview policy's headers, which
//!   are sent in their place ([`policy_headers`]: a sandboxed content security policy that
//!   denies framing and same-origin access, isolation and no-sniff headers, a permissions
//!   policy denying every device, no caching), then the body as the guest sent it, every
//!   byte charged by the gate before it left.
//!
//! A gate pump ([`PreviewHost::pump`]) moves every session's bytes and closes a session the
//! moment the sandbox's authority, the grant, the publication or its budget ends; a listener
//! whose publication stopped being active is closed by the same loop.

use std::collections::{BTreeMap, VecDeque};
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::foundation::ids::{ExecutionId, MonotonicTime};
use crate::sandbox::vm_service::{
    CallerRoom, GuestIngressWatch, PublicationAudience, SandboxId, SessionsPumped,
    OWNER_PRINCIPAL,
};
use crate::sandbox_contract::connections::{
    AuthenticationProof, GateRefusal, ProofBinding, ProofRefusal, ProofVerifier, SessionStream,
    StreamError, StreamRead, VerifiedProof,
};
use crate::sandbox_contract::destinations::{
    AuthenticationMode, IngressError, PrincipalId, RESERVED_CREDENTIAL_HEADERS,
};
use crate::sandbox_contract::untrusted::REQUIRED_PERMISSIONS_DENIALS;

/// The most bytes of one request head.
pub const MAX_REQUEST_HEAD: usize = 16 << 10;
/// The most bytes of one response head.
pub const MAX_RESPONSE_HEAD: usize = 64 << 10;
/// The largest request body forwarded.
pub const MAX_REQUEST_BODY: u64 = 32 << 20;
/// The most header lines of one head.
const MAX_HEADERS: usize = 100;
/// How long a caller may take to send its request head.
const HEAD_TIMEOUT: Duration = Duration::from_secs(10);
/// The most connections one listener serves at once.
const MAX_CONNECTIONS: usize = 32;
/// The most of the guest's answer held for a caller that does not read it.
const MAX_PENDING_TO_CALLER: usize = 4 << 20;
/// The most of the answer the connection's thread holds for the socket at once.
const IN_FLIGHT_BYTES: usize = 256 << 10;
/// How often the pump checks that each listener's publication still stands.
const LISTENER_CHECK: Duration = Duration::from_secs(1);
/// The domain of a `<token>.localhost` address.
const LOCAL_DOMAIN: &str = "localhost";

/// The response headers of every preview: the preview policy's (`untrusted::PreviewPolicy`
/// with `FrameAncestors::None`), sent in place of any copy the guest sends.
pub fn policy_headers() -> Vec<(&'static str, String)> {
    let permissions = REQUIRED_PERMISSIONS_DENIALS
        .iter()
        .map(|feature| format!("{feature}=()"))
        .collect::<Vec<_>>()
        .join(", ");
    vec![
        (
            "Content-Security-Policy",
            "sandbox allow-scripts allow-forms; frame-ancestors 'none'".to_owned(),
        ),
        ("Cross-Origin-Opener-Policy", "same-origin".to_owned()),
        ("Cross-Origin-Resource-Policy", "same-origin".to_owned()),
        ("Referrer-Policy", "no-referrer".to_owned()),
        ("X-Content-Type-Options", "nosniff".to_owned()),
        ("Permissions-Policy", permissions),
        ("Cache-Control", "no-store".to_owned()),
    ]
}

/// Request and response fields never forwarded: the caller's credentials, hop-by-hop fields
/// (the preview carries one request per connection) and the host, which is set anew.
const DROPPED_REQUEST: [&str; 9] = [
    "host",
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",
    "expect",
    "http2-settings",
];
const DROPPED_RESPONSE: [&str; 6] = [
    "set-cookie",
    "set-cookie2",
    "connection",
    "keep-alive",
    "proxy-connection",
    "upgrade",
];

/// Why a request head was refused, and the status the caller is told.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeadRefusal {
    Malformed(&'static str),
    WrongHost,
    ChunkedBody,
    BodyTooLarge,
}

impl HeadRefusal {
    const fn status(&self) -> (u16, &'static str) {
        match self {
            Self::Malformed(_) => (400, "Bad Request"),
            Self::WrongHost => (421, "Misdirected Request"),
            Self::ChunkedBody => (501, "Not Implemented"),
            Self::BodyTooLarge => (413, "Content Too Large"),
        }
    }
}

/// One request head as the adapter reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestHead {
    pub method: String,
    pub target: String,
    pub headers: Vec<(String, String)>,
}

impl RequestHead {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(field, _)| field.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn count(&self, name: &str) -> usize {
        self.headers
            .iter()
            .filter(|(field, _)| field.eq_ignore_ascii_case(name))
            .count()
    }

    /// The body length the head declares; zero without one.
    pub fn content_length(&self) -> Result<u64, HeadRefusal> {
        match self.header("content-length") {
            None => Ok(0),
            Some(value) => {
                let length = value
                    .trim()
                    .parse::<u64>()
                    .map_err(|_| HeadRefusal::Malformed("content-length"))?;
                if length > MAX_REQUEST_BODY {
                    return Err(HeadRefusal::BodyTooLarge);
                }
                Ok(length)
            }
        }
    }
}

fn is_token(text: &str) -> bool {
    !text.is_empty()
        && text.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
        })
}

/// Where the head ends: the index just past its blank line.
pub fn head_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|at| at + 4)
}

/// Parses an HTTP/1.x head: the start line's three parts and the header fields. Refuses
/// obsolete line folding, a field name that is not a token, a value with a control
/// character, more than [`MAX_HEADERS`] fields and anything not ASCII.
fn parse_head(head: &[u8]) -> Result<(Vec<String>, Vec<(String, String)>), HeadRefusal> {
    let text = std::str::from_utf8(head).map_err(|_| HeadRefusal::Malformed("not ASCII"))?;
    if !text.is_ascii() {
        return Err(HeadRefusal::Malformed("not ASCII"));
    }
    let text = text
        .strip_suffix("\r\n\r\n")
        .ok_or(HeadRefusal::Malformed("no blank line"))?;
    let mut lines = text.split("\r\n");
    let start: Vec<String> = lines
        .next()
        .ok_or(HeadRefusal::Malformed("no start line"))?
        .splitn(3, ' ')
        .map(str::to_owned)
        .collect();
    let mut headers = Vec::new();
    for line in lines {
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(HeadRefusal::Malformed("folded header"));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or(HeadRefusal::Malformed("header without a colon"))?;
        if !is_token(name) {
            return Err(HeadRefusal::Malformed("header name"));
        }
        let value = value.trim_matches(|c| c == ' ' || c == '\t');
        if value.bytes().any(|byte| byte.is_ascii_control() && byte != b'\t') {
            return Err(HeadRefusal::Malformed("header value"));
        }
        headers.push((name.to_owned(), value.to_owned()));
        if headers.len() > MAX_HEADERS {
            return Err(HeadRefusal::Malformed("too many headers"));
        }
    }
    Ok((start, headers))
}

/// Parses and checks a request head (module docs).
pub fn parse_request(head: &[u8]) -> Result<RequestHead, HeadRefusal> {
    let (start, headers) = parse_head(head)?;
    let [method, target, version] = start.as_slice() else {
        return Err(HeadRefusal::Malformed("request line"));
    };
    if !is_token(method) {
        return Err(HeadRefusal::Malformed("method"));
    }
    if !target.starts_with('/') || target.contains(' ') {
        return Err(HeadRefusal::Malformed("target"));
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(HeadRefusal::Malformed("version"));
    }
    let request = RequestHead {
        method: method.clone(),
        target: target.clone(),
        headers,
    };
    if request.count("host") != 1 {
        return Err(HeadRefusal::Malformed("host"));
    }
    if request.count("content-length") > 1 {
        return Err(HeadRefusal::Malformed("content-length"));
    }
    if request.count("transfer-encoding") > 0 {
        return Err(HeadRefusal::ChunkedBody);
    }
    request.content_length()?;
    Ok(request)
}

/// The token a `<token>.localhost:<port>` host carries, after checking that the host names
/// this listener: `127.0.0.1`, `localhost`, `[::1]` or a single label under `localhost`, on
/// `port`. `None` inside `Ok` for a host without a token label.
pub fn check_host(host: &str, port: u16) -> Result<Option<String>, HeadRefusal> {
    let (name, given) = host.rsplit_once(':').ok_or(HeadRefusal::WrongHost)?;
    if given.parse::<u16>().ok() != Some(port) {
        return Err(HeadRefusal::WrongHost);
    }
    let name = name.to_ascii_lowercase();
    if name == "127.0.0.1" || name == LOCAL_DOMAIN || name == "[::1]" {
        return Ok(None);
    }
    let label = name
        .strip_suffix(&format!(".{LOCAL_DOMAIN}"))
        .ok_or(HeadRefusal::WrongHost)?;
    if label.is_empty()
        || label.len() > 63
        || !label.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        return Err(HeadRefusal::WrongHost);
    }
    Ok(Some(label.to_owned()))
}

/// The bearer token an `Authorization` field carries.
fn bearer(request: &RequestHead) -> Option<String> {
    let value = request.header("authorization")?;
    let (scheme, token) = value.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| token.trim().to_owned())
}

/// The head forwarded to the guest service on `guest_port` (module docs).
pub fn forwarded_head(request: &RequestHead, guest_port: u16) -> Vec<u8> {
    forwarded_head_mode(request, guest_port, false)
}

fn forwarded_head_mode(request: &RequestHead, guest_port: u16, application: bool) -> Vec<u8> {
    let mut out = format!("{} {} HTTP/1.1\r\n", request.method, request.target);
    if application {
        out.push_str(&format!("Host: {}\r\n", request.header("host").unwrap_or_default()));
    } else {
        out.push_str(&format!("Host: localhost:{guest_port}\r\n"));
    }
    for (name, value) in &request.headers {
        let lower = name.to_ascii_lowercase();
        let session = application && matches!(lower.as_str(), "authorization" | "cookie");
        if !session && (DROPPED_REQUEST.contains(&lower.as_str())
            || RESERVED_CREDENTIAL_HEADERS.contains(&lower.as_str())) {
            continue;
        }
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str("Connection: close\r\n\r\n");
    out.into_bytes()
}

/// The guest's response head as the caller gets it (module docs).
pub fn rewritten_response(head: &[u8]) -> Result<Vec<u8>, HeadRefusal> {
    rewritten_response_mode(head, false)
}

fn rewritten_response_mode(head: &[u8], application: bool) -> Result<Vec<u8>, HeadRefusal> {
    let (start, headers) = parse_head(head)?;
    let [version, code, ..] = start.as_slice() else {
        return Err(HeadRefusal::Malformed("status line"));
    };
    if !version.starts_with("HTTP/1.") || code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(HeadRefusal::Malformed("status line"));
    }
    let mut policy = policy_headers();
    if application {
        for (name, value) in &mut policy {
            if *name == "Content-Security-Policy" {
                *value = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'".into();
            }
        }
    }
    let mut out = format!("{}\r\n", start.join(" "));
    for (name, value) in &headers {
        let lower = name.to_ascii_lowercase();
        // Only host-only cookies may leave an explicitly selected application origin.
        let session = application && lower == "set-cookie"
            && !value.split(';').skip(1).any(|part| part.trim().split('=').next().unwrap_or("").trim().eq_ignore_ascii_case("domain"));
        if (!session && DROPPED_RESPONSE.contains(&lower.as_str()))
            || policy
                .iter()
                .any(|(policy_name, _)| policy_name.eq_ignore_ascii_case(&lower))
        {
            continue;
        }
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    for (name, value) in policy {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str("Connection: close\r\n\r\n");
    Ok(out.into_bytes())
}

/// A complete response of the adapter's own, under the preview policy's headers.
pub fn own_response(status: u16, reason: &str, body: &str) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status} {reason}\r\n");
    for (name, value) in policy_headers() {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str(&format!(
        "Content-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    ));
    out.into_bytes()
}

/// What the caller is told of a refusal: its authentication, or that nothing is served.
fn refusal_response(refusal: &GateRefusal) -> Vec<u8> {
    match refusal {
        GateRefusal::Proof(_)
        | GateRefusal::Ingress(
            IngressError::NotAuthenticated
            | IngressError::WrongAuthentication { .. }
            | IngressError::NotInAudience,
        ) => own_response(401, "Unauthorized", "This preview needs its address with its token.\n"),
        _ => own_response(404, "Not Found", "This preview is not published.\n"),
    }
}

/// The engine as the previews use it: the gate's admission and pump, and a publication's
/// state.
pub trait PreviewHost: Send + Sync {
    fn admit(
        &self,
        sandbox: &SandboxId,
        service: &str,
        proof: Option<AuthenticationProof>,
        verifier: &dyn ProofVerifier,
        outside: Box<dyn SessionStream>,
        caller_room: CallerRoom,
    ) -> Result<(u64, GuestIngressWatch), GateRefusal>;

    fn pump(&self) -> SessionsPumped;

    /// The state of `publication` of `sandbox`, `None` once it is gone.
    fn publication_state(&self, sandbox: &SandboxId, publication: u64) -> Option<&'static str>;
}

/// A token the engine issued for one publication: a capability for its owner.
#[derive(Clone)]
struct IssuedToken {
    token: String,
    binding: ProofBinding,
    valid_until: MonotonicTime,
}

/// Verifies the tokens this engine issued (module docs): each only for the publication,
/// sandbox and epoch it was issued for, until the publication's expiry.
#[derive(Clone, Default)]
pub struct TokenVerifier {
    tokens: Arc<Mutex<BTreeMap<(ExecutionId, u64), IssuedToken>>>,
}

impl TokenVerifier {
    fn issue(&self, binding: ProofBinding, valid_until: MonotonicTime) -> String {
        let token = format!("y{}", uuid::Uuid::new_v4().simple());
        let key = (binding.sandbox.clone(), binding.publication.get());
        self.tokens
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                key,
                IssuedToken {
                    token: token.clone(),
                    binding,
                    valid_until,
                },
            );
        token
    }

    fn forget(&self, sandbox: &ExecutionId, publication: u64) {
        self.tokens
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&(sandbox.clone(), publication));
    }
}

/// Compares two byte strings in time that does not depend on where they differ.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl ProofVerifier for TokenVerifier {
    fn verify(
        &self,
        binding: &ProofBinding,
        proof: &AuthenticationProof,
        now: MonotonicTime,
    ) -> Result<VerifiedProof, ProofRefusal> {
        if proof.mode() != AuthenticationMode::BearerToken {
            return Err(ProofRefusal::UnsupportedMode { mode: proof.mode() });
        }
        let tokens = self.tokens.lock().unwrap_or_else(PoisonError::into_inner);
        let issued = tokens
            .get(&(binding.sandbox.clone(), binding.publication.get()))
            .ok_or(ProofRefusal::WrongPublication)?;
        if !same(issued.token.as_bytes(), proof.material()) {
            return Err(ProofRefusal::Invalid);
        }
        if issued.binding != *binding {
            return Err(ProofRefusal::WrongPublication);
        }
        if now >= issued.valid_until {
            return Err(ProofRefusal::Expired);
        }
        Ok(VerifiedProof {
            principal: PrincipalId::new(OWNER_PRINCIPAL).map_err(|_| ProofRefusal::Invalid)?,
            valid_until: issued.valid_until,
        })
    }
}

/// The caller's end of one session, shared between the gate and the connection's thread.
#[derive(Default)]
struct Outside {
    /// The forwarded head and body bytes for the guest, not taken by the gate yet.
    to_gate: VecDeque<u8>,
    /// The guest's answer, not written to the caller yet: taken from the gate, or waiting
    /// on the caller's socket.
    from_gate: VecDeque<u8>,
    /// Of the answer, the bytes the connection's thread holds for the socket now.
    in_flight: usize,
    /// The gate closed the session.
    gate_closed: bool,
    /// The caller closed its connection.
    caller_closed: bool,
}

struct OutsideEnd {
    shared: Arc<Mutex<Outside>>,
}

impl SessionStream for OutsideEnd {
    fn read(&mut self, buffer: &mut [u8]) -> Result<StreamRead, StreamError> {
        let mut outside = self.shared.lock().unwrap_or_else(PoisonError::into_inner);
        if !outside.to_gate.is_empty() {
            let take = outside.to_gate.len().min(buffer.len());
            for (slot, byte) in buffer.iter_mut().zip(outside.to_gate.drain(..take)) {
                *slot = byte;
            }
            return Ok(StreamRead::Bytes(take));
        }
        // The request ends with its body, not with the connection: the session stays open
        // for the answer, and ends when the caller goes away.
        Ok(if outside.caller_closed {
            StreamRead::Ended
        } else {
            StreamRead::Idle
        })
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), StreamError> {
        let mut outside = self.shared.lock().unwrap_or_else(PoisonError::into_inner);
        if outside.gate_closed || outside.caller_closed {
            return Err(StreamError::Closed);
        }
        if outside
            .from_gate
            .len()
            .saturating_add(outside.in_flight)
            .saturating_add(bytes.len())
            > MAX_PENDING_TO_CALLER
        {
            return Err(StreamError::Failed {
                detail: "the caller does not read the answer".to_owned(),
            });
        }
        outside.from_gate.extend(bytes);
        Ok(())
    }

    /// The answer is complete: the caller gets the rest of it, then its connection closes
    /// (one request per connection, so nothing it sends afterwards is read).
    fn finish(&mut self) {
        self.close();
    }

    fn close(&mut self) {
        self.shared
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .gate_closed = true;
    }
}

/// One publication's listener.
struct Listener {
    sandbox: SandboxId,
    publication: u64,
    service: String,
    audience: PublicationAudience,
    port: u16,
    stop: Arc<AtomicBool>,
    served: Arc<AtomicUsize>,
}

/// What status shows of a preview listener; never its token.
#[derive(Clone, Debug, Serialize)]
pub struct PreviewView {
    pub publication: u64,
    pub service: String,
    pub audience: PublicationAudience,
    /// The address, with the token's label hidden for an owner's publication.
    pub address: String,
    pub connections_served: usize,
}

/// What opening a preview answers: its address, with the owner's token in it.
#[derive(Clone, Debug, Serialize)]
pub struct PreviewOpened {
    pub url: String,
    pub port: u16,
}

/// The previews of this engine (module docs).
pub struct Previews {
    verifier: TokenVerifier,
    listeners: Mutex<Vec<Listener>>,
    pump_started: AtomicBool,
}

impl Default for Previews {
    fn default() -> Self {
        Self::new()
    }
}

impl Previews {
    pub fn new() -> Self {
        Self {
            verifier: TokenVerifier::default(),
            listeners: Mutex::new(Vec::new()),
            pump_started: AtomicBool::new(false),
        }
    }

    fn listeners(&self) -> std::sync::MutexGuard<'_, Vec<Listener>> {
        self.listeners.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Opens the listener of `publication` (module docs); an owner's gets a token, bound to
    /// `binding` until `valid_until`.
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        &self,
        host: Weak<dyn PreviewHost>,
        sandbox: &SandboxId,
        publication: u64,
        service: &str,
        guest_port: u16,
        audience: PublicationAudience,
        binding: ProofBinding,
        valid_until: MonotonicTime,
    ) -> Result<PreviewOpened, String> {
        self.open_mode(host, sandbox, publication, service, guest_port, audience, binding, valid_until, false)
    }

    /// Application mode retains sessions only on an owner-token localhost origin.
    /// The owner must explicitly choose it; ordinary previews keep their sandbox CSP.
    #[allow(clippy::too_many_arguments)]
    pub fn open_mode(
        &self, host: Weak<dyn PreviewHost>, sandbox: &SandboxId, publication: u64,
        service: &str, guest_port: u16, audience: PublicationAudience,
        binding: ProofBinding, valid_until: MonotonicTime, application: bool,
    ) -> Result<PreviewOpened, String> {
        if application && audience != PublicationAudience::Owner {
            return Err("Application sessions require an isolated owner-token origin.".into());
        }
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .map_err(|error| format!("the preview's listener could not be opened: {error}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| format!("the preview's listener could not be set up: {error}"))?;
        let port = listener
            .local_addr()
            .map_err(|error| error.to_string())?
            .port();
        let url = match audience {
            PublicationAudience::Owner => {
                let token = self.verifier.issue(binding, valid_until);
                format!("http://{token}.{LOCAL_DOMAIN}:{port}/")
            }
            PublicationAudience::Public => format!("http://127.0.0.1:{port}/"),
        };
        let stop = Arc::new(AtomicBool::new(false));
        let served = Arc::new(AtomicUsize::new(0));
        let context = Arc::new(Context {
            host,
            verifier: self.verifier.clone(),
            sandbox: sandbox.clone(),
            service: service.to_owned(),
            guest_port,
            listen_port: port,
            audience,
            stop: Arc::clone(&stop),
            served: Arc::clone(&served),
            active: AtomicUsize::new(0),
            application,
        });
        thread::Builder::new()
            .name(format!("preview-{port}"))
            .spawn(move || accept_loop(listener, context))
            .map_err(|error| format!("the preview's listener thread could not start: {error}"))?;
        self.listeners().push(Listener {
            sandbox: sandbox.clone(),
            publication,
            service: service.to_owned(),
            audience,
            port,
            stop,
            served,
        });
        Ok(PreviewOpened { url, port })
    }

    /// Closes `publication`'s listener and forgets its token.
    pub fn close(&self, sandbox: &SandboxId, publication: u64) -> bool {
        let mut listeners = self.listeners();
        let before = listeners.len();
        listeners.retain(|listener| {
            let ours = listener.sandbox == *sandbox && listener.publication == publication;
            if ours {
                listener.stop.store(true, Ordering::Relaxed);
            }
            !ours
        });
        self.verifier.forget(sandbox.execution(), publication);
        listeners.len() != before
    }

    /// Closes every listener of `sandbox`.
    pub fn close_sandbox(&self, sandbox: &SandboxId) -> usize {
        let publications: Vec<u64> = self
            .listeners()
            .iter()
            .filter(|listener| listener.sandbox == *sandbox)
            .map(|listener| listener.publication)
            .collect();
        publications
            .iter()
            .filter(|publication| self.close(sandbox, **publication))
            .count()
    }

    /// `sandbox`'s open listeners, as status shows them.
    pub fn view(&self, sandbox: &SandboxId) -> Vec<PreviewView> {
        self.listeners()
            .iter()
            .filter(|listener| listener.sandbox == *sandbox)
            .map(|listener| PreviewView {
                publication: listener.publication,
                service: listener.service.clone(),
                audience: listener.audience,
                address: match listener.audience {
                    PublicationAudience::Owner => {
                        format!("http://<token>.{LOCAL_DOMAIN}:{}/", listener.port)
                    }
                    PublicationAudience::Public => format!("http://127.0.0.1:{}/", listener.port),
                },
                connections_served: listener.served.load(Ordering::Relaxed),
            })
            .collect()
    }

    /// Starts the gate's pump once, for the engine's life (module docs).
    pub fn start_pump(self: &Arc<Self>, host: Weak<dyn PreviewHost>) {
        if self.pump_started.swap(true, Ordering::SeqCst) {
            return;
        }
        let previews = Arc::downgrade(self);
        let _ = thread::Builder::new()
            .name("preview-pump".to_owned())
            .spawn(move || pump_loop(host, previews));
    }
}

fn pump_loop(host: Weak<dyn PreviewHost>, previews: Weak<Previews>) {
    let mut last_check = Instant::now();
    loop {
        let (Some(host), Some(previews)) = (host.upgrade(), previews.upgrade()) else {
            return;
        };
        let pumped = host.pump();
        if last_check.elapsed() >= LISTENER_CHECK {
            last_check = Instant::now();
            let open: Vec<(SandboxId, u64)> = previews
                .listeners()
                .iter()
                .map(|listener| (listener.sandbox.clone(), listener.publication))
                .collect();
            for (sandbox, publication) in open {
                if host.publication_state(&sandbox, publication) != Some("active") {
                    previews.close(&sandbox, publication);
                }
            }
        }
        drop(host);
        drop(previews);
        if pumped.is_idle() {
            thread::sleep(Duration::from_millis(2));
        }
    }
}

/// What a listener's threads share.
struct Context {
    application: bool,
    host: Weak<dyn PreviewHost>,
    verifier: TokenVerifier,
    sandbox: SandboxId,
    service: String,
    guest_port: u16,
    listen_port: u16,
    audience: PublicationAudience,
    stop: Arc<AtomicBool>,
    served: Arc<AtomicUsize>,
    active: AtomicUsize,
}

fn accept_loop(listener: TcpListener, context: Arc<Context>) {
    while !context.stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                if context.active.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
                    let mut stream = stream;
                    let _ = stream.write_all(&own_response(503, "Service Unavailable", "Too many connections.\n"));
                    continue;
                }
                context.active.fetch_add(1, Ordering::Relaxed);
                context.served.fetch_add(1, Ordering::Relaxed);
                let context = Arc::clone(&context);
                let spawned = thread::Builder::new()
                    .name(format!("preview-{}-conn", context.listen_port))
                    .spawn(move || {
                        serve(stream, &context);
                        context.active.fetch_sub(1, Ordering::Relaxed);
                    });
                if spawned.is_err() {
                    // The context went with the closure; the connection with it.
                }
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => thread::sleep(Duration::from_millis(50)),
        }
    }
}

/// Reads a request head within [`HEAD_TIMEOUT`]: the head and the bytes after it.
fn read_head(stream: &mut TcpStream) -> Result<(Vec<u8>, Vec<u8>), Option<HeadRefusal>> {
    let deadline = Instant::now() + HEAD_TIMEOUT;
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(end) = head_end(&buffer) {
            let rest = buffer.split_off(end);
            return Ok((buffer, rest));
        }
        if buffer.len() > MAX_REQUEST_HEAD {
            return Err(Some(HeadRefusal::Malformed("head too large")));
        }
        if Instant::now() >= deadline {
            return Err(None);
        }
        match stream.read(&mut chunk) {
            Ok(0) => return Err(None),
            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(_) => return Err(None),
        }
    }
}

/// Serves one connection: one request through the gate (module docs).
fn serve(mut stream: TcpStream, context: &Context) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(250)));
    let _ = stream.set_nodelay(true);
    let refuse = |stream: &mut TcpStream, refusal: &HeadRefusal| {
        let (status, reason) = refusal.status();
        let _ = stream.write_all(&own_response(status, reason, &format!("{reason}.\n")));
        let _ = stream.shutdown(Shutdown::Both);
    };
    let (head, rest) = match read_head(&mut stream) {
        Ok(read) => read,
        Err(Some(refusal)) => return refuse(&mut stream, &refusal),
        Err(None) => return,
    };
    let request = match parse_request(&head) {
        Ok(request) => request,
        Err(refusal) => return refuse(&mut stream, &refusal),
    };
    let label = match check_host(request.header("host").unwrap_or_default(), context.listen_port) {
        Ok(label) => label,
        Err(refusal) => return refuse(&mut stream, &refusal),
    };
    if context.application && label.is_none() {
        return refuse(&mut stream, &HeadRefusal::WrongHost);
    }
    let body = match request.content_length() {
        Ok(body) => body,
        Err(refusal) => return refuse(&mut stream, &refusal),
    };
    let proof = match context.audience {
        PublicationAudience::Owner => label
            .or_else(|| bearer(&request))
            .map(|token| AuthenticationProof::new(AuthenticationMode::BearerToken, token.into_bytes())),
        PublicationAudience::Public => None,
    };
    let Some(host) = context.host.upgrade() else {
        let _ = stream.write_all(&own_response(503, "Service Unavailable", "Yougori is stopping.\n"));
        return;
    };
    // The forwarded head, then the body bytes that came with it, up to the declared length.
    let mut forwarded = forwarded_head_mode(&request, context.guest_port, context.application);
    let take = usize::try_from(body).unwrap_or(usize::MAX).min(rest.len());
    forwarded.extend_from_slice(&rest[..take]);
    let mut body_left = body.saturating_sub(take as u64);
    let shared = Arc::new(Mutex::new(Outside {
        to_gate: forwarded.into(),
        ..Outside::default()
    }));
    // The guest end gives the gate no more than this side can hold: the guest is slowed to
    // the caller's pace, and nothing charged is lost to a full buffer.
    let room_of = Arc::clone(&shared);
    let caller_room: CallerRoom = Arc::new(move || {
        let outside = room_of.lock().unwrap_or_else(PoisonError::into_inner);
        MAX_PENDING_TO_CALLER
            .saturating_sub(outside.from_gate.len())
            .saturating_sub(outside.in_flight)
    });
    let admitted = host.admit(
        &context.sandbox,
        &context.service,
        proof,
        &context.verifier,
        Box::new(OutsideEnd {
            shared: Arc::clone(&shared),
        }),
        caller_room,
    );
    drop(host);
    let room = match admitted {
        Ok((_, room)) => room,
        Err(refusal) => {
            let _ = stream.write_all(&refusal_response(&refusal));
            let _ = stream.shutdown(Shutdown::Both);
            return;
        }
    };
    let _ = stream.set_nonblocking(true);
    let mut head_buffer: Option<Vec<u8>> = Some(Vec::new());
    let mut to_caller: VecDeque<u8> = VecDeque::new();
    let mut chunk = vec![0u8; 64 << 10];
    let mut caller_done = false;
    loop {
        let mut moved = false;
        // The caller's body toward the gate, no faster than the guest takes it.
        if body_left > 0 && !caller_done {
            let room_now = room.room().min(chunk.len());
            if room_now > 0 {
                let want = room_now.min(usize::try_from(body_left).unwrap_or(usize::MAX));
                match stream.read(&mut chunk[..want]) {
                    Ok(0) => caller_done = true,
                    Ok(read) => {
                        body_left -= read as u64;
                        shared
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .to_gate
                            .extend(&chunk[..read]);
                        moved = true;
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                    Err(_) => caller_done = true,
                }
            }
        } else if !caller_done {
            // Past the body: only a close is expected; anything more is not forwarded.
            match stream.read(&mut chunk) {
                Ok(0) => caller_done = true,
                Ok(_) | Err(_) => {}
            }
        }
        if caller_done {
            shared.lock().unwrap_or_else(PoisonError::into_inner).caller_closed = true;
        }
        // The guest's answer toward the caller: its head rewritten, then the rest.
        let (answer, gate_closed) = {
            let mut outside = shared.lock().unwrap_or_else(PoisonError::into_inner);
            // Taken only while the socket keeps up: what waits stays counted against the
            // caller's room.
            let take = if to_caller.len() < IN_FLIGHT_BYTES {
                outside.from_gate.len().min(IN_FLIGHT_BYTES)
            } else {
                0
            };
            let answer: Vec<u8> = outside.from_gate.drain(..take).collect();
            outside.in_flight = to_caller.len() + answer.len();
            (answer, outside.gate_closed && outside.from_gate.is_empty())
        };
        if !answer.is_empty() {
            moved = true;
            match head_buffer.as_mut() {
                Some(pending) => {
                    pending.extend_from_slice(&answer);
                    if let Some(end) = head_end(pending) {
                        let body_part = pending.split_off(end);
                        match rewritten_response_mode(pending, context.application) {
                            Ok(head) => {
                                to_caller.extend(head);
                                to_caller.extend(body_part);
                                head_buffer = None;
                            }
                            Err(_) => {
                                let _ = stream.set_nonblocking(false);
                                let _ = stream.write_all(&own_response(502, "Bad Gateway", "The guest's answer was not HTTP.\n"));
                                break;
                            }
                        }
                    } else if pending.len() > MAX_RESPONSE_HEAD {
                        let _ = stream.set_nonblocking(false);
                        let _ = stream.write_all(&own_response(502, "Bad Gateway", "The guest's answer head is too large.\n"));
                        break;
                    }
                }
                None => to_caller.extend(answer),
            }
        }
        while !to_caller.is_empty() {
            let (front, _) = to_caller.as_slices();
            match stream.write(front) {
                Ok(0) => break,
                Ok(written) => {
                    to_caller.drain(..written);
                    moved = true;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(_) => {
                    caller_done = true;
                    to_caller.clear();
                    break;
                }
            }
        }
        if gate_closed && to_caller.is_empty() {
            if head_buffer.as_ref().is_some_and(|pending| !pending.is_empty() || !caller_done) {
                // The session ended before a whole answer head: the caller is told.
                let _ = stream.set_nonblocking(false);
                let _ = stream.write_all(&own_response(502, "Bad Gateway", "The guest gave no answer.\n"));
            }
            break;
        }
        if caller_done && to_caller.is_empty() && gate_closed {
            break;
        }
        if context.stop.load(Ordering::Relaxed) && to_caller.is_empty() {
            break;
        }
        if !moved {
            thread::sleep(Duration::from_millis(2));
        }
    }
    let _ = stream.set_nonblocking(false);
    let _ = stream.flush();
    let _ = stream.shutdown(Shutdown::Both);
    shared.lock().unwrap_or_else(PoisonError::into_inner).caller_closed = true;
}

#[cfg(test)]
#[path = "preview_tests.rs"]
mod tests;
