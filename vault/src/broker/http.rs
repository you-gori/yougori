//! Authenticated Streamable HTTP MCP. Only MCP messages cross this transport;
//! management, secret entry and approval remain native-only operations.
use super::*;
use axum::{
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

struct TlsListener {
    listener: tokio::net::TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
}
impl axum::serve::Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Addr = std::net::SocketAddr;
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.listener.accept().await {
                Ok((stream, address)) => {
                    if let Ok(Ok(tls)) =
                        tokio::time::timeout(Duration::from_secs(3), self.acceptor.accept(stream))
                            .await
                    {
                        return (tls, address);
                    }
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
            }
        }
    }
    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}

pub(super) fn read_key() -> Result<zeroize::Zeroizing<String>, String> {
    let path = platform::data_directory()?.join("http-key.dpapi");
    let bytes = crate::storage::dpapi(&crate::storage::bounded_read(&path, 4096)?, false)?;
    let value = std::str::from_utf8(&bytes)
        .map_err(|_| "Invalid MCP connection key")?
        .to_owned();
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Invalid MCP connection key".into());
    }
    Ok(zeroize::Zeroizing::new(value))
}
pub(super) fn create_key() -> Result<(), String> {
    let path = platform::data_directory()?.join("http-key.dpapi");
    if path.exists() {
        return read_key().map(|_| ());
    }
    let key = zeroize::Zeroizing::new(format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    ));
    crate::storage::atomic_write(&path, &crate::storage::dpapi(key.as_bytes(), true)?)
}
struct HttpSession {
    session: Arc<Session>,
    touched: Instant,
}
#[derive(Clone)]
pub(super) struct HttpState {
    pub(super) shared: Arc<Shared>,
    pub(super) sender: std::sync::mpsc::SyncSender<Job>,
    key_hash: [u8; 32],
    sessions: Arc<Mutex<BTreeMap<String, HttpSession>>>,
    slots: Arc<tokio::sync::Semaphore>,
}
fn principal(headers: &HeaderMap, state: &HttpState) -> Option<(Identity, Option<u64>)> {
    if headers.contains_key("origin") {
        return None;
    }
    let token = headers
        .get("authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")?;
    if let Some(identity) = state.shared.oauth.lock().unwrap().principal(token) {
        // A valid OAuth grant is issued only after native connection consent.
        let epoch = *state
            .shared
            .revocations
            .lock()
            .unwrap()
            .get(&identity.id)
            .unwrap_or(&0);
        return Some((identity, Some(epoch)));
    }
    if !authorized(headers, &state.key_hash) {
        return None;
    }
    let fingerprint = hex::encode(state.key_hash);
    Some((
        Identity {
            id: format!("http-{fingerprint}"),
            executable: "MCP HTTP client — connection key authenticated".into(),
            digest: fingerprint,
            device: "Bearer-key holder (shared connection key)".into(),
            user: "Remote account is not attested".into(),
            process: 0,
            environment: "Localhost or Cloudflare Tunnel; review every requested operation".into(),
        },
        None,
    ))
}
fn authorized(headers: &HeaderMap, key_hash: &[u8; 32]) -> bool {
    // Browser origins are deliberately unsupported. MCP agents authenticate
    // using a header, never a query string, cookie, or referrer-visible URL.
    if headers.contains_key("origin") {
        return false;
    }
    let Some(token) = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    else {
        return false;
    };
    let hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    bool::from(hash.ct_eq(key_hash))
}
pub(super) fn router(state: HttpState) -> Router {
    Router::new()
        .route("/mcp", post(mcp).delete(disconnect).get(stream))
        .merge(super::oauth::routes())
        .layer(DefaultBodyLimit::max(protocol::MAX_FRAME))
        .with_state(state)
}
pub(super) fn start(
    shared: Arc<Shared>,
    sender: std::sync::mpsc::SyncSender<Job>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Value, String>> + Send>> {
    Box::pin(async move {
        let mut active = shared.http.lock().await;
        if !active.is_null() {
            return Ok(active.clone());
        }
        let key = read_key().map_err(|_| "Create your Personal Vault first")?;
        let key_hash = Sha256::digest(key.as_bytes()).into();
        let state = HttpState {
            shared: shared.clone(),
            sender,
            key_hash,
            sessions: Default::default(),
            slots: Arc::new(tokio::sync::Semaphore::new(16)),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|_| "Cannot start MCP endpoint")?;
        let port = listener
            .local_addr()
            .map_err(|_| "Cannot read MCP endpoint")?
            .port();
        let identity = crate::transport::DeviceKey::generate()?;
        let fingerprint = identity.fingerprint()?;
        let tls =
            tokio_rustls::rustls::ServerConfig::builder_with_provider(crate::transport::provider())
                .with_safe_default_protocol_versions()
                .map_err(|_| "TLS configuration failed")?
                .with_no_client_auth()
                .with_single_cert(
                    vec![identity.certificate()?],
                    identity.private_key()?.into(),
                )
                .map_err(|_| "TLS identity failed")?;
        let listener = TlsListener {
            listener,
            acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(tls)),
        };
        let router = router(state);
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        *active = json!({"brokerPort":port,"fingerprint":fingerprint});
        Ok(active.clone())
    })
}
async fn disconnect(State(state): State<HttpState>, headers: HeaderMap) -> Response {
    let Some((identity, _)) = principal(&headers, &state) else {
        return super::oauth::challenge(&state);
    };
    let Some(id) = headers.get("mcp-session-id").and_then(|v| v.to_str().ok()) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let mut sessions = state.sessions.lock().unwrap();
    if sessions
        .get(id)
        .is_some_and(|s| s.session.identity.id != identity.id)
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    if let Some(old) = sessions.remove(id) {
        old.session.connected.store(false, Ordering::SeqCst);
        old.session.cancelled.store(true, Ordering::SeqCst);
        cancel_pending(&state, &old.session);
    }
    StatusCode::NO_CONTENT.into_response()
}
async fn stream(State(state): State<HttpState>, headers: HeaderMap) -> Response {
    if principal(&headers, &state).is_none() {
        return super::oauth::challenge(&state);
    }
    // JSON responses are supported; a separate SSE stream is optional in MCP.
    StatusCode::METHOD_NOT_ALLOWED.into_response()
}
fn cancel_pending(state: &HttpState, session: &Arc<Session>) {
    for pending in state.shared.pending.lock().unwrap().values() {
        if pending
            .session
            .upgrade()
            .is_some_and(|owner| Arc::ptr_eq(&owner, session))
        {
            pending.cancel.store(true, Ordering::SeqCst);
        }
    }
}
async fn mcp(
    State(state): State<HttpState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let Some((identity, oauth_admission)) = principal(&headers, &state) else {
        return super::oauth::challenge(&state);
    };
    if !headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(';').next() == Some("application/json"))
    {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    if headers.get("mcp-protocol-version").is_some_and(|v| {
        !matches!(
            v.to_str(),
            Ok("2024-11-05" | "2025-03-26" | "2025-06-18" | "2025-11-25")
        )
    }) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let Ok(_permit) = state.slots.clone().try_acquire_owned() else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    let Ok(message) = serde_json::from_slice::<Value>(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let initialize = message["method"] == "initialize" && message.get("id").is_some();
    let (id, session) = {
        let mut sessions = state.sessions.lock().unwrap();
        sessions.retain(|_, entry| {
            let keep = entry.touched.elapsed() < Duration::from_secs(1800);
            if !keep {
                entry.session.connected.store(false, Ordering::SeqCst);
                entry.session.cancelled.store(true, Ordering::SeqCst);
            }
            keep
        });
        // Discovery can initialize repeatedly. Reuse the authenticated client's
        // live session instead of filling the session limit with duplicates.
        let reusable = oauth_admission.filter(|_| initialize).and_then(|epoch| {
            sessions
                .iter()
                .find(|(_, entry)| {
                    entry.session.identity.id == identity.id
                        && entry.session.allowed.load(Ordering::SeqCst)
                        && entry.session.admission.load(Ordering::SeqCst) == epoch
                        && !entry.session.cancelled.load(Ordering::SeqCst)
                        && entry.session.connected.load(Ordering::SeqCst)
                })
                .map(|(id, _)| id.clone())
        });
        if let Some(id) = reusable {
            let entry = sessions.get_mut(&id).unwrap();
            entry.touched = Instant::now();
            (id, entry.session.clone())
        } else if initialize {
            if sessions.len() >= 24 {
                return StatusCode::TOO_MANY_REQUESTS.into_response();
            }
            let id = uuid::Uuid::new_v4().to_string();
            let session = Arc::new(Session {
                identity,
                desktop: false,
                cancelled: Arc::new(AtomicBool::new(false)),
                connected: AtomicBool::new(true),
                allowed: AtomicBool::new(oauth_admission.is_some()),
                admission: AtomicU64::new(oauth_admission.unwrap_or(0)),
            });
            sessions.insert(
                id.clone(),
                HttpSession {
                    session: session.clone(),
                    touched: Instant::now(),
                },
            );
            (id, session)
        } else {
            let Some(id) = headers.get("mcp-session-id").and_then(|v| v.to_str().ok()) else {
                return StatusCode::BAD_REQUEST.into_response();
            };
            let Some(entry) = sessions.get_mut(id) else {
                return StatusCode::NOT_FOUND.into_response();
            };
            if entry.session.identity.id != identity.id {
                return StatusCode::NOT_FOUND.into_response();
            }
            entry.touched = Instant::now();
            (id.to_owned(), entry.session.clone())
        }
    };
    if message["method"] == "notifications/cancelled" && message.get("id").is_none() {
        // Cancellation is deliberately conservative: end all pending approvals
        // from this session rather than risk approving an abandoned request.
        cancel_pending(&state, &session);
        return StatusCode::ACCEPTED.into_response();
    }
    let request_id = message.get("id").cloned();
    let result = tokio::time::timeout(
        Duration::from_secs(125),
        handle(
            Request::Mcp { message },
            &session,
            &state.sender,
            &state.shared,
        ),
    )
    .await;
    let mut value = match result {
        Ok(Ok(value)) => value,
        _ => {
            json!({"jsonrpc":"2.0","id":request_id,"error":{"code":-32000,"message":"Vault request did not finish. Open Personal Vault MCP in Yougori to review it, then retry."}})
        }
    };
    if initialize && value.get("error").is_some() {
        state.sessions.lock().unwrap().remove(&id);
        session.connected.store(false, Ordering::SeqCst);
        session.cancelled.store(true, Ordering::SeqCst);
    }
    let mut response = if value.is_null() {
        StatusCode::ACCEPTED.into_response()
    } else {
        Json(&value).into_response()
    };
    // The serialized body is sent as is; wipe the disclosed values in memory.
    protocol::wipe(&mut value);
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    response
        .headers_mut()
        .insert("mcp-session-id", id.parse().unwrap());
    response
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    pub(in crate::broker) fn fixture() -> (HttpState, std::sync::mpsc::Receiver<Job>) {
        let shared = Arc::new(Shared {
            locked: AtomicBool::new(false),
            generation: AtomicU64::new(0),
            snapshot: Mutex::new(json!({})),
            pending: Mutex::new(BTreeMap::new()),
            remote: Mutex::new(Value::Null),
            remote_stop: Mutex::new(None),
            revocations: Mutex::new(BTreeMap::new()),
            http: tokio::sync::Mutex::new(Value::Null),
            oauth: Mutex::new(super::super::oauth::OAuth::default()),
        });
        let (sender, receiver) = std::sync::mpsc::sync_channel(16);
        (
            HttpState {
                shared,
                sender,
                key_hash: Sha256::digest(b"fixture-key").into(),
                sessions: Default::default(),
                slots: Arc::new(tokio::sync::Semaphore::new(16)),
            },
            receiver,
        )
    }
    fn headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer fixture-key".parse().unwrap());
        headers.insert("content-type", "application/json".parse().unwrap());
        headers
    }
    #[tokio::test]
    async fn unknown_session_and_unsupported_protocol_fail_before_approval() {
        let (state, receiver) = fixture();
        let body =
            axum::body::Bytes::from_static(br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#);
        let mut request_headers = headers();
        assert_eq!(
            mcp(State(state.clone()), request_headers.clone(), body.clone())
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
        request_headers.insert("mcp-session-id", "missing".parse().unwrap());
        assert_eq!(
            mcp(State(state.clone()), request_headers.clone(), body.clone())
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
        request_headers.insert("mcp-protocol-version", "unsupported".parse().unwrap());
        assert_eq!(
            mcp(State(state), request_headers, body).await.status(),
            StatusCode::BAD_REQUEST
        );
        assert!(receiver.try_recv().is_err());
    }
    #[tokio::test]
    async fn initialize_queues_native_approval_and_denial_removes_session() {
        let (state, receiver) = fixture();
        let serving_state = state.clone();
        let request = tokio::spawn(async move {
            mcp(State(serving_state), headers(), axum::body::Bytes::from_static(br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}"#)).await
        });
        let job = tokio::task::spawn_blocking(move || {
            receiver.recv_timeout(Duration::from_secs(3)).unwrap()
        })
        .await
        .unwrap();
        assert!(matches!(job.action, Action::Connect));
        assert!(!job.session.allowed.load(Ordering::SeqCst));
        job.response.send(Err("Connection denied".into())).unwrap();
        let response = request.await.unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(value.get("error").is_some());
        assert!(state.sessions.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn request_body_limit_rejects_oversized_messages() {
        let (state, receiver) = fixture();
        let router = Router::new()
            .route("/mcp", post(mcp))
            .layer(DefaultBodyLimit::max(protocol::MAX_FRAME))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let response = client
            .post(format!("http://{address}/mcp"))
            .bearer_auth("fixture-key")
            .header("Content-Type", "application/json")
            .body(vec![b' '; protocol::MAX_FRAME + 1])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(receiver.try_recv().is_err());
        task.abort();
    }
    #[tokio::test]
    async fn http_is_encrypted_and_pinned_across_the_relay() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (state, _receiver) = fixture();
        let identity = crate::transport::DeviceKey::generate().unwrap();
        let pin = identity.fingerprint().unwrap();
        let config =
            tokio_rustls::rustls::ServerConfig::builder_with_provider(crate::transport::provider())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![identity.certificate().unwrap()],
                    identity.private_key().unwrap().into(),
                )
                .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = Router::new().route("/mcp", post(mcp)).with_state(state);
        let task = tokio::spawn(async move {
            axum::serve(
                TlsListener {
                    listener,
                    acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(config)),
                },
                router,
            )
            .await
            .unwrap()
        });
        let socket = tokio::net::TcpStream::connect(address).await.unwrap();
        assert!(crate::transport::seal_gateway(socket, &"0".repeat(64))
            .await
            .is_err());
        let socket = tokio::net::TcpStream::connect(address).await.unwrap();
        let mut stream = crate::transport::seal_gateway(socket, &pin).await.unwrap();
        stream.write_all(b"POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 401"));
        task.abort();
    }
    #[test]
    fn http_requires_exact_key_and_rejects_browser_origins() {
        let hash = Sha256::digest(b"test-key").into();
        let mut headers = HeaderMap::new();
        assert!(!authorized(&headers, &hash));
        headers.insert("authorization", "Bearer wrong".parse().unwrap());
        assert!(!authorized(&headers, &hash));
        headers.insert("authorization", "Bearer test-key".parse().unwrap());
        assert!(authorized(&headers, &hash));
        headers.insert("origin", "https://attacker.example".parse().unwrap());
        assert!(!authorized(&headers, &hash));
    }
}
