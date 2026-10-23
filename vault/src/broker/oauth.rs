//! OAuth authorization code + S256 PKCE. Browser consent only requests the
//! existing protected broker approval; it cannot approve vault operations.
use super::http::HttpState;
use super::*;
use axum::{
    extract::{Form, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const SCOPE: &str = "vault:requests";
const MONTH: i64 = 30 * 86400;
/// A rotated refresh token is remembered this long to detect replay.
const REUSE_WINDOW: i64 = 86400;
/// Per-grant retention keeps busy connectors from filling the token store.
const ACCESS_PER_GRANT: usize = 4;
const USED_REFRESH_PER_GRANT: usize = 8;
fn now() -> i64 {
    chrono::Utc::now().timestamp()
}
fn random() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}
fn hash(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}
fn matches_hash(s: &str, digest: &str) -> bool {
    bool::from(hash(s).as_bytes().ct_eq(digest.as_bytes()))
}

#[derive(Clone, Serialize, Deserialize)]
struct Client {
    name: String,
    redirects: Vec<String>,
    method: String,
    secret: Option<String>,
    expires: i64,
}
#[derive(Clone, Serialize, Deserialize)]
struct Grant {
    client: String,
    origin: String,
    expires: i64,
}
#[derive(Clone, Serialize, Deserialize)]
struct Token {
    grant: String,
    expires: i64,
    used: bool,
    #[serde(default)]
    issued: i64,
    #[serde(default)]
    used_at: i64,
}
#[derive(Default, Serialize, Deserialize)]
struct Database {
    clients: BTreeMap<String, Client>,
    grants: BTreeMap<String, Grant>,
    access: BTreeMap<String, Token>,
    refresh: BTreeMap<String, Token>,
}
struct Authorization {
    client: String,
    redirect: String,
    challenge: String,
    state: String,
    origin: String,
    expires: i64,
    cookie: String,
}
pub(super) struct OAuth {
    origin: Option<String>,
    db: Database,
    pending: BTreeMap<String, Authorization>,
    codes: BTreeMap<String, Authorization>,
    path: Option<std::path::PathBuf>,
    /// Unauthenticated registration and sign-in attempts.
    signin: (i64, usize),
    /// Failed token requests; valid exchanges and refreshes are never throttled.
    token_failures: (i64, usize),
    /// Why the saved sign-ins could not be loaded. While set, remote sign-in stays off and
    /// nothing is saved, so the file that could not be read is never written over.
    unavailable: Option<String>,
}
impl Default for OAuth {
    fn default() -> Self {
        Self {
            origin: None,
            db: Database::default(),
            pending: BTreeMap::new(),
            codes: BTreeMap::new(),
            path: None,
            signin: (0, 0),
            token_failures: (0, 0),
            unavailable: None,
        }
    }
}
fn within(bucket: &mut (i64, usize), limit: usize) -> bool {
    let time = now();
    if time - bucket.0 >= 60 {
        *bucket = (time, 0);
    }
    bucket.1 += 1;
    bucket.1 <= limit
}
impl OAuth {
    pub(super) fn configured(&self) -> bool {
        self.origin.is_some()
    }
    /// Remote sign-in switched off because its saved sign-ins could not be loaded (`reason`).
    pub(super) fn unavailable(reason: String) -> Self {
        Self { unavailable: Some(reason), ..Default::default() }
    }
    pub(super) fn unavailable_reason(&self) -> Option<&str> {
        self.unavailable.as_deref()
    }
    pub(super) fn load() -> Result<Self, String> {
        Self::load_from(&platform::data_directory()?.join("oauth.dpapi"))
    }
    pub(super) fn load_from(path: &std::path::Path) -> Result<Self, String> {
        let path = path.to_owned();
        // Sign-ins that could not be checked never load as none: the next save would erase them.
        let db = if crate::storage::present(&path)? {
            let bytes = crate::storage::dpapi(
                &crate::storage::bounded_read(&path, 4 * 1024 * 1024)?,
                false,
            )?;
            serde_json::from_slice(&bytes).map_err(|_| "OAuth registration storage is damaged")?
        } else {
            Database::default()
        };
        let mut this = Self {
            db,
            path: Some(path),
            ..Default::default()
        };
        this.prune();
        Ok(this)
    }
    fn save(&self) -> Result<(), String> {
        if let Some(path) = &self.path {
            let bytes = zeroize::Zeroizing::new(
                serde_json::to_vec(&self.db).map_err(|_| "Cannot save OAuth")?,
            );
            crate::storage::atomic_write(path, &crate::storage::dpapi(&bytes, true)?)?;
        }
        Ok(())
    }
    /// Forgets every registration, grant and code; the destroyed vault's file is wiped apart.
    pub(super) fn reset(&mut self) {
        let path = self.path.take();
        let unavailable = self.unavailable.take();
        *self = Self { path, unavailable, ..Default::default() };
    }
    pub(super) fn set_origin(&mut self, origin: Option<String>) -> Result<(), String> {
        // Sign-ins that could not be loaded keep remote sign-in off; the status says why. The
        // public link itself is not refused for it.
        if self.unavailable.is_some() {
            return Ok(());
        }
        if let Some(origin) = &origin {
            let url = reqwest::Url::parse(origin).map_err(|_| "Invalid OAuth public origin")?;
            if url.scheme() != "https"
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
                || url.path() != "/"
                || url.origin().ascii_serialization() != *origin
            {
                return Err("OAuth requires an exact HTTPS public origin".into());
            }
        }
        if self.origin != origin {
            self.pending.clear();
            self.codes.clear();
        }
        self.origin = origin;
        Ok(())
    }
    pub(super) fn revoke_client(&mut self, identity: &str) -> Result<(), String> {
        if let Some(client) = identity.strip_prefix("oauth-") {
            self.db.grants.retain(|_, g| g.client != client);
            self.pending.retain(|_, a| a.client != client);
            self.codes.retain(|_, a| a.client != client);
            self.prune();
            self.save()?;
        }
        Ok(())
    }
    fn prune(&mut self) {
        let time = now();
        self.db.grants.retain(|_, g| g.expires > time);
        self.db
            .access
            .retain(|_, t| t.expires > time && self.db.grants.contains_key(&t.grant));
        self.db.refresh.retain(|_, t| {
            t.expires > time
                && self.db.grants.contains_key(&t.grant)
                && !(t.used && time - t.used_at > REUSE_WINDOW)
        });
        self.db
            .clients
            .retain(|id, c| c.expires > time || self.db.grants.values().any(|g| &g.client == id));
        self.pending.retain(|_, a| a.expires > time);
        self.codes.retain(|_, a| a.expires > time);
    }
    fn signin_rate(&mut self) -> bool {
        within(&mut self.signin, 60)
    }
    fn token_failure(&mut self) -> bool {
        within(&mut self.token_failures, 60)
    }
    pub(super) fn principal(&self, token: &str) -> Option<Identity> {
        let t = self.db.access.get(&hash(token))?;
        let grant = self.db.grants.get(&t.grant)?;
        if t.expires <= now()
            || grant.expires <= now()
            || self.origin.as_deref() != Some(&grant.origin)
        {
            return None;
        }
        let client = self.db.clients.get(&grant.client)?;
        Some(identity(
            &grant.client,
            client,
            "OAuth connection approved; every protected action still needs approval in Yougori Desktop",
        ))
    }
}
fn identity(id: &str, client: &Client, context: &str) -> Identity {
    Identity {
        id: format!("oauth-{id}"),
        executable: format!("{} (OAuth; name supplied by client)", client.name),
        digest: hash(id),
        device: "OAuth client with PKCE".into(),
        user: "Remote account is not attested".into(),
        process: 0,
        environment: context.into(),
    }
}
fn error(status: StatusCode, code: &str, description: &str) -> Response {
    secure(
        (
            status,
            Json(json!({"error":code,"error_description":description})),
        )
            .into_response(),
    )
}
fn secure(mut response: Response) -> Response {
    // no-referrer also makes browsers send Origin: null on form POSTs, breaking
    // consent's CSRF check. Preserve same-origin POSTs without leaking the
    // authorization URL to another site.
    for (name,value) in [("cache-control","no-store"),("pragma","no-cache"),("referrer-policy","same-origin"),("x-content-type-options","nosniff"),("x-frame-options","DENY"),("content-security-policy","default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")] {
        response.headers_mut().insert(name,value.parse().unwrap());
    }
    response
}
fn allow_consent_redirect(response: &mut Response, redirect: &str) {
    // Chromium applies form-action to the entire POST redirect chain. Only
    // permit the origin of this request's already validated, registered callback.
    let callback_origin = reqwest::Url::parse(redirect)
        .unwrap()
        .origin()
        .ascii_serialization();
    let policy = format!("default-src 'none'; style-src 'unsafe-inline'; form-action 'self' {callback_origin}; frame-ancestors 'none'; base-uri 'none'");
    response
        .headers_mut()
        .insert("content-security-policy", policy.parse().unwrap());
}
pub(super) fn routes() -> Router<HttpState> {
    Router::new()
        .route("/.well-known/oauth-protected-resource", get(resource))
        .route("/.well-known/oauth-protected-resource/mcp", get(resource))
        .route("/.well-known/oauth-authorization-server", get(metadata))
        .route("/oauth/register", post(register))
        .route("/oauth/authorize", get(authorize).post(consent))
        .route("/oauth/token", post(token))
}
pub(super) fn challenge(state: &HttpState) -> Response {
    let mut response = error(
        StatusCode::UNAUTHORIZED,
        "invalid_token",
        "Connect with OAuth, or supply your vault connection key.",
    );
    let origin = state.shared.oauth.lock().unwrap().origin.clone();
    let challenge = origin.map(|o|format!("Bearer resource_metadata=\"{o}/.well-known/oauth-protected-resource/mcp\", scope=\"{SCOPE}\"" )).unwrap_or("Bearer".into());
    response
        .headers_mut()
        .insert("www-authenticate", challenge.parse().unwrap());
    response
}
async fn resource(State(state): State<HttpState>) -> Response {
    let oauth = state.shared.oauth.lock().unwrap();
    let Some(origin) = &oauth.origin else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "Connect a public tunnel in Yougori first.",
        );
    };
    secure(Json(json!({"resource":format!("{origin}/mcp"),"authorization_servers":[origin],"scopes_supported":[SCOPE],"bearer_methods_supported":["header"],"resource_name":"Yougori Personal Vault"})).into_response())
}
async fn metadata(State(state): State<HttpState>) -> Response {
    let oauth = state.shared.oauth.lock().unwrap();
    let Some(o) = &oauth.origin else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "Connect a public tunnel in Yougori first.",
        );
    };
    secure(Json(json!({"issuer":o,"authorization_endpoint":format!("{o}/oauth/authorize"),"token_endpoint":format!("{o}/oauth/token"),"registration_endpoint":format!("{o}/oauth/register"),"response_types_supported":["code"],"grant_types_supported":["authorization_code","refresh_token"],"token_endpoint_auth_methods_supported":["none","client_secret_basic","client_secret_post"],"code_challenge_methods_supported":["S256"],"scopes_supported":[SCOPE],"authorization_response_iss_parameter_supported":true})).into_response())
}
fn valid_redirect(value: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(value) else {
        return false;
    };
    crate::policy::safe_text(value, 2048)
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
        && (url.scheme() == "https"
            || (url.scheme() == "http"
                && matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "localhost"))))
        && !url
            .query_pairs()
            .any(|(k, _)| matches!(k.as_ref(), "code" | "state" | "error" | "iss"))
}
async fn register(State(state): State<HttpState>, Json(body): Json<Value>) -> Response {
    let mut oauth = state.shared.oauth.lock().unwrap();
    oauth.prune();
    if oauth.origin.is_none() {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "Public OAuth is offline.",
        );
    }
    if !oauth.signin_rate() || oauth.db.clients.len() >= 128 {
        return error(
            StatusCode::TOO_MANY_REQUESTS,
            "temporarily_unavailable",
            "Registration limit reached. Try again later.",
        );
    }
    let Some(uris) = body["redirect_uris"].as_array() else {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            "Provide redirect_uris.",
        );
    };
    if uris.is_empty()
        || uris.len() > 8
        || uris.iter().any(|u| !u.as_str().is_some_and(valid_redirect))
    {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            "Use exact HTTPS callback URLs (HTTP allowed only on loopback).",
        );
    }
    let method = body["token_endpoint_auth_method"]
        .as_str()
        .unwrap_or("client_secret_basic");
    if !matches!(
        method,
        "none" | "client_secret_basic" | "client_secret_post"
    ) || body.get("grant_types").is_some_and(|v| {
        !v.as_array().is_some_and(|a| {
            a.iter()
                .all(|v| matches!(v.as_str(), Some("authorization_code" | "refresh_token")))
        })
    }) || body
        .get("response_types")
        .is_some_and(|v| v != &json!(["code"]))
        || body.get("scope").is_some_and(|v| v != SCOPE)
    {
        return error(StatusCode::BAD_REQUEST,"invalid_client_metadata","Supported: authorization_code, refresh_token, code response, vault:requests scope, and none/basic/post client authentication.");
    }
    let name = body["client_name"].as_str().unwrap_or("MCP connector");
    if !crate::policy::safe_text(name, 100) {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "Client name is invalid.",
        );
    }
    let id = random();
    let secret = (method != "none").then(random);
    let client = Client {
        name: name.into(),
        redirects: uris.iter().map(|u| u.as_str().unwrap().into()).collect(),
        method: method.into(),
        secret: secret.as_deref().map(hash),
        // Unapproved registrations must not fill the store for a month.
        expires: now() + 600,
    };
    let mut result = json!({"client_id":id,"client_id_issued_at":now(),"client_name":name,"redirect_uris":client.redirects,"token_endpoint_auth_method":method,"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"scope":SCOPE});
    if let Some(secret) = secret {
        result["client_secret"] = json!(secret);
        result["client_secret_expires_at"] = json!(0);
    }
    oauth.db.clients.insert(id.clone(), client);
    if oauth.save().is_err() {
        oauth.db.clients.remove(&id);
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "Could not save registration.",
        );
    }
    secure((StatusCode::CREATED, Json(result)).into_response())
}
#[derive(Deserialize)]
struct AuthQuery {
    client_id: String,
    redirect_uri: String,
    response_type: String,
    code_challenge: String,
    code_challenge_method: String,
    #[serde(default)]
    state: String,
    scope: Option<String>,
    resource: Option<String>,
}
fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
fn page(title: &str, body: &str) -> Response {
    secure(Html(format!("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>{title} · Yougori</title><style>body{{font:16px/1.6 system-ui,sans-serif;background:#101112;color:#edeeee;margin:0;padding:8vh 24px}}main{{max-width:460px;margin:auto;padding:32px;border:1px solid #343637;border-radius:20px;background:#191b1c}}h1{{font-size:24px;line-height:1.3}}p{{color:#b9bfc2;overflow-wrap:anywhere}}small{{color:#9ba2a6}}button{{border:0;border-radius:10px;padding:12px 18px;font:inherit;cursor:pointer;background:#f0f2f3;color:#17191a}}.secondary{{background:#303436;color:#eee;margin-left:8px}}code{{font-size:20px;letter-spacing:3px}}</style><main><small>YOUGORI PERSONAL VAULT</small><h1>{title}</h1>{body}</main></html>")).into_response())
}
async fn authorize(State(state): State<HttpState>, Query(q): Query<AuthQuery>) -> Response {
    let mut oauth = state.shared.oauth.lock().unwrap();
    oauth.prune();
    let Some(origin) = oauth.origin.clone() else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "Public OAuth is offline.",
        );
    };
    let Some(client) = oauth.db.clients.get(&q.client_id).cloned() else {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_client",
            "Reconnect the connector to register it again.",
        );
    };
    if !client.redirects.contains(&q.redirect_uri) {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            "Callback must exactly match the registered URL.",
        );
    }
    if q.response_type != "code"
        || q.code_challenge_method != "S256"
        || URL_SAFE_NO_PAD
            .decode(&q.code_challenge)
            .map_or(true, |v| v.len() != 32)
        || q.code_challenge.len() != 43
        || q.state.len() > 2048
        || q.scope.as_deref().is_some_and(|s| s != SCOPE)
        || q.resource
            .as_deref()
            .is_some_and(|s| s != format!("{origin}/mcp"))
    {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Use code with S256 PKCE and the advertised resource and scope.",
        );
    }
    if !oauth.signin_rate() || oauth.pending.len() >= 16 {
        return error(
            StatusCode::TOO_MANY_REQUESTS,
            "temporarily_unavailable",
            "Too many sign-in requests. Try again later.",
        );
    }
    let ticket = random();
    let cookie = random();
    let name = escape(&client.name);
    let redirect = escape(&q.redirect_uri);
    let pairing = &ticket[..8];
    let mut response=page("Connect your agent",&format!("<p><strong>{name}</strong> is asking to submit requests to your vault. This name is supplied by the connecting app.</p><p>Return address:<br>{redirect}</p><p>Continue, then open Personal Vault MCP in Yougori on your PC. Check that the request shows this code:</p><p><code>{pairing}</code></p><p>This does not share your items. You review each protected action separately.</p><form method=\"post\" action=\"/oauth/authorize\"><input type=\"hidden\" name=\"ticket\" value=\"{ticket}\"><button name=\"decision\" value=\"continue\">Continue on my PC</button><button class=\"secondary\" name=\"decision\" value=\"cancel\">Cancel</button></form>"));
    response.headers_mut().insert(
        "set-cookie",
        format!(
            "__Host-yougori-oauth={cookie}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=300"
        )
        .parse()
        .unwrap(),
    );
    allow_consent_redirect(&mut response, &q.redirect_uri);
    oauth.pending.insert(
        hash(&ticket),
        Authorization {
            client: q.client_id,
            redirect: q.redirect_uri,
            challenge: q.code_challenge,
            state: q.state,
            origin,
            expires: now() + 300,
            cookie: hash(&cookie),
        },
    );
    response
}
#[derive(Deserialize)]
struct Consent {
    ticket: String,
    decision: String,
}
async fn consent(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Form(form): Form<Consent>,
) -> Response {
    let (authorization, client) = {
        let mut oauth = state.shared.oauth.lock().unwrap();
        oauth.prune();
        let Some(a) = oauth.pending.get(&hash(&form.ticket)) else {
            return error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "This sign-in request expired. Start again in your agent.",
            );
        };
        let cookie = headers
            .get("cookie")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| {
                s.split(';')
                    .find_map(|v| v.trim().strip_prefix("__Host-yougori-oauth="))
            });
        if headers.get("origin").and_then(|v| v.to_str().ok()) != Some(&a.origin)
            || !cookie.is_some_and(|s| matches_hash(s, &a.cookie))
            || oauth.origin.as_deref() != Some(&a.origin)
        {
            return error(
                StatusCode::FORBIDDEN,
                "access_denied",
                "Sign-in browser verification failed.",
            );
        }
        let Some(client) = oauth.db.clients.get(&a.client).cloned() else {
            return error(StatusCode::BAD_REQUEST, "invalid_client", "Register again.");
        };
        (oauth.pending.remove(&hash(&form.ticket)).unwrap(), client)
    };
    let redirect = |code: Option<&str>| {
        let mut url = reqwest::Url::parse(&authorization.redirect).unwrap();
        {
            let mut pairs = url.query_pairs_mut();
            if let Some(code) = code {
                pairs.append_pair("code", code);
            } else {
                pairs.append_pair("error", "access_denied");
            }
            pairs.append_pair("state", &authorization.state);
            pairs.append_pair("iss", &authorization.origin);
        }
        let mut result = secure(axum::response::Redirect::to(url.as_str()).into_response());
        allow_consent_redirect(&mut result, &authorization.redirect);
        result.headers_mut().insert(
            "set-cookie",
            "__Host-yougori-oauth=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0"
                .parse()
                .unwrap(),
        );
        result
    };
    if form.decision != "continue" {
        return redirect(None);
    }
    let context = format!(
        "Sign-in code: {}\nCallback: {}\nIssuer: {}",
        &form.ticket[..8],
        authorization.redirect,
        authorization.origin
    );
    let session = Arc::new(Session {
        identity: identity(&authorization.client, &client, &context),
        desktop: false,
        cancelled: Arc::new(AtomicBool::new(false)),
        connected: AtomicBool::new(true),
        allowed: AtomicBool::new(false),
        admission: AtomicU64::new(0),
        vault: AtomicU64::new(0),
    });
    // Anyone with the tunnel address can reach this page. Wait for the Desktop
    // decision outside the single operation worker; only the approved result
    // is recorded by the worker.
    let result = match super::connection_decision(&state.shared, &session).await {
        Ok(()) => enqueue(Action::ApprovedConnect, &session, &state.sender, &state.shared).await,
        Err(error) => Err(error),
    };
    session.connected.store(false, Ordering::SeqCst);
    if result.is_err() {
        return redirect(None);
    }
    let mut oauth = state.shared.oauth.lock().unwrap();
    oauth.prune();
    let epoch = *state
        .shared
        .revocations
        .lock()
        .unwrap()
        .get(&session.identity.id)
        .unwrap_or(&0);
    if oauth.origin.as_deref() != Some(&authorization.origin)
        || authorization.expires <= now()
        || state.shared.locked.load(Ordering::SeqCst)
        || session.admission.load(Ordering::SeqCst) != epoch
        || oauth.codes.len() >= 32
    {
        return redirect(None);
    }
    let code = random();
    let response = redirect(Some(&code));
    oauth.codes.insert(
        hash(&code),
        Authorization {
            expires: now() + 60,
            ..authorization
        },
    );
    response
}
fn authenticate_client(
    db: &Database,
    headers: &HeaderMap,
    form: &BTreeMap<String, String>,
) -> Option<String> {
    let basic = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
        .and_then(|v| STANDARD.decode(v).ok())
        .and_then(|v| String::from_utf8(v).ok());
    let (id, secret, method) = if let Some(basic) = basic.as_ref() {
        let (id, secret) = basic.split_once(':')?;
        if form.contains_key("client_secret") || form.get("client_id").is_some_and(|c| c != id) {
            return None;
        }
        (id, Some(secret), "client_secret_basic")
    } else {
        (
            form.get("client_id")?.as_str(),
            form.get("client_secret").map(String::as_str),
            if form.contains_key("client_secret") {
                "client_secret_post"
            } else {
                "none"
            },
        )
    };
    let client = db.clients.get(id)?;
    if client.method != method
        || client
            .secret
            .as_deref()
            .is_some_and(|hash| !secret.is_some_and(|s| matches_hash(s, hash)))
    {
        return None;
    }
    Some(id.into())
}
/// Removes the oldest tokens selected by `select` beyond `keep`.
fn evict(tokens: &mut BTreeMap<String, Token>, keep: usize, select: impl Fn(&Token) -> bool) {
    let mut chosen: Vec<(i64, String)> = tokens
        .iter()
        .filter(|(_, t)| select(t))
        .map(|(id, t)| (t.used_at.max(t.issued), id.clone()))
        .collect();
    if chosen.len() <= keep {
        return;
    }
    chosen.sort();
    for (_, id) in chosen.drain(..chosen.len() - keep) {
        tokens.remove(&id);
    }
}
/// Issues an access/refresh pair. `rotated` is the hash of the refresh token
/// being exchanged; it is marked used only if the new pair is saved. Store
/// limits evict the oldest superseded tokens; they never revoke a grant.
fn issue(oauth: &mut OAuth, grant: &str, rotated: Option<&str>) -> Result<Value, String> {
    let expiry = oauth.db.grants.get(grant).ok_or("Grant expired")?.expires;
    let time = now();
    evict(&mut oauth.db.access, ACCESS_PER_GRANT - 1, |t| t.grant == grant);
    evict(&mut oauth.db.access, 511, |_| true);
    evict(&mut oauth.db.refresh, USED_REFRESH_PER_GRANT - 1, |t| t.grant == grant && t.used);
    evict(&mut oauth.db.refresh, 4095, |t| t.used);
    let access = random();
    let refresh = random();
    let previous = rotated.and_then(|hash| {
        let token = oauth.db.refresh.get_mut(hash)?;
        let previous = (token.used, token.used_at);
        (token.used, token.used_at) = (true, time);
        Some(previous)
    });
    if let Some(client) = oauth
        .db
        .grants
        .get(grant)
        .and_then(|g| oauth.db.clients.get_mut(&g.client))
    {
        client.expires = expiry;
    }
    oauth.db.access.insert(
        hash(&access),
        Token {
            grant: grant.into(),
            expires: (time + 3600).min(expiry),
            used: false,
            issued: time,
            used_at: 0,
        },
    );
    oauth.db.refresh.insert(
        hash(&refresh),
        Token {
            grant: grant.into(),
            expires: expiry,
            used: false,
            issued: time,
            used_at: 0,
        },
    );
    if let Err(e) = oauth.save() {
        oauth.db.access.remove(&hash(&access));
        oauth.db.refresh.remove(&hash(&refresh));
        if let (Some(hash), Some((used, used_at))) = (rotated, previous) {
            if let Some(token) = oauth.db.refresh.get_mut(hash) {
                (token.used, token.used_at) = (used, used_at);
            }
        }
        return Err(e);
    }
    Ok(
        json!({"access_token":access,"token_type":"Bearer","expires_in":(expiry-now()).min(3600),"refresh_token":refresh,"scope":SCOPE}),
    )
}
async fn token(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Form(form): Form<BTreeMap<String, String>>,
) -> Response {
    let mut oauth = state.shared.oauth.lock().unwrap();
    oauth.prune();
    let Some(origin) = oauth.origin.clone() else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "Public OAuth is offline.",
        );
    };
    let Some(client) = authenticate_client(&oauth.db, &headers, &form) else {
        if !oauth.token_failure() {
            return error(StatusCode::TOO_MANY_REQUESTS, "temporarily_unavailable", "Too many failed requests.");
        }
        return error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "Client authentication failed. Reconnect your connector.",
        );
    };
    if form
        .get("resource")
        .is_some_and(|v| v != &format!("{origin}/mcp"))
        || form.get("scope").is_some_and(|v| v != SCOPE)
    {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "Use the advertised resource and scope.",
        );
    }
    let invalid = |oauth: &mut OAuth| {
        if !oauth.token_failure() {
            return error(StatusCode::TOO_MANY_REQUESTS, "temporarily_unavailable", "Too many failed requests.");
        }
        error(StatusCode::BAD_REQUEST,"invalid_grant","Authorization expired, was already used, or does not match this client. Connect again.")
    };
    let mut rotated = None;
    let grant = match form.get("grant_type").map(String::as_str) {
        Some("authorization_code") => {
            let Some(code) = form.get("code") else {
                return invalid(&mut oauth);
            };
            let Some(a) = oauth.codes.get(&hash(code)) else {
                return invalid(&mut oauth);
            };
            let Some(verifier) = form.get("code_verifier").filter(|v| {
                (43..=128).contains(&v.len())
                    && v.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
            }) else {
                return invalid(&mut oauth);
            };
            let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
            if a.client != client
                || a.origin != origin
                || form.get("redirect_uri") != Some(&a.redirect)
                || !bool::from(challenge.as_bytes().ct_eq(a.challenge.as_bytes()))
            {
                return invalid(&mut oauth);
            }
            oauth.codes.remove(&hash(code));
            if oauth.db.grants.len() >= 128 {
                return error(
                    StatusCode::TOO_MANY_REQUESTS,
                    "temporarily_unavailable",
                    "Too many connections. Disconnect unused agents in Yougori.",
                );
            }
            let id = random();
            oauth.db.grants.insert(
                id.clone(),
                Grant {
                    client,
                    origin,
                    expires: now() + MONTH,
                },
            );
            id
        }
        Some("refresh_token") => {
            let Some(refresh) = form.get("refresh_token") else {
                return invalid(&mut oauth);
            };
            let Some(t) = oauth.db.refresh.get(&hash(refresh)).cloned() else {
                return invalid(&mut oauth);
            };
            let Some(g) = oauth.db.grants.get(&t.grant) else {
                return invalid(&mut oauth);
            };
            if g.client != client || g.origin != origin {
                return invalid(&mut oauth);
            }
            if t.used {
                oauth.db.grants.remove(&t.grant);
                oauth.prune();
                let _ = oauth.save();
                return invalid(&mut oauth);
            }
            rotated = Some(hash(refresh));
            t.grant
        }
        _ => {
            return error(
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                "Use authorization_code or refresh_token.",
            )
        }
    };
    match issue(&mut oauth, &grant, rotated.as_deref()) {
        Ok(value) => secure(Json(value).into_response()),
        Err(_) => {
            // A failed refresh keeps the grant and its unused token for a retry;
            // only a new, never-delivered authorization is discarded.
            if rotated.is_none() {
                oauth.db.grants.remove(&grant);
                oauth.prune();
                let _ = oauth.save();
            }
            error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Could not save authorization. Retry, or connect again.",
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn browser_sign_in_then_mcp_initialization_and_cross_client_isolation() {
        let (state, receiver) = fixture();
        let client = fixture_client(&state, "none").await;
        let id = client["client_id"].as_str().unwrap();
        let verifier = "v".repeat(64);
        let auth = authorize(
            State(state.clone()),
            Query(AuthQuery {
                client_id: id.into(),
                redirect_uri: "https://client.example/callback".into(),
                response_type: "code".into(),
                code_challenge: URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())),
                code_challenge_method: "S256".into(),
                state: "return-to-this-chat".into(),
                scope: None,
                resource: None,
            }),
        )
        .await;
        let consent_policy = auth.headers()["content-security-policy"].clone();
        assert_eq!(consent_policy.to_str().unwrap(), "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https://client.example; frame-ancestors 'none'; base-uri 'none'");
        let cookie = auth.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let html = String::from_utf8(
            axum::body::to_bytes(auth.into_body(), 20000)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        let ticket = html
            .split("name=\"ticket\" value=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap()
            .to_string();
        let mut headers = HeaderMap::new();
        headers.insert("origin", "https://vault.example".parse().unwrap());
        headers.insert("cookie", cookie.parse().unwrap());
        let worker_state = state.clone();
        // Desktop approves the sign-in prompt, which waits outside the worker.
        let approval = tokio::spawn(sign_in_prompt(state.clone(), 1));
        // Simulated native worker exists only in this isolated test fixture.
        let worker = tokio::task::spawn_blocking(move || {
            for _ in 0..1 {
                let job = receiver.recv_timeout(Duration::from_secs(5)).unwrap();
                assert!(matches!(job.action, Action::ApprovedConnect));
                assert!(!job.session.allowed.load(Ordering::SeqCst));
                job.session.allowed.store(true, Ordering::SeqCst);
                job.session.admission.store(0, Ordering::SeqCst);
                worker_state.shared.locked.store(false, Ordering::SeqCst);
                job.response
                    .send(Ok(json!({"allowedRequests":true})))
                    .unwrap();
            }
            receiver
        });
        let approved = consent(
            State(state.clone()),
            headers,
            Form(Consent {
                ticket,
                decision: "continue".into(),
            }),
        )
        .await;
        assert_eq!(approved.status(), StatusCode::SEE_OTHER);
        assert_eq!(approval.await.unwrap()["title"], CONNECT_TITLE);
        assert_eq!(
            approved.headers()["content-security-policy"],
            consent_policy
        );
        let redirect =
            reqwest::Url::parse(approved.headers()["location"].to_str().unwrap()).unwrap();
        let params: BTreeMap<_, _> = redirect.query_pairs().into_owned().collect();
        assert_eq!(params["state"], "return-to-this-chat");
        assert_eq!(params["iss"], "https://vault.example");
        let tokens = value(
            token(
                State(state.clone()),
                HeaderMap::new(),
                Form(exchange(id, &params["code"], &verifier)),
            )
            .await,
        )
        .await;
        let receiver = worker.await.unwrap();
        let access = tokens["access_token"].as_str().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = super::super::http::router(state.clone());
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let http = reqwest::Client::builder().no_proxy().build().unwrap();
        let url = format!("http://{address}/mcp");
        let initialize=http.post(&url).bearer_auth(access).json(&json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}})).send().await.unwrap();
        assert_eq!(initialize.status(), StatusCode::OK);
        let session = initialize.headers()["mcp-session-id"]
            .to_str()
            .unwrap()
            .to_owned();
        let initialized: Value = initialize.json().await.unwrap();
        assert_eq!(initialized["result"]["protocolVersion"], "2025-06-18");
        let body = json!({"jsonrpc":"2.0","id":2,"method":"tools/list"});
        let list: Value = http
            .post(&url)
            .bearer_auth(access)
            .header("mcp-session-id", &session)
            .header("mcp-protocol-version", "2025-06-18")
            .json(&body)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(list["result"]["tools"].as_array().unwrap().len(), 5);
        assert!(list["result"]["tools"].as_array().unwrap().iter().any(|tool| tool["name"] == "list_vault_items"));
        assert!(list["result"]["tools"].as_array().unwrap().iter().any(|tool| tool["name"] == "read_all_credentials"));
        assert!(list["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|tool| tool["name"] == "read_credential"));
        // Agents initialize repeatedly for discovery and separate tool calls.
        // OAuth already represents native connection consent, even while locked.
        state.shared.locked.store(true, Ordering::SeqCst);
        for _ in 0..30 {
            let reconnected: Value = http.post(&url).bearer_auth(access)
                .json(&json!({"jsonrpc":"2.0","id":3,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}))
                .send().await.unwrap().json().await.unwrap();
            assert_eq!(reconnected["result"]["protocolVersion"], "2025-06-18");
            assert!(receiver.try_recv().is_err());
        }
        state.shared.locked.store(false, Ordering::SeqCst);
        // The user's exact item-name request reaches the native operation queue,
        // and cannot return data until that worker responds.
        for (tool, args) in [
            (
                "personal_info",
                json!({"item":"openSourceName","fields":["openSourceName"]}),
            ),
            ("read_credential", json!({"item":"OpenSourceName"})),
        ] {
            for approved in [false, true] {
                let request = http.post(&url).bearer_auth(access)
                .header("mcp-session-id", &session)
                .json(&json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":tool,"arguments":args}}));
                let call = tokio::spawn(async move {
                    request.send().await.unwrap().json::<Value>().await.unwrap()
                });
                let mut job = None;
                for _ in 0..100 {
                    if let Ok(next) = receiver.try_recv() {
                        job = Some(next);
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                let job = job.expect("Native tool approval must be queued");
                assert!(
                    matches!(&job.action, Action::Tool(op) if op.name() == tool && op.item() == args["item"].as_str())
                );
                assert!(!call.is_finished(), "No disclosure before in-app approval");
                job.response
                .send(if approved {
                    Ok(if tool == "read_credential" { json!({"item":"fixture-id","name":"OpenSourceName","kind":"api_key","value":"fixture-profile"}) } else { json!({"openSourceName":"fixture-profile"}) })
                } else {
                    Err("Request denied; nothing disclosed. Do not automatically retry.".into())
                })
                .unwrap();
                let result = call.await.unwrap();
                assert_eq!(result["result"]["isError"], !approved);
                assert!(result.get("error").is_none());
                assert_eq!(result.to_string().contains("fixture-profile"), approved);
            }
        }
        for (tool, expected) in [
            ("list_vault_items", json!({"count":1,"items":[{"id":"fixture-id","name":"OpenSourceName","kind":"api_key","fields":[]}]})),
            ("read_all_credentials", json!({"count":1,"credentials":[{"id":"fixture-id","name":"OpenSourceName","kind":"api_key","value":"fixture-secret"}]})),
        ] {
            for approved in [false, true] {
                let request = http.post(&url).bearer_auth(access)
                    .header("mcp-session-id", &session)
                    .json(&json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":tool,"arguments":{}}}));
                let call = tokio::spawn(async move { request.send().await.unwrap().json::<Value>().await.unwrap() });
                let mut job = None;
                for _ in 0..100 {
                    if let Ok(next) = receiver.try_recv() { job = Some(next); break; }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                let job = job.expect("New tool must reach native approval queue");
                assert!(matches!(&job.action, Action::Tool(op) if op.name() == tool && op.item().is_none()));
                assert!(!call.is_finished(), "No inventory or secrets before in-app approval");
                job.response.send(if approved { Ok(expected.clone()) } else { Err("Request denied".into()) }).unwrap();
                let result = call.await.unwrap();
                assert_eq!(result["result"]["isError"], !approved);
                assert_eq!(result.to_string().contains("fixture-secret"), approved && tool == "read_all_credentials");
            }
        }
        let invalid: Value = http.post(&url).bearer_auth(access).header("mcp-session-id", &session)
            .json(&json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"personal_info","arguments":{"item":"openSourceName","fields":[]}}}))
            .send().await.unwrap().json().await.unwrap();
        assert_eq!(invalid["result"]["isError"], true);
        assert!(invalid["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("distinct fields"));
        assert!(receiver.try_recv().is_err());
        // A valid but different credential must not borrow or delete this session.
        for method in [reqwest::Method::POST, reqwest::Method::DELETE] {
            assert_eq!(
                http.request(method, &url)
                    .bearer_auth("fixture-key")
                    .header("mcp-session-id", &session)
                    .json(&body)
                    .send()
                    .await
                    .unwrap()
                    .status(),
                StatusCode::NOT_FOUND
            );
        }
        state
            .shared
            .oauth
            .lock()
            .unwrap()
            .revoke_client(&format!("oauth-{id}"))
            .unwrap();
        assert_eq!(
            http.post(&url)
                .bearer_auth(access)
                .header("mcp-session-id", session)
                .json(&body)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert!(
            receiver.try_recv().is_err(),
            "OAuth reconnects must not enqueue native connection prompts"
        );
        server.abort();
    }
    #[test]
    fn oauth_database_is_encrypted_and_survives_a_broker_restart() {
        let data = tempfile::tempdir().unwrap();
        let path = data.path().join("fixture.dpapi");
        let mut oauth = OAuth {
            path: Some(path.clone()),
            ..Default::default()
        };
        oauth
            .set_origin(Some("https://vault.example".into()))
            .unwrap();
        oauth.db.clients.insert(
            "fixture".into(),
            Client {
                name: "fixture client".into(),
                redirects: vec!["https://client.example/callback".into()],
                method: "none".into(),
                secret: None,
                expires: now() + MONTH,
            },
        );
        oauth.db.grants.insert(
            "grant".into(),
            Grant {
                client: "fixture".into(),
                origin: "https://vault.example".into(),
                expires: now() + MONTH,
            },
        );
        // The ordinary test temp directory must fail the production ACL check.
        assert!(oauth.save().is_err());
        oauth.path = None;
        let tokens = issue(&mut oauth, "grant", None).unwrap();
        let access = tokens["access_token"].as_str().unwrap();
        let bytes = crate::storage::dpapi(&serde_json::to_vec(&oauth.db).unwrap(), true).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("fixture client"));
        let decoded = crate::storage::dpapi(&bytes, false).unwrap();
        let db: Database = serde_json::from_slice(&decoded).unwrap();
        let mut restored = OAuth {
            db,
            ..Default::default()
        };
        assert!(restored.principal(access).is_none()); // No public origin until desktop sets it.
        restored
            .set_origin(Some("https://vault.example".into()))
            .unwrap();
        assert!(restored.principal(access).is_some());
    }
    async fn value(response: Response) -> Value {
        serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap(),
        )
        .unwrap()
    }
    async fn fixture_client(state: &HttpState, method: &str) -> Value {
        let response=register(State(state.clone()),Json(json!({"client_name":"Fixture connector","redirect_uris":["https://client.example/callback"],"token_endpoint_auth_method":method}))).await;
        assert_eq!(response.status(), StatusCode::CREATED);
        value(response).await
    }
    fn fixture() -> (HttpState, std::sync::mpsc::Receiver<Job>) {
        let (state, receiver) = super::super::http::tests::fixture();
        state
            .shared
            .oauth
            .lock()
            .unwrap()
            .set_origin(Some("https://vault.example".into()))
            .unwrap();
        (state, receiver)
    }
    fn code(state: &HttpState, id: &str, verifier: &str) -> String {
        let code = random();
        state.shared.oauth.lock().unwrap().codes.insert(
            hash(&code),
            Authorization {
                client: id.into(),
                redirect: "https://client.example/callback".into(),
                challenge: URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())),
                state: "state".into(),
                origin: "https://vault.example".into(),
                expires: now() + 60,
                cookie: String::new(),
            },
        );
        code
    }
    fn exchange(id: &str, code: &str, verifier: &str) -> BTreeMap<String, String> {
        [
            ("client_id", id),
            ("code", code),
            ("code_verifier", verifier),
            ("redirect_uri", "https://client.example/callback"),
            ("grant_type", "authorization_code"),
            ("resource", "https://vault.example/mcp"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect()
    }
    #[tokio::test]
    async fn registration_rejects_identity_text_that_can_spoof_native_consent() {
        for name in [
            "",
            "Agent\u{202e}trusted",
            "Agent\u{2066}trusted",
            "Agent\u{2028}Approved",
            "Agent\u{2029}Approved",
        ] {
            let (state, receiver) = fixture();
            let response = register(
                State(state.clone()),
                Json(json!({
                    "client_name": name,
                    "redirect_uris": ["https://client.example/callback"],
                    "token_endpoint_auth_method": "none"
                })),
            )
            .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{name:?}");
            assert!(state.shared.oauth.lock().unwrap().db.clients.is_empty());
            assert!(receiver.try_recv().is_err());
        }
        for callback in [
            "https://client.example/\nApproved",
            "https://client.example/\tcallback",
            "https://client.example/\u{202e}trusted",
            "https://client.example/\u{2028}Approved",
            "https://client.example/\u{2029}Approved",
        ] {
            let (state, receiver) = fixture();
            let response = register(
                State(state.clone()),
                Json(json!({
                    "client_name": "Fixture connector",
                    "redirect_uris": [callback],
                    "token_endpoint_auth_method": "none"
                })),
            )
            .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{callback:?}");
            assert!(state.shared.oauth.lock().unwrap().db.clients.is_empty());
            assert!(receiver.try_recv().is_err());
        }
        // Keep ordinary localized names and legal encoded callback paths usable.
        let (state, _) = fixture();
        assert_eq!(
            register(
                State(state),
                Json(json!({
                    "client_name": "Mon agent privé",
                    "redirect_uris": ["https://client.example/callback%20path?source=yougori"],
                    "token_endpoint_auth_method": "none"
                }))
            )
            .await
            .status(),
            StatusCode::CREATED
        );
    }
    #[tokio::test]
    async fn discovery_and_registration_work_over_http_without_trusting_forwarded_host() {
        let (state, _receiver) = fixture();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = super::super::http::router(state);
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let base = format!("http://{address}");
        let denied = client.get(format!("{base}/mcp")).send().await.unwrap();
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
        assert!(denied.headers()["www-authenticate"]
            .to_str()
            .unwrap()
            .contains("https://vault.example/.well-known/oauth-protected-resource/mcp"));
        let metadata: Value = client
            .get(format!("{base}/.well-known/oauth-authorization-server"))
            .header("host", "attacker.example")
            .header("x-forwarded-host", "attacker.example")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(metadata["issuer"], "https://vault.example");
        assert_eq!(
            metadata["registration_endpoint"],
            "https://vault.example/oauth/register"
        );
        let registered=client.post(format!("{base}/oauth/register")).json(&json!({"redirect_uris":["https://claude.ai/api/mcp/auth_callback"],"token_endpoint_auth_method":"none"})).send().await.unwrap();
        assert_eq!(registered.status(), StatusCode::CREATED);
        task.abort();
    }
    #[tokio::test]
    async fn pkce_exact_redirect_audience_client_auth_and_code_replay() {
        for method in ["none", "client_secret_basic", "client_secret_post"] {
            let (state, _receiver) = fixture();
            let client = fixture_client(&state, method).await;
            let id = client["client_id"].as_str().unwrap();
            let verifier = "a".repeat(64);
            let code = code(&state, id, &verifier);
            let mut form = exchange(id, &code, &verifier);
            let mut headers = HeaderMap::new();
            if method == "client_secret_basic" {
                headers.insert(
                    "authorization",
                    format!(
                        "Basic {}",
                        STANDARD.encode(format!(
                            "{id}:{}",
                            client["client_secret"].as_str().unwrap()
                        ))
                    )
                    .parse()
                    .unwrap(),
                );
            }
            if method == "client_secret_post" {
                form.insert(
                    "client_secret".into(),
                    client["client_secret"].as_str().unwrap().into(),
                );
            }
            for (field, bad) in [
                ("redirect_uri", "https://attacker.example/callback"),
                ("code_verifier", &"b".repeat(64)),
                ("resource", "https://attacker.example/mcp"),
            ] {
                let mut wrong = form.clone();
                wrong.insert(field.into(), bad.into());
                assert_eq!(
                    token(State(state.clone()), headers.clone(), Form(wrong))
                        .await
                        .status(),
                    StatusCode::BAD_REQUEST
                );
            }
            let response = token(State(state.clone()), headers.clone(), Form(form.clone())).await;
            assert_eq!(response.status(), StatusCode::OK);
            let issued = value(response).await;
            assert!(state
                .shared
                .oauth
                .lock()
                .unwrap()
                .principal(issued["access_token"].as_str().unwrap())
                .is_some());
            assert_eq!(
                token(State(state), headers, Form(form)).await.status(),
                StatusCode::BAD_REQUEST
            );
        }
    }
    #[tokio::test]
    async fn refresh_rotates_replay_revokes_family_and_disconnect_revokes_all_client_tokens() {
        let (state, _receiver) = fixture();
        let client = fixture_client(&state, "none").await;
        let id = client["client_id"].as_str().unwrap();
        let verifier = "a".repeat(64);
        let issued = value(
            token(
                State(state.clone()),
                HeaderMap::new(),
                Form(exchange(id, &code(&state, id, &verifier), &verifier)),
            )
            .await,
        )
        .await;
        let form: BTreeMap<String, String> = [
            ("grant_type", "refresh_token"),
            ("client_id", id),
            ("refresh_token", issued["refresh_token"].as_str().unwrap()),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
        let renewed =
            value(token(State(state.clone()), HeaderMap::new(), Form(form.clone())).await).await;
        assert_ne!(issued["refresh_token"], renewed["refresh_token"]);
        assert_eq!(
            token(State(state.clone()), HeaderMap::new(), Form(form))
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert!(state
            .shared
            .oauth
            .lock()
            .unwrap()
            .principal(renewed["access_token"].as_str().unwrap())
            .is_none());
        let issued = value(
            token(
                State(state.clone()),
                HeaderMap::new(),
                Form(exchange(id, &code(&state, id, &verifier), &verifier)),
            )
            .await,
        )
        .await;
        let mut oauth = state.shared.oauth.lock().unwrap();
        oauth.revoke_client(&format!("oauth-{id}")).unwrap();
        assert!(oauth
            .principal(issued["access_token"].as_str().unwrap())
            .is_none());
        assert!(oauth.db.refresh.is_empty());
    }
    #[tokio::test]
    async fn consent_requires_browser_cookie_origin_and_native_approval() {
        let (state, receiver) = fixture();
        let client = fixture_client(&state, "none").await;
        let id = client["client_id"].as_str().unwrap();
        let response = authorize(
            State(state.clone()),
            Query(AuthQuery {
                client_id: id.into(),
                redirect_uri: "https://client.example/callback".into(),
                response_type: "code".into(),
                code_challenge: URL_SAFE_NO_PAD.encode(Sha256::digest(
                    b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )),
                code_challenge_method: "S256".into(),
                state: "client-state".into(),
                scope: Some(SCOPE.into()),
                resource: Some("https://vault.example/mcp".into()),
            }),
        )
        .await;
        let cookie = response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let body = String::from_utf8(
            axum::body::to_bytes(response.into_body(), 20000)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        let ticket = body
            .split("name=\"ticket\" value=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap()
            .to_owned();
        assert_eq!(
            consent(
                State(state.clone()),
                HeaderMap::new(),
                Form(Consent {
                    ticket: ticket.clone(),
                    decision: "continue".into()
                })
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        assert!(receiver.try_recv().is_err());
        let mut headers = HeaderMap::new();
        headers.insert("origin", "https://vault.example".parse().unwrap());
        headers.insert("cookie", cookie.parse().unwrap());
        let request_state = state.clone();
        for origin in ["null", "https://attacker.example"] {
            let mut rejected = headers.clone();
            rejected.insert("origin", origin.parse().unwrap());
            assert_eq!(
                consent(
                    State(state.clone()),
                    rejected,
                    Form(Consent {
                        ticket: ticket.clone(),
                        decision: "continue".into(),
                    })
                )
                .await
                .status(),
                StatusCode::FORBIDDEN
            );
            assert!(receiver.try_recv().is_err());
        }
        let task = tokio::spawn(async move {
            consent(
                State(request_state),
                headers,
                Form(Consent {
                    ticket,
                    decision: "continue".into(),
                }),
            )
            .await
        });
        // Deny in Desktop: nothing reaches the operation worker and no code is minted.
        let prompt = sign_in_prompt(state.clone(), 2).await;
        assert!(prompt["client"]["environment"].as_str().unwrap().contains("Sign-in code:"));
        assert!(state.shared.oauth.lock().unwrap().codes.is_empty());
        let response = task.await.unwrap();
        assert!(response.headers()["location"]
            .to_str()
            .unwrap()
            .contains("error=access_denied"));
        assert!(receiver.try_recv().is_err());
        assert!(state.shared.oauth.lock().unwrap().codes.is_empty());
        assert!(state.shared.pending.lock().unwrap().is_empty());
    }
    /// Waits for the unauthenticated sign-in prompt, then approves (1) or
    /// denies (2) it as Desktop would. Returns the prompt shown to the user.
    async fn sign_in_prompt(state: HttpState, decision: u8) -> Value {
        for _ in 0..200 {
            let found = state.shared.pending.lock().unwrap().values().find(|p| p.summary.lock().unwrap()["unauthenticated"] == true).cloned();
            if let Some(pending) = found {
                let summary = pending.summary.lock().unwrap().clone();
                assert_eq!(summary["ready"], true);
                if decision == 1 {
                    pending.decision.store(1, Ordering::SeqCst);
                } else {
                    pending.cancel.store(true, Ordering::SeqCst);
                }
                return summary;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("No sign-in prompt was shown");
    }
    async fn sign_in_form(state: &HttpState, id: &str) -> (HeaderMap, String) {
        let response = authorize(
            State(state.clone()),
            Query(AuthQuery {
                client_id: id.into(),
                redirect_uri: "https://client.example/callback".into(),
                response_type: "code".into(),
                code_challenge: URL_SAFE_NO_PAD.encode(Sha256::digest(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")),
                code_challenge_method: "S256".into(),
                state: "client-state".into(),
                scope: None,
                resource: None,
            }),
        )
        .await;
        let cookie = response.headers()["set-cookie"].to_str().unwrap().split(';').next().unwrap().to_string();
        let body = String::from_utf8(axum::body::to_bytes(response.into_body(), 20000).await.unwrap().to_vec()).unwrap();
        let ticket = body.split("name=\"ticket\" value=\"").nth(1).unwrap().split('"').next().unwrap().to_owned();
        let mut headers = HeaderMap::new();
        headers.insert("origin", "https://vault.example".parse().unwrap());
        headers.insert("cookie", cookie.parse().unwrap());
        (headers, ticket)
    }
    #[tokio::test]
    async fn waiting_sign_ins_never_occupy_the_worker_and_wait_one_at_a_time() {
        let (state, receiver) = fixture();
        let client = fixture_client(&state, "none").await;
        let id = client["client_id"].as_str().unwrap().to_owned();
        let (headers, ticket) = sign_in_form(&state, &id).await;
        let first_state = state.clone();
        let first = tokio::spawn(async move {
            consent(State(first_state), headers, Form(Consent { ticket, decision: "continue".into() })).await
        });
        for _ in 0..200 {
            if !state.shared.pending.lock().unwrap().is_empty() { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // The waiting prompt holds no operation-worker job: agents keep working.
        assert!(receiver.try_recv().is_err());
        // A second anonymous sign-in cannot queue behind it.
        let (headers, ticket) = sign_in_form(&state, &id).await;
        let second = consent(State(state.clone()), headers, Form(Consent { ticket, decision: "continue".into() })).await;
        assert!(second.headers()["location"].to_str().unwrap().contains("error=access_denied"));
        assert_eq!(state.shared.pending.lock().unwrap().len(), 1);
        // Windows lock or vault lock (a generation change) ends the wait.
        state.shared.lock();
        assert!(first.await.unwrap().headers()["location"].to_str().unwrap().contains("error=access_denied"));
        assert!(receiver.try_recv().is_err());
        assert!(state.shared.pending.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn refresh_rotation_evicts_superseded_tokens_and_never_revokes_live_grants() {
        let mut oauth = OAuth::default();
        oauth.set_origin(Some("https://vault.example".into())).unwrap();
        oauth.db.clients.insert("fixture".into(), Client { name: "fixture".into(), redirects: vec![], method: "none".into(), secret: None, expires: now() + MONTH });
        oauth.db.grants.insert("grant".into(), Grant { client: "fixture".into(), origin: "https://vault.example".into(), expires: now() + MONTH });
        let mut refresh = issue(&mut oauth, "grant", None).unwrap()["refresh_token"].as_str().unwrap().to_owned();
        for _ in 0..600 {
            let next = issue(&mut oauth, "grant", Some(&hash(&refresh))).unwrap();
            refresh = next["refresh_token"].as_str().unwrap().to_owned();
            assert!(oauth.principal(next["access_token"].as_str().unwrap()).is_some());
        }
        assert!(oauth.db.grants.contains_key("grant"));
        assert!(oauth.db.access.len() <= ACCESS_PER_GRANT);
        assert!(oauth.db.refresh.values().filter(|t| t.used).count() <= USED_REFRESH_PER_GRANT);
        assert_eq!(oauth.db.refresh.values().filter(|t| !t.used).count(), 1);
        // Recently rotated tokens are still recognized as replays; old ones expire.
        for token in oauth.db.refresh.values_mut().filter(|t| t.used) {
            token.used_at = now() - REUSE_WINDOW - 1;
        }
        oauth.prune();
        assert_eq!(oauth.db.refresh.len(), 1);
    }
    #[tokio::test]
    async fn expired_tokens_origin_changes_and_registration_validation_fail_closed() {
        let (state, _receiver) = fixture();
        for uri in [
            "https://user:pass@client.example/cb",
            "javascript:alert(1)",
            "http://remote.example/cb",
            "https://client.example/cb#fragment",
            "https://client.example/cb?code=injected",
        ] {
            assert_eq!(
                register(State(state.clone()), Json(json!({"redirect_uris":[uri]})))
                    .await
                    .status(),
                StatusCode::BAD_REQUEST
            );
        }
        let client = fixture_client(&state, "none").await;
        let id = client["client_id"].as_str().unwrap();
        let verifier = "a".repeat(64);
        let issued = value(
            token(
                State(state.clone()),
                HeaderMap::new(),
                Form(exchange(id, &code(&state, id, &verifier), &verifier)),
            )
            .await,
        )
        .await;
        let access = issued["access_token"].as_str().unwrap();
        let mut oauth = state.shared.oauth.lock().unwrap();
        oauth
            .set_origin(Some("https://new.example".into()))
            .unwrap();
        assert!(oauth.principal(access).is_none());
        oauth
            .set_origin(Some("https://vault.example".into()))
            .unwrap();
        assert!(oauth.principal(access).is_some());
        oauth.db.access.get_mut(&hash(access)).unwrap().expires = now() - 1;
        assert!(oauth.principal(access).is_none());
        assert!(oauth
            .set_origin(Some("https://bad.example/path".into()))
            .is_err());
        assert!(oauth.set_origin(Some("http://bad.example".into())).is_err());
    }
}
