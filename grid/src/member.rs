//! A member computer: joins with the company name and password, reports what it runs, receives
//! its assignment from the admin's plans and, while allowed, asks the hub for work, runs it on
//! its local model and streams the reply back.
use crate::{
    desks::{Capacity, DeskOrder, DeskReport},
    hub::{ModelReport, GENERATION, POLL},
    invite::Invite,
    is_token, model_key, net, password,
};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::{body::Incoming, header, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use crate::net::HubAddress;
use std::{future::Future, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::watch,
};
use tokio_rustls::rustls::ClientConfig;

/// Any connection to a local model server's HTTP port.
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + ?Sized> Io for T {}

/// An open connection to the local model server and its API key.
pub struct LocalModel {
    pub io: Box<dyn Io>,
    pub api_key: String,
}

/// The admin's instructions for this computer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Assignment {
    pub plan_id: String,
    pub model: String,
    #[serde(default)]
    pub quant: Option<String>,
    pub idle_after_minutes: u32,
    #[serde(default)]
    pub schedule: Option<String>,
}

impl Assignment {
    pub fn policy(&self) -> Result<crate::policy::IdlePolicy, String> {
        crate::policy::IdlePolicy::new(Some(self.idle_after_minutes), self.schedule.as_deref())
    }
    /// Whether switching to `other` needs a different model environment.
    pub fn same_model(&self, other: &Assignment) -> bool {
        model_key(&self.model) == model_key(&other.model) && self.quant.as_deref().map(str::to_ascii_lowercase) == other.quant.as_deref().map(str::to_ascii_lowercase)
    }
}

fn assignment(value: &Value) -> Option<Assignment> {
    serde_json::from_value(value.clone()).ok()
}

#[derive(Clone)]
pub struct Membership {
    pub address: HubAddress,
    pub member_id: String,
    token: String,
    tls: Arc<ClientConfig>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum MemberError {
    /// The hub no longer knows this computer: the admin removed it or recreated the grid.
    Removed,
    /// The admin deleted the grid: leave it and clean up what it put here.
    Deleted,
    /// The hub answered, and this computer could not read what it said. Distinct from `Failed`
    /// because the hub is not silent: the loops that watch for silence start a clock on a failed
    /// check-in, and after seven days they tell the person the hub is gone and to leave the
    /// grid — which unshares every desk on this computer. Following good advice about the wrong
    /// problem would be a worse outcome than the one this reports.
    Unreadable(String),
    Failed(String),
}

/// The "the hub has not answered" clock after one check-in, in seconds, or `None` for no clock.
///
/// It is what ends, after seven days, in telling somebody the hub is gone and to leave the grid —
/// which unshares every desk on this computer — so only real silence may run it. `running` is a
/// clock already going, kept rather than restarted, so the days are counted from the first
/// silence.
///
/// Anything the hub actually said clears it, and that includes words this build cannot read.
/// Refusing to *start* the clock on those was not enough on its own: a restart for a hub upgrade
/// fails one check-in and starts a clock, and if every answer after that is unreadable, nothing
/// stopped it. The advice then arrived seven days later over a hub that had been answering all
/// along.
pub fn silence_clock(answered: bool, running: Option<i64>, now: i64) -> Option<i64> {
    if answered {
        None
    } else {
        Some(running.unwrap_or(now))
    }
}

impl std::fmt::Display for MemberError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemberError::Removed => write!(f, "The grid's admin removed this computer; join again with the company password"),
            MemberError::Deleted => write!(f, "{}", crate::GRID_DELETED),
            MemberError::Unreadable(said) => write!(f, "{said}"),
            MemberError::Failed(message) => write!(f, "{message}"),
        }
    }
}

pub struct Joined {
    pub membership: Membership,
    pub token: String,
    pub grid_id: String,
    pub grid_name: String,
    /// The hub's certificate, pinned from now on.
    pub certificate: String,
    pub fingerprint: String,
    pub assignment: Option<Assignment>,
}

fn message(value: &Value, fallback: &str) -> String {
    value["error"]["message"].as_str().unwrap_or(fallback).to_owned()
}

async fn exchange(address: &HubAddress, tls: &Arc<ClientConfig>, path: &str, bearer: Option<&str>, body: Option<&Value>, wait: Duration) -> Result<(StatusCode, Value), String> {
    let mut request = Request::builder().uri(path).method(if body.is_some() { "POST" } else { "GET" });
    if let Some(bearer) = bearer {
        request = request.header(header::AUTHORIZATION, format!("Bearer {bearer}"));
    }
    let response = match body {
        Some(body) => {
            let request = request.header(header::CONTENT_TYPE, "application/json").body(Full::new(Bytes::from(body.to_string()))).map_err(|error| error.to_string())?;
            net::send(address, tls, request, wait).await?
        }
        None => net::send(address, tls, request.body(Empty::<Bytes>::new()).map_err(|error| error.to_string())?, wait).await?,
    };
    let status = response.status();
    let bytes = tokio::time::timeout(Duration::from_secs(20), http_body_util::Limited::new(response.into_body(), 1024 * 1024).collect())
        .await
        .map_err(|_| "The grid hub's answer was interrupted")?
        .map_err(|_| "The grid hub's answer was interrupted")?
        .to_bytes();
    Ok((status, if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap_or(Value::Null) }))
}

/// A POST whose answer is raw bytes rather than JSON, bounded by `limit`.
async fn exchange_raw(address: &HubAddress, tls: &Arc<ClientConfig>, path: &str, bearer: Option<&str>, body: &Value, wait: Duration, limit: usize) -> Result<(StatusCode, header::HeaderMap, Bytes), String> {
    let mut request = Request::builder().uri(path).method("POST").header(header::CONTENT_TYPE, "application/json");
    if let Some(bearer) = bearer {
        request = request.header(header::AUTHORIZATION, format!("Bearer {bearer}"));
    }
    let request = request.body(Full::new(Bytes::from(body.to_string()))).map_err(|error| error.to_string())?;
    let response = net::send(address, tls, request, wait).await?;
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = tokio::time::timeout(wait, http_body_util::Limited::new(response.into_body(), limit).collect())
        .await
        .map_err(|_| "The grid hub's answer was interrupted")?
        .map_err(|_| "The grid hub's answer was interrupted")?
        .to_bytes();
    Ok((status, headers, bytes))
}

/// Takes up a membership the hub made ahead of time (`Hub::preregister_member`): the hub is
/// found at `address`, its certificate pinned by `fingerprint`, and the token proves this
/// computer is the one the membership was made for. No password is involved.
pub async fn adopt(company: &str, address: impl Into<HubAddress>, fingerprint: &str, member_id: &str, token: &str) -> Result<Joined, String> {
    let address = address.into();
    let expected = net::normalize_fingerprint(fingerprint).ok_or("The fingerprint must be the hub's SHA-256 fingerprint (64 hex digits)")?;
    if !is_token(token) || member_id.is_empty() || member_id.len() > 64 {
        return Err("The membership is incomplete".into());
    }
    let (capture, seen) = net::capturing_config()?;
    let (status, hello) = exchange(&address, &capture, "/grid/v1/hello", None, None, Duration::from_secs(20)).await?;
    let certificate = seen.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).take().ok_or("The hub did not present a certificate")?;
    if status != StatusCode::OK {
        return Err(format!("{address} is not a Closed Neo Grid hub"));
    }
    let print = net::fingerprint_der(&certificate);
    if expected != print {
        return Err(format!("The hub's certificate fingerprint is {print}, not the one in the membership. Do not join; ask the admin."));
    }
    let grid_name = hello["name"].as_str().unwrap_or_default().to_owned();
    if !grid_name.trim().eq_ignore_ascii_case(company.trim()) {
        return Err(format!("The hub at {address} belongs to '{grid_name}', not '{company}'"));
    }
    let pem = net::certificate_pem(&certificate);
    let tls = net::client_config(&pem)?;
    let membership = Membership { address, member_id: member_id.to_owned(), token: token.to_owned(), tls };
    // The first check-in proves the token; a hub that does not know it answers 401.
    let instructions = membership.heartbeat("adopt", false, &[]).await.map_err(|error| error.to_string())?;
    Ok(Joined {
        membership,
        token: token.to_owned(),
        grid_id: hello["gridId"].as_str().unwrap_or_default().to_owned(),
        grid_name,
        certificate: pem,
        fingerprint: print,
        assignment: instructions.assignment,
    })
}

/// Joins `company`'s grid at `address`. The password is checked by proof, never sent; the
/// hub's certificate is pinned only after the hub proves that it knows the password too.
/// `fingerprint` optionally pins the certificate the admin read out in advance.
pub async fn join(company: &str, address: impl Into<HubAddress>, secret: &str, name: &str, platform: &str, capable: bool, fingerprint: Option<&str>) -> Result<Joined, String> {
    let address = address.into();
    if let HubAddress::Direct(direct) = &address {
        if !net::private(direct.ip()) || direct.port() == 0 {
            return Err("The hub must be on a private LAN or VPN address such as 10.0.0.5, or reached through its tunnel".into());
        }
    }
    let expected = fingerprint.map(|text| net::normalize_fingerprint(text).ok_or("--fingerprint must be the hub's SHA-256 fingerprint (64 hex digits)")).transpose()?;
    let (capture, seen) = net::capturing_config()?;
    let (status, hello) = exchange(&address, &capture, "/grid/v1/hello", None, None, Duration::from_secs(20)).await?;
    let certificate = seen.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).take().ok_or("The hub did not present a certificate")?;
    if status != StatusCode::OK {
        return Err(format!("{address} is not a Closed Neo Grid hub"));
    }
    let print = net::fingerprint_der(&certificate);
    if expected.as_ref().is_some_and(|expected| *expected != print) {
        return Err(format!("The hub's certificate fingerprint is {print}, not the one you gave. Do not join; ask the admin."));
    }
    let grid_name = hello["name"].as_str().unwrap_or_default().to_owned();
    if !grid_name.trim().eq_ignore_ascii_case(company.trim()) {
        return Err(format!("The hub at {address} belongs to '{grid_name}', not '{company}'"));
    }
    let salt = hello["salt"].as_str().filter(|salt| !salt.is_empty() && salt.len() <= 128).ok_or("The hub sent an invalid answer")?.to_owned();
    let secret = secret.to_owned();
    let key = tokio::task::spawn_blocking(move || password::derive(&secret, &salt)).await.map_err(|error| error.to_string())??;
    let nonce = crate::token();
    let proof = password::prove(&key, "member", &print, &nonce, "");
    // Join over a connection pinned to the certificate seen above.
    let pem = net::certificate_pem(&certificate);
    let tls = net::client_config(&pem)?;
    let body = json!({"nonce": nonce, "proof": proof, "name": name, "platform": platform, "capable": capable});
    let (status, value) = exchange(&address, &tls, "/grid/v1/join", None, Some(&body), Duration::from_secs(20)).await?;
    if status != StatusCode::OK {
        return Err(message(&value, "The hub refused to let this computer join"));
    }
    let member_id = value["memberId"].as_str().filter(|id| !id.is_empty() && id.len() <= 64).ok_or("The hub sent an invalid answer")?.to_owned();
    if !password::verify(&key, "hub", &print, &nonce, &member_id, value["proof"].as_str().unwrap_or_default()) {
        return Err("The hub could not prove that it knows the company password. Do not trust it; ask the admin.".into());
    }
    let token = value["memberToken"].as_str().filter(|token| is_token(token)).ok_or("The hub sent an invalid answer")?.to_owned();
    Ok(Joined {
        membership: Membership { address, member_id, token: token.clone(), tls },
        token,
        grid_id: value["grid"]["id"].as_str().unwrap_or_default().to_owned(),
        grid_name,
        certificate: pem,
        fingerprint: print,
        assignment: assignment(&value["assignment"]),
    })
}

/// One answer from a check-in: the admin's current instructions for this computer.
pub struct Instructions {
    pub assignment: Option<Assignment>,
    pub grid_name: String,
    /// The desks this computer hosts; one missing from here is dropped.
    pub desks: Vec<DeskOrder>,
    /// The admin scheduled the grid for deletion at this time: until then it is paused, and
    /// nothing it put on this computer is removed, so a restore brings it straight back.
    pub paused_until: Option<i64>,
    /// Bucket credentials for a desk this computer is packing or unpacking right now:
    /// `{provider, location, accessKey, secretKey}`. Used at once, never saved.
    pub parking: Option<Value>,
}

/// A person signed in to their grid: who they are and the desks they may open.
#[derive(Debug)]
pub struct PersonSession {
    pub person_id: String,
    pub admin_role: crate::enterprise::AdminRole,
    pub session: DeskSession,
    pub name: String,
    pub grid_id: String,
    pub grid_name: String,
    /// Each desk as the hub shows it, with `invitation` when it can be opened now.
    pub desks: Vec<Value>,
}

/// Signs a person in to the grid an invite names, over a connection pinned to the hub's
/// certificate from the invite. The password's derived key, never the password, crosses that
/// pinned connection, and the hub keeps only its hash.
pub async fn person_login(invite: &Invite, username: &str, password: &str, code: Option<&str>) -> Result<PersonSession, String> {
    let username = crate::desks::username(username)?;
    let (pem, grid_name) = pinned_hello(invite).await?;
    let tls = net::client_config(&pem)?;
    let (status, value) = exchange(&invite.address, &tls, "/grid/v1/person/salt", None, Some(&json!({"username": username})), Duration::from_secs(20)).await?;
    if status != StatusCode::OK {
        return Err(message(&value, "The hub refused the sign-in"));
    }
    let salt = value["salt"].as_str().filter(|salt| !salt.is_empty() && salt.len() <= 128).ok_or("The hub sent an invalid answer")?.to_owned();
    let secret = password.to_owned();
    let key = tokio::task::spawn_blocking(move || password::derive(&secret, &salt)).await.map_err(|error| error.to_string())??;
    let (status, value) = exchange(&invite.address, &tls, "/grid/v1/person/login", None, Some(&json!({"username": username, "key": key, "code": code})), Duration::from_secs(20)).await?;
    if status == StatusCode::UNAUTHORIZED && value["error"]["code"] == "mfa_required" {
        return Err(crate::MFA_REQUIRED.into());
    }
    if status != StatusCode::OK {
        return Err(message(&value, "The hub refused the sign-in"));
    }
    session_from(&value, invite, pem, grid_name)
}

/// Opens a connection whose body this computer keeps writing to and whose answer it keeps
/// reading: one relayed desk session, carried by the hub.
async fn stream_request(address: &HubAddress, tls: &Arc<ClientConfig>, path: &str, bearer: Option<&str>) -> Result<crate::relay::Stream, String> {
    use http_body_util::{BodyExt, StreamBody};
    let (sending, sent) = tokio::sync::mpsc::channel(crate::relay::WINDOW);
    let stream = futures_util::stream::unfold(sent, |mut sent| async move { sent.recv().await.map(|item| (item, sent)) });
    let mut request = Request::builder().uri(path).method("POST").header(header::CONTENT_TYPE, "application/octet-stream");
    if let Some(bearer) = bearer {
        request = request.header(header::AUTHORIZATION, format!("Bearer {bearer}"));
    }
    let request = request.body(StreamBody::new(stream).boxed_unsync()).map_err(|error| error.to_string())?;
    let response = net::send(address, tls, request, Duration::from_secs(30)).await?;
    let status = response.status();
    if status != StatusCode::OK {
        let bytes = http_body_util::Limited::new(response.into_body(), 4096).collect().await.map_err(|_| "The grid hub's answer was interrupted")?.to_bytes();
        let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        return Err(message(&value, "The grid hub refused to carry this desk session"));
    }
    Ok(crate::relay::Stream::new(response.into_body(), sending))
}

/// How long a host waits on a held connection before opening another.
pub const RELAY_HOLD: Duration = Duration::from_secs(70);

impl Membership {
    /// Offers the hub a connection it can use to carry one desk session to this computer, and
    /// waits on it. Answers with the desk the hub joined to it, and the session's bytes.
    pub async fn hold_desk_relay(&self) -> Result<(String, crate::relay::Stream), String> {
        let mut stream = stream_request(&self.address, &self.tls, "/grid/v1/desks/relay/host", Some(&self.token)).await?;
        let desk = tokio::time::timeout(RELAY_HOLD, crate::relay::read_line(&mut stream, 128))
            .await
            .map_err(|_| "No desk session arrived".to_owned())??;
        let desk = desk.trim().to_owned();
        if desk.is_empty() || desk.len() > 64 || !desk.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-') {
            return Err("The hub named an invalid desk".into());
        }
        Ok((desk, stream))
    }
}

impl DeskSession {
    /// One request to a desk, carried by the hub: the desk's own TLS, pinned to the certificate
    /// in its invitation, is negotiated inside the relayed connection, so the hub passes bytes
    /// it cannot read. Answers with the status and the parsed body.
    pub async fn desk_request(&self, desk: &str, address: &str, certificate: &str, token: &str, body: &Value, wait: Duration) -> Result<(u16, Value), String> {
        use tokio_rustls::rustls::pki_types::ServerName;
        let relayed = self.open_desk(desk).await?;
        let address: std::net::SocketAddr = address.parse().map_err(|_| "The desk's address is invalid")?;
        let tls = net::client_config(certificate)?;
        let name = ServerName::IpAddress(address.ip().into());
        let stream = tokio::time::timeout(Duration::from_secs(20), tokio_rustls::TlsConnector::from(tls).connect(name, relayed))
            .await
            .map_err(|_| "The desk did not answer through the grid in time".to_owned())?
            .map_err(|_| "The desk's certificate changed; ask your admin for a new invitation".to_owned())?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.map_err(|error| error.to_string())?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let request = Request::builder()
            .method("POST")
            .uri("/rpc")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Full::new(Bytes::from(body.to_string())))
            .map_err(|error| error.to_string())?;
        let response = tokio::time::timeout(wait, sender.send_request(request))
            .await
            .map_err(|_| "The desk did not answer through the grid in time".to_owned())?
            .map_err(|error| error.to_string())?;
        let status = response.status().as_u16();
        let bytes = tokio::time::timeout(wait, http_body_util::Limited::new(response.into_body(), 8 * 1024 * 1024).collect())
            .await
            .map_err(|_| "The desk's answer through the grid was cut short".to_owned())?
            .map_err(|_| "The desk's answer exceeds 8 MiB or was interrupted".to_owned())?
            .to_bytes();
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| "Invalid response from the desk")?;
        Ok((status, value))
    }

    /// Opens `desk` through the hub, from wherever this computer is: the bytes of the desk's own
    /// pinned TLS travel inside, so the hub carries the session without reading it.
    pub async fn open_desk(&self, desk: &str) -> Result<crate::relay::Stream, String> {
        if self.expires_at <= crate::now() {
            return Err("Sign in again; your desk session expired".into());
        }
        if desk.is_empty() || desk.len() > 64 || !desk.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-') {
            return Err("Invalid desk".into());
        }
        let tls = net::client_config(&self.certificate)?;
        stream_request(&HubAddress::parse(&self.address)?, &tls, &format!("/grid/v1/desks/relay/open?desk={desk}"), Some(&self.token)).await
    }
}

/// The hub's certificate (PEM), checked against the invite's fingerprint, and the grid's name.
async fn pinned_hello(invite: &Invite) -> Result<(String, String), String> {
    let (capture, seen) = net::capturing_config()?;
    let (status, hello) = exchange(&invite.address, &capture, "/grid/v1/hello", None, None, Duration::from_secs(20)).await?;
    let certificate = seen.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).take().ok_or("The hub did not present a certificate")?;
    if status != StatusCode::OK {
        return Err(format!("{} is not a Closed Neo Grid hub", invite.address));
    }
    let print = net::fingerprint_der(&certificate);
    if print != invite.fingerprint {
        return Err(format!("The hub's certificate fingerprint is {print}, not the one in the invite. Do not sign in; ask the admin."));
    }
    let grid_name = hello["name"].as_str().unwrap_or_default().to_owned();
    if !grid_name.trim().eq_ignore_ascii_case(invite.company.trim()) {
        return Err(format!("The hub belongs to '{grid_name}', not '{}'", invite.company));
    }
    Ok((net::certificate_pem(&certificate), grid_name))
}

fn session_from(value: &Value, invite: &Invite, pem: String, grid_name: String) -> Result<PersonSession, String> {
    let person_id = value["personId"].as_str().filter(|id| !id.is_empty() && id.len() <= 64).ok_or("The hub sent an invalid answer")?.to_owned();
    Ok(PersonSession {
        person_id,
        admin_role: serde_json::from_value(value["adminRole"].clone()).unwrap_or_default(),
        session: DeskSession { address: invite.address.to_string(), certificate: pem, token: value["sessionToken"].as_str().ok_or("Hub did not issue a desk session")?.to_owned(), expires_at: value["sessionExpiresAt"].as_i64().unwrap_or_default() },
        name: value["name"].as_str().unwrap_or_default().to_owned(),
        grid_id: value["grid"]["id"].as_str().unwrap_or_default().to_owned(),
        grid_name,
        desks: value["desks"].as_array().cloned().unwrap_or_default(),
    })
}

/// Whether the grid signs people in through an identity provider, and where: what the hub
/// publishes for a person's computer, over the pinned connection.
pub async fn sso_config(invite: &Invite) -> Result<Option<Value>, String> {
    let (pem, _) = pinned_hello(invite).await?;
    let tls = net::client_config(&pem)?;
    let (status, value) = exchange(&invite.address, &tls, "/grid/v1/person/sso", None, None, Duration::from_secs(30)).await?;
    if status == StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if status != StatusCode::OK {
        return Err(message(&value, "The hub could not reach the identity provider"));
    }
    Ok(Some(value))
}

/// How long the person has to finish signing in at the provider in their browser.
const BROWSER_WAIT: Duration = Duration::from_secs(5 * 60);

/// Signs a person in through the company's identity provider: the browser goes to the provider
/// (`open` is given the address), which sends it back to this computer with a code; the code is
/// exchanged for an ID token with the PKCE verifier only this process knows, and the token goes
/// to the hub over the pinned connection. No password and no client secret are involved.
pub async fn person_login_sso(invite: &Invite, open: impl FnOnce(&str) -> Result<(), String>) -> Result<PersonSession, String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use sha2::{Digest, Sha256};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (pem, grid_name) = pinned_hello(invite).await?;
    let tls = net::client_config(&pem)?;
    let (status, config) = exchange(&invite.address, &tls, "/grid/v1/person/sso", None, None, Duration::from_secs(30)).await?;
    if status == StatusCode::NOT_FOUND {
        return Err("This grid does not sign people in through an identity provider; sign in with your username and password".into());
    }
    if status != StatusCode::OK {
        return Err(message(&config, "The hub could not reach the identity provider"));
    }
    let (authorization, token_endpoint, client_id) = (config["authorizationEndpoint"].as_str().unwrap_or_default().to_owned(), config["tokenEndpoint"].as_str().unwrap_or_default().to_owned(), config["clientId"].as_str().unwrap_or_default().to_owned());
    if !authorization.starts_with("http") || !token_endpoint.starts_with("http") || client_id.is_empty() {
        return Err("The hub's sign-in setup is incomplete".into());
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.map_err(|error| format!("Cannot wait for the browser: {error}"))?;
    let redirect = format!("http://127.0.0.1:{}/callback", listener.local_addr().map_err(|error| error.to_string())?.port());
    let (verifier, state, nonce) = (crate::token(), crate::token(), crate::token());
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let url = format!("{authorization}{}response_type=code&client_id={}&redirect_uri={}&scope={}&state={state}&nonce={nonce}&code_challenge={challenge}&code_challenge_method=S256", if authorization.contains('?') { "&" } else { "?" }, crate::https::encode(&client_id), crate::https::encode(&redirect), crate::https::encode("openid email profile"));
    open(&url)?;
    // One visit from the browser: the provider sends it back here with the code and the state.
    let code = tokio::time::timeout(BROWSER_WAIT, async {
        loop {
            let (mut socket, _) = listener.accept().await.map_err(|error| error.to_string())?;
            let mut buffer = vec![0u8; 8192];
            let read = socket.read(&mut buffer).await.map_err(|error| error.to_string())?;
            let request = String::from_utf8_lossy(&buffer[..read]).into_owned();
            let line = request.lines().next().unwrap_or_default();
            let path = line.split_whitespace().nth(1).unwrap_or_default();
            let query = path.split_once('?').map(|(_, query)| query).unwrap_or_default();
            let fields = crate::https::fields(query);
            let get = |name: &str| fields.iter().find(|(key, _)| key == name).map(|(_, value)| value.clone()).unwrap_or_default();
            if !path.starts_with("/callback") {
                let _ = socket.write_all(b"HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").await;
                continue;
            }
            let outcome = if get("state") != state {
                Err("The sign-in that came back is not the one that was started".to_owned())
            } else if !get("error").is_empty() {
                Err(format!("The identity provider refused the sign-in: {} {}", get("error"), get("error_description")))
            } else if get("code").is_empty() {
                Err("The identity provider sent no code".to_owned())
            } else {
                Ok(get("code"))
            };
            let page = match &outcome {
                Ok(_) => "<!doctype html><title>Signed in</title><body style=\"font-family:system-ui;padding:40px\"><h1>Signed in</h1><p>You can close this window and go back to Yougori.</p></body>",
                Err(_) => "<!doctype html><title>Sign-in failed</title><body style=\"font-family:system-ui;padding:40px\"><h1>Sign-in failed</h1><p>Go back to Yougori; it says what went wrong.</p></body>",
            };
            let _ = socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{page}", page.len()).as_bytes()).await;
            let _ = socket.shutdown().await;
            return outcome;
        }
    })
    .await
    .map_err(|_| "The sign-in in the browser was not finished in time".to_owned())??;
    let answer = crate::https::form(&token_endpoint, &[("grant_type", "authorization_code"), ("code", &code), ("redirect_uri", &redirect), ("client_id", &client_id), ("code_verifier", &verifier)], &[], Duration::from_secs(30)).await?;
    if !answer.ok() {
        return Err(format!("The identity provider refused to issue a token ({})", answer.said()));
    }
    let id_token = answer.json()["id_token"].as_str().map(str::to_owned).ok_or("The identity provider issued no ID token; the app must be registered with OpenID Connect")?;
    let (status, value) = exchange(&invite.address, &tls, "/grid/v1/person/sso", None, Some(&json!({"idToken": id_token, "nonce": nonce})), Duration::from_secs(30)).await?;
    if status != StatusCode::OK {
        return Err(message(&value, "The hub refused the sign-in"));
    }
    session_from(&value, invite, pem, grid_name)
}

/// The token is stored only in the client's credential vault, never in status output.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeskSession { pub address: String, pub certificate: String, pub token: String, pub expires_at: i64 }
impl std::fmt::Debug for DeskSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.debug_struct("DeskSession").field("expires_at", &self.expires_at).finish_non_exhaustive() }
}
impl DeskSession {
    pub async fn manage(&self, request: Value) -> Result<Value, String> {
        if self.expires_at <= crate::now() { return Err("Sign in again; your desk session expired".into()); }
        let tls = net::client_config(&self.certificate)?;
        let (status, value) = exchange(&HubAddress::parse(&self.address)?, &tls, "/grid/v1/desks/manage", Some(&self.token), Some(&request), Duration::from_secs(30)).await?;
        if !status.is_success() { return Err(message(&value, "Desk management was refused")); }
        Ok(value)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Served { status: u16 },
    /// Handed back so another computer can run it.
    Released(String),
    /// The app that sent the request left before it started.
    Cancelled,
    Failed(String),
}

pub struct Job {
    pub id: String,
    pub request: Value,
}

impl Membership {
    /// A saved membership; `certificate` is the hub's pinned certificate.
    pub fn new(address: impl Into<HubAddress>, certificate: &str, member_id: String, token: String) -> Result<Self, String> {
        Ok(Self { address: address.into(), member_id, token, tls: net::client_config(certificate)? })
    }

    async fn call(&self, path: &str, body: &Value, wait: Duration) -> Result<(StatusCode, Value), MemberError> {
        let (status, value) = exchange(&self.address, &self.tls, path, Some(&self.token), Some(body), wait).await.map_err(MemberError::Failed)?;
        if status == StatusCode::UNAUTHORIZED {
            return Err(MemberError::Removed);
        }
        if status == StatusCode::GONE && value["error"]["code"] == "grid_deleted" {
            return Err(MemberError::Deleted);
        }
        Ok((status, value))
    }

    /// A piece of a prepared image the hub holds, for a host assigned a desk that uses it: raw
    /// bytes from `offset`, up to `enterprise::IMAGE_PIECE`, with the image's full size.
    pub async fn desk_image_bytes(&self, sha256: &str, offset: u64) -> Result<(u64, Bytes), String> {
        let body = json!({"sha256": sha256, "offset": offset});
        let (status, headers, bytes) = exchange_raw(&self.address, &self.tls, "/grid/v1/desks/image", Some(&self.token), &body, Duration::from_secs(120), crate::enterprise::IMAGE_PIECE).await?;
        if !status.is_success() {
            let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
            return Err(message(&value, "Image access refused"));
        }
        let size = headers.get("x-image-size").and_then(|value| value.to_str().ok()).and_then(|value| value.parse::<u64>().ok()).ok_or("The hub sent no image size")?;
        Ok((size, bytes))
    }

    /// Sends a piece of a desk's packed-up data to the hub, which holds it until the computer
    /// that takes the desk over fetches it. `last` names the final piece.
    pub async fn desk_parcel_put(&self, desk: &str, offset: u64, bytes: Vec<u8>, last: bool) -> Result<(), String> {
        let request = Request::post("/grid/v1/desks/parcel")
            .header(header::AUTHORIZATION, format!("Bearer {}", self.token))
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header("x-desk", desk)
            .header("x-offset", offset.to_string())
            .header("x-parcel-complete", if last { "1" } else { "0" })
            .body(Full::new(Bytes::from(bytes)))
            .map_err(|error| error.to_string())?;
        let response = net::send(&self.address, &self.tls, request, Duration::from_secs(180)).await?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let bytes = http_body_util::Limited::new(response.into_body(), 8192).collect().await.map(|body| body.to_bytes()).unwrap_or_default();
        Err(message(&serde_json::from_slice(&bytes).unwrap_or(Value::Null), "The hub did not take the desk's data"))
    }

    /// Reads a piece of a desk's packed-up data from the hub, with the whole size.
    pub async fn desk_parcel_get(&self, desk: &str, offset: u64) -> Result<(u64, Bytes), String> {
        let body = json!({"desk": desk, "offset": offset});
        let (status, headers, bytes) = exchange_raw(&self.address, &self.tls, "/grid/v1/desks/parcel/fetch", Some(&self.token), &body, Duration::from_secs(180), crate::enterprise::IMAGE_PIECE).await?;
        if !status.is_success() {
            return Err(message(&serde_json::from_slice(&bytes).unwrap_or(Value::Null), "The hub did not give the desk's data"));
        }
        let size = headers.get("x-parcel-size").and_then(|value| value.to_str().ok()).and_then(|value| value.parse::<u64>().ok()).ok_or("The hub sent no parcel size")?;
        Ok((size, bytes))
    }

    pub async fn desk_lease(&self, desk: &str, person: &str, generation: u64) -> Result<(), String> {
        let (status, value) = self.call("/grid/v1/desks/lease", &json!({"deskId":desk,"personId":person,"generation":generation}), Duration::from_secs(10)).await.map_err(|e|e.to_string())?;
        if status.is_success() && value["authorized"] == true { Ok(()) } else { Err(message(&value,"Desk access was revoked")) }
    }

    pub async fn heartbeat(&self, app_version: &str, capable: bool, models: &[ModelReport]) -> Result<Instructions, MemberError> {
        self.ask(app_version, capable, models, None, &[], false).await
    }

    /// A check-in that also says what this computer can host and how its desks are doing.
    pub async fn check_in(&self, app_version: &str, capable: bool, models: &[ModelReport], capacity: Option<&Capacity>, desks: &[DeskReport]) -> Result<Instructions, MemberError> {
        self.ask(app_version, capable, models, capacity, desks, true).await
    }

    /// One check-in. `reads_desks` says whether this computer acts on desk orders at all: a
    /// member that hosts no desks never looks at them, so it must not be stopped by an answer
    /// about desks it would ignore either way.
    async fn ask(&self, app_version: &str, capable: bool, models: &[ModelReport], capacity: Option<&Capacity>, desks: &[DeskReport], reads_desks: bool) -> Result<Instructions, MemberError> {
        let body = json!({"appVersion": app_version, "capable": capable, "models": models, "capacity": capacity, "desks": desks});
        let (status, value) = self.call("/grid/v1/heartbeat", &body, Duration::from_secs(20)).await?;
        if !status.is_success() {
            return Err(MemberError::Failed(message(&value, "The grid hub refused this computer's report")));
        }
        // The same rule one line up, for the same reason. `assignment` used to swallow anything
        // it could not parse into None, and on a model grid `apply(None)` stops the worker and
        // retires the model environment — deleted with its weights when the grid created it. So
        // a hub that changed the shape of an assignment made every older member delete its
        // model. Absent or null still means none; present and unreadable is a refusal.
        let assignment = match value.get("assignment").filter(|found| !found.is_null()) {
            Some(found) => Some(assignment(found).ok_or_else(|| {
                MemberError::Unreadable("This grid's hub sent a model assignment this version of Yougori cannot read. The model on this computer is untouched, but it serves nothing for the grid until Yougori is updated here.".into())
            })?),
            None => None,
        };
        let desks = if reads_desks { orders_in(&value)? } else { Vec::new() };
        let paused_until = value["closing"]["until"].as_i64().filter(|_| value["closing"]["gone"] != true);
        let parking = value.get("parking").filter(|parking| parking.is_object()).cloned();
        Ok(Instructions { assignment, grid_name: value["grid"]["name"].as_str().unwrap_or_default().to_owned(), desks, paused_until, parking })
    }

    pub async fn leave(&self) -> Result<(), MemberError> {
        match self.call("/grid/v1/leave", &json!({}), Duration::from_secs(20)).await {
            Ok(_) | Err(MemberError::Removed | MemberError::Deleted) => Ok(()),
            Err(error) => Err(error),
        }
    }

    pub async fn next_job(&self, models: &[String]) -> Result<Option<Job>, MemberError> {
        let (status, value) = self.call("/grid/v1/work", &json!({"models": models}), POLL + Duration::from_secs(15)).await?;
        match status {
            StatusCode::NO_CONTENT => Ok(None),
            StatusCode::OK => {
                let id = value["jobId"].as_str().filter(|id| id.len() <= 64 && id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'));
                match (id, value["request"].is_object()) {
                    (Some(id), true) => Ok(Some(Job { id: id.to_owned(), request: value["request"].clone() })),
                    _ => Err(MemberError::Failed("The grid hub sent an invalid job".into())),
                }
            }
            _ => Err(MemberError::Failed(message(&value, "The grid hub refused to hand out work"))),
        }
    }

    async fn accept(&self, job: &str) -> Result<bool, MemberError> {
        let (status, _) = self.call(&format!("/grid/v1/jobs/{job}/accept"), &json!({}), Duration::from_secs(20)).await?;
        Ok(status == StatusCode::NO_CONTENT)
    }

    async fn release(&self, job: &str) {
        let _ = self.call(&format!("/grid/v1/jobs/{job}/release"), &json!({}), Duration::from_secs(20)).await;
    }

    async fn respond(&self, job: &str, status: u16, content_type: &str, body: Incoming) -> Result<(), String> {
        let request = Request::post(format!("/grid/v1/jobs/{job}/response"))
            .header(header::AUTHORIZATION, format!("Bearer {}", self.token))
            .header("x-grid-status", status.to_string())
            .header(header::CONTENT_TYPE, content_type)
            .body(body)
            .map_err(|error| error.to_string())?;
        let response = net::send(&self.address, &self.tls, request, GENERATION + Duration::from_secs(60)).await?;
        match response.status() {
            StatusCode::NO_CONTENT => Ok(()),
            StatusCode::GONE => Err("The app that sent this request left before the reply finished".into()),
            status => Err(format!("The grid hub refused the reply (HTTP {status})")),
        }
    }
}

/// Sends the request to the local model server over `local`.
async fn ask(local: LocalModel, request: &Value) -> Result<Response<Incoming>, String> {
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(local.io)).await.map_err(|_| "Cannot talk to the local model server".to_owned())?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let body = serde_json::to_vec(request).map_err(|error| error.to_string())?;
    let request = Request::post("/v1/chat/completions")
        .header(header::HOST, "localhost")
        .header(header::AUTHORIZATION, format!("Bearer {}", local.api_key))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))
        .map_err(|error| error.to_string())?;
    tokio::time::timeout(GENERATION, sender.send_request(request))
        .await
        .map_err(|_| "The local model did not answer in time".to_owned())?
        .map_err(|_| "The local model server closed the connection".to_owned())
}

/// Confirms the job, runs it on the local model and streams the reply to the hub. A model
/// that is busy (for example with its person's own chat) or unreachable hands the job back.
pub async fn run_job<F: Future<Output = Result<LocalModel, String>>>(membership: &Membership, job: Job, local: F) -> Outcome {
    match membership.accept(&job.id).await {
        Ok(true) => {}
        Ok(false) => return Outcome::Cancelled,
        Err(error) => return Outcome::Failed(error.to_string()),
    }
    let response = match local.await {
        Ok(local) => ask(local, &job.request).await,
        Err(error) => Err(error),
    };
    let response = match response {
        Ok(response) if !matches!(response.status(), StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE) => response,
        Ok(response) => {
            membership.release(&job.id).await;
            return Outcome::Released(format!("The local model answered HTTP {}", response.status()));
        }
        Err(error) => {
            membership.release(&job.id).await;
            return Outcome::Released(error);
        }
    };
    let status = response.status().as_u16();
    let content_type = response.headers().get(header::CONTENT_TYPE).and_then(|value| value.to_str().ok()).unwrap_or("application/json").to_owned();
    match membership.respond(&job.id, status, &content_type, response.into_body()).await {
        Ok(()) => Outcome::Served { status },
        Err(error) => Outcome::Failed(error),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum WorkerEvent {
    Started,
    Finished(Outcome),
    Removed,
    Error(String),
}

/// Serves `model` while `gate` is true and returns when the gate's sender is dropped. A
/// request already running when the gate closes is finished; no new one is taken.
pub async fn serve<C, F, E>(membership: Membership, model: String, mut gate: watch::Receiver<bool>, connect: C, events: E)
where
    C: Fn() -> F + Send,
    F: Future<Output = Result<LocalModel, String>> + Send,
    E: Fn(WorkerEvent) + Send + Sync,
{
    let models = [model_key(&model)];
    loop {
        while !*gate.borrow_and_update() {
            if gate.changed().await.is_err() {
                return;
            }
        }
        let job = tokio::select! {
            changed = gate.changed() => {
                if changed.is_err() {
                    return;
                }
                continue;
            }
            job = membership.next_job(&models) => job,
        };
        match job {
            Ok(Some(job)) => {
                events(WorkerEvent::Started);
                let outcome = run_job(&membership, job, connect()).await;
                events(WorkerEvent::Finished(outcome));
            }
            Ok(None) => {}
            Err(MemberError::Removed | MemberError::Deleted) => {
                events(WorkerEvent::Removed);
                return;
            }
            // Both wait the same way here: the work loop has nothing to decide about why the
            // hub's answer was no good, only that it should not spin.
            Err(MemberError::Unreadable(error) | MemberError::Failed(error)) => {
                events(WorkerEvent::Error(error));
                tokio::select! {
                    changed = gate.changed() => if changed.is_err() { return },
                    _ = tokio::time::sleep(Duration::from_secs(10)) => {}
                }
            }
        }
    }
}

pub fn platform() -> &'static str {
    std::env::consts::OS
}

/// The desk orders in a hub's answer, or why this computer must not act on it.
///
/// An answer this computer cannot read is a failed check-in, never an empty list of desks. These
/// are strict enums with no fallback, and the caller treats a desk the hub did not mention as one
/// to delete along with its data — so a hub that gained a single new kind, access or store value
/// would have emptied every desk on every computer that had not been updated yet. Absence is the
/// same: the hub always sends this field, so its absence means the answer did not come from a hub
/// that understands this protocol, which is also what a 2xx body that is not JSON looks like.
pub(crate) fn orders_in(value: &Value) -> Result<Vec<DeskOrder>, MemberError> {
    match value.get("desks").filter(|desks| !desks.is_null()) {
        Some(desks) => serde_json::from_value(desks.clone()).map_err(|_| {
            MemberError::Unreadable("This grid's hub sent desk orders this version of Yougori cannot read. The desks on this computer and their data are untouched, but nobody can open them from here until Yougori is updated on this computer.".into())
        }),
        None => Err(MemberError::Unreadable(
            "This grid's hub did not say what this computer's desks should be doing. They and their data are untouched, but nobody can open them from here until this is settled; if it keeps happening, update Yougori on this computer and on the hub.".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_answer_nobody_could_read_stops_a_silence_clock_that_is_already_running() {
        // The ordinary sequence that produced this: the hub restarts for an upgrade, so one
        // check-in fails and starts the clock; every answer after that is in words this build
        // cannot read. Not starting a clock on an unreadable answer was never enough on its own,
        // because this one was already running — and seven days later the page and the CLI told
        // somebody the hub had not answered and to leave the grid, over a hub that was answering
        // the whole time. Leaving unshares every desk on the computer.
        let started = silence_clock(false, None, 100);
        assert_eq!(started, Some(100), "silence starts the clock");
        assert_eq!(silence_clock(false, started, 500), Some(100), "counted from the first silence, never restarted");
        assert_eq!(silence_clock(true, started, 500), None, "an answer stops a clock already running");
        assert_eq!(silence_clock(true, None, 500), None, "and never starts one");
    }

    /// PROVES that a hub answer this computer cannot read fails the check-in, instead of reading
    /// as "this computer has no desks".
    ///
    /// The caller deletes a hosted desk, with its data, when the hub's answer does not mention
    /// it. So every way that answer can be wrong becomes a delete. `DeskKind`, `DeskAccess` and
    /// `ParcelStore` are strict enums with no fallback, and the list was parsed with
    /// `unwrap_or_default`, so ONE order carrying a value this build did not know emptied the
    /// whole list — meaning a hub that gained a single new variant would have wiped every desk
    /// on every computer that had not been updated yet. A 2xx body that is not JSON arrives as
    /// Null and did the same thing.
    #[test]
    fn an_answer_this_computer_cannot_read_is_a_failed_check_in_not_an_empty_grid() {
        let order = |kind: &str| serde_json::json!({"desks": [{
            "id": "desk-1", "name": "Design", "personName": "Ada", "needsInvitation": false,
            "park": false, "parkIn": "hub", "generation": 1,
            "spec": {"kind": kind, "cpu": 2.0, "memoryGb": 8.0, "diskGb": 40.0, "gpu": false, "image": ""}
        }]});

        // A kind this build knows reads normally.
        assert_eq!(orders_in(&order("container")).map(|desks| desks.len()), Ok(1));

        // One it does not know fails the whole check-in rather than emptying the list.
        let refused = orders_in(&order("holographic")).unwrap_err();
        assert!(matches!(refused, MemberError::Unreadable(ref said) if said.contains("cannot read")), "{refused}");

        // No desks field at all, and an answer that was not JSON, are the same answer.
        for unreadable in [serde_json::json!({"grid": {"name": "Acme"}}), serde_json::json!({"desks": null}), Value::Null] {
            let refused = orders_in(&unreadable).unwrap_err();
            assert!(matches!(refused, MemberError::Unreadable(_)), "an answer with nothing to read was taken for a grid with no desks");
        }

        // An empty list is still an empty list: a hub that says so is believed.
        assert_eq!(orders_in(&serde_json::json!({"desks": []})).map(|desks| desks.len()), Ok(0));

        // And the other half, which matters just as much: a field this build has never heard of
        // must still read. Every additive change a hub makes arrives looking exactly like this,
        // and the day somebody adds `deny_unknown_fields` to tidy these up, every grid with a
        // newer hub freezes. The refusal above is for values that cannot be mapped at all, not
        // for the hub having more to say than this version knows about.
        let with_extra = serde_json::json!({"desks": [{
            "id": "desk-1", "name": "Design", "personName": "Ada", "needsInvitation": false,
            "park": false, "parkIn": "hub", "generation": 1, "somethingAddedLater": {"nested": true},
            "spec": {"kind": "container", "cpu": 2.0, "memoryGb": 8.0, "diskGb": 40.0, "gpu": false, "image": "", "alsoNew": 7}
        }]});
        assert_eq!(orders_in(&with_extra).map(|desks| desks.len()), Ok(1), "an order carrying a field this build does not know was refused: {:?}", orders_in(&with_extra).err());
    }

    #[test]
    fn assignments_switch_environments_only_for_another_model() {
        let a = Assignment { plan_id: "p".into(), model: "Acme/Chat".into(), quant: Some("Q4_K_M".into()), idle_after_minutes: 10, schedule: None };
        let mut b = a.clone();
        b.idle_after_minutes = 30;
        b.schedule = Some("Sat-Sun".into());
        assert!(a.same_model(&b), "new rules keep the model");
        b.model = "hf.co/acme/chat".into();
        b.quant = Some("q4_k_m".into());
        assert!(a.same_model(&b));
        b.quant = None;
        assert!(!a.same_model(&b));
        assert_eq!(assignment(&serde_json::to_value(&a).unwrap()), Some(a));
        assert_eq!(assignment(&Value::Null), None);
    }
}
