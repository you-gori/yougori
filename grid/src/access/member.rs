//! A person's computer: signs in to the Access Grid an invite names, then calls it for the
//! person's agents. The password never leaves the computer; its scrypt key crosses a connection
//! pinned to the hub's certificate, and the hub keeps only that key's hash. A sign-in gives the
//! computer a device token, kept in its OS vault, that signs it in again by itself until the
//! person's password changes, two-step is reset or the computer is signed out.
use super::forward;
use crate::{
    invite::Invite,
    net::{self, HubAddress},
    password,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::{header, Request, StatusCode};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use tokio_rustls::rustls::ClientConfig;

const WAIT: Duration = Duration::from_secs(30);
const ANSWER_LIMIT: usize = 4 * 1024 * 1024;
/// A person has this long to finish signing in at their identity provider in the browser.
const BROWSER_WAIT: Duration = Duration::from_secs(5 * 60);
/// What a password sign-in says when the account has two-step sign-in on and no code was given.
pub const TWO_STEP: &str = "Enter the six-digit code from your authenticator app";

/// A fresh sign-in.
#[derive(Clone)]
pub struct SignedIn {
    pub token: String,
    pub expires_at: i64,
    /// Signs this computer in again by itself; only given by a full sign-in.
    pub device_token: Option<String>,
    pub device_id: Option<String>,
    /// Signed in with a second factor.
    pub strong: bool,
    /// The hub's certificate, pinned from now on.
    pub certificate: String,
    pub fingerprint: String,
    pub company: String,
    pub access_id: String,
    pub person: Value,
}

impl std::fmt::Debug for SignedIn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedIn").field("company", &self.company).field("expires_at", &self.expires_at).field("strong", &self.strong).finish_non_exhaustive()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CallError {
    /// The sign-in lapsed or the hub restarted: sign in again with the device token.
    SignedOut,
    /// The admin deleted the grid; the message says whose.
    Deleted(String),
    /// The hub answered with a refusal or an error; the code and message say why.
    Refused { code: String, message: String },
    /// The hub could not be reached.
    Failed(String),
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::SignedOut => write!(f, "Sign in to the Access Grid again"),
            CallError::Deleted(message) | CallError::Refused { message, .. } | CallError::Failed(message) => write!(f, "{message}"),
        }
    }
}

fn message(value: &Value, fallback: &str) -> String {
    value["error"]["message"].as_str().unwrap_or(fallback).to_owned()
}

async fn exchange(address: &HubAddress, tls: &Arc<ClientConfig>, path: &str, bearer: Option<&str>, body: Option<&Value>) -> Result<(StatusCode, Value), String> {
    let mut request = Request::builder().uri(path).method(if body.is_some() { "POST" } else { "GET" });
    if let Some(bearer) = bearer {
        request = request.header(header::AUTHORIZATION, format!("Bearer {bearer}"));
    }
    let response = match body {
        Some(body) => {
            let request = request.header(header::CONTENT_TYPE, "application/json").body(Full::new(Bytes::from(body.to_string()))).map_err(|error| error.to_string())?;
            net::send(address, tls, request, WAIT).await?
        }
        None => net::send(address, tls, request.body(Empty::<Bytes>::new()).map_err(|error| error.to_string())?, WAIT).await?,
    };
    let status = response.status();
    let bytes = tokio::time::timeout(WAIT, http_body_util::Limited::new(response.into_body(), ANSWER_LIMIT).collect())
        .await
        .map_err(|_| "The Access Grid's answer was interrupted")?
        .map_err(|_| "The Access Grid's answer was interrupted")?
        .to_bytes();
    Ok((status, if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap_or(Value::Null) }))
}

fn classify(status: StatusCode, value: &Value) -> CallError {
    let code = value["error"]["code"].as_str().unwrap_or_default().to_owned();
    if status == StatusCode::GONE && code == "access_deleted" {
        return CallError::Deleted(message(value, "The admin deleted this Access Grid"));
    }
    if status == StatusCode::UNAUTHORIZED && code == "signed_out" {
        return CallError::SignedOut;
    }
    CallError::Refused { code, message: message(value, "The Access Grid refused the request") }
}

fn signed(value: &Value, certificate: &str, fingerprint: &str) -> Result<SignedIn, String> {
    let token = value["sessionToken"].as_str().filter(|token| crate::is_token(token)).ok_or("The Access Grid sent an invalid answer")?.to_owned();
    Ok(SignedIn {
        token,
        expires_at: value["expiresAt"].as_i64().unwrap_or_default(),
        device_token: value["deviceToken"].as_str().filter(|token| crate::is_token(token)).map(str::to_owned),
        device_id: value["deviceId"].as_str().map(str::to_owned),
        strong: value["strong"].as_bool().unwrap_or(false),
        certificate: certificate.to_owned(),
        fingerprint: fingerprint.to_owned(),
        company: value["company"].as_str().unwrap_or_default().to_owned(),
        access_id: value["accessId"].as_str().unwrap_or_default().to_owned(),
        person: value["person"].clone(),
    })
}

/// Pins the hub the invite names: its certificate must match the invite's fingerprint and it
/// must belong to the invite's company. Returns the certificate and the hub's greeting.
pub async fn hello(invite: &Invite) -> Result<(String, Value), String> {
    let (capture, seen) = net::capturing_config()?;
    let (status, hello) = exchange(&invite.address, &capture, "/access/v1/hello", None, None).await?;
    let certificate = seen.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).take().ok_or("The Access Grid did not present a certificate")?;
    let print = net::fingerprint_der(&certificate);
    if print != invite.fingerprint {
        return Err(format!("The Access Grid's certificate fingerprint is {print}, not the one in the invite. Do not sign in; ask your admin."));
    }
    if status == StatusCode::GONE {
        return Err(message(&hello, "The admin deleted this Access Grid"));
    }
    if status != StatusCode::OK {
        return Err(format!("{} is not an Access Grid", invite.address));
    }
    let company = hello["company"].as_str().unwrap_or_default().to_owned();
    if !company.trim().eq_ignore_ascii_case(invite.company.trim()) {
        return Err(format!("This Access Grid belongs to '{company}', not '{}'", invite.company));
    }
    Ok((net::certificate_pem(&certificate), hello))
}

/// Signs `username` in with their password (and, with two-step on, the code from their app).
pub async fn signin(invite: &Invite, username: &str, password: &str, code: Option<&str>, computer: &str) -> Result<SignedIn, String> {
    let username = super::policy::username(username)?;
    let (pem, _) = hello(invite).await?;
    let tls = net::client_config(&pem)?;
    let fingerprint = net::fingerprint(&pem)?;
    let (status, value) = exchange(&invite.address, &tls, "/access/v1/salt", None, Some(&json!({"username": username}))).await?;
    if status != StatusCode::OK {
        return Err(message(&value, "The Access Grid refused the sign-in"));
    }
    let salt = value["salt"].as_str().filter(|salt| !salt.is_empty() && salt.len() <= 128).ok_or("The Access Grid sent an invalid answer")?.to_owned();
    let secret = password.to_owned();
    let key = tokio::task::spawn_blocking(move || password::derive(&secret, &salt)).await.map_err(|error| error.to_string())??;
    let (status, value) = exchange(&invite.address, &tls, "/access/v1/signin", None, Some(&json!({"username": username, "key": key, "code": code, "computer": computer}))).await?;
    if status == StatusCode::UNAUTHORIZED && value["error"]["code"] == "two_step_required" {
        return Err(TWO_STEP.into());
    }
    if status != StatusCode::OK {
        return Err(message(&value, "The Access Grid refused the sign-in"));
    }
    signed(&value, &pem, &fingerprint)
}

/// Signs in through the company's identity provider: opens the provider's page in the browser
/// (`open`), waits for it to send the browser back to this computer, trades the code for an ID
/// token (PKCE; no client secret) and brings that token to the hub, which checks it.
pub async fn signin_sso(invite: &Invite, computer: &str, open: impl FnOnce(&str) -> Result<(), String>) -> Result<SignedIn, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (pem, _) = hello(invite).await?;
    let tls = net::client_config(&pem)?;
    let fingerprint = net::fingerprint(&pem)?;
    let (status, config) = exchange(&invite.address, &tls, "/access/v1/sso", None, None).await?;
    if status == StatusCode::NOT_FOUND {
        return Err("This Access Grid does not sign people in through an identity provider; sign in with your username and password".into());
    }
    if status != StatusCode::OK {
        return Err(message(&config, "The Access Grid could not reach the identity provider"));
    }
    let text = |key: &str| config[key].as_str().unwrap_or_default().to_owned();
    let (authorization, token_endpoint, client_id) = (text("authorizationEndpoint"), text("tokenEndpoint"), text("clientId"));
    forward::token_url(&authorization).map_err(|_| "The identity provider's sign-in page is not an https:// address")?;
    if client_id.is_empty() {
        return Err("The Access Grid's sign-in setup is incomplete".into());
    }
    let port = config["redirectPort"].as_u64().and_then(|port| u16::try_from(port).ok()).unwrap_or(0);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await.map_err(|error| format!("Cannot wait for the browser on 127.0.0.1:{port}: {error}"))?;
    let redirect = format!("http://127.0.0.1:{}/callback", listener.local_addr().map_err(|error| error.to_string())?.port());
    let (verifier, state, nonce) = (crate::token(), crate::token(), crate::token());
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let encode = |value: &str| value.bytes().map(|byte| if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) { (byte as char).to_string() } else { format!("%{byte:02X}") }).collect::<String>();
    let url = format!("{authorization}{}response_type=code&client_id={}&redirect_uri={}&scope={}&state={state}&nonce={nonce}&code_challenge={challenge}&code_challenge_method=S256", if authorization.contains('?') { "&" } else { "?" }, encode(&client_id), encode(&redirect), encode("openid email profile"));
    open(&url)?;
    let code = tokio::time::timeout(BROWSER_WAIT, async {
        loop {
            let (mut socket, _) = listener.accept().await.map_err(|error| error.to_string())?;
            let mut buffer = vec![0u8; 8192];
            let read = socket.read(&mut buffer).await.map_err(|error| error.to_string())?;
            let request = String::from_utf8_lossy(&buffer[..read]).into_owned();
            let path = request.lines().next().unwrap_or_default().split_whitespace().nth(1).unwrap_or_default().to_owned();
            if !path.starts_with("/callback") {
                let _ = socket.write_all(b"HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").await;
                continue;
            }
            let query = path.split_once('?').map(|(_, query)| query).unwrap_or_default();
            let get = |name: &str| query.split('&').filter_map(|pair| pair.split_once('=')).find(|(key, _)| *key == name).map(|(_, value)| decode(value)).unwrap_or_default();
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
    let form = [("grant_type", "authorization_code"), ("code", code.as_str()), ("redirect_uri", redirect.as_str()), ("client_id", client_id.as_str()), ("code_verifier", verifier.as_str())].iter().map(|(key, value)| format!("{}={}", encode(key), encode(value))).collect::<Vec<_>>().join("&");
    let answer = forward::fetch("POST", &token_endpoint, &[("content-type", "application/x-www-form-urlencoded".into()), ("accept", "application/json".into())], Some(form.into_bytes())).await?;
    if !answer.ok() {
        return Err(format!("The identity provider refused to issue a token ({})", answer.said()));
    }
    let id_token = answer.json()["id_token"].as_str().map(str::to_owned).ok_or("The identity provider issued no ID token; the app must be registered with OpenID Connect")?;
    let (status, value) = exchange(&invite.address, &tls, "/access/v1/sso", None, Some(&json!({"idToken": id_token, "nonce": nonce, "computer": computer}))).await?;
    if status != StatusCode::OK {
        return Err(message(&value, "The Access Grid refused the sign-in"));
    }
    signed(&value, &pem, &fingerprint)
}

fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
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

/// Signs in again with this computer's device token, to the hub it already pinned.
pub async fn resume(address: &HubAddress, certificate: &str, device: &str, computer: &str) -> Result<SignedIn, CallError> {
    let tls = net::client_config(certificate).map_err(CallError::Failed)?;
    let (status, value) = exchange(address, &tls, "/access/v1/resume", None, Some(&json!({"device": device, "computer": computer}))).await.map_err(CallError::Failed)?;
    if status != StatusCode::OK {
        return Err(classify(status, &value));
    }
    signed(&value, certificate, &net::fingerprint(certificate).map_err(CallError::Failed)?).map_err(CallError::Failed)
}

/// One call as a signed-in person: `me`, `use`, `reveal`, `request`, `manage`, `account` or
/// `signout`.
pub async fn call(address: &HubAddress, certificate: &str, token: &str, action: &str, body: &Value) -> Result<Value, CallError> {
    let tls = net::client_config(certificate).map_err(CallError::Failed)?;
    let (status, value) = exchange(address, &tls, &format!("/access/v1/{action}"), Some(token), Some(body)).await.map_err(CallError::Failed)?;
    if !status.is_success() {
        return Err(classify(status, &value));
    }
    Ok(value)
}
