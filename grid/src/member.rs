//! A member computer: joins with the company name and password, reports what it runs, receives
//! its assignment from the admin's plans and, while allowed, asks the hub for work, runs it on
//! its local model and streams the reply back.
use crate::{
    hub::{ModelReport, GENERATION, POLL},
    is_token, model_key, net, password,
};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::{body::Incoming, header, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{future::Future, net::SocketAddr, sync::Arc, time::Duration};
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
    pub address: SocketAddr,
    pub member_id: String,
    token: String,
    tls: Arc<ClientConfig>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum MemberError {
    /// The hub no longer knows this computer: the admin removed it or recreated the grid.
    Removed,
    Failed(String),
}

impl std::fmt::Display for MemberError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemberError::Removed => write!(f, "The grid's admin removed this computer; join again with the company password"),
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

async fn exchange(address: SocketAddr, tls: &Arc<ClientConfig>, path: &str, bearer: Option<&str>, body: Option<&Value>, wait: Duration) -> Result<(StatusCode, Value), String> {
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

/// Joins `company`'s grid at `address`. The password is checked by proof, never sent; the
/// hub's certificate is pinned only after the hub proves that it knows the password too.
/// `fingerprint` optionally pins the certificate the admin read out in advance.
pub async fn join(company: &str, address: SocketAddr, secret: &str, name: &str, platform: &str, capable: bool, fingerprint: Option<&str>) -> Result<Joined, String> {
    if !net::private(address.ip()) || address.port() == 0 {
        return Err("The hub must be on a private LAN or VPN address such as 10.0.0.5".into());
    }
    let expected = fingerprint.map(|text| net::normalize_fingerprint(text).ok_or("--fingerprint must be the hub's SHA-256 fingerprint (64 hex digits)")).transpose()?;
    let (capture, seen) = net::capturing_config()?;
    let (status, hello) = exchange(address, &capture, "/grid/v1/hello", None, None, Duration::from_secs(20)).await?;
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
    let (status, value) = exchange(address, &tls, "/grid/v1/join", None, Some(&body), Duration::from_secs(20)).await?;
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
    pub fn new(address: SocketAddr, certificate: &str, member_id: String, token: String) -> Result<Self, String> {
        Ok(Self { address, member_id, token, tls: net::client_config(certificate)? })
    }

    async fn call(&self, path: &str, body: &Value, wait: Duration) -> Result<(StatusCode, Value), MemberError> {
        let (status, value) = exchange(self.address, &self.tls, path, Some(&self.token), Some(body), wait).await.map_err(MemberError::Failed)?;
        if status == StatusCode::UNAUTHORIZED {
            return Err(MemberError::Removed);
        }
        Ok((status, value))
    }

    pub async fn heartbeat(&self, app_version: &str, capable: bool, models: &[ModelReport]) -> Result<Instructions, MemberError> {
        let body = json!({"appVersion": app_version, "capable": capable, "models": models});
        let (status, value) = self.call("/grid/v1/heartbeat", &body, Duration::from_secs(20)).await?;
        if !status.is_success() {
            return Err(MemberError::Failed(message(&value, "The grid hub refused this computer's report")));
        }
        Ok(Instructions { assignment: assignment(&value["assignment"]), grid_name: value["grid"]["name"].as_str().unwrap_or_default().to_owned() })
    }

    pub async fn leave(&self) -> Result<(), MemberError> {
        match self.call("/grid/v1/leave", &json!({}), Duration::from_secs(20)).await {
            Ok(_) | Err(MemberError::Removed) => Ok(()),
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
        let response = net::send(self.address, &self.tls, request, GENERATION + Duration::from_secs(60)).await?;
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
            Err(MemberError::Removed) => {
                events(WorkerEvent::Removed);
                return;
            }
            Err(MemberError::Failed(error)) => {
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

#[cfg(test)]
mod tests {
    use super::*;
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
