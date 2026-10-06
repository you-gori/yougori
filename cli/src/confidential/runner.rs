//! Reference encrypted-only ingress for a future independently measured CVM.
//! Starting this service is NOT evidence of confidential execution.
use super::*;
use axum::{
    extract::Request,
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use std::{collections::BTreeMap, process::Stdio, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex,
};

struct StateData {
    keys: RunnerKeys,
    model: String,
    revision: String,
    node: String,
    attester: String,
    relay_token: Zeroizing<String>,
    model_token: Zeroizing<String>,
    used: Mutex<BTreeMap<String, u64>>,
    client: reqwest::Client,
}
type Failure = (StatusCode, Json<Value>);
fn failed(status: StatusCode) -> Failure {
    (
        status,
        Json(json!({"error":"The confidential runner refused the request"})),
    )
}
fn authorized(headers: &HeaderMap, state: &StateData) -> Result<(), Failure> {
    let value = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let expected = Zeroizing::new(format!("Bearer {}", state.relay_token.as_str()));
    if Sha256::digest(value.as_bytes()) != Sha256::digest(expected.as_bytes()) {
        return Err(failed(StatusCode::UNAUTHORIZED));
    }
    Ok(())
}
async fn ingress(State(state): State<Arc<StateData>>, request: Request, next: Next) -> Response {
    // Authenticate before the JSON extractor reads an untrusted request body.
    if request.uri().path() != "/health" {
        if let Err(error) = authorized(request.headers(), &state) {
            return error.into_response();
        }
    }
    match tokio::time::timeout(std::time::Duration::from_secs(180), next.run(request)).await {
        Ok(response) => response,
        Err(_) => failed(StatusCode::REQUEST_TIMEOUT).into_response(),
    }
}
async fn health(State(state): State<Arc<StateData>>) -> Json<Value> {
    Json(
        json!({"status":"ready","model":state.model,"revision":state.revision,"protocol":VERSION,"hardwareAttestationVerified":false}),
    )
}
async fn attestation(
    State(state): State<Arc<StateData>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Proof>, Failure> {
    authorized(&headers, &state)?;
    let nonce = body["nonce"]
        .as_str()
        .filter(|v| fixed(v, 32))
        .ok_or_else(|| failed(StatusCode::BAD_REQUEST))?;
    if body.as_object().is_none_or(|o| o.len() != 1) {
        return Err(failed(StatusCode::BAD_REQUEST));
    }
    let descriptor = state.keys.descriptor(
        state.node.clone(),
        state.model.clone(),
        state.revision.clone(),
        nonce.into(),
        now(),
    );
    // The collector must be part of the measured, approved image. It receives
    // only public runtime data; it must quote that exact data and all local GPUs.
    let mut child = tokio::process::Command::new(&state.attester)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| failed(StatusCode::SERVICE_UNAVAILABLE))?;
    let work = async {
        let mut stdin = child.stdin.take().ok_or(())?;
        stdin
            .write_all(&serde_json::to_vec(&descriptor).map_err(|_| ())?)
            .await
            .map_err(|_| ())?;
        drop(stdin);
        let mut out = Vec::new();
        child
            .stdout
            .take()
            .ok_or(())?
            .take(262145)
            .read_to_end(&mut out)
            .await
            .map_err(|_| ())?;
        if out.len() > 262144 {
            return Err(());
        }
        if !child.wait().await.map_err(|_| ())?.success() {
            return Err(());
        }
        let token = String::from_utf8(out).map_err(|_| ())?.trim().to_owned();
        if token.split('.').count() != 3 {
            return Err(());
        }
        Ok(token)
    };
    let token = tokio::time::timeout(std::time::Duration::from_secs(30), work)
        .await
        .map_err(|_| failed(StatusCode::SERVICE_UNAVAILABLE))?
        .map_err(|_| failed(StatusCode::SERVICE_UNAVAILABLE))?;
    Ok(Json(Proof { descriptor, token }))
}

struct Sensitive(Value);
impl Drop for Sensitive {
    fn drop(&mut self) {
        fn clear(v: &mut Value) {
            match v {
                Value::String(s) => zeroize::Zeroize::zeroize(s),
                Value::Array(a) => a.iter_mut().for_each(clear),
                Value::Object(o) => o.values_mut().for_each(clear),
                _ => (),
            }
        }
        clear(&mut self.0)
    }
}

async fn chat(
    State(state): State<Arc<StateData>>,
    headers: HeaderMap,
    Json(envelope): Json<Envelope>,
) -> Result<Json<EncryptedReply>, Failure> {
    authorized(&headers, &state)?;
    if envelope.node_id != state.node
        || envelope.model != state.model
        || !(1..=4096).contains(&envelope.max_tokens)
    {
        return Err(failed(StatusCode::BAD_REQUEST));
    }
    let request = Sensitive(
        state
            .keys
            .open(&envelope, now())
            .map_err(|_| failed(StatusCode::BAD_REQUEST))?,
    );
    if request.0["stream"].as_bool().unwrap_or(false)
        || request.0["max_tokens"].as_u64().unwrap_or(1024) != envelope.max_tokens
    {
        return Err(failed(StatusCode::BAD_REQUEST));
    }
    {
        let mut used = state.used.lock().await;
        used.retain(|_, expiry| *expiry > now());
        if used.contains_key(&envelope.request_id) {
            return Err(failed(StatusCode::CONFLICT));
        }
        if used.len() >= 10000 {
            return Err(failed(StatusCode::TOO_MANY_REQUESTS));
        }
        used.insert(envelope.request_id.clone(), envelope.expires_at);
    }
    // The fixed loopback connection cannot use environment proxies or redirects.
    let answer=async {
        let mut response=state.client.post("http://127.0.0.1:8000/v1/chat/completions").bearer_auth(state.model_token.as_str()).json(&request.0).send().await.map_err(|_|())?;
        if !response.status().is_success(){return Err(())}
        let mut bytes=Zeroizing::new(Vec::new());
        while let Some(part)=response.chunk().await.map_err(|_|())?{if bytes.len()+part.len()>MAX_CIPHERTEXT-1024{return Err(())}bytes.extend_from_slice(&part)}
        let value=Sensitive(serde_json::from_slice::<Value>(&bytes).map_err(|_|())?);
        let input=value.0["usage"]["prompt_tokens"].as_u64().filter(|n|*n<=65536).ok_or(())?;
        let output=value.0["usage"]["completion_tokens"].as_u64().filter(|n|*n<=envelope.max_tokens).ok_or(())?;
        let content=value.0["choices"][0]["message"]["content"].as_str().ok_or(())?;
        if content.len()>262144{return Err(())}
        let safe=Sensitive(json!({"model":state.model,"choices":[{"index":0,"message":{"role":"assistant","content":content},"finish_reason":"stop"}],"usage":{"prompt_tokens":input,"completion_tokens":output,"total_tokens":input+output}}));
        state.keys.reply(&envelope,safe.0.clone(),input,output).map_err(|_|())
    }.await;
    let answer = match answer {
        Ok(answer) => answer,
        Err(()) => state
            .keys
            .reply(
                &envelope,
                json!({"error":{"message":"Inference inside the confidential runner failed"}}),
                0,
                0,
            )
            .map_err(|_| failed(StatusCode::INTERNAL_SERVER_ERROR))?,
    };
    Ok(Json(answer))
}

pub async fn serve() -> Result<(), String> {
    let config = |name: &str| {
        std::env::var(name).map_err(|_| format!("Missing runner configuration {name}"))
    };
    let model = config("YOUGORI_MODEL")?;
    let revision = config("YOUGORI_MODEL_REVISION")?;
    if revision.len() != 40 || !revision.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("An immutable model revision is required".into());
    }
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(150))
        .build()
        .map_err(|_| "Cannot initialize internal model connection")?;
    let model_token = Zeroizing::new(config("YOUGORI_MODEL_TOKEN")?);
    let mut health_response = client
        .get("http://127.0.0.1:8000/health")
        .bearer_auth(model_token.as_str())
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|_| "Internal model is unavailable")?;
    let mut health_bytes = Vec::new();
    while let Some(chunk) = health_response
        .chunk()
        .await
        .map_err(|_| "Invalid internal model status")?
    {
        if health_bytes.len() + chunk.len() > 65536 {
            return Err("Internal model status exceeds its limit".into());
        }
        health_bytes.extend_from_slice(&chunk);
    }
    let status: Value =
        serde_json::from_slice(&health_bytes).map_err(|_| "Invalid internal model status")?;
    if status["status"] != "ready"
        || status["model"] != model
        || status["revision"] != revision
        || status["weightsVerified"] != true
    {
        return Err("Internal model has not verified its pinned checkpoint".into());
    }
    let state = Arc::new(StateData {
        keys: RunnerKeys::generate()?,
        model,
        revision,
        node: config("YOUGORI_CONFIDENTIAL_NODE_ID")?,
        attester: config("YOUGORI_CONFIDENTIAL_ATTESTER")?,
        relay_token: Zeroizing::new(config("YOUGORI_CONFIDENTIAL_RELAY_TOKEN")?),
        model_token,
        used: Mutex::new(BTreeMap::new()),
        client,
    });
    let router = Router::new()
        .route("/health", get(health))
        .route("/confidential/v1/attestation", post(attestation))
        .route("/confidential/v1/chat/completions", post(chat))
        .layer(DefaultBodyLimit::max(2 * MAX_CIPHERTEXT))
        .layer(middleware::from_fn_with_state(state.clone(), ingress))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8448")
        .await
        .map_err(|_| "Cannot bind encrypted runner ingress")?;
    axum::serve(listener, router)
        .await
        .map_err(|_| "Confidential runner stopped".into())
}
