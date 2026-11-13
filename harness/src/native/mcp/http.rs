//! MCP over Streamable HTTP: each message is POSTed; the server answers with JSON or with a
//! server-sent event stream holding the answer. The `Mcp-Session-Id` from the server's answer to
//! `initialize` goes with every later request, and so does the negotiated protocol version.
use super::rpc::{error_text, id_of};
use crate::native::agent::lock;
use crate::native::cancel::Cancel;
use crate::native::llm::server_message;
use crate::native::sse::SseParser;
use futures::StreamExt;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const SESSION: &str = "mcp-session-id";
const VERSION: &str = "mcp-protocol-version";

pub enum HttpError {
    /// The server forgot the session: initialize again.
    Expired,
    Other(String),
}

impl HttpError {
    pub fn text(self) -> String {
        match self {
            HttpError::Expired => "The MCP server ended the session.".into(),
            HttpError::Other(text) => text,
        }
    }
}

pub struct HttpPeer {
    name: String,
    url: String,
    client: reqwest::Client,
    session: Mutex<Option<String>>,
    version: Mutex<Option<String>>,
    next: AtomicU64,
    pub changed: Arc<AtomicBool>,
}

impl HttpPeer {
    pub fn new(name: &str, url: &str, client: reqwest::Client) -> HttpPeer {
        HttpPeer {
            name: name.to_owned(),
            url: url.to_owned(),
            client,
            session: Mutex::new(None),
            version: Mutex::new(None),
            next: AtomicU64::new(1),
            changed: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn set_version(&self, version: &str) {
        *lock(&self.version) = Some(version.to_owned());
    }

    /// Forgets the session before initializing again.
    pub fn reset(&self) {
        *lock(&self.session) = None;
        *lock(&self.version) = None;
    }

    fn post(&self, body: &Value) -> reqwest::RequestBuilder {
        let mut request = self
            .client
            .post(&self.url)
            .header(ACCEPT, "application/json, text/event-stream")
            .header(CONTENT_TYPE, "application/json")
            .body(body.to_string());
        if let Some(session) = lock(&self.session).clone() {
            request = request.header(SESSION, session);
        }
        if let Some(version) = lock(&self.version).clone() {
            request = request.header(VERSION, version);
        }
        request
    }

    pub async fn request(&self, method: &str, params: Value, wait: Duration, cancel: Option<&Cancel>) -> Result<Value, HttpError> {
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        let mut body = json!({ "jsonrpc": "2.0", "id": id, "method": method });
        if !params.is_null() {
            body["params"] = params;
        }
        let never = Cancel::new();
        let cancel = cancel.unwrap_or(&never);
        let exchange = self.exchange(&body, id);
        tokio::select! {
            result = tokio::time::timeout(wait, exchange) => match result {
                Ok(result) => result,
                Err(_) => {
                    self.give_up(method, id, "It took too long.");
                    Err(HttpError::Other(format!("The MCP server {} did not answer {method} within {} s.", self.name, wait.as_secs())))
                }
            },
            _ = cancel.cancelled() => {
                self.give_up(method, id, "The person stopped it.");
                Err(HttpError::Other("Stopped.".into()))
            }
        }
    }

    /// Tells the server a request is given up, in the background: the person's stop does not
    /// wait for a slow server to take the notice. `initialize` is never cancelled.
    fn give_up(&self, method: &str, id: u64, reason: &str) {
        if method == "initialize" {
            return;
        }
        let notice = json!({ "jsonrpc": "2.0", "method": "notifications/cancelled", "params": { "requestId": id, "reason": reason } });
        let request = self.post(&notice);
        tokio::spawn(async move {
            let _ = tokio::time::timeout(Duration::from_secs(15), request.send()).await;
        });
    }

    async fn exchange(&self, body: &Value, id: u64) -> Result<Value, HttpError> {
        let had_session = lock(&self.session).is_some();
        let response = self
            .post(body)
            .send()
            .await
            .map_err(|e| HttpError::Other(format!("Cannot reach the MCP server {}: {}.", self.name, crate::native::llm::root_cause(&e))))?;
        if let Some(session) = response.headers().get(SESSION).and_then(|v| v.to_str().ok()) {
            *lock(&self.session) = Some(session.to_owned());
        }
        let status = response.status();
        if status.as_u16() == 404 && had_session {
            return Err(HttpError::Expired);
        }
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(HttpError::Other(format!("The MCP server {} answered {status}: {}", self.name, server_message(&text))));
        }
        let content_type = response.headers().get(CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("").to_ascii_lowercase();
        if content_type.starts_with("text/event-stream") {
            let mut stream = response.bytes_stream();
            let mut parser = SseParser::default();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|e| HttpError::Other(format!("The MCP server {} broke off: {e}.", self.name)))?;
                for event in parser.push(&chunk) {
                    if let Some(answer) = self.message(&event.data, id).await {
                        return answer;
                    }
                }
            }
            for event in parser.finish() {
                if let Some(answer) = self.message(&event.data, id).await {
                    return answer;
                }
            }
            return Err(HttpError::Other(format!("The MCP server {} ended its stream without an answer.", self.name)));
        }
        let text = response.text().await.map_err(|e| HttpError::Other(e.to_string()))?;
        match self.message(&text, id).await {
            Some(answer) => answer,
            None => Err(HttpError::Other(format!("The MCP server {} sent no answer.", self.name))),
        }
    }

    /// One JSON-RPC message (or batch) from the server: the answer to `id` when it is one.
    async fn message(&self, data: &str, id: u64) -> Option<Result<Value, HttpError>> {
        let value: Value = serde_json::from_str(data.trim()).ok()?;
        let messages = match value {
            Value::Array(items) => items,
            other => vec![other],
        };
        let mut answer = None;
        for message in messages {
            let method = message.get("method").and_then(Value::as_str);
            let message_id = message.get("id").filter(|v| !v.is_null());
            match (method, message_id) {
                (Some(method), Some(their_id)) => {
                    let reply = if method == "ping" {
                        json!({ "jsonrpc": "2.0", "id": their_id, "result": {} })
                    } else {
                        json!({ "jsonrpc": "2.0", "id": their_id, "error": { "code": -32601, "message": format!("{method} is not supported by this client") } })
                    };
                    let _ = self.post(&reply).send().await;
                }
                (Some(method), None) => {
                    if method == "notifications/tools/list_changed" {
                        self.changed.store(true, Ordering::SeqCst);
                    }
                }
                (None, Some(their_id)) if id_of(their_id) == Some(id) => {
                    answer = Some(match message.get("error").filter(|e| !e.is_null()) {
                        Some(error) => Err(HttpError::Other(error_text(error))),
                        None => Ok(message.get("result").cloned().unwrap_or(Value::Null)),
                    });
                }
                _ => {}
            }
        }
        answer
    }

    pub async fn notify(&self, method: &str, params: Value) -> Result<(), String> {
        let mut body = json!({ "jsonrpc": "2.0", "method": method });
        if !params.is_null() {
            body["params"] = params;
        }
        let send = self.post(&body).send();
        let response = tokio::time::timeout(Duration::from_secs(15), send)
            .await
            .map_err(|_| format!("The MCP server {} did not take {method} in time.", self.name))?
            .map_err(|e| format!("Cannot reach the MCP server {}: {e}.", self.name))?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!("The MCP server {} refused {method} ({}).", self.name, response.status()))
        }
    }

    /// Ends the session on the server (best effort).
    pub async fn close(&self) {
        let Some(session) = lock(&self.session).take() else { return };
        let request = self.client.delete(&self.url).header(SESSION, session).send();
        let _ = tokio::time::timeout(Duration::from_secs(5), request).await;
    }
}
