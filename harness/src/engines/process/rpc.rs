//! JSON-RPC 2.0 over JSON lines (ACP), or the same messages without the `"jsonrpc"` member
//! (Codex's app-server). Requests and responses are matched by id in the engine's own loop: a
//! request returns its id, and the response comes back as a [`Message::Response`].
use super::LineWriter;
use serde_json::{json, Map, Value};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

/// JSON-RPC's and ACP's error codes.
pub const METHOD_NOT_FOUND: i64 = -32601;
pub const INVALID_PARAMS: i64 = -32602;
pub const INTERNAL_ERROR: i64 = -32603;
pub const AUTH_REQUIRED: i64 = -32000;
pub const RESOURCE_NOT_FOUND: i64 = -32002;

#[derive(Clone, Debug, PartialEq)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    pub data: Option<Value>,
}

impl RpcError {
    pub fn new(code: i64, message: impl Into<String>) -> RpcError {
        RpcError { code, message: message.into(), data: None }
    }

    fn from_value(value: &Value) -> RpcError {
        RpcError {
            code: value.get("code").and_then(Value::as_i64).unwrap_or(INTERNAL_ERROR),
            message: value.get("message").and_then(Value::as_str).unwrap_or("Unknown error").to_owned(),
            data: value.get("data").cloned().filter(|d| !d.is_null()),
        }
    }

    /// The message with whatever detail `data` adds, for the person.
    pub fn text(&self) -> String {
        let detail = match &self.data {
            Some(Value::String(s)) => Some(s.clone()),
            Some(Value::Object(map)) => map
                .get("message")
                .or_else(|| map.get("details"))
                .or_else(|| map.get("detail"))
                .and_then(Value::as_str)
                .map(str::to_owned),
            _ => None,
        };
        match detail {
            Some(d) if !d.is_empty() && !self.message.contains(&d) => format!("{} ({d})", self.message),
            _ => self.message.clone(),
        }
    }
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Message {
    Request { id: Value, method: String, params: Value },
    Notification { method: String, params: Value },
    Response { id: Value, outcome: Result<Value, RpcError> },
}

/// What a line holds, or None for something that is not a JSON-RPC message.
pub fn classify(value: Value) -> Option<Message> {
    let Value::Object(mut map) = value else { return None };
    let method = map.remove("method").and_then(|m| m.as_str().map(str::to_owned));
    let id = map.remove("id").filter(|id| id.is_string() || id.is_number());
    let params = map.remove("params").unwrap_or(Value::Null);
    match (method, id) {
        (Some(method), Some(id)) => Some(Message::Request { id, method, params }),
        (Some(method), None) => Some(Message::Notification { method, params }),
        (None, Some(id)) => {
            if let Some(error) = map.get("error").filter(|e| !e.is_null()) {
                Some(Message::Response { id, outcome: Err(RpcError::from_value(error)) })
            } else {
                Some(Message::Response { id, outcome: Ok(map.remove("result").unwrap_or(Value::Null)) })
            }
        }
        (None, None) => None,
    }
}

/// Our end of the connection: sends requests, notifications and responses. Clones share the id
/// counter, so tasks can answer requests themselves.
#[derive(Clone)]
pub struct Rpc {
    out: LineWriter,
    next: Arc<AtomicI64>,
    /// Leave out `"jsonrpc": "2.0"` (Codex's app-server).
    bare: bool,
}

impl Rpc {
    pub fn new(out: LineWriter, bare: bool) -> Rpc {
        Rpc { out, next: Arc::new(AtomicI64::new(0)), bare }
    }

    fn envelope(&self) -> Map<String, Value> {
        let mut map = Map::new();
        if !self.bare {
            map.insert("jsonrpc".into(), json!("2.0"));
        }
        map
    }

    /// Sends a request; its response arrives as a [`Message::Response`] with this id.
    pub fn request(&self, method: &str, params: Value) -> i64 {
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        let mut map = self.envelope();
        map.insert("id".into(), json!(id));
        map.insert("method".into(), json!(method));
        map.insert("params".into(), params);
        self.out.send(&Value::Object(map));
        id
    }

    /// A notification; `Value::Null` params are left out.
    pub fn notify(&self, method: &str, params: Value) -> bool {
        let mut map = self.envelope();
        map.insert("method".into(), json!(method));
        if !params.is_null() {
            map.insert("params".into(), params);
        }
        self.out.send(&Value::Object(map))
    }

    pub fn respond(&self, id: Value, result: Value) -> bool {
        let mut map = self.envelope();
        map.insert("id".into(), id);
        map.insert("result".into(), result);
        self.out.send(&Value::Object(map))
    }

    pub fn fail(&self, id: Value, error: RpcError) -> bool {
        let mut map = self.envelope();
        map.insert("id".into(), id);
        let mut body = Map::new();
        body.insert("code".into(), json!(error.code));
        body.insert("message".into(), json!(error.message));
        if let Some(data) = error.data {
            body.insert("data".into(), data);
        }
        map.insert("error".into(), Value::Object(body));
        self.out.send(&Value::Object(map))
    }
}

#[derive(Debug)]
pub enum CallError {
    Rpc(RpcError),
    /// The engine closed its output (it ended).
    Closed,
    Timeout,
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::Rpc(error) => write!(f, "{error}"),
            CallError::Closed => f.write_str("it ended before answering"),
            CallError::Timeout => f.write_str("it did not answer in time"),
        }
    }
}

/// Messages from the engine: the backlog first (kept while waiting for a response), then the
/// stream. None once the engine's output ended.
pub struct Incoming {
    pub stream: mpsc::UnboundedReceiver<Value>,
    pub backlog: VecDeque<Message>,
}

impl Incoming {
    pub fn new(stream: mpsc::UnboundedReceiver<Value>) -> Incoming {
        Incoming { stream, backlog: VecDeque::new() }
    }

    pub async fn next(&mut self) -> Option<Message> {
        if let Some(message) = self.backlog.pop_front() {
            return Some(message);
        }
        loop {
            let value = self.stream.recv().await?;
            if let Some(message) = classify(value) {
                return Some(message);
            }
        }
    }

    /// Sends a request and waits for its response. Other messages wait in the backlog, except
    /// requests `early` answers at once (returning true): file reads during start-up, say.
    pub async fn call(
        &mut self,
        rpc: &Rpc,
        method: &str,
        params: Value,
        limit: Duration,
        early: &mut (dyn FnMut(&Rpc, &Message) -> bool + Send),
    ) -> Result<Value, CallError> {
        let id = rpc.request(method, params);
        let deadline = tokio::time::Instant::now() + limit;
        loop {
            let value = match tokio::time::timeout_at(deadline, self.stream.recv()).await {
                Err(_) => return Err(CallError::Timeout),
                Ok(None) => return Err(CallError::Closed),
                Ok(Some(value)) => value,
            };
            let Some(message) = classify(value) else { continue };
            match message {
                Message::Response { id: got, outcome } if same_id(&got, id) => {
                    return outcome.map_err(CallError::Rpc);
                }
                other => {
                    if !early(rpc, &other) {
                        self.backlog.push_back(other);
                    }
                }
            }
        }
    }
}

/// Whether a response id is our numeric request id (some engines echo it as a string).
pub fn same_id(got: &Value, id: i64) -> bool {
    match got {
        Value::Number(n) => n.as_i64() == Some(id),
        Value::String(s) => s.parse::<i64>().ok() == Some(id),
        _ => false,
    }
}

/// The numeric id of a response to one of our requests.
pub fn our_id(got: &Value) -> Option<i64> {
    match got {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_are_told_apart() {
        let request = classify(json!({"jsonrpc":"2.0","id":3,"method":"fs/read_text_file","params":{"path":"/a"}})).unwrap();
        assert!(matches!(request, Message::Request { ref method, .. } if method == "fs/read_text_file"));
        let note = classify(json!({"method":"session/update","params":{}})).unwrap();
        assert!(matches!(note, Message::Notification { .. }));
        let ok = classify(json!({"id":"7","result":{"x":1}})).unwrap();
        assert!(matches!(ok, Message::Response { outcome: Ok(_), .. }));
        let failed = classify(json!({"id":1,"error":{"code":-32000,"message":"Authentication required","data":{"details":"log in"}}})).unwrap();
        let Message::Response { outcome: Err(error), .. } = failed else { panic!() };
        assert_eq!(error.code, AUTH_REQUIRED);
        assert_eq!(error.text(), "Authentication required (log in)");
        assert!(classify(json!({"hello":1})).is_none());
        assert!(same_id(&json!("4"), 4) && !same_id(&json!(5), 4));
    }

    #[tokio::test]
    async fn a_call_keeps_other_messages_for_later() {
        let (write, mut read) = tokio::io::duplex(4096);
        let rpc = Rpc::new(LineWriter::new(write), true);
        let (sender, receiver) = mpsc::unbounded_channel();
        let mut incoming = Incoming::new(receiver);
        sender.send(json!({"method":"note","params":1})).unwrap();
        sender.send(json!({"id":99,"method":"ask","params":{}})).unwrap();
        sender.send(json!({"id":0,"result":"done"})).unwrap();
        let mut answered = Vec::new();
        let result = incoming
            .call(&rpc, "start", json!({}), Duration::from_secs(5), &mut |_, m| {
                if let Message::Request { method, .. } = m {
                    answered.push(method.clone());
                    return true;
                }
                false
            })
            .await
            .unwrap();
        assert_eq!(result, json!("done"));
        assert_eq!(answered, vec!["ask".to_owned()]);
        assert!(matches!(incoming.next().await, Some(Message::Notification { .. })));
        use tokio::io::AsyncReadExt;
        let mut sent = vec![0u8; 256];
        let n = read.read(&mut sent).await.unwrap();
        let line: Value = serde_json::from_slice(&sent[..n]).unwrap();
        assert_eq!(line, json!({"id":0,"method":"start","params":{}}), "bare messages have no jsonrpc member");
        drop(sender);
        assert!(incoming.next().await.is_none());
    }
}
