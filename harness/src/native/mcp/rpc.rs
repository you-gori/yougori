//! JSON-RPC 2.0 over a pair of byte streams, one message per line: an MCP server's stdin and
//! stdout (or in-memory pipes in tests). Answers the server's `ping`, refuses its other requests,
//! notes `notifications/tools/list_changed`, and keeps requests apart by id.
use crate::native::agent::lock;
use crate::native::cancel::Cancel;
use crate::native::util;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::oneshot;

/// The longest line read; longer ones are skipped.
const MAX_LINE: usize = 64 * 1024 * 1024;

/// The last lines a server wrote to stderr, for its error messages.
#[derive(Default)]
pub struct Tail {
    lines: VecDeque<String>,
}

impl Tail {
    pub fn push(&mut self, line: String) {
        let line = util::one_line(&line, 300);
        if line.is_empty() {
            return;
        }
        self.lines.push_back(line);
        while self.lines.len() > 20 {
            self.lines.pop_front();
        }
    }

    /// The last few lines, joined.
    pub fn text(&self) -> String {
        self.lines.iter().rev().take(4).rev().cloned().collect::<Vec<_>>().join(" / ")
    }
}

type Writer = Box<dyn AsyncWrite + Send + Unpin>;
type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<Result<Value, String>>>>>;

pub struct Peer {
    name: String,
    writer: Arc<tokio::sync::Mutex<Option<Writer>>>,
    pending: Pending,
    next: AtomicU64,
    closed: Arc<Mutex<Option<String>>>,
    pub changed: Arc<AtomicBool>,
    reader: tokio::task::JoinHandle<()>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

/// A JSON-RPC error object in plain words.
pub fn error_text(error: &Value) -> String {
    let message = error.get("message").and_then(Value::as_str).unwrap_or("unknown error");
    match error.get("code").and_then(Value::as_i64) {
        Some(code) => format!("{message} ({code})"),
        None => message.to_owned(),
    }
}

/// An id as a number (servers may echo it as a string).
pub fn id_of(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| value.as_str().and_then(|s| s.parse().ok()))
}

async fn read_line(reader: &mut (impl AsyncBufRead + Unpin), out: &mut Vec<u8>) -> std::io::Result<usize> {
    let mut total = 0;
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(total);
        }
        let (used, done) = match available.iter().position(|b| *b == b'\n') {
            Some(at) => (at + 1, true),
            None => (available.len(), false),
        };
        if out.len() + used <= MAX_LINE {
            out.extend_from_slice(&available[..used]);
        }
        reader.consume(used);
        total += used;
        if done {
            return Ok(total);
        }
    }
}

async fn send(writer: &tokio::sync::Mutex<Option<Writer>>, message: &Value) -> Result<(), String> {
    let mut line = serde_json::to_vec(message).map_err(|e| e.to_string())?;
    line.push(b'\n');
    let mut guard = writer.lock().await;
    let Some(stream) = guard.as_mut() else { return Err("the connection is closed".into()) };
    stream.write_all(&line).await.map_err(|e| e.to_string())?;
    stream.flush().await.map_err(|e| e.to_string())
}

impl Peer {
    pub fn start<R, W>(name: &str, reader: R, writer: W, tail: Arc<Mutex<Tail>>) -> Peer
    where
        R: AsyncRead + Send + Unpin + 'static,
        W: AsyncWrite + Send + Unpin + 'static,
    {
        let writer: Arc<tokio::sync::Mutex<Option<Writer>>> = Arc::new(tokio::sync::Mutex::new(Some(Box::new(writer))));
        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
        let closed = Arc::new(Mutex::new(None));
        let changed = Arc::new(AtomicBool::new(false));
        let task = {
            let (writer, pending, closed, changed, name) = (writer.clone(), pending.clone(), closed.clone(), changed.clone(), name.to_owned());
            tokio::spawn(async move {
                let mut reader = BufReader::new(reader);
                let mut line = Vec::new();
                let why = loop {
                    line.clear();
                    match read_line(&mut reader, &mut line).await {
                        Ok(0) => break "it closed its output".to_owned(),
                        Ok(_) => {}
                        Err(e) => break format!("reading from it failed: {e}"),
                    }
                    let text = String::from_utf8_lossy(&line);
                    let text = text.trim();
                    if text.is_empty() {
                        continue;
                    }
                    let Ok(value) = serde_json::from_str::<Value>(text) else {
                        lock(&tail).push(format!("(on stdout) {text}"));
                        continue;
                    };
                    let messages = match value {
                        Value::Array(items) => items,
                        other => vec![other],
                    };
                    for message in messages {
                        handle(&message, &writer, &pending, &changed).await;
                    }
                };
                let stderr = lock(&tail).text();
                let reason = if stderr.is_empty() {
                    format!("The MCP server {name} stopped: {why}.")
                } else {
                    format!("The MCP server {name} stopped: {why}. It said: {stderr}")
                };
                *lock(&closed) = Some(reason.clone());
                for (_, waiting) in lock(&pending).drain() {
                    let _ = waiting.send(Err(reason.clone()));
                }
            })
        };
        Peer { name: name.to_owned(), writer, pending, next: AtomicU64::new(1), closed, changed, reader: task }
    }

    fn closed(&self) -> Option<String> {
        lock(&self.closed).clone()
    }

    pub async fn request(&self, method: &str, params: Value, wait: Duration, cancel: Option<&Cancel>) -> Result<Value, String> {
        if let Some(reason) = self.closed() {
            return Err(reason);
        }
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        let (sender, receiver) = oneshot::channel();
        lock(&self.pending).insert(id, sender);
        let mut message = json!({ "jsonrpc": "2.0", "id": id, "method": method });
        if !params.is_null() {
            message["params"] = params;
        }
        if let Err(error) = send(&self.writer, &message).await {
            lock(&self.pending).remove(&id);
            return Err(self.closed().unwrap_or_else(|| format!("Cannot write to the MCP server {}: {error}.", self.name)));
        }
        let never = Cancel::new();
        let cancel = cancel.unwrap_or(&never);
        let failure = tokio::select! {
            answer = receiver => {
                return match answer {
                    Ok(result) => result,
                    Err(_) => Err(self.closed().unwrap_or_else(|| format!("The MCP server {} stopped.", self.name))),
                };
            }
            _ = tokio::time::sleep(wait) => format!("The MCP server {} did not answer {method} within {} s.", self.name, wait.as_secs()),
            _ = cancel.cancelled() => "Stopped.".to_owned(),
        };
        lock(&self.pending).remove(&id);
        if method != "initialize" {
            let reason = if cancel.is_cancelled() { "The person stopped it." } else { "It took too long." };
            // A server that stopped reading its input does not hold the stop up.
            let notice = self.notify("notifications/cancelled", json!({ "requestId": id, "reason": reason }));
            let _ = tokio::time::timeout(Duration::from_secs(1), notice).await;
        }
        Err(failure)
    }

    pub async fn notify(&self, method: &str, params: Value) -> Result<(), String> {
        let mut message = json!({ "jsonrpc": "2.0", "method": method });
        if !params.is_null() {
            message["params"] = params;
        }
        send(&self.writer, &message).await.map_err(|e| format!("Cannot write to the MCP server {}: {e}.", self.name))
    }

    /// Closes the server's input: a well-behaved server exits on its own.
    pub async fn close_input(&self) {
        if let Some(mut stream) = self.writer.lock().await.take() {
            let _ = stream.shutdown().await;
        }
    }
}

async fn handle(message: &Value, writer: &tokio::sync::Mutex<Option<Writer>>, pending: &Pending, changed: &AtomicBool) {
    let method = message.get("method").and_then(Value::as_str);
    let id = message.get("id").filter(|id| !id.is_null());
    match (method, id) {
        (Some(method), Some(id)) => {
            let reply = if method == "ping" {
                json!({ "jsonrpc": "2.0", "id": id, "result": {} })
            } else {
                json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32601, "message": format!("{method} is not supported by this client") } })
            };
            let _ = send(writer, &reply).await;
        }
        (Some(method), None) => {
            if method == "notifications/tools/list_changed" {
                changed.store(true, Ordering::SeqCst);
            }
        }
        (None, Some(id)) => {
            let Some(id) = id_of(id) else { return };
            let Some(waiting) = lock(pending).remove(&id) else { return };
            let result = match message.get("error").filter(|e| !e.is_null()) {
                Some(error) => Err(error_text(error)),
                None => Ok(message.get("result").cloned().unwrap_or(Value::Null)),
            };
            let _ = waiting.send(result);
        }
        (None, None) => {}
    }
}
