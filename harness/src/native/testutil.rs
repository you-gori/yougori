//! Test helpers: a local HTTP server answering with scripted replies (server-sent event streams,
//! JSON, slow chunks) and recording every request it got.
use serde_json::Value;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Clone, Debug)]
pub struct Recorded {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Recorded {
    pub fn header(&self, name: &str) -> Option<String> {
        self.headers.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, value)| value.clone())
    }

    pub fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
}

pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub chunks: Vec<Vec<u8>>,
    /// Waited between chunks.
    pub delay: Duration,
}

impl Reply {
    pub fn sse(body: Vec<u8>) -> Reply {
        Reply {
            status: 200,
            headers: vec![("Content-Type".into(), "text/event-stream".into())],
            chunks: vec![body],
            delay: Duration::ZERO,
        }
    }

    pub fn sse_slow(chunks: Vec<Vec<u8>>, delay: Duration) -> Reply {
        Reply { status: 200, headers: vec![("Content-Type".into(), "text/event-stream".into())], chunks, delay }
    }

    pub fn json(status: u16, value: Value) -> Reply {
        Reply {
            status,
            headers: vec![("Content-Type".into(), "application/json".into())],
            chunks: vec![value.to_string().into_bytes()],
            delay: Duration::ZERO,
        }
    }

    pub fn text(status: u16, content_type: &str, body: &str) -> Reply {
        Reply {
            status,
            headers: vec![("Content-Type".into(), content_type.into())],
            chunks: vec![body.as_bytes().to_vec()],
            delay: Duration::ZERO,
        }
    }

    pub fn empty(status: u16) -> Reply {
        Reply { status, headers: Vec::new(), chunks: Vec::new(), delay: Duration::ZERO }
    }

    pub fn header(mut self, name: &str, value: &str) -> Reply {
        self.headers.push((name.into(), value.into()));
        self
    }
}

/// The body of an SSE stream: one `data:` event per value, then `[DONE]`.
pub fn sse_body(values: &[Value]) -> Vec<u8> {
    let mut body = String::new();
    for value in values {
        body.push_str(&format!("data: {value}\n\n"));
    }
    body.push_str("data: [DONE]\n\n");
    body.into_bytes()
}

/// A streamed reply that says `text`.
pub fn say(text: &str) -> Reply {
    Reply::sse(sse_body(&[serde_json::json!({
        "choices": [{ "index": 0, "delta": { "role": "assistant", "content": text }, "finish_reason": "stop" }]
    })]))
}

/// A streamed reply that calls one tool (without an id, as some servers send it).
pub fn call(name: &str, args: Value) -> Reply {
    Reply::sse(sse_body(&[serde_json::json!({
        "choices": [{ "index": 0, "delta": { "tool_calls": [{ "index": 0, "id": "", "type": "function",
            "function": { "name": name, "arguments": args.to_string() } }] }, "finish_reason": "tool_calls" }]
    })]))
}

/// A spec for our own engine against a fake relay.
pub fn spec(url: &str, cwd: &std::path::Path, state: &std::path::Path) -> crate::spec::EngineSpec {
    crate::spec::EngineSpec {
        harness: "yougori".into(),
        name: "Yougori".into(),
        category: "coding".into(),
        protocol: crate::spec::Protocol::Native,
        argv: Vec::new(),
        env: Default::default(),
        secret_env: Default::default(),
        cwd: cwd.to_path_buf(),
        model: "test-model".into(),
        models: vec!["test-model".into(), "other-model".into()],
        model_switch: crate::protocol::ModelSwitch::Live,
        respec: Vec::new(),
        profile: Some("yougori".into()),
        mcp: Vec::new(),
        services: Vec::new(),
        context_window: 32768,
        max_output: 4096,
        base_url: url.into(),
        api_key: "solver-local-relay".into(),
        answers: Value::Null,
        reach: Default::default(),
        state_dir: state.to_path_buf(),
    }
}

type Handler = dyn Fn(usize, &Recorded) -> Reply + Send + Sync;

pub struct FakeServer {
    /// `http://127.0.0.1:PORT`, no trailing slash.
    pub url: String,
    log: Arc<Mutex<Vec<Recorded>>>,
    task: tokio::task::JoinHandle<()>,
}

impl FakeServer {
    /// Serves until dropped; `handler` gets each request with its number (from 0).
    pub async fn start<F>(handler: F) -> FakeServer
    where
        F: Fn(usize, &Recorded) -> Reply + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let log: Arc<Mutex<Vec<Recorded>>> = Arc::new(Mutex::new(Vec::new()));
        let handler: Arc<Handler> = Arc::new(handler);
        let shared = log.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else { return };
                let log = shared.clone();
                let handler = handler.clone();
                tokio::spawn(async move {
                    let Some(request) = read_request(&mut socket).await else { return };
                    let index = {
                        let mut log = log.lock().unwrap();
                        log.push(request.clone());
                        log.len() - 1
                    };
                    let reply = handler(index, &request);
                    let mut head = format!("HTTP/1.1 {} {}\r\n", reply.status, reason(reply.status));
                    for (name, value) in &reply.headers {
                        head.push_str(&format!("{name}: {value}\r\n"));
                    }
                    let streaming =
                        reply.headers.iter().any(|(n, v)| n.eq_ignore_ascii_case("content-type") && v.contains("event-stream"));
                    if !streaming {
                        let length: usize = reply.chunks.iter().map(Vec::len).sum();
                        head.push_str(&format!("Content-Length: {length}\r\n"));
                    }
                    head.push_str("Connection: close\r\n\r\n");
                    if socket.write_all(head.as_bytes()).await.is_err() {
                        return;
                    }
                    for (number, chunk) in reply.chunks.iter().enumerate() {
                        if number > 0 && !reply.delay.is_zero() {
                            tokio::time::sleep(reply.delay).await;
                        }
                        if socket.write_all(chunk).await.is_err() || socket.flush().await.is_err() {
                            return;
                        }
                    }
                    let _ = socket.shutdown().await;
                });
            }
        });
        FakeServer { url, log, task }
    }

    pub fn requests(&self) -> Vec<Recorded> {
        self.log.lock().unwrap().clone()
    }
}

impl Drop for FakeServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

async fn read_request(socket: &mut tokio::net::TcpStream) -> Option<Recorded> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 8192];
    let head_end = loop {
        if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break at;
        }
        let read = socket.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
    };
    let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split_whitespace();
    let method = first.next()?.to_owned();
    let path = first.next()?.to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':').map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned())))
        .collect();
    let length: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    let mut body = buffer[head_end + 4..].to_vec();
    while body.len() < length {
        let read = socket.read(&mut chunk).await.ok()?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    Some(Recorded { method, path, headers, body: String::from_utf8_lossy(&body).into_owned() })
}
