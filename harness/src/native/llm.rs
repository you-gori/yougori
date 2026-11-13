//! The relay client: OpenAI-compatible chat completions, streamed.
//!
//! Every model request goes straight to the relay (`spec.base_url`, never through a proxy).
//! Replies stream as server-sent events: tool-call deltas are put together by index, and
//! reasoning arrives in `reasoning_content` / `reasoning` or inside `<think>` tags in the text,
//! split out here even when a tag is cut across chunks. A call that fails before any of its
//! output was used is tried again (5 attempts, waits from 2 s doubling, Retry-After honoured).
use super::cancel::Cancel;
use super::sse::{SseEvent, SseParser};
use super::util;
use futures::StreamExt;
use reqwest::header::{HeaderMap, ACCEPT, CONTENT_TYPE};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Something a streaming reply produced, in order.
#[derive(Clone, Debug, PartialEq)]
pub enum Piece {
    Text(String),
    Reasoning(String),
    /// A tool call began: its place among the reply's calls, and its name.
    ToolStart { index: usize, name: String },
    /// The call waits before it tries again: a plain sentence for the person.
    Wait(String),
    /// A `</think>` came without its `<think>` (the template opened it): the text so far was
    /// reasoning. The reply's record is put right; the screen, which has shown that text already,
    /// gets the answer after it as a message of its own, so the two never run together.
    Rethink,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct RawCall {
    /// Its place in the stream (what `Piece::ToolStart` named); `usize::MAX` for a call the
    /// model wrote as text.
    pub index: usize,
    pub id: String,
    pub name: String,
    /// As the model wrote them (normally a JSON object).
    pub arguments: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tokens {
    pub prompt: u64,
    pub completion: u64,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Reply {
    pub text: String,
    pub reasoning: String,
    pub calls: Vec<RawCall>,
    /// `stop`, `tool_calls`, `length`...
    pub finish: Option<String>,
    pub usage: Option<Tokens>,
}

impl Reply {
    /// The reply stopped at the output limit.
    pub fn cut_off(&self) -> bool {
        self.finish.as_deref() == Some("length")
    }
}

#[derive(Debug)]
pub enum CallError {
    /// The person stopped it; what streamed so far.
    Cancelled(Reply),
    /// The request does not fit the model's context window.
    Overflow(String),
    /// Anything else, in plain words, with what streamed so far.
    Failed { message: String, partial: Reply },
}

pub struct Request<'a> {
    pub model: &'a str,
    pub messages: &'a [Value],
    pub tools: &'a [Value],
    /// Keep the tools in the prompt but ask for a plain reply (the closing message).
    pub no_tools: bool,
    pub max_tokens: u32,
    pub temperature: Option<f64>,
    pub top_p: Option<f64>,
}

#[derive(Clone, Debug)]
pub struct RetryPolicy {
    pub attempts: u32,
    pub first: Duration,
    /// The longest wait a Retry-After may ask for; a longer one fails the call at once.
    pub longest: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        RetryPolicy { attempts: 5, first: Duration::from_secs(2), longest: Duration::from_secs(300) }
    }
}

pub struct Llm {
    http: reqwest::Client,
    base: String,
    key: String,
    stream_usage: AtomicBool,
    pub retry: RetryPolicy,
    /// How long the relay may take to start a reply (a long prompt is read first).
    pub first_byte: Duration,
    /// How long a reply may pause between chunks.
    pub idle: Duration,
    /// How long to wait for the end of a stream after its finish_reason.
    pub finish_grace: Duration,
}

/// Why one attempt failed.
enum Attempt {
    Cancelled(Box<Reply>),
    UsageRefused,
    Overflow(String),
    Retry { message: String, wait: Option<Duration> },
    Fatal { message: String, partial: Box<Reply> },
}

impl Llm {
    pub fn new(base: &str, key: &str) -> anyhow::Result<Llm> {
        let http = reqwest::Client::builder()
            .no_proxy()
            .connect_timeout(Duration::from_secs(10))
            .tcp_keepalive(Duration::from_secs(30))
            .user_agent(concat!("yougori-harness/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| anyhow::anyhow!("Cannot set up the model client: {e}"))?;
        Ok(Llm {
            http,
            base: base.trim_end_matches('/').to_owned(),
            key: key.to_owned(),
            stream_usage: AtomicBool::new(true),
            retry: RetryPolicy::default(),
            first_byte: Duration::from_secs(300),
            idle: Duration::from_secs(180),
            finish_grace: Duration::from_secs(5),
        })
    }

    /// One chat completion, streamed through `on`.
    pub async fn chat(
        &self,
        request: &Request<'_>,
        cancel: &Cancel,
        on: &mut (dyn FnMut(Piece) + Send),
    ) -> Result<Reply, CallError> {
        let mut attempt = 1u32;
        loop {
            let usage = self.stream_usage.load(Ordering::Relaxed);
            let (message, wait) = match self.attempt(request, usage, cancel, on).await {
                Ok(reply) => return Ok(reply),
                Err(Attempt::Cancelled(partial)) => return Err(CallError::Cancelled(*partial)),
                Err(Attempt::Overflow(message)) => return Err(CallError::Overflow(message)),
                Err(Attempt::Fatal { message, partial }) => return Err(CallError::Failed { message, partial: *partial }),
                Err(Attempt::UsageRefused) => {
                    // The server takes no `stream_options`: ask again without, from now on.
                    self.stream_usage.store(false, Ordering::Relaxed);
                    continue;
                }
                Err(Attempt::Retry { message, wait }) => (message, wait),
            };
            if attempt >= self.retry.attempts {
                let message = format!("{message} Tried {attempt} times.");
                return Err(CallError::Failed { message, partial: Reply::default() });
            }
            let delay = match wait {
                Some(asked) if asked > self.retry.longest => {
                    let how_long = if asked == Duration::MAX {
                        format!("more than {} s", self.retry.longest.as_secs())
                    } else {
                        format!("{} s", asked.as_secs())
                    };
                    let message = format!("{message} It asked to wait {how_long}; try again later.");
                    return Err(CallError::Failed { message, partial: Reply::default() });
                }
                Some(asked) => asked,
                None => self.retry.first.mul_f64(2f64.powi(attempt as i32 - 1) * util::jitter()),
            };
            attempt += 1;
            on(Piece::Wait(format!(
                "{message} Trying again in {} ({attempt} of {}).",
                seconds(delay),
                self.retry.attempts
            )));
            tokio::select! {
                _ = cancel.cancelled() => return Err(CallError::Cancelled(Reply::default())),
                _ = tokio::time::sleep(delay) => {}
            }
        }
    }

    /// The models the relay serves (`GET /models`).
    pub async fn models(&self) -> Result<Vec<String>, String> {
        let send = self.http.get(format!("{}/models", self.base)).bearer_auth(&self.key).send();
        let response = tokio::time::timeout(Duration::from_secs(15), send)
            .await
            .map_err(|_| "The inference relay did not answer in time.".to_owned())?
            .map_err(|e| self.transport(&e))?;
        let status = response.status().as_u16();
        let body = tokio::time::timeout(Duration::from_secs(15), response.text())
            .await
            .map_err(|_| "The inference relay did not answer in time.".to_owned())?
            .map_err(|e| self.transport(&e))?;
        if !(200..300).contains(&status) {
            return Err(format!("The inference relay answered {status}: {}", server_message(&body)));
        }
        let value: Value = serde_json::from_str(&body).map_err(|_| "The model list is not JSON.".to_owned())?;
        Ok(value["data"]
            .as_array()
            .map(|items| items.iter().filter_map(|m| m["id"].as_str().map(str::to_owned)).collect())
            .unwrap_or_default())
    }

    fn body(&self, request: &Request<'_>, usage: bool) -> Value {
        let mut body = json!({
            "model": request.model,
            "messages": request.messages,
            "stream": true,
            "max_tokens": request.max_tokens,
        });
        if !request.tools.is_empty() {
            body["tools"] = Value::Array(request.tools.to_vec());
            body["tool_choice"] = json!(if request.no_tools { "none" } else { "auto" });
        }
        if usage {
            body["stream_options"] = json!({ "include_usage": true });
        }
        if let Some(temperature) = request.temperature {
            body["temperature"] = json!(temperature);
        }
        if let Some(top_p) = request.top_p {
            body["top_p"] = json!(top_p);
        }
        body
    }

    async fn attempt(
        &self,
        request: &Request<'_>,
        usage: bool,
        cancel: &Cancel,
        on: &mut (dyn FnMut(Piece) + Send),
    ) -> Result<Reply, Attempt> {
        let body = self.body(request, usage);
        let send = self
            .http
            .post(format!("{}/chat/completions", self.base))
            .bearer_auth(&self.key)
            .header(ACCEPT, "text/event-stream, application/json")
            .json(&body)
            .send();
        let response = tokio::select! {
            _ = cancel.cancelled() => return Err(Attempt::Cancelled(Box::default())),
            sent = tokio::time::timeout(self.first_byte, send) => match sent {
                Err(_) => return Err(Attempt::Retry { message: "The inference did not answer in time.".into(), wait: None }),
                Ok(Err(error)) => return Err(Attempt::Retry { message: self.transport(&error), wait: None }),
                Ok(Ok(response)) => response,
            },
        };
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        if !(200..300).contains(&status) {
            let wait = retry_after(response.headers());
            let body = read_text(response, 64 * 1024, cancel).await;
            if cancel.is_cancelled() {
                return Err(Attempt::Cancelled(Box::default()));
            }
            return Err(status_error(status, &server_message(&body), wait, usage));
        }
        let mut collect = Collect::new();
        if content_type.starts_with("application/json") {
            // A server that ignores `stream: true` sends the whole completion at once.
            let body = read_text(response, 32 * 1024 * 1024, cancel).await;
            if cancel.is_cancelled() {
                return Err(Attempt::Cancelled(Box::default()));
            }
            let value: Value = serde_json::from_str(&body).map_err(|_| Attempt::Retry {
                message: "The inference sent a reply that is not JSON.".into(),
                wait: None,
            })?;
            collect.whole(&value, on)?;
            return Ok(collect.reply(on));
        }
        let mut stream = response.bytes_stream();
        let mut parser = SseParser::default();
        let mut done = false;
        while !done {
            // After finish_reason only a usage chunk and [DONE] may follow: a server that sends
            // neither and keeps the connection open is not waited on for long.
            let wait = if collect.finish.is_some() {
                self.finish_grace
            } else if collect.started {
                self.idle
            } else {
                self.first_byte
            };
            let next = tokio::select! {
                _ = cancel.cancelled() => return Err(Attempt::Cancelled(Box::new(collect.reply(on)))),
                next = tokio::time::timeout(wait, stream.next()) => next,
            };
            let bytes = match next {
                Err(_) if collect.finish.is_some() => break,
                Err(_) => return Err(collect.broken("The inference stopped sending the reply.")),
                Ok(None) => break,
                Ok(Some(Err(error))) => return Err(collect.broken(&self.transport(&error))),
                Ok(Some(Ok(bytes))) => bytes,
            };
            collect.started = true;
            for event in parser.push(&bytes) {
                if collect.event(&event, on)? {
                    done = true;
                    break;
                }
            }
        }
        if !done {
            for event in parser.finish() {
                if collect.event(&event, on)? {
                    done = true;
                }
            }
        }
        if !done && collect.finish.is_none() {
            return Err(collect.broken("The connection closed before the reply ended."));
        }
        Ok(collect.reply(on))
    }

    fn transport(&self, error: &reqwest::Error) -> String {
        let cause = root_cause(error);
        if error.is_connect() {
            format!("Cannot reach the inference relay at {}: {cause}.", self.base)
        } else if error.is_timeout() {
            "The inference relay did not answer in time.".into()
        } else {
            format!("The connection to the inference relay failed: {cause}.")
        }
    }
}

/// The innermost cause of an error, as one sentence without its final stop.
pub fn root_cause(error: &(dyn std::error::Error + 'static)) -> String {
    let mut current = error;
    while let Some(next) = current.source() {
        current = next;
    }
    current.to_string().trim_end_matches('.').to_owned()
}

fn seconds(duration: Duration) -> String {
    let secs = duration.as_secs_f64();
    if secs >= 10.0 || secs.fract() < 0.05 {
        format!("{secs:.0} s")
    } else {
        format!("{secs:.1} s")
    }
}

async fn read_text(response: reqwest::Response, limit: usize, cancel: &Cancel) -> String {
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    loop {
        let next = tokio::select! {
            _ = cancel.cancelled() => break,
            next = tokio::time::timeout(Duration::from_secs(60), stream.next()) => next,
        };
        match next {
            Ok(Some(Ok(bytes))) => {
                body.extend_from_slice(&bytes);
                if body.len() >= limit {
                    body.truncate(limit);
                    break;
                }
            }
            _ => break,
        }
    }
    String::from_utf8_lossy(&body).into_owned()
}

fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok()).map(str::trim);
    if let Some(wait) = header("retry-after-ms").and_then(|v| v.parse::<f64>().ok()).and_then(|ms| wait_of(ms / 1000.0)) {
        return Some(wait);
    }
    let value = header("retry-after")?;
    if let Ok(secs) = value.parse::<f64>() {
        return wait_of(secs);
    }
    let at = util::http_date(value)?;
    Some(Duration::from_secs(at.saturating_sub(util::unix_now())))
}

/// A wait a server asked for in seconds: None when it is no number of seconds, the longest wait
/// there is when it is too long to count (it then fails the call as too long to wait).
fn wait_of(secs: f64) -> Option<Duration> {
    if !secs.is_finite() || secs < 0.0 {
        return None;
    }
    if secs == 0.0 {
        return Some(Duration::ZERO);
    }
    Some(Duration::try_from_secs_f64(secs).unwrap_or(Duration::MAX))
}

fn status_error(status: u16, message: &str, wait: Option<Duration>, usage: bool) -> Attempt {
    let detail = if message.is_empty() { String::new() } else { format!(": {message}") };
    if usage && matches!(status, 400 | 422) && message.to_ascii_lowercase().contains("stream_options") {
        return Attempt::UsageRefused;
    }
    if matches!(status, 400 | 413 | 422 | 500) && is_overflow(message) {
        return Attempt::Overflow(message.to_owned());
    }
    match status {
        429 => Attempt::Retry { message: format!("The inference is busy (429){detail}."), wait },
        408 => Attempt::Retry { message: "The inference timed out (408).".into(), wait },
        409 | 425 | 500 | 502 | 503 | 504 | 529 => {
            Attempt::Retry { message: format!("The inference failed ({status}){detail}."), wait }
        }
        401 | 403 => Attempt::Fatal {
            message: format!("The inference refused the request ({status}){detail}."),
            partial: Box::default(),
        },
        404 => Attempt::Fatal {
            message: format!("The inference relay found no such model or address (404){detail}."),
            partial: Box::default(),
        },
        400 | 422 => Attempt::Fatal {
            message: format!("The inference rejected the request ({status}){detail}."),
            partial: Box::default(),
        },
        _ => Attempt::Fatal { message: format!("The inference answered {status}{detail}."), partial: Box::default() },
    }
}

/// Whether an error message says the request is longer than the model's context.
pub fn is_overflow(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    [
        "context length",
        "context_length",
        "maximum context",
        "context window",
        "context size",
        "exceed_context",
        "too many tokens",
        "prompt is too long",
        "input is too long",
        "max_model_len",
        "maximum model length",
        "reduce the length of the messages",
    ]
    .iter()
    .any(|pattern| message.contains(pattern))
}

/// The message inside a server's error body (JSON or text), on one line.
pub fn server_message(body: &str) -> String {
    let trimmed = body.trim();
    if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
        let message = message_of(&value);
        if !message.is_empty() {
            return message;
        }
    }
    util::one_line(trimmed, 300)
}

fn message_of(value: &Value) -> String {
    for candidate in [&value["error"]["message"], &value["error"], &value["message"], &value["detail"]] {
        if let Value::String(text) = candidate {
            if !text.trim().is_empty() {
                return util::one_line(text, 400);
            }
        }
    }
    if let Some(items) = value["detail"].as_array() {
        let parts: Vec<String> = items.iter().filter_map(|i| i["msg"].as_str().map(str::to_owned)).collect();
        if !parts.is_empty() {
            return util::one_line(&parts.join("; "), 400);
        }
    }
    String::new()
}

const THINK_OPEN: &str = "<think>";
const THINK_CLOSE: &str = "</think>";
const CALL_OPEN: &str = "<tool_call>";
const CALL_CLOSE: &str = "</tool_call>";
/// Gemma 4 writes its thinking as `<|channel>thought\n…<channel|>`; the first line names the channel.
const CHANNEL_OPEN: &str = "<|channel>";
const CHANNEL_CLOSE: &str = "<channel|>";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Section {
    #[default]
    Text,
    Think,
    Call,
    /// The channel's name, up to the end of its line: not shown.
    ChannelName,
    /// A channel's text: reasoning.
    Channel,
}

/// Splits streamed text into visible text, reasoning (`<think>` blocks and Gemma's channel
/// blocks) and `<tool_call>` blocks that a server left in the text, holding back any tail that
/// could be the start of a tag.
pub struct Splitter {
    section: Section,
    pending: String,
    call: String,
    /// Tool calls written as text, for servers that did not parse them.
    pub calls: Vec<String>,
    trim_start: bool,
}

impl Default for Splitter {
    fn default() -> Self {
        Splitter { section: Section::Text, pending: String::new(), call: String::new(), calls: Vec::new(), trim_start: true }
    }
}

impl Splitter {
    pub fn push(&mut self, chunk: &str, out: &mut Vec<Piece>) {
        self.pending.push_str(chunk);
        loop {
            let tags: &[&str] = match self.section {
                Section::Text => &[THINK_OPEN, CALL_OPEN, THINK_CLOSE, CHANNEL_OPEN, CHANNEL_CLOSE],
                Section::Think => &[THINK_CLOSE],
                Section::Call => &[CALL_CLOSE],
                Section::ChannelName => &["\n", CHANNEL_CLOSE],
                Section::Channel => &[CHANNEL_CLOSE],
            };
            let found = tags
                .iter()
                .filter_map(|tag| self.pending.find(tag).map(|at| (at, *tag)))
                .min_by_key(|(at, _)| *at);
            match found {
                Some((at, tag)) => {
                    let before = self.pending[..at].to_owned();
                    self.emit(&before, out);
                    self.pending.drain(..at + tag.len());
                    self.section = match (self.section, tag) {
                        (_, THINK_OPEN) => Section::Think,
                        (_, CALL_OPEN) => Section::Call,
                        (_, CHANNEL_OPEN) => Section::ChannelName,
                        (Section::ChannelName, "\n") => Section::Channel,
                        (section, _) => {
                            if section == Section::Call {
                                self.calls.push(std::mem::take(&mut self.call));
                            } else if section == Section::Text {
                                // A close the template opened: the text so far was reasoning.
                                out.push(Piece::Rethink);
                            }
                            // Text after a reasoning block starts without its blank lines.
                            self.trim_start = true;
                            Section::Text
                        }
                    };
                }
                None => {
                    let keep = tags.iter().map(|tag| partial_tag(&self.pending, tag)).max().unwrap_or(0);
                    let cut = self.pending.len() - keep;
                    let head = self.pending[..cut].to_owned();
                    self.pending.drain(..cut);
                    self.emit(&head, out);
                    return;
                }
            }
        }
    }

    /// The text ended: flush what was held back.
    pub fn finish(&mut self, out: &mut Vec<Piece>) {
        let rest = std::mem::take(&mut self.pending);
        self.emit(&rest, out);
        if self.section == Section::Call && !self.call.trim().is_empty() {
            self.calls.push(std::mem::take(&mut self.call));
        }
        self.section = Section::Text;
    }

    fn emit(&mut self, text: &str, out: &mut Vec<Piece>) {
        if text.is_empty() {
            return;
        }
        match self.section {
            Section::Text => {
                let text = if self.trim_start { text.trim_start() } else { text };
                if text.is_empty() {
                    return;
                }
                self.trim_start = false;
                out.push(Piece::Text(text.to_owned()));
            }
            Section::Think | Section::Channel => out.push(Piece::Reasoning(text.to_owned())),
            Section::Call => self.call.push_str(text),
            Section::ChannelName => {}
        }
    }
}

/// How many bytes at the end of `text` could begin `tag`.
fn partial_tag(text: &str, tag: &str) -> usize {
    (1..tag.len().min(text.len() + 1)).rev().find(|&k| text.ends_with(&tag[..k])).unwrap_or(0)
}

#[derive(Default)]
struct Slot {
    index: Option<u64>,
    id: String,
    name: String,
    arguments: String,
    announced: bool,
}

/// One reply being put together.
struct Collect {
    splitter: Splitter,
    slots: Vec<Slot>,
    text: String,
    reasoning: String,
    finish: Option<String>,
    usage: Option<Tokens>,
    /// Some output reached the person: the call can no longer be tried again.
    used: bool,
    started: bool,
}

impl Collect {
    fn new() -> Self {
        Collect {
            splitter: Splitter::default(),
            slots: Vec::new(),
            text: String::new(),
            reasoning: String::new(),
            finish: None,
            usage: None,
            used: false,
            started: false,
        }
    }

    fn emit(&mut self, piece: Piece, on: &mut (dyn FnMut(Piece) + Send)) {
        match &piece {
            Piece::Text(text) => self.text.push_str(text),
            Piece::Reasoning(text) => self.reasoning.push_str(text),
            Piece::Rethink => {
                let before = std::mem::take(&mut self.text);
                self.reasoning = format!("{before}{}", self.reasoning);
                // Not output of its own: it only tells the screen where the answer starts.
                on(piece);
                return;
            }
            _ => {}
        }
        self.used = true;
        on(piece);
    }

    /// One server-sent event; true at `[DONE]`.
    fn event(&mut self, event: &SseEvent, on: &mut (dyn FnMut(Piece) + Send)) -> Result<bool, Attempt> {
        let data = event.data.trim();
        if data.is_empty() {
            return Ok(false);
        }
        if data == "[DONE]" {
            return Ok(true);
        }
        let value: Value = match serde_json::from_str(data) {
            Ok(value) => value,
            Err(_) if event.event == "error" => return Err(self.failure(data)),
            Err(_) => return Ok(false),
        };
        if event.event == "error" || value.get("error").is_some_and(|e| !e.is_null()) {
            let message = message_of(&value);
            let message = if message.is_empty() { util::one_line(data, 300) } else { message };
            return Err(self.failure(&message));
        }
        self.chunk(&value, on);
        Ok(false)
    }

    /// A whole (not streamed) completion.
    fn whole(&mut self, value: &Value, on: &mut (dyn FnMut(Piece) + Send)) -> Result<(), Attempt> {
        if value.get("error").is_some_and(|e| !e.is_null()) {
            return Err(self.failure(&message_of(value)));
        }
        if let Some(usage) = value.get("usage") {
            self.usage = usage_of(usage).or(self.usage);
        }
        if let Some(choice) = value["choices"].as_array().and_then(|c| c.first()) {
            let message = &choice["message"];
            self.delta(message, true, on);
            if let Some(reason) = choice["finish_reason"].as_str() {
                self.finish = Some(reason.to_owned());
            }
        }
        if self.finish.is_none() {
            self.finish = Some("stop".into());
        }
        Ok(())
    }

    fn chunk(&mut self, value: &Value, on: &mut (dyn FnMut(Piece) + Send)) {
        if let Some(usage) = value.get("usage") {
            self.usage = usage_of(usage).or(self.usage);
        }
        let Some(choices) = value.get("choices").and_then(Value::as_array) else { return };
        for choice in choices {
            if choice.get("index").and_then(Value::as_u64).unwrap_or(0) != 0 {
                continue;
            }
            if let Some(delta) = choice.get("delta").filter(|d| d.is_object()) {
                self.delta(delta, false, on);
            } else if let Some(message) = choice.get("message").filter(|m| m.is_object()) {
                self.delta(message, true, on);
            }
            if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
                self.finish = Some(reason.to_owned());
            }
        }
    }

    fn delta(&mut self, delta: &Value, whole: bool, on: &mut (dyn FnMut(Piece) + Send)) {
        // Some servers send both names with the same text: take the first one present.
        let reasoning = ["reasoning_content", "reasoning"].iter().find_map(|key| delta.get(*key).and_then(Value::as_str));
        if let Some(text) = reasoning.filter(|t| !t.is_empty()) {
            self.emit(Piece::Reasoning(text.to_owned()), on);
        }
        let content = match delta.get("content") {
            Some(Value::String(text)) => text.clone(),
            Some(Value::Array(parts)) => parts.iter().filter_map(|p| p["text"].as_str()).collect(),
            _ => String::new(),
        };
        if !content.is_empty() {
            let mut pieces = Vec::new();
            self.splitter.push(&content, &mut pieces);
            for piece in pieces {
                self.emit(piece, on);
            }
        }
        if let Some(items) = delta.get("tool_calls").and_then(Value::as_array) {
            self.tool_deltas(items, whole, on);
        }
    }

    fn tool_deltas(&mut self, items: &[Value], whole: bool, on: &mut (dyn FnMut(Piece) + Send)) {
        for (position, item) in items.iter().enumerate() {
            let index = item.get("index").and_then(Value::as_u64).or(whole.then_some(position as u64));
            let id = item.get("id").and_then(Value::as_str).unwrap_or("");
            let slot = match index {
                Some(index) => match self.slots.iter().position(|s| s.index == Some(index)) {
                    Some(at) => at,
                    None => {
                        self.slots.push(Slot { index: Some(index), ..Slot::default() });
                        self.slots.len() - 1
                    }
                },
                None if !id.is_empty() => match self.slots.iter().position(|s| s.id == id) {
                    Some(at) => at,
                    None => {
                        self.slots.push(Slot::default());
                        self.slots.len() - 1
                    }
                },
                None if self.slots.is_empty() => {
                    self.slots.push(Slot::default());
                    0
                }
                None => self.slots.len() - 1,
            };
            let function = item.get("function").unwrap_or(&Value::Null);
            let entry = &mut self.slots[slot];
            if !id.is_empty() && entry.id.is_empty() {
                entry.id = id.to_owned();
            }
            if let Some(name) = function.get("name").and_then(Value::as_str) {
                if entry.name.is_empty() {
                    entry.name = name.trim().to_owned();
                }
            }
            match function.get("arguments") {
                Some(Value::String(part)) => entry.arguments.push_str(part),
                Some(value @ Value::Object(_)) => entry.arguments = value.to_string(),
                _ => {}
            }
            if !entry.announced && !entry.name.is_empty() {
                entry.announced = true;
                let name = entry.name.clone();
                self.emit(Piece::ToolStart { index: slot, name }, on);
            }
        }
    }

    fn failure(&mut self, message: &str) -> Attempt {
        if !self.used && is_overflow(message) {
            return Attempt::Overflow(message.to_owned());
        }
        if self.used {
            Attempt::Fatal { message: format!("The inference failed during the reply: {message}"), partial: Box::new(self.partial()) }
        } else {
            Attempt::Retry { message: format!("The inference failed: {message}"), wait: None }
        }
    }

    /// The stream broke: tried again unless output was already used.
    fn broken(&mut self, message: &str) -> Attempt {
        if self.used {
            Attempt::Fatal { message: message.to_owned(), partial: Box::new(self.partial()) }
        } else {
            Attempt::Retry { message: message.to_owned(), wait: None }
        }
    }

    fn partial(&self) -> Reply {
        Reply {
            text: self.text.trim().to_owned(),
            reasoning: self.reasoning.trim().to_owned(),
            calls: Vec::new(),
            finish: None,
            usage: self.usage,
        }
    }

    fn reply(&mut self, on: &mut (dyn FnMut(Piece) + Send)) -> Reply {
        let mut pieces = Vec::new();
        self.splitter.finish(&mut pieces);
        for piece in pieces {
            self.emit(piece, on);
        }
        let mut calls: Vec<RawCall> = self
            .slots
            .iter()
            .enumerate()
            .filter(|(_, s)| !(s.name.is_empty() && s.arguments.trim().is_empty()))
            .map(|(index, s)| RawCall { index, id: s.id.clone(), name: s.name.clone(), arguments: s.arguments.clone() })
            .collect();
        if calls.is_empty() {
            calls = self.splitter.calls.iter().map(|text| text_call(text)).collect();
        }
        Reply {
            text: self.text.trim().to_owned(),
            reasoning: self.reasoning.trim().to_owned(),
            calls,
            finish: self.finish.clone(),
            usage: self.usage,
        }
    }
}

fn usage_of(value: &Value) -> Option<Tokens> {
    let prompt = value.get("prompt_tokens").and_then(Value::as_u64)?;
    let completion = value.get("completion_tokens").and_then(Value::as_u64).unwrap_or(0);
    Some(Tokens { prompt, completion })
}

/// A tool call the model wrote as text (`{"name": ..., "arguments": {...}}`).
fn text_call(text: &str) -> RawCall {
    let trimmed = text.trim().trim_start_matches("```json").trim_start_matches("```").trim_end_matches("```").trim();
    if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
        let body = if value.get("function").is_some_and(Value::is_object) { &value["function"] } else { &value };
        if let Some(name) = body["name"].as_str() {
            let arguments = match body.get("arguments").or_else(|| body.get("parameters")) {
                Some(Value::String(text)) => text.clone(),
                Some(value) => value.to_string(),
                None => "{}".into(),
            };
            return RawCall { index: usize::MAX, id: String::new(), name: name.to_owned(), arguments };
        }
    }
    RawCall { index: usize::MAX, id: String::new(), name: String::new(), arguments: trimmed.to_owned() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::testutil::{sse_body, FakeServer, Reply as HttpReply};
    use std::sync::{Arc, Mutex};

    fn split(chunks: &[&str]) -> Vec<Piece> {
        let mut splitter = Splitter::default();
        let mut out = Vec::new();
        for chunk in chunks {
            splitter.push(chunk, &mut out);
        }
        splitter.finish(&mut out);
        merge(out)
    }

    /// Adjacent pieces of the same kind joined, as the screen shows them.
    fn merge(pieces: Vec<Piece>) -> Vec<Piece> {
        let mut out: Vec<Piece> = Vec::new();
        for piece in pieces {
            match (out.last_mut(), piece) {
                (Some(Piece::Text(a)), Piece::Text(b)) => a.push_str(&b),
                (Some(Piece::Reasoning(a)), Piece::Reasoning(b)) => a.push_str(&b),
                (_, piece) => out.push(piece),
            }
        }
        out
    }

    #[test]
    fn think_tags_split_across_chunks() {
        let pieces = split(&["Hel", "lo <thi", "nk>reason", "ing</th", "ink>\n\nworld <", "b>"]);
        assert_eq!(
            pieces,
            vec![Piece::Text("Hello ".into()), Piece::Reasoning("reasoning".into()), Piece::Text("world <b>".into())]
        );
        // A reply that opens with reasoning, one character at a time.
        let text = "<think>plan it</think>Done.";
        let chars: Vec<String> = text.chars().map(String::from).collect();
        let refs: Vec<&str> = chars.iter().map(String::as_str).collect();
        assert_eq!(split(&refs), vec![Piece::Reasoning("plan it".into()), Piece::Text("Done.".into())]);
        // An unclosed think block at the end is still reasoning.
        assert_eq!(split(&["<think>still thinking"]), vec![Piece::Reasoning("still thinking".into())]);
        // A close without an open: what came before was reasoning.
        assert_eq!(
            split(&["planning it</th", "ink>

Answer."]),
            vec![Piece::Text("planning it".into()), Piece::Rethink, Piece::Text("Answer.".into())]
        );
    }

    #[test]
    fn gemma_channel_blocks_are_reasoning() {
        // Gemma 4 through llama.cpp: an empty thinking block, then the answer.
        assert_eq!(split(&["<|channel>", "thought", "\n", "<channel|>", "ready"]), vec![Piece::Text("ready".into())]);
        assert_eq!(split(&["<|channel>thought\n<channel|>ready"]), vec![Piece::Text("ready".into())]);
        // One character at a time, the channel's name left out.
        let text = "<|channel>thought\nplan it<channel|>\n\nDone.";
        let chars: Vec<String> = text.chars().map(String::from).collect();
        let refs: Vec<&str> = chars.iter().map(String::as_str).collect();
        assert_eq!(split(&refs), vec![Piece::Reasoning("plan it".into()), Piece::Text("Done.".into())]);
        // Cut off while thinking: still reasoning. A block closed on its name line shows nothing.
        assert_eq!(split(&["<|channel>thought\nstill"]), vec![Piece::Reasoning("still".into())]);
        assert_eq!(split(&["<|channel>thought<channel|>Done."]), vec![Piece::Text("Done.".into())]);
        // A close the template opened: what came before was reasoning.
        assert_eq!(
            split(&["planning it<chan", "nel|>Answer."]),
            vec![Piece::Text("planning it".into()), Piece::Rethink, Piece::Text("Answer.".into())]
        );
    }

    #[test]
    fn tool_calls_written_as_text_are_found() {
        let mut splitter = Splitter::default();
        let mut out = Vec::new();
        splitter.push("Let me look.<tool_", &mut out);
        splitter.push("call>{\"name\": \"read\", \"arguments\": {\"path\": \"a.rs\"}}</tool_call>", &mut out);
        splitter.finish(&mut out);
        assert_eq!(merge(out), vec![Piece::Text("Let me look.".into())]);
        let call = text_call(&splitter.calls[0]);
        assert_eq!(call.name, "read");
        assert_eq!(serde_json::from_str::<Value>(&call.arguments).unwrap(), json!({"path": "a.rs"}));
    }

    fn quick(server: &FakeServer) -> Llm {
        let mut llm = Llm::new(&server.url, "solver-local-relay").unwrap();
        llm.retry.first = Duration::from_millis(20);
        llm.first_byte = Duration::from_secs(5);
        llm.idle = Duration::from_secs(5);
        llm
    }

    fn request<'a>(messages: &'a [Value]) -> Request<'a> {
        Request { model: "m", messages, tools: &[], no_tools: false, max_tokens: 100, temperature: None, top_p: None }
    }

    async fn chat(llm: &Llm, cancel: &Cancel) -> (Result<Reply, CallError>, Vec<Piece>) {
        let messages = vec![json!({"role": "user", "content": "hi"})];
        let mut pieces = Vec::new();
        let result = llm.chat(&request(&messages), cancel, &mut |p| pieces.push(p)).await;
        (result, pieces)
    }

    #[tokio::test]
    async fn streamed_tool_call_deltas_are_assembled_by_index() {
        let body = sse_body(&[
            json!({"choices": [{"index": 0, "delta": {"role": "assistant", "content": ""}}]}),
            json!({"choices": [{"index": 0, "delta": {"reasoning_content": "Need the file."}}]}),
            json!({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "id": "call_1", "type": "function", "function": {"name": "read", "arguments": ""}}]}}]}),
            json!({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "function": {"arguments": "{\"pa"}}]}}]}),
            json!({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 1, "id": "call_2", "function": {"name": "grep", "arguments": "{\"pattern\":"}}]}}]}),
            json!({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "function": {"arguments": "th\": \"a.rs\"}"}}]}}]}),
            json!({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 1, "function": {"arguments": " \"x\"}"}}]}}]}),
            json!({"choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]}),
            json!({"choices": [], "usage": {"prompt_tokens": 120, "completion_tokens": 30}}),
        ]);
        let server = FakeServer::start(move |_, _| HttpReply::sse(body.clone())).await;
        let (result, pieces) = chat(&quick(&server), &Cancel::new()).await;
        let reply = result.unwrap();
        assert_eq!(reply.calls.len(), 2);
        assert_eq!((reply.calls[0].id.as_str(), reply.calls[0].name.as_str()), ("call_1", "read"));
        assert_eq!(reply.calls[0].arguments, "{\"path\": \"a.rs\"}");
        assert_eq!(reply.calls[1].arguments, "{\"pattern\": \"x\"}");
        assert_eq!(reply.reasoning, "Need the file.");
        assert_eq!(reply.usage, Some(Tokens { prompt: 120, completion: 30 }));
        assert_eq!(reply.finish.as_deref(), Some("tool_calls"));
        let starts: Vec<_> = pieces.iter().filter(|p| matches!(p, Piece::ToolStart { .. })).collect();
        assert_eq!(
            starts,
            vec![
                &Piece::ToolStart { index: 0, name: "read".into() },
                &Piece::ToolStart { index: 1, name: "grep".into() }
            ]
        );
        let sent: Value = serde_json::from_str(&server.requests()[0].body).unwrap();
        assert_eq!(sent["stream"], json!(true));
        assert_eq!(sent["stream_options"], json!({"include_usage": true}));
        assert_eq!(server.requests()[0].header("authorization").as_deref(), Some("Bearer solver-local-relay"));
    }

    #[tokio::test]
    async fn think_tags_in_streamed_content_become_reasoning() {
        let body = sse_body(&[
            json!({"choices": [{"delta": {"content": "<thi"}}]}),
            json!({"choices": [{"delta": {"content": "nk>Check the"}}]}),
            json!({"choices": [{"delta": {"content": " tests.</thi"}}]}),
            json!({"choices": [{"delta": {"content": "nk>All good."}, "finish_reason": "stop"}]}),
        ]);
        let server = FakeServer::start(move |_, _| HttpReply::sse(body.clone())).await;
        let (result, pieces) = chat(&quick(&server), &Cancel::new()).await;
        let reply = result.unwrap();
        assert_eq!(reply.reasoning, "Check the tests.");
        assert_eq!(reply.text, "All good.");
        assert_eq!(merge(pieces), vec![Piece::Reasoning("Check the tests.".into()), Piece::Text("All good.".into())]);
    }

    #[tokio::test]
    async fn a_close_tag_without_its_open_tag_keeps_the_answer_apart() {
        let body = sse_body(&[
            json!({"choices": [{"delta": {"content": "Let me see.</think>"}}]}),
            json!({"choices": [{"delta": {"content": "\n\nThe answer."}, "finish_reason": "stop"}]}),
        ]);
        let server = FakeServer::start(move |_, _| HttpReply::sse(body.clone())).await;
        let (result, pieces) = chat(&quick(&server), &Cancel::new()).await;
        let reply = result.unwrap();
        assert_eq!((reply.text.as_str(), reply.reasoning.as_str()), ("The answer.", "Let me see."));
        // The screen learns where the answer starts, so it does not join it to the text before.
        assert_eq!(merge(pieces), vec![Piece::Text("Let me see.".into()), Piece::Rethink, Piece::Text("The answer.".into())]);
    }

    #[tokio::test]
    async fn a_retry_after_too_long_to_count_fails_the_call_plainly() {
        let mut headers = HeaderMap::new();
        for (value, wanted) in [
            ("1e20", Some(Duration::MAX)),
            ("2.5", Some(Duration::from_millis(2500))),
            ("0", Some(Duration::ZERO)),
            ("-1", None),
            ("NaN", None),
            ("inf", None),
        ] {
            headers.insert("retry-after", value.parse().unwrap());
            assert_eq!(retry_after(&headers), wanted, "{value}");
        }
        headers.clear();
        headers.insert("retry-after-ms", "1e23".parse().unwrap());
        assert_eq!(retry_after(&headers), Some(Duration::MAX));
        // A server that asks for an absurd wait ends the call at once, without a panic.
        let server = FakeServer::start(|_, _| {
            HttpReply::json(429, json!({"error": {"message": "slow down"}})).header("Retry-After", "1e20")
        })
        .await;
        let (result, _) = chat(&quick(&server), &Cancel::new()).await;
        match result {
            Err(CallError::Failed { message, .. }) => {
                assert!(message.contains("busy (429)") && message.contains("more than 300 s; try again later"), "{message}")
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(server.requests().len(), 1);
    }

    #[tokio::test]
    async fn a_429_with_retry_after_is_waited_out() {
        let ok = sse_body(&[json!({"choices": [{"delta": {"content": "fine"}, "finish_reason": "stop"}]})]);
        let server = FakeServer::start(move |index, _| {
            if index == 0 {
                HttpReply::json(429, json!({"error": {"message": "Too many requests"}})).header("Retry-After", "1")
            } else {
                HttpReply::sse(ok.clone())
            }
        })
        .await;
        let started = std::time::Instant::now();
        let (result, pieces) = chat(&quick(&server), &Cancel::new()).await;
        assert_eq!(result.unwrap().text, "fine");
        assert!(started.elapsed() >= Duration::from_millis(900), "Retry-After was not honoured");
        assert_eq!(server.requests().len(), 2);
        let wait = pieces.iter().find_map(|p| if let Piece::Wait(w) = p { Some(w.clone()) } else { None }).unwrap();
        assert!(wait.contains("busy (429)") && wait.contains("1 s") && wait.contains("2 of 5"), "{wait}");
    }

    #[tokio::test]
    async fn five_failures_give_up_with_a_plain_message() {
        let server = FakeServer::start(|_, _| HttpReply::json(503, json!({"error": "loading model"}))).await;
        let (result, _) = chat(&quick(&server), &Cancel::new()).await;
        match result {
            Err(CallError::Failed { message, .. }) => {
                assert_eq!(message, "The inference failed (503): loading model. Tried 5 times.")
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(server.requests().len(), 5);
    }

    #[tokio::test]
    async fn a_context_overflow_is_reported_as_such() {
        let server = FakeServer::start(|_, _| {
            HttpReply::json(
                400,
                json!({"error": {"code": 400, "message": "the request exceeds the available context size, try increasing it", "type": "exceed_context_size_error"}}),
            )
        })
        .await;
        let (result, _) = chat(&quick(&server), &Cancel::new()).await;
        assert!(matches!(result, Err(CallError::Overflow(ref m)) if m.contains("context size")), "{result:?}");
        assert_eq!(server.requests().len(), 1, "an overflow is not retried here");
        assert!(is_overflow("This model's maximum context length is 32768 tokens. However, you requested 33000 tokens"));
        assert!(!is_overflow("Invalid model name"));
    }

    #[tokio::test]
    async fn refused_stream_options_are_dropped_and_remembered() {
        let ok = sse_body(&[json!({"choices": [{"delta": {"content": "hi"}, "finish_reason": "stop"}]})]);
        let server = FakeServer::start(move |_, request| {
            if request.body.contains("stream_options") {
                HttpReply::json(400, json!({"error": {"message": "Unrecognized request argument supplied: stream_options"}}))
            } else {
                HttpReply::sse(ok.clone())
            }
        })
        .await;
        let llm = quick(&server);
        assert_eq!(chat(&llm, &Cancel::new()).await.0.unwrap().text, "hi");
        assert_eq!(chat(&llm, &Cancel::new()).await.0.unwrap().text, "hi");
        assert_eq!(server.requests().len(), 3, "the second call goes straight without stream_options");
    }

    #[tokio::test]
    async fn a_broken_stream_after_output_is_not_retried() {
        let server = FakeServer::start(|_, _| {
            HttpReply::sse(b"data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\n".to_vec())
        })
        .await;
        let (result, _) = chat(&quick(&server), &Cancel::new()).await;
        match result {
            Err(CallError::Failed { message, partial }) => {
                assert!(message.contains("closed before the reply ended"), "{message}");
                assert_eq!(partial.text, "partial");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(server.requests().len(), 1);
    }

    #[tokio::test]
    async fn cancel_stops_a_stream_and_keeps_its_text() {
        let server = FakeServer::start(|_, _| {
            HttpReply::sse_slow(
                vec![
                    b"data: {\"choices\":[{\"delta\":{\"content\":\"one \"}}]}\n\n".to_vec(),
                    b"data: {\"choices\":[{\"delta\":{\"content\":\"two\"}}]}\n\n".to_vec(),
                ],
                Duration::from_secs(10),
            )
        })
        .await;
        let llm = quick(&server);
        let cancel = Cancel::new();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let messages = vec![json!({"role": "user", "content": "hi"})];
        let trigger = cancel.clone();
        let log = seen.clone();
        let started = std::time::Instant::now();
        let result = llm
            .chat(&request(&messages), &cancel, &mut move |piece| {
                log.lock().unwrap().push(piece);
                trigger.cancel();
            })
            .await;
        assert!(started.elapsed() < Duration::from_secs(5));
        match result {
            Err(CallError::Cancelled(partial)) => assert_eq!(partial.text, "one"),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn a_whole_json_reply_is_accepted() {
        let server = FakeServer::start(|_, _| {
            HttpReply::json(
                200,
                json!({"choices": [{"message": {"content": "<think>hm</think>Hi", "tool_calls": [{"id": "a", "function": {"name": "list", "arguments": "{}"}}]}, "finish_reason": "tool_calls"}], "usage": {"prompt_tokens": 9, "completion_tokens": 2}}),
            )
        })
        .await;
        let (result, _) = chat(&quick(&server), &Cancel::new()).await;
        let reply = result.unwrap();
        assert_eq!((reply.text.as_str(), reply.reasoning.as_str()), ("Hi", "hm"));
        assert_eq!(reply.calls[0].name, "list");
        assert_eq!(reply.usage, Some(Tokens { prompt: 9, completion: 2 }));
    }

    #[tokio::test]
    async fn a_stream_left_open_after_its_finish_still_ends() {
        let server = FakeServer::start(|_, _| {
            HttpReply::sse_slow(
                vec![
                    b"data: {\"choices\":[{\"delta\":{\"content\":\"all done\"},\"finish_reason\":\"stop\"}]}

".to_vec(),
                    b"data: [DONE]

".to_vec(),
                ],
                Duration::from_secs(10),
            )
        })
        .await;
        let mut llm = quick(&server);
        llm.finish_grace = Duration::from_millis(200);
        let started = std::time::Instant::now();
        let (result, _) = chat(&llm, &Cancel::new()).await;
        assert_eq!(result.unwrap().text, "all done");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn models_are_listed() {
        let server = FakeServer::start(|_, request| {
            assert_eq!(request.path, "/models");
            HttpReply::json(200, json!({"object": "list", "data": [{"id": "a"}, {"id": "b"}]}))
        })
        .await;
        assert_eq!(quick(&server).models().await.unwrap(), vec!["a".to_owned(), "b".to_owned()]);
    }

    #[tokio::test]
    async fn an_unreachable_relay_is_named_plainly() {
        // A port nothing listens on.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let mut llm = Llm::new(&url, "k").unwrap();
        llm.retry.attempts = 2;
        llm.retry.first = Duration::from_millis(10);
        let (result, _) = chat(&llm, &Cancel::new()).await;
        match result {
            Err(CallError::Failed { message, .. }) => {
                assert!(message.starts_with(&format!("Cannot reach the inference relay at {url}")), "{message}");
                assert!(message.ends_with("Tried 2 times."), "{message}");
            }
            other => panic!("{other:?}"),
        }
    }
}
