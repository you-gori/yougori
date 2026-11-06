//! Host adapter for the shared Chat Completions contract. Text streams immediately;
//! tool calls leave this module only after the entire turn validates.
use crate::serving_protocol::{
    classify_http_error, validate_turn, AssemblyLimits, Dialect, ErrorClass, Flow, RequestProfile,
    ServiceError, SseDecoder, StreamAssembler, StreamEnd, TurnOutcome,
};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};

mod buffered;
pub(super) use buffered::read as read_buffered;
mod negotiation;
#[cfg(test)]
mod protocol_integration;
#[cfg(test)]
mod tests;
mod transport;

const DIALECT: Dialect = Dialect::OpenAiChatCompletions;
const MAX_RESPONSE: usize = 8 * 1024 * 1024;
const MAX_ERROR: usize = 64 * 1024;
const IDLE: Duration = Duration::from_secs(1800);

pub(super) struct Profile {
    policy: RequestProfile,
    contract: negotiation::Contract,
}

impl Profile {
    pub(super) fn headers(&self) -> String {
        self.contract.headers()
    }
}

pub(super) fn profile(body: &Value) -> Result<Profile, String> {
    // Environment-scoped chat selects the model by its connection, not a body field.
    // This placeholder is only for request policy parsing, never a capability identity.
    let mut request = body.clone();
    if let Some(object) = request.as_object_mut() {
        object
            .entry("model")
            .or_insert(json!("environment-selected"));
    }
    let policy = RequestProfile::from_request(DIALECT, &request)
        .map_err(|e| format!("Invalid model request: {e}"))?;
    let contract = negotiation::Contract::new(body, &policy);
    Ok(Profile { policy, contract })
}

/// The GPU-memory refusal of the engine's own model server (`yougori_gpu_memory`), in the
/// engine's words.
const GPU_MEMORY_REFUSED: &str = "The GPU ran out of memory for this request; the model stays loaded. Shorten the conversation or choose a smaller model.";

/// The model server's typed refusals rendered from their codes and the runner's own
/// integers, never from its message text: the context window a conversation or `max_tokens`
/// does not fit (`yougori_context_window`, with the prompt's tokens, `max_tokens` and the
/// context the GPU grant covers when one does) and GPU memory running out during a request
/// (`yougori_gpu_memory`). `None` for every other body, which the classifier handles without
/// echoing it.
pub(super) fn typed_refusal(body: &Value) -> Option<String> {
    let error = &body["error"];
    match error["code"].as_str()? {
        "yougori_context_window" => {
            let context = error["context"].as_u64()?;
            let grant = match error["grantContext"].as_u64() {
                Some(covered) if covered == context => {
                    " (the GPU grant covers that many tokens)".to_owned()
                }
                _ => String::new(),
            };
            let prompt = error["promptTokens"].as_u64();
            let count = error["maxTokens"].as_u64();
            Some(match (prompt, count) {
                (Some(prompt), Some(count)) => format!(
                    "This conversation needs {prompt} prompt tokens plus up to {count} reply tokens, more than the model's {context}-token context window{grant}. Shorten the conversation or lower max_tokens."
                ),
                (None, Some(count)) => format!(
                    "max_tokens {count} is not below the model's {context}-token context window{grant}. Lower max_tokens."
                ),
                _ => format!(
                    "This conversation exceeds the model's {context}-token context window{grant}. Shorten it or lower max_tokens."
                ),
            })
        }
        "yougori_gpu_memory" => Some(GPU_MEMORY_REFUSED.to_owned()),
        _ => None,
    }
}

fn service_error(error: &ServiceError) -> String {
    if error.code.as_deref() == Some("yougori_gpu_memory") {
        return GPU_MEMORY_REFUSED.to_owned();
    }
    match &error.class {
        // Keep the existing retry signal, without copying an untrusted error message.
        ErrorClass::RateLimited | ErrorClass::Overloaded => {
            format!("Model service {}; busy, retry shortly", error.class)
        }
        class => format!("Model service {class}"),
    }
}

struct Turn {
    assembler: StreamAssembler,
    decoder: SseDecoder,
    utf8: Vec<u8>,
    stopped: bool,
    usage: Option<Value>,
}

impl Turn {
    fn new() -> Self {
        Self {
            assembler: StreamAssembler::new(
                DIALECT,
                AssemblyLimits {
                    max_tool_calls: 32,
                    max_argument_bytes: 64 * 1024,
                    max_text_bytes: MAX_RESPONSE,
                },
            ),
            decoder: SseDecoder::new(),
            utf8: Vec::new(),
            stopped: false,
            usage: None,
        }
    }

    fn push(
        &mut self,
        bytes: &[u8],
        delta: &mut impl FnMut(&Value) -> Result<(), String>,
    ) -> Result<(), String> {
        self.utf8.extend_from_slice(bytes);
        let valid = match std::str::from_utf8(&self.utf8) {
            Ok(_) => self.utf8.len(),
            Err(e) if e.error_len().is_none() => e.valid_up_to(),
            Err(_) => return Err("Invalid UTF-8 in model stream".into()),
        };
        // The only undecoded bytes retained between reads are an incomplete codepoint.
        let frames = self
            .decoder
            .push(std::str::from_utf8(&self.utf8[..valid]).unwrap());
        self.utf8.drain(..valid);
        for frame in frames {
            let flow = self.assembler.push(&frame);
            if flow == Flow::Stop {
                self.stopped = true;
                continue;
            }
            let event: Value =
                serde_json::from_str(&frame.data).map_err(|_| "Invalid JSON in model stream")?;
            if event["usage"].is_object() {
                self.usage = Some(event["usage"].clone());
            }
            // Never leak raw tool/function fragments to consumers. Preserve the
            // existing reasoning extension as display text, not executable data.
            if let Some(piece) = event["choices"][0]["delta"].as_object() {
                let mut display = serde_json::Map::new();
                for field in ["content", "reasoning_content", "refusal", "role"] {
                    if let Some(value) = piece.get(field).filter(|v| v.is_string()) {
                        display.insert(field.into(), value.clone());
                    }
                }
                if !display.is_empty() {
                    delta(&Value::Object(display))?;
                }
            }
        }
        Ok(())
    }

    fn finish(
        self,
        request: &RequestProfile,
        delta: &mut impl FnMut(&Value) -> Result<(), String>,
    ) -> Result<Value, String> {
        if !self.utf8.is_empty() || self.decoder.finish().discarded_partial_event {
            return Err("The model closed with an incomplete event".into());
        }
        let finish = match self.assembler.finish(StreamEnd::Eof) {
            TurnOutcome::Completed(turn) => {
                validate_turn(&turn, request)
                    .map_err(|_| "The model returned tool calls that do not satisfy the request")?;
                if !turn.tool_calls().is_empty() {
                    let calls: Vec<Value> = turn
                        .tool_calls()
                        .iter()
                        .map(|call| {
                            json!({
                                "index":call.index, "id":call.call_id, "type":"function",
                                "function":{"name":call.name,"arguments":call.arguments_json}
                            })
                        })
                        .collect();
                    delta(&json!({"tool_calls":calls}))?;
                }
                turn.finish().raw.clone()
            }
            TurnOutcome::Refused { finish, .. } | TurnOutcome::Truncated { finish, .. } => {
                finish.raw
            }
            TurnOutcome::Failed { error, .. } => return Err(service_error(&error)),
            TurnOutcome::Violation { violation, .. } => {
                return Err(format!("Invalid model stream: {:?}", violation.kind))
            }
            TurnOutcome::Disconnected { .. } => {
                return Err("The model closed the connection before finishing".into())
            }
            TurnOutcome::Cancelled { .. } => "cancelled".into(),
        };
        let mut result = json!({"finishReason":finish});
        if let Some(usage) = self.usage {
            result["usage"] = usage;
        }
        Ok(result)
    }
}

pub(super) async fn read(
    stream: impl AsyncRead + Unpin,
    cancel: &tokio::sync::Notify,
    request: &Profile,
    delta: impl FnMut(&Value) -> Result<(), String>,
) -> Result<Value, String> {
    read_with_idle(stream, cancel, request, delta, IDLE).await
}

async fn read_with_idle(
    mut stream: impl AsyncRead + Unpin,
    cancel: &tokio::sync::Notify,
    request: &Profile,
    mut delta: impl FnMut(&Value) -> Result<(), String>,
    idle: Duration,
) -> Result<Value, String> {
    if !request.contract.stream {
        return Err("Streaming chat requires stream=true".into());
    }
    let mut http = transport::Response::default();
    let mut turn = Turn::new();
    let mut errors = Vec::new();
    let mut total = 0usize;
    let mut agreement = None;
    let mut chunk = [0u8; 16 * 1024];
    loop {
        let count = tokio::select! {
            biased;
            _ = cancel.notified() => return Ok(json!({"finishReason":"cancelled"})),
            read = tokio::time::timeout(idle, stream.read(&mut chunk)) => read
                .map_err(|_| "The model stopped responding; try again or shorten the conversation")?
                .map_err(|_| "The model connection could not be read")?,
        };
        total += count;
        if total > MAX_RESPONSE {
            return Err("Model response exceeded 8 MiB".into());
        }
        let body = http.push(&chunk[..count], count == 0)?;
        let Some(status) = http.status() else {
            continue;
        };
        if status != 200 {
            if errors.len() + body.len() > MAX_ERROR {
                return Err("Model error response exceeded 64 KiB".into());
            }
            errors.extend_from_slice(&body);
            if http.done() {
                let value = serde_json::from_slice(&errors).unwrap_or(Value::Null);
                if let Some(message) = typed_refusal(&value) {
                    return Err(message);
                }
                if let Some(message) = negotiation::refusal(&value) {
                    return Err(message.into());
                }
                return Err(service_error(&classify_http_error(DIALECT, status, &value)));
            }
        } else {
            if agreement.is_none() {
                agreement = Some(request.contract.accept(http.version(), http.features())?);
            }
            turn.push(&body, &mut delta)?;
            // A close-delimited SSE stream ends at its terminal event; framed HTTP
            // must also finish its declared body before any calls are released.
            if http.done() || (turn.stopped && http.close_delimited()) {
                // A display callback may cancel while processing this very read.
                // Honour that permit before making any completed calls observable.
                tokio::select! {
                    biased;
                    _ = cancel.notified() => return Ok(json!({"finishReason":"cancelled"})),
                    _ = std::future::ready(()) => {},
                }
                let mut result = turn.finish(&request.policy, &mut delta)?;
                result["servingProtocol"] = agreement.unwrap();
                return Ok(result);
            }
        }
    }
}
