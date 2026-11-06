//! Anthropic Messages stream assembly (S7 line 126; S9 line 167).
//!
//! Every event is named, and the name must equal the data's `type`. The flow is
//! `message_start`, then content blocks one at a time (`content_block_start`, deltas,
//! `content_block_stop`) whose `index` is their position in the final content, then one
//! or more `message_delta` events carrying `stop_reason` and cumulative usage, then
//! `message_stop`. A `tool_use` block streams its input as `input_json_delta`
//! `partial_json` strings, parsed only after the block stops and the message ends.
//! `ping` may appear anywhere before `message_stop`; unknown event types are tolerated,
//! as the API's versioning requires, but an unknown block or delta type is refused,
//! since its effect on a tool call cannot be known.

use serde::Deserialize;
use serde_json::Value;

use super::dialect::Dialect;
use super::errors::{anthropic_error, ServiceError};
use super::sse::SseFrame;
use super::turn::{
    append_bounded, parse_event, resolve_terminal, violation, AssemblyLimits, CallBuilder,
    FinishReason, Flow, PendingToolCall, ProtocolViolation, StreamEnd, TurnOutcome, Usage,
    ViolationKind, WireFinish,
};

#[derive(Deserialize)]
struct MessageStart {
    message: WireMessage,
}

#[derive(Deserialize)]
struct WireMessage {
    role: String,
    content: Vec<Value>,
    usage: Option<WireUsage>,
}

#[derive(Deserialize)]
struct BlockStart {
    index: u32,
    content_block: WireBlock,
}

#[derive(Deserialize)]
struct WireBlock {
    #[serde(rename = "type")]
    kind: String,
    id: Option<String>,
    name: Option<String>,
    input: Option<Value>,
    text: Option<String>,
}

#[derive(Deserialize)]
struct BlockDelta {
    index: u32,
    delta: WireDelta,
}

#[derive(Deserialize)]
struct WireDelta {
    #[serde(rename = "type")]
    kind: String,
    text: Option<String>,
    partial_json: Option<String>,
}

#[derive(Deserialize)]
struct BlockStop {
    index: u32,
}

#[derive(Deserialize)]
struct MessageDelta {
    delta: StopDelta,
    usage: Option<WireUsage>,
}

#[derive(Deserialize)]
struct StopDelta {
    stop_reason: Option<String>,
}

#[derive(Deserialize)]
struct WireUsage {
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    cache_read_input_tokens: Option<u64>,
}

#[derive(Deserialize)]
struct ErrorEvent {
    error: Value,
}

#[derive(Debug)]
enum Body {
    Text(String),
    /// The arguments come from `partial_json`; `start_input` is the start event's
    /// `input`, used only when no delta arrives.
    ToolUse {
        call: CallBuilder,
        start_input: String,
    },
    Thinking,
    Fallback,
}

#[derive(Debug)]
struct Block {
    body: Body,
    stopped: bool,
}

#[derive(Debug)]
enum State {
    Open,
    Stopped,
    Failed(ServiceError),
    Violated(ProtocolViolation),
}

/// Assembles one Anthropic Messages stream (S7 line 126; S9 line 167).
#[derive(Debug)]
pub struct MessagesAssembler {
    limits: AssemblyLimits,
    frames: usize,
    state: State,
    started: bool,
    blocks: Vec<Block>,
    open: Option<usize>,
    stop: Option<WireFinish>,
    /// Whether a `message_delta` arrived; content blocks come before it.
    delta_seen: bool,
    usage: Usage,
    ignored_events: usize,
}

impl MessagesAssembler {
    /// An assembler at the start of a stream.
    pub fn new(limits: AssemblyLimits) -> Self {
        Self {
            limits,
            frames: 0,
            state: State::Open,
            started: false,
            blocks: Vec::new(),
            open: None,
            stop: None,
            delta_seen: false,
            usage: Usage::default(),
            ignored_events: 0,
        }
    }

    /// Takes the next frame in arrival order.
    pub fn push(&mut self, frame: &SseFrame) -> Flow {
        let position = self.frames;
        self.frames = self.frames.saturating_add(1);
        match self.state {
            State::Open => {}
            State::Stopped => {
                self.state = State::Violated(violation(
                    ViolationKind::EventAfterTerminal,
                    position,
                    "an event after message_stop",
                ));
                return Flow::Stop;
            }
            State::Failed(_) | State::Violated(_) => return Flow::Stop,
        }
        match self.apply(frame, position) {
            Ok(flow) => flow,
            Err(broken) => {
                self.state = State::Violated(broken);
                Flow::Stop
            }
        }
    }

    /// Event types outside this module's set, tolerated as the API's versioning requires.
    pub fn ignored_events(&self) -> usize {
        self.ignored_events
    }

    /// The calls declared so far; none is executable before the turn completes.
    pub fn pending_tool_calls(&self) -> Vec<PendingToolCall> {
        self.calls().map(CallBuilder::pending).collect()
    }

    /// Ends the stream and resolves its outcome.
    pub fn finish(self, end: StreamEnd) -> TurnOutcome {
        let dropped = self.pending_tool_calls();
        let last = self.frames.saturating_sub(1);
        match self.state {
            State::Violated(violation) => TurnOutcome::Violation { violation, dropped },
            State::Failed(error) => TurnOutcome::Failed { error, dropped },
            State::Stopped => match self.stop {
                Some(finish) => {
                    let mut text = String::new();
                    let mut calls = Vec::new();
                    for block in &self.blocks {
                        match &block.body {
                            Body::Text(content) => text.push_str(content),
                            Body::ToolUse { call, .. } => calls.push(call.clone()),
                            Body::Thinking | Body::Fallback => {}
                        }
                    }
                    resolve_terminal(
                        Dialect::AnthropicMessages,
                        text,
                        String::new(),
                        &calls,
                        finish,
                        Some(self.usage),
                        last,
                    )
                }
                None => TurnOutcome::Violation {
                    violation: violation(
                        ViolationKind::MissingFinishReason,
                        last,
                        "message_stop without a stop_reason",
                    ),
                    dropped,
                },
            },
            State::Open => match end {
                StreamEnd::ClientCancel => TurnOutcome::Cancelled { dropped },
                StreamEnd::Eof => TurnOutcome::Disconnected {
                    after_finish: self.stop.is_some(),
                    dropped,
                },
            },
        }
    }

    fn calls(&self) -> impl Iterator<Item = &CallBuilder> {
        self.blocks.iter().filter_map(|block| match &block.body {
            Body::ToolUse { call, .. } => Some(call),
            _ => None,
        })
    }

    fn apply(&mut self, frame: &SseFrame, position: usize) -> Result<Flow, ProtocolViolation> {
        let value: Value = serde_json::from_str(&frame.data).map_err(|error| {
            violation(
                ViolationKind::MalformedFrame,
                position,
                format!("data is not JSON: {error}"),
            )
        })?;
        let kind = value
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                violation(
                    ViolationKind::MalformedFrame,
                    position,
                    "an event without type",
                )
            })?
            .to_owned();
        if frame.event.as_deref() != Some(kind.as_str()) {
            return Err(violation(
                ViolationKind::EventNameMismatch,
                position,
                format!("event name {:?} with type {kind:?}", frame.event),
            ));
        }
        match kind.as_str() {
            "ping" => {}
            "error" => {
                let event: ErrorEvent = parse_event(value, position)?;
                self.state = State::Failed(anthropic_error(&event.error, None, true));
                return Ok(Flow::Stop);
            }
            "message_start" => self.message_start(parse_event(value, position)?, position)?,
            "content_block_start"
            | "content_block_delta"
            | "content_block_stop"
            | "message_delta"
            | "message_stop"
                if !self.started =>
            {
                return Err(violation(
                    ViolationKind::UnexpectedEvent,
                    position,
                    format!("{kind} before message_start"),
                ))
            }
            "content_block_start" => self.block_start(parse_event(value, position)?, position)?,
            "content_block_delta" => self.block_delta(parse_event(value, position)?, position)?,
            "content_block_stop" => self.block_stop(parse_event(value, position)?, position)?,
            "message_delta" => self.message_delta(parse_event(value, position)?, position)?,
            "message_stop" => {
                if let Some(open) = self.open {
                    return Err(violation(
                        ViolationKind::UnexpectedEvent,
                        position,
                        format!("message_stop while block {open} is open"),
                    ));
                }
                if self.stop.is_none() {
                    return Err(violation(
                        ViolationKind::MissingFinishReason,
                        position,
                        "message_stop without a stop_reason",
                    ));
                }
                self.state = State::Stopped;
                return Ok(Flow::Stop);
            }
            _ => self.ignored_events = self.ignored_events.saturating_add(1),
        }
        Ok(Flow::Continue)
    }

    fn message_start(
        &mut self,
        event: MessageStart,
        position: usize,
    ) -> Result<(), ProtocolViolation> {
        if self.started {
            return Err(violation(
                ViolationKind::DuplicateEvent,
                position,
                "message_start repeated",
            ));
        }
        if event.message.role != "assistant" {
            return Err(violation(
                ViolationKind::MalformedFrame,
                position,
                format!("message role {:?}", event.message.role),
            ));
        }
        if !event.message.content.is_empty() {
            return Err(violation(
                ViolationKind::UnsupportedContent,
                position,
                "message_start with content; content arrives as blocks",
            ));
        }
        if let Some(usage) = event.message.usage {
            self.merge_usage(usage);
        }
        self.started = true;
        Ok(())
    }

    fn block_start(&mut self, event: BlockStart, position: usize) -> Result<(), ProtocolViolation> {
        let declared = self.blocks.len();
        let index = event.index as usize;
        if index < declared {
            return Err(violation(
                ViolationKind::DuplicateEvent,
                position,
                format!("content block {index} started again"),
            ));
        }
        if index > declared {
            return Err(violation(
                ViolationKind::OutOfOrderIndex,
                position,
                format!("content block {index} started before block {declared}"),
            ));
        }
        if let Some(open) = self.open {
            return Err(violation(
                ViolationKind::UnexpectedEvent,
                position,
                format!("content block {index} started while block {open} is open"),
            ));
        }
        if self.delta_seen {
            return Err(violation(
                ViolationKind::UnexpectedEvent,
                position,
                format!("content block {index} after message_delta"),
            ));
        }
        let block = event.content_block;
        let body = match block.kind.as_str() {
            "text" => {
                let mut text = String::new();
                let initial = block.text.unwrap_or_default();
                append_bounded(&mut text, &initial, self.limits.max_text_bytes, position)?;
                Body::Text(text)
            }
            "tool_use" => self.tool_use(event.index, block, position)?,
            "thinking" | "redacted_thinking" => Body::Thinking,
            "fallback" => Body::Fallback,
            other => {
                return Err(violation(
                    ViolationKind::UnsupportedContent,
                    position,
                    format!("content block type {other:?}"),
                ))
            }
        };
        self.blocks.push(Block {
            body,
            stopped: false,
        });
        self.open = Some(index);
        Ok(())
    }

    fn tool_use(
        &self,
        index: u32,
        block: WireBlock,
        position: usize,
    ) -> Result<Body, ProtocolViolation> {
        if self.calls().count() >= self.limits.max_tool_calls {
            return Err(violation(
                ViolationKind::LimitExceeded,
                position,
                format!("more than {} tool calls", self.limits.max_tool_calls),
            ));
        }
        let call_id = block.id.filter(|id| !id.is_empty()).ok_or_else(|| {
            violation(
                ViolationKind::MissingToolCallHeader,
                position,
                format!("tool_use block {index} without an id"),
            )
        })?;
        let name = block.name.filter(|name| !name.is_empty()).ok_or_else(|| {
            violation(
                ViolationKind::MissingToolCallHeader,
                position,
                format!("tool_use block {index} without a name"),
            )
        })?;
        if self.calls().any(|call| call.call_id == call_id) {
            return Err(violation(
                ViolationKind::DuplicateCallId,
                position,
                format!("tool_use id {call_id:?} used twice"),
            ));
        }
        let start_input = match block.input {
            Some(input @ Value::Object(_)) => input.to_string(),
            _ => {
                return Err(violation(
                    ViolationKind::MalformedFrame,
                    position,
                    format!("tool_use block {index} input is not an object"),
                ))
            }
        };
        Ok(Body::ToolUse {
            call: CallBuilder::new(index, call_id, name),
            start_input,
        })
    }

    fn block_delta(&mut self, event: BlockDelta, position: usize) -> Result<(), ProtocolViolation> {
        let limits = self.limits;
        let index = event.index as usize;
        let block = self.open_block(index, "content_block_delta", position)?;
        let delta = event.delta;
        match (delta.kind.as_str(), &mut block.body) {
            ("text_delta", Body::Text(text)) => {
                let fragment = delta.text.ok_or_else(|| {
                    violation(
                        ViolationKind::MalformedFrame,
                        position,
                        "text_delta without text",
                    )
                })?;
                append_bounded(text, &fragment, limits.max_text_bytes, position)
            }
            ("input_json_delta", Body::ToolUse { call, .. }) => {
                let fragment = delta.partial_json.ok_or_else(|| {
                    violation(
                        ViolationKind::MalformedFrame,
                        position,
                        "input_json_delta without partial_json",
                    )
                })?;
                append_bounded(
                    &mut call.arguments,
                    &fragment,
                    limits.max_argument_bytes,
                    position,
                )
            }
            ("thinking_delta" | "signature_delta", Body::Thinking) => Ok(()),
            ("citations_delta", Body::Text(_)) => Ok(()),
            (
                "text_delta" | "input_json_delta" | "thinking_delta" | "signature_delta"
                | "citations_delta",
                _,
            ) => Err(violation(
                ViolationKind::UnexpectedEvent,
                position,
                format!("{} for block {index} of another type", delta.kind),
            )),
            (other, _) => Err(violation(
                ViolationKind::UnsupportedContent,
                position,
                format!("delta type {other:?}"),
            )),
        }
    }

    fn block_stop(&mut self, event: BlockStop, position: usize) -> Result<(), ProtocolViolation> {
        let index = event.index as usize;
        let block = self.open_block(index, "content_block_stop", position)?;
        if let Body::ToolUse { call, start_input } = &mut block.body {
            if call.arguments.is_empty() {
                call.arguments = start_input.clone();
            } else if start_input != "{}" {
                return Err(violation(
                    ViolationKind::ContentMismatch,
                    position,
                    format!("tool_use block {index} has both a start input and deltas"),
                ));
            }
            call.arguments_closed = true;
        }
        block.stopped = true;
        self.open = None;
        Ok(())
    }

    /// The open block at `index`, or the violation that addressing it is.
    fn open_block(
        &mut self,
        index: usize,
        event: &str,
        position: usize,
    ) -> Result<&mut Block, ProtocolViolation> {
        let open = self.open;
        let block = self.blocks.get_mut(index).ok_or_else(|| {
            violation(
                ViolationKind::UnknownIndex,
                position,
                format!("{event} for block {index}, which never started"),
            )
        })?;
        if block.stopped {
            let kind = if event == "content_block_stop" {
                ViolationKind::DuplicateEvent
            } else {
                ViolationKind::UnexpectedEvent
            };
            return Err(violation(
                kind,
                position,
                format!("{event} for block {index} after it stopped"),
            ));
        }
        if open != Some(index) {
            return Err(violation(
                ViolationKind::UnexpectedEvent,
                position,
                format!("{event} for block {index}, which is not the open block"),
            ));
        }
        Ok(block)
    }

    fn message_delta(
        &mut self,
        event: MessageDelta,
        position: usize,
    ) -> Result<(), ProtocolViolation> {
        if let Some(open) = self.open {
            return Err(violation(
                ViolationKind::UnexpectedEvent,
                position,
                format!("message_delta while block {open} is open"),
            ));
        }
        self.delta_seen = true;
        if let Some(raw) = event.delta.stop_reason {
            if let Some(previous) = &self.stop {
                if previous.raw != raw {
                    return Err(violation(
                        ViolationKind::ConflictingFinishReason,
                        position,
                        format!("stop_reason {raw:?} after {:?}", previous.raw),
                    ));
                }
            }
            self.stop = Some(messages_finish(raw, position)?);
        }
        if let Some(usage) = event.usage {
            self.merge_usage(usage);
        }
        Ok(())
    }

    /// Messages usage is cumulative: a later report replaces each field it carries.
    fn merge_usage(&mut self, usage: WireUsage) {
        if usage.input_tokens.is_some() {
            self.usage.input_tokens = usage.input_tokens;
        }
        if usage.output_tokens.is_some() {
            self.usage.output_tokens = usage.output_tokens;
        }
        if usage.cache_read_input_tokens.is_some() {
            self.usage.cached_input_tokens = usage.cache_read_input_tokens;
        }
    }
}

fn messages_finish(raw: String, position: usize) -> Result<WireFinish, ProtocolViolation> {
    let reason = match raw.as_str() {
        "end_turn" => FinishReason::Stop,
        "stop_sequence" => FinishReason::StopSequence,
        "tool_use" => FinishReason::ToolCalls,
        "max_tokens" => FinishReason::Length,
        "model_context_window_exceeded" => FinishReason::ContextWindowExceeded,
        "refusal" => FinishReason::Refusal,
        "pause_turn" => FinishReason::PauseTurn,
        other => {
            return Err(violation(
                ViolationKind::UnknownFinishReason,
                position,
                format!("stop_reason {other:?}"),
            ))
        }
    };
    Ok(WireFinish { raw, reason })
}
