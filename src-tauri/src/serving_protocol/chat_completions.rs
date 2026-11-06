//! OpenAI Chat Completions stream assembly (S7 line 126; S9 line 167).
//!
//! Each `chat.completion.chunk` carries `choices[0].delta`. Tool calls arrive as
//! `delta.tool_calls[]` fragments addressed by `index`: the first fragment of a call
//! carries its `id` and `function.name`, later ones only `function.arguments` text, which
//! is concatenated per index and judged only after `finish_reason` and `data: [DONE]`.
//! New indices must be declared in order 0, 1, 2, …; fragments of declared calls may
//! interleave. A terminal `stop` on a turn with calls, which OpenAI sends for a forced
//! named tool choice, completes as [`FinishReason::StopWithToolCalls`]; validation runs
//! such calls only under that choice. Chat Completions carries no event sequence number,
//! so a repeated header or finish reason is detectable as a duplicate event, while a
//! repeated argument fragment is caught only when it breaks the complete payload's JSON
//! or schema.

use serde::Deserialize;
use serde_json::Value;

use super::dialect::Dialect;
use super::errors::{openai_error, ServiceError};
use super::sse::SseFrame;
use super::turn::{
    append_bounded, resolve_terminal, violation, AssemblyLimits, CallBuilder, FinishReason, Flow,
    PendingToolCall, ProtocolViolation, StreamEnd, TurnOutcome, Usage, ViolationKind, WireFinish,
};

#[derive(Deserialize)]
struct Chunk {
    object: Option<String>,
    choices: Option<Vec<ChunkChoice>>,
    usage: Option<WireUsage>,
}

#[derive(Deserialize)]
struct ChunkChoice {
    index: u32,
    delta: Option<ChunkDelta>,
    finish_reason: Option<String>,
}

#[derive(Deserialize)]
struct ChunkDelta {
    role: Option<String>,
    content: Option<String>,
    refusal: Option<String>,
    tool_calls: Option<Vec<ToolCallFragment>>,
    function_call: Option<Value>,
}

#[derive(Deserialize)]
struct ToolCallFragment {
    index: u32,
    id: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
    function: Option<FunctionFragment>,
}

#[derive(Deserialize)]
struct FunctionFragment {
    name: Option<String>,
    arguments: Option<String>,
}

#[derive(Deserialize)]
struct WireUsage {
    prompt_tokens: Option<u64>,
    completion_tokens: Option<u64>,
    total_tokens: Option<u64>,
    prompt_tokens_details: Option<PromptDetails>,
}

#[derive(Deserialize)]
struct PromptDetails {
    cached_tokens: Option<u64>,
}

impl WireUsage {
    fn usage(self) -> Usage {
        Usage {
            input_tokens: self.prompt_tokens,
            output_tokens: self.completion_tokens,
            total_tokens: self.total_tokens,
            cached_input_tokens: self.prompt_tokens_details.and_then(|d| d.cached_tokens),
        }
    }
}

#[derive(Debug)]
enum State {
    Open,
    Done,
    Failed(ServiceError),
    Violated(ProtocolViolation),
}

/// Assembles one OpenAI Chat Completions stream (S7 line 126; S9 line 167).
#[derive(Debug)]
pub struct ChatCompletionsAssembler {
    limits: AssemblyLimits,
    frames: usize,
    state: State,
    text: String,
    refusal: String,
    calls: Vec<CallBuilder>,
    finish: Option<WireFinish>,
    usage: Option<Usage>,
}

impl ChatCompletionsAssembler {
    /// An assembler at the start of a stream.
    pub fn new(limits: AssemblyLimits) -> Self {
        Self {
            limits,
            frames: 0,
            state: State::Open,
            text: String::new(),
            refusal: String::new(),
            calls: Vec::new(),
            finish: None,
            usage: None,
        }
    }

    /// Takes the next frame in arrival order.
    pub fn push(&mut self, frame: &SseFrame) -> Flow {
        let position = self.frames;
        self.frames = self.frames.saturating_add(1);
        match self.state {
            State::Open => {}
            State::Done => {
                self.state = State::Violated(violation(
                    ViolationKind::EventAfterTerminal,
                    position,
                    "a frame after data: [DONE]",
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

    /// The calls declared so far; none is executable before the turn completes.
    pub fn pending_tool_calls(&self) -> Vec<PendingToolCall> {
        self.calls.iter().map(CallBuilder::pending).collect()
    }

    /// Ends the stream and resolves its outcome.
    pub fn finish(self, end: StreamEnd) -> TurnOutcome {
        let dropped = self.pending_tool_calls();
        match self.state {
            State::Violated(violation) => TurnOutcome::Violation { violation, dropped },
            State::Failed(error) => TurnOutcome::Failed { error, dropped },
            State::Done => match self.finish {
                Some(mut finish) => {
                    // OpenAI ends a forced named tool call with `stop`. The turn completes
                    // with the raw finish kept; validation decides whether the calls run.
                    if finish.reason == FinishReason::Stop && !self.calls.is_empty() {
                        finish.reason = FinishReason::StopWithToolCalls;
                    }
                    resolve_terminal(
                        Dialect::OpenAiChatCompletions,
                        self.text,
                        self.refusal,
                        &self.calls,
                        finish,
                        self.usage,
                        self.frames.saturating_sub(1),
                    )
                }
                None => TurnOutcome::Violation {
                    violation: violation(
                        ViolationKind::MissingFinishReason,
                        self.frames.saturating_sub(1),
                        "data: [DONE] without a finish_reason",
                    ),
                    dropped,
                },
            },
            State::Open => match end {
                StreamEnd::ClientCancel => TurnOutcome::Cancelled { dropped },
                StreamEnd::Eof => TurnOutcome::Disconnected {
                    after_finish: self.finish.is_some(),
                    dropped,
                },
            },
        }
    }

    fn apply(&mut self, frame: &SseFrame, position: usize) -> Result<Flow, ProtocolViolation> {
        if let Some(event) = &frame.event {
            return Err(violation(
                ViolationKind::EventNameMismatch,
                position,
                format!("Chat Completions frames carry no event name; found {event:?}"),
            ));
        }
        if frame.data == "[DONE]" {
            if self.finish.is_none() {
                return Err(violation(
                    ViolationKind::MissingFinishReason,
                    position,
                    "data: [DONE] before any finish_reason",
                ));
            }
            self.state = State::Done;
            return Ok(Flow::Stop);
        }
        let value: Value = serde_json::from_str(&frame.data).map_err(|error| {
            violation(
                ViolationKind::MalformedFrame,
                position,
                format!("data is not JSON: {error}"),
            )
        })?;
        if let Some(error) = value.get("error").filter(|error| !error.is_null()) {
            self.state = State::Failed(openai_error(error, None, true));
            return Ok(Flow::Stop);
        }
        let chunk: Chunk = serde_json::from_value(value).map_err(|error| {
            violation(
                ViolationKind::MalformedFrame,
                position,
                format!("not a chat.completion.chunk: {error}"),
            )
        })?;
        if let Some(object) = chunk.object.as_deref() {
            if object != "chat.completion.chunk" {
                return Err(violation(
                    ViolationKind::MalformedFrame,
                    position,
                    format!("object {object:?} is not chat.completion.chunk"),
                ));
            }
        }
        let choices = chunk.choices.ok_or_else(|| {
            violation(
                ViolationKind::MalformedFrame,
                position,
                "a chunk without choices",
            )
        })?;
        for choice in choices {
            self.apply_choice(choice, position)?;
        }
        if let Some(usage) = chunk.usage {
            self.usage = Some(usage.usage());
        }
        Ok(Flow::Continue)
    }

    fn apply_choice(
        &mut self,
        choice: ChunkChoice,
        position: usize,
    ) -> Result<(), ProtocolViolation> {
        if choice.index != 0 {
            return Err(violation(
                ViolationKind::UnsupportedContent,
                position,
                format!("choice {}; only a single choice is assembled", choice.index),
            ));
        }
        if self.finish.is_some() {
            return Err(if choice.finish_reason.is_some() {
                violation(
                    ViolationKind::DuplicateEvent,
                    position,
                    "finish_reason repeated",
                )
            } else {
                violation(
                    ViolationKind::UnexpectedEvent,
                    position,
                    "a delta after finish_reason",
                )
            });
        }
        if let Some(delta) = choice.delta {
            self.apply_delta(delta, position)?;
        }
        if let Some(raw) = choice.finish_reason {
            self.finish = Some(chat_finish(raw, position)?);
        }
        Ok(())
    }

    fn apply_delta(&mut self, delta: ChunkDelta, position: usize) -> Result<(), ProtocolViolation> {
        if let Some(role) = delta.role.as_deref() {
            if role != "assistant" {
                return Err(violation(
                    ViolationKind::UnexpectedEvent,
                    position,
                    format!("delta role {role:?}"),
                ));
            }
        }
        if delta.function_call.is_some() {
            return Err(violation(
                ViolationKind::UnsupportedContent,
                position,
                "legacy delta.function_call",
            ));
        }
        let max_text_bytes = self.limits.max_text_bytes;
        if let Some(text) = delta.content.as_deref() {
            append_bounded(&mut self.text, text, max_text_bytes, position)?;
        }
        if let Some(text) = delta.refusal.as_deref() {
            append_bounded(&mut self.refusal, text, max_text_bytes, position)?;
        }
        for fragment in delta.tool_calls.unwrap_or_default() {
            self.apply_fragment(fragment, position)?;
        }
        Ok(())
    }

    fn apply_fragment(
        &mut self,
        fragment: ToolCallFragment,
        position: usize,
    ) -> Result<(), ProtocolViolation> {
        if let Some(kind) = fragment.kind.as_deref() {
            if kind != "function" {
                return Err(violation(
                    ViolationKind::UnsupportedContent,
                    position,
                    format!("tool call type {kind:?}"),
                ));
            }
        }
        let (name, arguments) = match fragment.function {
            Some(function) => (function.name, function.arguments),
            None => (None, None),
        };
        let arguments = arguments.unwrap_or_default();
        let max_argument_bytes = self.limits.max_argument_bytes;
        let declared = self.calls.len();
        let index = fragment.index as usize;
        if index < declared {
            if fragment.id.is_some() || name.is_some() {
                return Err(violation(
                    ViolationKind::DuplicateEvent,
                    position,
                    format!("the header of tool call {index} repeated"),
                ));
            }
            let call = self.calls.get_mut(index).ok_or_else(|| {
                violation(
                    ViolationKind::UnknownIndex,
                    position,
                    format!("tool call {index}"),
                )
            })?;
            return append_bounded(
                &mut call.arguments,
                &arguments,
                max_argument_bytes,
                position,
            );
        }
        if index > declared {
            return Err(violation(
                ViolationKind::OutOfOrderIndex,
                position,
                format!("tool call index {index} declared before index {declared}"),
            ));
        }
        if declared >= self.limits.max_tool_calls {
            return Err(violation(
                ViolationKind::LimitExceeded,
                position,
                format!("more than {} tool calls", self.limits.max_tool_calls),
            ));
        }
        let call_id = fragment.id.filter(|id| !id.is_empty()).ok_or_else(|| {
            violation(
                ViolationKind::MissingToolCallHeader,
                position,
                format!("tool call {index} without an id"),
            )
        })?;
        let name = name.filter(|name| !name.is_empty()).ok_or_else(|| {
            violation(
                ViolationKind::MissingToolCallHeader,
                position,
                format!("tool call {index} without a function name"),
            )
        })?;
        if self.calls.iter().any(|call| call.call_id == call_id) {
            return Err(violation(
                ViolationKind::DuplicateCallId,
                position,
                format!("tool call id {call_id:?} used twice"),
            ));
        }
        let mut call = CallBuilder::new(fragment.index, call_id, name);
        append_bounded(
            &mut call.arguments,
            &arguments,
            max_argument_bytes,
            position,
        )?;
        self.calls.push(call);
        Ok(())
    }
}

fn chat_finish(raw: String, position: usize) -> Result<WireFinish, ProtocolViolation> {
    let reason = match raw.as_str() {
        "stop" => FinishReason::Stop,
        "length" => FinishReason::Length,
        "tool_calls" => FinishReason::ToolCalls,
        "content_filter" => FinishReason::ContentFilter,
        "function_call" => {
            return Err(violation(
                ViolationKind::UnsupportedContent,
                position,
                "legacy finish_reason function_call",
            ))
        }
        other => {
            return Err(violation(
                ViolationKind::UnknownFinishReason,
                position,
                format!("finish_reason {other:?}"),
            ))
        }
    };
    Ok(WireFinish { raw, reason })
}
