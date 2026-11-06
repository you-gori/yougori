//! One entry point over the three dialect assemblers (S7 line 126; S9 line 167).

use serde_json::Value;

use super::chat_completions::ChatCompletionsAssembler;
use super::dialect::Dialect;
use super::errors::classify_http_error;
use super::messages::MessagesAssembler;
use super::responses::ResponsesAssembler;
use super::sse::{decode_sse, SseFrame};
use super::turn::{AssemblyLimits, Flow, PendingToolCall, StreamEnd, TurnOutcome};

/// Assembles one streamed response in its dialect, by the dialect's declared indices and
/// event order (S9 line 167).
#[derive(Debug)]
pub enum StreamAssembler {
    ChatCompletions(ChatCompletionsAssembler),
    Responses(ResponsesAssembler),
    Messages(MessagesAssembler),
}

impl StreamAssembler {
    /// An assembler for one stream of `dialect` (S9 line 167).
    pub fn new(dialect: Dialect, limits: AssemblyLimits) -> Self {
        match dialect {
            Dialect::OpenAiChatCompletions => {
                Self::ChatCompletions(ChatCompletionsAssembler::new(limits))
            }
            Dialect::OpenAiResponses => Self::Responses(ResponsesAssembler::new(limits)),
            Dialect::AnthropicMessages => Self::Messages(MessagesAssembler::new(limits)),
        }
    }

    /// The dialect being assembled.
    pub fn dialect(&self) -> Dialect {
        match self {
            Self::ChatCompletions(_) => Dialect::OpenAiChatCompletions,
            Self::Responses(_) => Dialect::OpenAiResponses,
            Self::Messages(_) => Dialect::AnthropicMessages,
        }
    }

    /// Takes the next frame in arrival order. A fragment of tool-call JSON is accepted
    /// as it is; it is judged only as part of the complete payload (S9 line 167).
    pub fn push(&mut self, frame: &SseFrame) -> Flow {
        match self {
            Self::ChatCompletions(assembler) => assembler.push(frame),
            Self::Responses(assembler) => assembler.push(frame),
            Self::Messages(assembler) => assembler.push(frame),
        }
    }

    /// The calls declared so far, without their argument text; none is executable
    /// before the turn completes (S9 line 167).
    pub fn pending_tool_calls(&self) -> Vec<PendingToolCall> {
        match self {
            Self::ChatCompletions(assembler) => assembler.pending_tool_calls(),
            Self::Responses(assembler) => assembler.pending_tool_calls(),
            Self::Messages(assembler) => assembler.pending_tool_calls(),
        }
    }

    /// Ends the stream and resolves its typed outcome (S9 line 167).
    pub fn finish(self, end: StreamEnd) -> TurnOutcome {
        match self {
            Self::ChatCompletions(assembler) => assembler.finish(end),
            Self::Responses(assembler) => assembler.finish(end),
            Self::Messages(assembler) => assembler.finish(end),
        }
    }
}

/// Assembles a whole recorded stream. Every frame is pushed, so anything after a
/// terminal event is still seen and refused (S9 line 167).
pub fn assemble_frames(
    dialect: Dialect,
    frames: &[SseFrame],
    end: StreamEnd,
    limits: AssemblyLimits,
) -> TurnOutcome {
    let mut assembler = StreamAssembler::new(dialect, limits);
    for frame in frames {
        assembler.push(frame);
    }
    assembler.finish(end)
}

/// Assembles a raw event stream. An event cut off by the end of the text is discarded,
/// as SSE requires, so a cut can only end the stream early (S9 line 167: disconnect).
pub fn assemble_sse(
    dialect: Dialect,
    text: &str,
    end: StreamEnd,
    limits: AssemblyLimits,
) -> TurnOutcome {
    let (frames, _tail) = decode_sse(text);
    assemble_frames(dialect, &frames, end, limits)
}

/// The outcome of a response that failed before streaming began (S9 line 167: quota
/// failure, context overflow).
pub fn failed_before_stream(dialect: Dialect, http_status: u16, body: &Value) -> TurnOutcome {
    TurnOutcome::Failed {
        error: classify_http_error(dialect, http_status, body),
        dropped: Vec::new(),
    }
}
