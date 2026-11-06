//! What a stream assembles into, and the typed result of every way it can end
//! (S9 line 167).
//!
//! Only [`TurnOutcome::Completed`] carries a [`CompletedTurn`], and only a completed turn
//! can be validated into calls an executor accepts. Every other outcome lists its
//! [`PendingToolCall`]s as dropped; a pending call exposes no argument text at all.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::dialect::Dialect;
use super::errors::ServiceError;

/// How the transport of a stream ended (S9 line 167: disconnect, cancellation).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamEnd {
    /// The connection closed. The outcome depends on whether the dialect's terminal
    /// event arrived first.
    Eof,
    /// The client cancelled before the stream ended.
    ClientCancel,
}

/// Whether an assembler wants more frames (S9 line 167).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    Continue,
    /// A terminal event, failure or violation was reached; further frames cannot help.
    Stop,
}

/// Bounds on what one stream may accumulate, so a broken or hostile stream cannot grow
/// memory without limit. Exceeding one is a [`ViolationKind::LimitExceeded`]. The
/// numbers are the caller's engineering choice, not plan figures (S9 line 167).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssemblyLimits {
    /// Most tool calls one turn may declare.
    pub max_tool_calls: usize,
    /// Most argument text one tool call may accumulate.
    pub max_argument_bytes: usize,
    /// Most text one text buffer (a choice, part or block) may accumulate.
    pub max_text_bytes: usize,
}

/// Why generation stopped, normalised across dialects (S7 line 126 "finish reasons").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinishReason {
    /// A natural stop: Chat Completions `stop`, Messages `end_turn`, Responses completed
    /// without calls.
    Stop,
    /// Messages `stop_sequence`.
    StopSequence,
    /// The turn ends in tool calls: `tool_calls`, `tool_use`, or Responses completed with
    /// function calls.
    ToolCalls,
    /// Chat Completions `stop` on a turn that carries tool calls: the form OpenAI sends
    /// for a forced named tool choice. The raw finish stays `stop`, and validation lets
    /// such calls run only under that choice (S9 line 167).
    StopWithToolCalls,
    /// The output limit: `length`, `max_tokens`, `max_output_tokens`.
    Length,
    /// Messages `model_context_window_exceeded`: the response filled the context window.
    ContextWindowExceeded,
    /// Output withheld by a content filter.
    ContentFilter,
    /// Messages `refusal`.
    Refusal,
    /// Messages `pause_turn`: the client must continue the turn.
    PauseTurn,
    /// Another Responses incomplete reason, such as `max_messages`.
    Incomplete,
}

/// A finish reason exactly as sent, with its normalised meaning (S11 BENCH-03 "exact
/// finish reason conformance").
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireFinish {
    /// The wire value: a `finish_reason`, `stop_reason`, Responses status or incomplete
    /// reason.
    pub raw: String,
    pub reason: FinishReason,
}

/// Token usage as the dialect reported it (S9 line 165 "usage"). Messages usage is
/// cumulative, so the last report wins.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Usage {
    #[serde(default)]
    pub input_tokens: Option<u64>,
    #[serde(default)]
    pub output_tokens: Option<u64>,
    #[serde(default)]
    pub total_tokens: Option<u64>,
    #[serde(default)]
    pub cached_input_tokens: Option<u64>,
}

/// A tool call whose arguments the dialect closed and whose turn completed
/// (S9 line 167). It still needs validation before any execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AssembledToolCall {
    /// The declared index: Chat Completions `tool_calls[].index`, Responses
    /// `output_index`, Messages content block `index`.
    pub index: u32,
    pub call_id: String,
    pub name: String,
    /// The complete argument text, concatenated in arrival order.
    pub arguments_json: String,
}

/// A tool call that never became executable: still streaming, or dropped when the turn
/// ended otherwise than completed (S9 line 167). It carries no argument text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PendingToolCall {
    pub index: u32,
    pub call_id: String,
    pub name: String,
    pub received_argument_bytes: usize,
    /// Whether the dialect had closed this call's arguments (Responses
    /// `function_call_arguments.done`, Messages `content_block_stop`).
    pub arguments_closed: bool,
}

/// A turn whose terminal event arrived and whose finish reason matches its content
/// (S9 line 167). Only the assemblers make one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CompletedTurn {
    dialect: Dialect,
    text: String,
    tool_calls: Vec<AssembledToolCall>,
    finish: WireFinish,
    usage: Option<Usage>,
}

impl CompletedTurn {
    /// The dialect the turn was assembled in.
    pub fn dialect(&self) -> Dialect {
        self.dialect
    }

    /// The assembled text content.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The calls in declared index order.
    pub fn tool_calls(&self) -> &[AssembledToolCall] {
        &self.tool_calls
    }

    /// The finish reason, exactly as sent.
    pub fn finish(&self) -> &WireFinish {
        &self.finish
    }

    /// The reported token usage, if any.
    pub fn usage(&self) -> Option<&Usage> {
        self.usage.as_ref()
    }
}

/// How a stream ended (S9 line 167). Every variant but `Completed` drops its calls.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum TurnOutcome {
    /// The terminal event arrived and the finish reason matches the content.
    Completed(CompletedTurn),
    /// The model refused: refusal content or a refusal stop reason ("tool refusal").
    Refused {
        refusal: String,
        finish: WireFinish,
        dropped: Vec<PendingToolCall>,
    },
    /// Generation stopped early: output limit, context window, filter or pause.
    Truncated {
        finish: WireFinish,
        dropped: Vec<PendingToolCall>,
    },
    /// The service reported a failure, before or during the stream.
    Failed {
        error: ServiceError,
        dropped: Vec<PendingToolCall>,
    },
    /// The connection closed before the terminal event.
    Disconnected {
        /// Whether a finish reason had arrived before the terminal event was missed.
        after_finish: bool,
        dropped: Vec<PendingToolCall>,
    },
    /// The client cancelled before the terminal event.
    Cancelled { dropped: Vec<PendingToolCall> },
    /// The stream broke the dialect's rules.
    Violation {
        violation: ProtocolViolation,
        dropped: Vec<PendingToolCall>,
    },
}

/// The variant of a [`TurnOutcome`], for fixtures and reports (S9 line 167).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeKind {
    Completed,
    Refused,
    Truncated,
    Failed,
    Disconnected,
    Cancelled,
    Violation,
}

impl TurnOutcome {
    /// The outcome's variant (S9 line 167).
    pub fn kind(&self) -> OutcomeKind {
        match self {
            Self::Completed(_) => OutcomeKind::Completed,
            Self::Refused { .. } => OutcomeKind::Refused,
            Self::Truncated { .. } => OutcomeKind::Truncated,
            Self::Failed { .. } => OutcomeKind::Failed,
            Self::Disconnected { .. } => OutcomeKind::Disconnected,
            Self::Cancelled { .. } => OutcomeKind::Cancelled,
            Self::Violation { .. } => OutcomeKind::Violation,
        }
    }

    /// The completed turn, the only source of executable calls.
    pub fn completed(&self) -> Option<&CompletedTurn> {
        match self {
            Self::Completed(turn) => Some(turn),
            _ => None,
        }
    }

    /// The calls that will never run because the turn did not complete.
    pub fn dropped(&self) -> &[PendingToolCall] {
        match self {
            Self::Completed(_) => &[],
            Self::Refused { dropped, .. }
            | Self::Truncated { dropped, .. }
            | Self::Failed { dropped, .. }
            | Self::Disconnected { dropped, .. }
            | Self::Cancelled { dropped }
            | Self::Violation { dropped, .. } => dropped,
        }
    }

    /// The finish reason, where the stream delivered one.
    pub fn finish(&self) -> Option<&WireFinish> {
        match self {
            Self::Completed(turn) => Some(&turn.finish),
            Self::Refused { finish, .. } | Self::Truncated { finish, .. } => Some(finish),
            _ => None,
        }
    }
}

/// The kind of rule a stream broke (S9 line 167: duplicate event, declared index and
/// order).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationKind {
    /// Data that is not JSON, or a field of the wrong type or missing.
    MalformedFrame,
    /// The SSE event name is missing, unexpected or differs from the data's `type`.
    EventNameMismatch,
    /// An event the stream's state does not allow.
    UnexpectedEvent,
    /// An event seen before: a repeated sequence number, header, start, stop or finish.
    DuplicateEvent,
    /// A Responses sequence number was skipped: an event was lost.
    SequenceGap,
    /// A Responses sequence number earlier than the stream's first.
    OutOfOrderEvent,
    /// A new tool call, output item, content part or block declared out of order.
    OutOfOrderIndex,
    /// A delta, done or stop for an index never declared, or for another item's id.
    UnknownIndex,
    /// Anything after the dialect's terminal event.
    EventAfterTerminal,
    /// A new call without its id or name.
    MissingToolCallHeader,
    /// A call's id, name or type differs between its events.
    ConflictingToolCallHeader,
    /// Two calls share an id.
    DuplicateCallId,
    /// A done event's payload differs from the accumulated deltas.
    ContentMismatch,
    /// A tool-call finish without calls, or a natural stop with calls.
    FinishReasonMismatch,
    /// The terminal event arrived without a finish or stop reason.
    MissingFinishReason,
    /// A finish or stop reason the dialect does not define.
    UnknownFinishReason,
    /// Two different finish or stop reasons.
    ConflictingFinishReason,
    /// Content this module does not assemble: extra choices, legacy function calls,
    /// hosted-tool items, unknown block or delta types.
    UnsupportedContent,
    /// An [`AssemblyLimits`] bound was exceeded.
    LimitExceeded,
}

/// A broken rule, where in the stream it happened, and what was seen (S9 line 167).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProtocolViolation {
    pub kind: ViolationKind,
    /// Zero-based position of the offending frame.
    pub frame: usize,
    pub detail: String,
}

impl fmt::Display for ProtocolViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "frame {}: {:?}: {}", self.frame, self.kind, self.detail)
    }
}

pub(super) fn violation(
    kind: ViolationKind,
    frame: usize,
    detail: impl Into<String>,
) -> ProtocolViolation {
    ProtocolViolation {
        kind,
        frame,
        detail: detail.into(),
    }
}

/// Reads an event's fields; a missing or mistyped field is a malformed frame.
pub(super) fn parse_event<T: serde::de::DeserializeOwned>(
    value: serde_json::Value,
    frame: usize,
) -> Result<T, ProtocolViolation> {
    serde_json::from_value(value).map_err(|error| {
        violation(
            ViolationKind::MalformedFrame,
            frame,
            format!("an event with missing or mistyped fields: {error}"),
        )
    })
}

/// A tool call while its arguments stream in.
#[derive(Clone, Debug)]
pub(super) struct CallBuilder {
    pub(super) index: u32,
    pub(super) call_id: String,
    pub(super) name: String,
    pub(super) arguments: String,
    pub(super) arguments_closed: bool,
}

impl CallBuilder {
    pub(super) fn new(index: u32, call_id: String, name: String) -> Self {
        Self {
            index,
            call_id,
            name,
            arguments: String::new(),
            arguments_closed: false,
        }
    }

    pub(super) fn pending(&self) -> PendingToolCall {
        PendingToolCall {
            index: self.index,
            call_id: self.call_id.clone(),
            name: self.name.clone(),
            received_argument_bytes: self.arguments.len(),
            arguments_closed: self.arguments_closed,
        }
    }

    fn assembled(&self) -> AssembledToolCall {
        AssembledToolCall {
            index: self.index,
            call_id: self.call_id.clone(),
            name: self.name.clone(),
            arguments_json: self.arguments.clone(),
        }
    }
}

/// Appends a fragment without judging it: a fragment of JSON is not malformed while its
/// call is still streaming (S9 line 167).
pub(super) fn append_bounded(
    target: &mut String,
    fragment: &str,
    max_bytes: usize,
    frame: usize,
) -> Result<(), ProtocolViolation> {
    if target.len().saturating_add(fragment.len()) > max_bytes {
        return Err(violation(
            ViolationKind::LimitExceeded,
            frame,
            format!("more than {max_bytes} bytes accumulated"),
        ));
    }
    target.push_str(fragment);
    Ok(())
}

/// Resolves a stream whose terminal event arrived (S9 line 167). A refusal drops every
/// call; a tool-call finish needs calls and a natural stop needs none, except that a
/// Chat Completions `stop` with calls arrives here already relabelled
/// [`FinishReason::StopWithToolCalls`]; an early stop drops every call.
pub(super) fn resolve_terminal(
    dialect: Dialect,
    text: String,
    refusal: String,
    calls: &[CallBuilder],
    finish: WireFinish,
    usage: Option<Usage>,
    frame: usize,
) -> TurnOutcome {
    let dropped = || calls.iter().map(CallBuilder::pending).collect::<Vec<_>>();
    if !refusal.is_empty() {
        return TurnOutcome::Refused {
            refusal,
            finish,
            dropped: dropped(),
        };
    }
    match finish.reason {
        FinishReason::Refusal => TurnOutcome::Refused {
            refusal: text,
            finish,
            dropped: dropped(),
        },
        FinishReason::ToolCalls
        | FinishReason::StopWithToolCalls
        | FinishReason::Stop
        | FinishReason::StopSequence => {
            let wants_calls = matches!(
                finish.reason,
                FinishReason::ToolCalls | FinishReason::StopWithToolCalls
            );
            if wants_calls == calls.is_empty() {
                let detail = format!("finish {:?} with {} tool call(s)", finish.raw, calls.len());
                return TurnOutcome::Violation {
                    violation: violation(ViolationKind::FinishReasonMismatch, frame, detail),
                    dropped: dropped(),
                };
            }
            TurnOutcome::Completed(CompletedTurn {
                dialect,
                text,
                tool_calls: calls.iter().map(CallBuilder::assembled).collect(),
                finish,
                usage,
            })
        }
        FinishReason::Length
        | FinishReason::ContextWindowExceeded
        | FinishReason::ContentFilter
        | FinishReason::PauseTurn
        | FinishReason::Incomplete => TurnOutcome::Truncated {
            finish,
            dropped: dropped(),
        },
    }
}
