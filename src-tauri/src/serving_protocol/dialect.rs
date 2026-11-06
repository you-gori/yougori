//! The API dialects a runner may serve and the features a capability row covers (S9).

use std::fmt;

use serde::{Deserialize, Serialize};

/// An agent-facing API dialect (S7 line 126; S9 line 165).
///
/// Every dialect is checked on its own evidence. A row for one dialect is never derived
/// from another, because no generic proxy can promise complete semantic conversion
/// (S7 line 126).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Dialect {
    /// OpenAI Chat Completions: `chat.completion.chunk` frames ending in `data: [DONE]`.
    #[serde(rename = "openai_chat_completions")]
    OpenAiChatCompletions,
    /// OpenAI Responses: typed events carrying `sequence_number`.
    #[serde(rename = "openai_responses")]
    OpenAiResponses,
    /// Anthropic Messages: named events over indexed content blocks.
    #[serde(rename = "anthropic_messages")]
    AnthropicMessages,
}

impl Dialect {
    /// Every dialect this module assembles (S7 line 126).
    pub const ALL: [Self; 3] = [
        Self::OpenAiChatCompletions,
        Self::OpenAiResponses,
        Self::AnthropicMessages,
    ];

    /// The stable tag used in fixtures and digests (S9).
    pub const fn tag(self) -> &'static str {
        match self {
            Self::OpenAiChatCompletions => "openai_chat_completions",
            Self::OpenAiResponses => "openai_responses",
            Self::AnthropicMessages => "anthropic_messages",
        }
    }
}

impl fmt::Display for Dialect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::OpenAiChatCompletions => "OpenAI Chat Completions",
            Self::OpenAiResponses => "OpenAI Responses",
            Self::AnthropicMessages => "Anthropic Messages",
        })
    }
}

/// One feature of a capability row (S9 line 165).
///
/// The plan's "tool schema/tool choice" is kept as two features, because a runner can
/// accept tool schemas while ignoring a forced tool choice.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Feature {
    /// The dialect's request fields are accepted and honoured.
    RequestFields,
    /// System instructions and earlier turns, including tool calls and results, are kept.
    SystemContextPreservation,
    /// Declared tool schemas reach the model and calls are checked against them.
    ToolSchema,
    /// An explicit tool choice (auto, none, required or one named tool) is honoured.
    ToolChoice,
    /// Streamed deltas follow the dialect's event index and order.
    StreamingDeltas,
    /// Several tool calls in one turn are assembled by their own indices.
    ParallelCalls,
    /// The finish or stop reason is one the dialect defines and matches the content.
    FinishReason,
    /// Token usage is reported in the dialect's fields.
    Usage,
    /// The dialect's token counting endpoint answers.
    TokenCounting,
    /// Failures arrive in the dialect's error shapes and map to a typed class.
    Errors,
    /// A client cancellation ends the request without executing a pending call.
    Cancellation,
}

impl Feature {
    /// Every feature of a row, in row order (S9 line 165).
    pub const ALL: [Self; 11] = [
        Self::RequestFields,
        Self::SystemContextPreservation,
        Self::ToolSchema,
        Self::ToolChoice,
        Self::StreamingDeltas,
        Self::ParallelCalls,
        Self::FinishReason,
        Self::Usage,
        Self::TokenCounting,
        Self::Errors,
        Self::Cancellation,
    ];

    /// Features every exchange uses: a request is sent, and its response ends in a finish
    /// reason or an error. A dialect is advertised only when all three are supported
    /// (S9 line 165).
    pub const EVERY_EXCHANGE: [Self; 3] = [Self::RequestFields, Self::FinishReason, Self::Errors];

    /// The stable tag used in fixtures and digests (S9).
    pub const fn tag(self) -> &'static str {
        match self {
            Self::RequestFields => "request_fields",
            Self::SystemContextPreservation => "system_context_preservation",
            Self::ToolSchema => "tool_schema",
            Self::ToolChoice => "tool_choice",
            Self::StreamingDeltas => "streaming_deltas",
            Self::ParallelCalls => "parallel_calls",
            Self::FinishReason => "finish_reason",
            Self::Usage => "usage",
            Self::TokenCounting => "token_counting",
            Self::Errors => "errors",
            Self::Cancellation => "cancellation",
        }
    }

    /// Whether `dialect` defines this feature at all. Chat Completions has no token
    /// counting endpoint, so its rows record token counting as absent from the dialect
    /// rather than untested (S9 line 165).
    pub const fn in_dialect(self, dialect: Dialect) -> bool {
        !matches!(
            (self, dialect),
            (Self::TokenCounting, Dialect::OpenAiChatCompletions)
        )
    }
}

impl fmt::Display for Feature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.tag())
    }
}
