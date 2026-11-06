//! Error mapping for the three dialects (S7 line 126 "error mapping"; S11 BENCH-03
//! "error taxonomy").
//!
//! Classes come from the documented codes, types and HTTP statuses only; error messages
//! are never matched as text. Where a dialect has no distinct signal, the class says so:
//! an Anthropic prompt that is too long arrives as `invalid_request_error`, so it is
//! classed as an invalid request, while a response that fills the context window ends
//! with `stop_reason: model_context_window_exceeded`, which the Messages assembler
//! reports as a truncation.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::dialect::Dialect;

/// The typed class of a service failure (S11 BENCH-03 error taxonomy).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClass {
    /// The prompt and requested output exceed the model's context window.
    ContextOverflow,
    /// The account's quota or billing does not allow the request.
    QuotaExceeded,
    /// Too many requests; a later retry can progress.
    RateLimited,
    /// The service is temporarily overloaded.
    Overloaded,
    /// The request's format or content is invalid.
    InvalidRequest,
    /// The credential is missing, malformed, revoked or expired.
    Authentication,
    /// The credential may not use this resource.
    Permission,
    /// The model or resource does not exist.
    NotFound,
    /// The request conflicts with the resource's current state.
    Conflict,
    /// The request is larger than the service accepts.
    RequestTooLarge,
    /// The service timed out while processing.
    Timeout,
    /// The service failed internally.
    Server,
    /// No documented code, type or status identified the failure.
    Unrecognized,
}

impl fmt::Display for ErrorClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ContextOverflow => "context overflow",
            Self::QuotaExceeded => "quota exceeded",
            Self::RateLimited => "rate limited",
            Self::Overloaded => "overloaded",
            Self::InvalidRequest => "invalid request",
            Self::Authentication => "authentication failed",
            Self::Permission => "permission denied",
            Self::NotFound => "not found",
            Self::Conflict => "conflict",
            Self::RequestTooLarge => "request too large",
            Self::Timeout => "timed out",
            Self::Server => "server error",
            Self::Unrecognized => "unrecognized error",
        })
    }
}

/// A failure the service reported, with its typed class (S9 line 167: a quota failure or
/// context overflow leads to a defined result).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceError {
    pub class: ErrorClass,
    /// The HTTP status of a failure before streaming began; `None` inside a stream.
    pub http_status: Option<u16>,
    /// The dialect's error code or type, as sent.
    pub code: Option<String>,
    pub message: String,
    /// Whether the failure arrived after the stream had started.
    pub during_stream: bool,
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.class)?;
        if let Some(code) = &self.code {
            write!(f, " ({code})")?;
        }
        if !self.message.is_empty() {
            write!(f, ": {}", self.message)?;
        }
        Ok(())
    }
}

/// Classifies a response that failed before streaming began, from its HTTP status and
/// JSON body (S7 line 126; S9 line 167).
pub fn classify_http_error(dialect: Dialect, http_status: u16, body: &Value) -> ServiceError {
    let error = body.get("error").unwrap_or(&Value::Null);
    match dialect {
        Dialect::OpenAiChatCompletions | Dialect::OpenAiResponses => {
            openai_error(error, Some(http_status), false)
        }
        Dialect::AnthropicMessages => anthropic_error(error, Some(http_status), false),
    }
}

/// An OpenAI error object (`message`, `type`, `param`, `code`), from an HTTP body, a
/// streamed `error` frame or a failed response.
pub(super) fn openai_error(
    error: &Value,
    http_status: Option<u16>,
    during_stream: bool,
) -> ServiceError {
    let code = text_or_number(error.get("code"));
    let kind = error.get("type").and_then(Value::as_str);
    ServiceError {
        class: openai_class(code.as_deref(), kind, http_status),
        http_status,
        code: code.or_else(|| kind.map(str::to_owned)),
        message: message_of(error),
        during_stream,
    }
}

/// An Anthropic error object (`type`, `message`), from an HTTP body or an `error` event.
pub(super) fn anthropic_error(
    error: &Value,
    http_status: Option<u16>,
    during_stream: bool,
) -> ServiceError {
    let kind = error.get("type").and_then(Value::as_str);
    ServiceError {
        class: anthropic_class(kind, http_status),
        http_status,
        code: kind.map(str::to_owned),
        message: message_of(error),
        during_stream,
    }
}

fn message_of(error: &Value) -> String {
    error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// OpenAI-compatible servers send `code` as a string; some send the HTTP status number.
fn text_or_number(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(text)) if !text.is_empty() => Some(text.clone()),
        Some(Value::Number(number)) => Some(number.to_string()),
        _ => None,
    }
}

/// The most specific signal wins: a documented code, then the type, then the status.
fn openai_class(code: Option<&str>, kind: Option<&str>, status: Option<u16>) -> ErrorClass {
    let is = |value: Option<&str>, expected: &str| value == Some(expected);
    if is(code, "context_length_exceeded") {
        ErrorClass::ContextOverflow
    } else if is(code, "insufficient_quota") || is(kind, "insufficient_quota") {
        ErrorClass::QuotaExceeded
    } else if is(code, "rate_limit_exceeded") || status == Some(429) {
        ErrorClass::RateLimited
    } else if is(code, "invalid_api_key") || status == Some(401) {
        ErrorClass::Authentication
    } else if status == Some(403) {
        ErrorClass::Permission
    } else if is(code, "model_not_found") || status == Some(404) {
        ErrorClass::NotFound
    } else if status == Some(409) {
        ErrorClass::Conflict
    } else if status == Some(413) {
        ErrorClass::RequestTooLarge
    } else if is(code, "server_error")
        || is(kind, "server_error")
        || matches!(status, Some(500 | 502))
    {
        ErrorClass::Server
    } else if status == Some(503) {
        ErrorClass::Overloaded
    } else if matches!(status, Some(408 | 504)) {
        ErrorClass::Timeout
    } else if is(kind, "invalid_request_error") || matches!(status, Some(400 | 422)) {
        ErrorClass::InvalidRequest
    } else {
        ErrorClass::Unrecognized
    }
}

/// The documented Anthropic error types, then the documented statuses.
fn anthropic_class(kind: Option<&str>, status: Option<u16>) -> ErrorClass {
    match kind {
        Some("invalid_request_error") => ErrorClass::InvalidRequest,
        Some("authentication_error") => ErrorClass::Authentication,
        Some("billing_error") => ErrorClass::QuotaExceeded,
        Some("permission_error") => ErrorClass::Permission,
        Some("not_found_error") => ErrorClass::NotFound,
        Some("conflict_error") => ErrorClass::Conflict,
        Some("request_too_large") => ErrorClass::RequestTooLarge,
        Some("rate_limit_error") => ErrorClass::RateLimited,
        Some("api_error") => ErrorClass::Server,
        Some("timeout_error") => ErrorClass::Timeout,
        Some("overloaded_error") => ErrorClass::Overloaded,
        _ => match status {
            Some(400) => ErrorClass::InvalidRequest,
            Some(401) => ErrorClass::Authentication,
            Some(402) => ErrorClass::QuotaExceeded,
            Some(403) => ErrorClass::Permission,
            Some(404) => ErrorClass::NotFound,
            Some(409) => ErrorClass::Conflict,
            Some(413) => ErrorClass::RequestTooLarge,
            Some(429) => ErrorClass::RateLimited,
            Some(500) => ErrorClass::Server,
            Some(504) => ErrorClass::Timeout,
            Some(529) => ErrorClass::Overloaded,
            _ => ErrorClass::Unrecognized,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn openai(status: u16, error: Value) -> ErrorClass {
        classify_http_error(
            Dialect::OpenAiChatCompletions,
            status,
            &json!({ "error": error }),
        )
        .class
    }

    #[test]
    fn openai_codes_beat_types_and_statuses() {
        let overflow = json!({"message": "synthetic", "type": "invalid_request_error",
                              "code": "context_length_exceeded"});
        assert_eq!(openai(400, overflow), ErrorClass::ContextOverflow);
        let quota = json!({"type": "insufficient_quota", "code": "insufficient_quota"});
        assert_eq!(openai(429, quota), ErrorClass::QuotaExceeded);
        assert_eq!(
            openai(429, json!({"code": "rate_limit_exceeded"})),
            ErrorClass::RateLimited
        );
        assert_eq!(
            openai(400, json!({"type": "invalid_request_error"})),
            ErrorClass::InvalidRequest
        );
        assert_eq!(openai(503, json!({})), ErrorClass::Overloaded);
        assert_eq!(openai(500, json!({})), ErrorClass::Server);
        assert_eq!(openai(418, json!({})), ErrorClass::Unrecognized);
        // A server sending the status number as its code keeps that code.
        let error = classify_http_error(
            Dialect::OpenAiResponses,
            400,
            &json!({"error": {"message": "m", "type": "BadRequestError", "code": 400}}),
        );
        assert_eq!(error.class, ErrorClass::InvalidRequest);
        assert_eq!(error.code.as_deref(), Some("400"));
        assert_eq!(error.message, "m");
        assert!(!error.during_stream);
    }

    #[test]
    fn anthropic_types_then_statuses() {
        let classify = |status: u16, kind: &str| {
            classify_http_error(
                Dialect::AnthropicMessages,
                status,
                &json!({"type": "error", "error": {"type": kind, "message": "synthetic"}}),
            )
            .class
        };
        assert_eq!(classify(402, "billing_error"), ErrorClass::QuotaExceeded);
        assert_eq!(classify(529, "overloaded_error"), ErrorClass::Overloaded);
        assert_eq!(classify(429, "rate_limit_error"), ErrorClass::RateLimited);
        assert_eq!(classify(504, "timeout_error"), ErrorClass::Timeout);
        // A too-long prompt is only an invalid request: messages are never matched.
        assert_eq!(
            classify(400, "invalid_request_error"),
            ErrorClass::InvalidRequest
        );
        assert_eq!(classify(402, "a_future_type"), ErrorClass::QuotaExceeded);
        assert_eq!(classify(418, "a_future_type"), ErrorClass::Unrecognized);
        let error = classify_http_error(Dialect::AnthropicMessages, 500, &json!("not json"));
        assert_eq!(error.class, ErrorClass::Server);
        assert_eq!(error.code, None);
    }
}
