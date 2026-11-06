//! From a completed turn to calls an executor accepts (S9 lines 167 and 175).
//!
//! Tool execution requires the validated complete payload. A [`ValidatedToolCall`] can
//! only be made here, from a [`CompletedTurn`], after every call of the turn is declared,
//! parses as a JSON object and satisfies its schema, and the turn respects the request's
//! tool choice and parallel-call setting. A Chat Completions turn that ended in `stop`
//! with calls is accepted only under a named tool choice and only for calls to that tool. Validation is all or nothing: one invalid call
//! makes the whole turn non-executable, so half of a parallel set never runs. A valid
//! schema still does not make a call useful or authorized (S9 line 175); authorization
//! belongs to the executor.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::dialect::Dialect;
use super::request::{RequestProfile, ToolChoice};
use super::turn::{AssembledToolCall, CompletedTurn, FinishReason};

/// Why a completed turn's calls cannot run (S9 line 167).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalKind {
    /// The turn was assembled in another dialect than the request's.
    DialectMismatch,
    /// The request said `none`, yet the model called a tool.
    ToolChoiceNone,
    /// The request required a call, yet the turn has none.
    ToolChoiceRequired,
    /// The request named one tool, yet the model called another or none.
    ToolChoiceNamed,
    /// Several calls where the request switched parallel calls off.
    ParallelNotAllowed,
    /// A call to a tool the request did not declare.
    UndeclaredTool,
    /// Arguments that are not JSON.
    MalformedArguments,
    /// Arguments that are JSON but not an object.
    ArgumentsNotObject,
    /// Arguments that break the tool's schema.
    SchemaViolation,
    /// The finish reason did not say tool calls (Chat Completions `stop`), which is
    /// accepted only under a forced named tool choice.
    FinishReasonMismatch,
}

/// A refusal to execute, naming the call where one is at fault (S9 line 167).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ToolCallRefusal {
    pub kind: RefusalKind,
    /// The declared index of the offending call.
    pub index: Option<u32>,
    pub detail: String,
}

impl fmt::Display for ToolCallRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.index {
            Some(index) => write!(f, "call {index}: {:?}: {}", self.kind, self.detail),
            None => write!(f, "{:?}: {}", self.kind, self.detail),
        }
    }
}

impl std::error::Error for ToolCallRefusal {}

fn refusal(kind: RefusalKind, index: Option<u32>, detail: impl Into<String>) -> ToolCallRefusal {
    ToolCallRefusal {
        kind,
        index,
        detail: detail.into(),
    }
}

/// One call with its complete, schema-checked arguments (S9 line 167). Only
/// [`validate_turn`] makes one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ValidatedToolCall {
    index: u32,
    call_id: String,
    name: String,
    arguments: Map<String, Value>,
}

impl ValidatedToolCall {
    /// The call's declared index.
    pub fn index(&self) -> u32 {
        self.index
    }

    /// The call's id, which the tool result answers.
    pub fn call_id(&self) -> &str {
        &self.call_id
    }

    /// The declared tool called.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The complete arguments, validated against the tool's schema.
    pub fn arguments(&self) -> &Map<String, Value> {
        &self.arguments
    }
}

/// Every call of one completed turn, validated together (S9 line 167).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ValidatedTurn {
    dialect: Dialect,
    calls: Vec<ValidatedToolCall>,
}

impl ValidatedTurn {
    /// The dialect of the turn.
    pub fn dialect(&self) -> Dialect {
        self.dialect
    }

    /// The calls in declared index order; empty for a turn that ended in text.
    pub fn calls(&self) -> &[ValidatedToolCall] {
        &self.calls
    }
}

/// Runs validated calls (S9 line 167). Its only input is a [`ValidatedToolCall`], which
/// exists only for a completed turn whose every call passed validation, so a partial or
/// unvalidated call cannot reach an executor.
pub trait ToolExecutor {
    /// Runs one validated call.
    fn execute(&mut self, call: &ValidatedToolCall);
}

/// Executes a validated turn's calls in declared index order; returns how many ran.
pub fn execute_turn(executor: &mut dyn ToolExecutor, turn: &ValidatedTurn) -> usize {
    for call in &turn.calls {
        executor.execute(call);
    }
    turn.calls.len()
}

/// Validates a completed turn against the request it answered (S9 line 167).
pub fn validate_turn(
    turn: &CompletedTurn,
    request: &RequestProfile,
) -> Result<ValidatedTurn, ToolCallRefusal> {
    if turn.dialect() != request.dialect() {
        return Err(refusal(
            RefusalKind::DialectMismatch,
            None,
            format!(
                "a {} turn for a {} request",
                turn.dialect(),
                request.dialect()
            ),
        ));
    }
    let calls = turn.tool_calls();
    // OpenAI's form for a forced named call: under any other choice, a `stop` with calls
    // is a finish that contradicts its content, and nothing runs.
    if turn.finish().reason == FinishReason::StopWithToolCalls
        && !matches!(request.tool_choice(), ToolChoice::Named { .. })
    {
        return Err(refusal(
            RefusalKind::FinishReasonMismatch,
            calls.first().map(|call| call.index),
            format!(
                "finish {:?} with {} tool call(s) is accepted only under a named tool_choice",
                turn.finish().raw,
                calls.len()
            ),
        ));
    }
    match request.tool_choice() {
        ToolChoice::Disabled if !calls.is_empty() => {
            return Err(refusal(
                RefusalKind::ToolChoiceNone,
                calls.first().map(|call| call.index),
                "tool_choice none, yet a tool was called",
            ))
        }
        ToolChoice::Required if calls.is_empty() => {
            return Err(refusal(
                RefusalKind::ToolChoiceRequired,
                None,
                "a tool call was required",
            ))
        }
        ToolChoice::Named { name } => {
            if calls.is_empty() {
                return Err(refusal(
                    RefusalKind::ToolChoiceNamed,
                    None,
                    format!("a call to {name:?} was required"),
                ));
            }
            if let Some(call) = calls.iter().find(|call| call.name != *name) {
                return Err(refusal(
                    RefusalKind::ToolChoiceNamed,
                    Some(call.index),
                    format!("{:?} called where {name:?} was required", call.name),
                ));
            }
        }
        _ => {}
    }
    if !request.parallel_calls_allowed() && calls.len() > 1 {
        return Err(refusal(
            RefusalKind::ParallelNotAllowed,
            calls.get(1).map(|call| call.index),
            format!("{} calls with parallel calls switched off", calls.len()),
        ));
    }
    let validated = calls
        .iter()
        .map(|call| validate_call(call, request))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ValidatedTurn {
        dialect: turn.dialect(),
        calls: validated,
    })
}

/// How many of a completed turn's calls satisfy their declared schema, ignoring tool
/// choice and parallel settings: the numerator of schema accuracy (S7 line 127, S9
/// line 175).
pub fn schema_valid_calls(turn: &CompletedTurn, request: &RequestProfile) -> usize {
    turn.tool_calls()
        .iter()
        .filter(|call| validate_call(call, request).is_ok())
        .count()
}

fn validate_call(
    call: &AssembledToolCall,
    request: &RequestProfile,
) -> Result<ValidatedToolCall, ToolCallRefusal> {
    let schema = request.tool(&call.name).ok_or_else(|| {
        refusal(
            RefusalKind::UndeclaredTool,
            Some(call.index),
            format!("{:?} is not a declared tool", call.name),
        )
    })?;
    let value: Value = serde_json::from_str(&call.arguments_json).map_err(|error| {
        refusal(
            RefusalKind::MalformedArguments,
            Some(call.index),
            format!("the complete arguments are not JSON: {error}"),
        )
    })?;
    let not_object = || {
        refusal(
            RefusalKind::ArgumentsNotObject,
            Some(call.index),
            "the arguments are not a JSON object",
        )
    };
    if !value.is_object() {
        return Err(not_object());
    }
    schema.validate(&value).map_err(|violation| {
        refusal(
            RefusalKind::SchemaViolation,
            Some(call.index),
            violation.to_string(),
        )
    })?;
    let Value::Object(arguments) = value else {
        return Err(not_object());
    };
    Ok(ValidatedToolCall {
        index: call.index,
        call_id: call.call_id.clone(),
        name: call.name.clone(),
        arguments,
    })
}
