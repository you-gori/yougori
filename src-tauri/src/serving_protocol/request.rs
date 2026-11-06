//! What a request asks of a runner (S9 line 165), read from the dialect's request body.
//!
//! The profile names the capability-row features the request needs and the tool policy
//! its calls must satisfy: declared tools with checked schemas, the tool choice and
//! whether parallel calls are allowed. Only the fields that decide these are read; other
//! fields are left to the runner.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde_json::{Map, Value};

use super::dialect::{Dialect, Feature};
use super::schema::{SchemaError, ToolSchema};

/// Whether a request generates a response or only counts tokens (S9 line 165).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RequestKind {
    Generate,
    CountTokens,
}

/// The tool choice a request declared, normalised across dialects (S9 line 165).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ToolChoice {
    /// The model decides (`auto`, the default when tools are declared).
    Auto,
    /// No tool may be called (`none`).
    Disabled,
    /// At least one call is required (`required`, Messages `any`).
    Required,
    /// This tool must be called.
    Named { name: String },
}

/// Why a request body could not be read (S9 line 165 "request fields").
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestError {
    NotAnObject,
    MissingField {
        field: String,
    },
    WrongType {
        field: String,
        expected: &'static str,
    },
    InvalidValue {
        field: String,
        detail: String,
    },
    /// A tool type other than a client function, such as a hosted search tool.
    UnsupportedToolType {
        index: usize,
        kind: String,
    },
    DuplicateToolName {
        name: String,
    },
    Schema {
        tool: String,
        error: SchemaError,
    },
    ToolChoiceWithoutTools,
    UnknownToolChoice {
        name: String,
    },
    /// The dialect has no such endpoint (Chat Completions token counting).
    FeatureNotInDialect {
        feature: Feature,
    },
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAnObject => f.write_str("the request body is not a JSON object"),
            Self::MissingField { field } => write!(f, "{field} is required"),
            Self::WrongType { field, expected } => write!(f, "{field} must be {expected}"),
            Self::InvalidValue { field, detail } => write!(f, "{field}: {detail}"),
            Self::UnsupportedToolType { index, kind } => {
                write!(f, "tools[{index}] has unsupported type {kind:?}")
            }
            Self::DuplicateToolName { name } => write!(f, "tool {name:?} is declared twice"),
            Self::Schema { tool, error } => write!(f, "tool {tool:?}: {error}"),
            Self::ToolChoiceWithoutTools => f.write_str("tool_choice needs declared tools"),
            Self::UnknownToolChoice { name } => {
                write!(f, "tool_choice names {name:?}, which is not declared")
            }
            Self::FeatureNotInDialect { feature } => {
                write!(f, "the dialect has no {feature} endpoint")
            }
        }
    }
}

impl std::error::Error for RequestError {}

/// The features a request needs and the policy its tool calls must satisfy
/// (S9 lines 165 and 167).
#[derive(Clone, Debug, PartialEq)]
pub struct RequestProfile {
    dialect: Dialect,
    kind: RequestKind,
    needs: BTreeSet<Feature>,
    tools: BTreeMap<String, ToolSchema>,
    tool_choice: ToolChoice,
    explicit_tool_choice: bool,
    parallel_calls_allowed: bool,
    streaming: bool,
}

/// What the dialect parsers read before needs are derived.
struct Parsed {
    system_or_context: bool,
    tools: BTreeMap<String, ToolSchema>,
    tool_choice: ToolChoice,
    explicit_tool_choice: bool,
    parallel_calls_allowed: bool,
    streaming: bool,
    usage_reported: bool,
}

impl RequestProfile {
    /// Reads a generation request in `dialect` (S9 line 165).
    pub fn from_request(dialect: Dialect, body: &Value) -> Result<Self, RequestError> {
        Self::read(dialect, RequestKind::Generate, body)
    }

    /// Reads a token counting request in `dialect` (S9 line 165 "token counting").
    pub fn from_token_count_request(dialect: Dialect, body: &Value) -> Result<Self, RequestError> {
        Self::read(dialect, RequestKind::CountTokens, body)
    }

    fn read(dialect: Dialect, kind: RequestKind, body: &Value) -> Result<Self, RequestError> {
        if kind == RequestKind::CountTokens && !Feature::TokenCounting.in_dialect(dialect) {
            return Err(RequestError::FeatureNotInDialect {
                feature: Feature::TokenCounting,
            });
        }
        let body = body.as_object().ok_or(RequestError::NotAnObject)?;
        let parsed = match dialect {
            Dialect::OpenAiChatCompletions => chat_completions(body)?,
            Dialect::OpenAiResponses => responses(body)?,
            Dialect::AnthropicMessages => messages(body, kind)?,
        };
        if kind == RequestKind::CountTokens && parsed.streaming {
            return Err(RequestError::InvalidValue {
                field: "stream".to_owned(),
                detail: "a token count is not streamed".to_owned(),
            });
        }
        if parsed.explicit_tool_choice && parsed.tools.is_empty() {
            return Err(RequestError::ToolChoiceWithoutTools);
        }
        if let ToolChoice::Named { name } = &parsed.tool_choice {
            if !parsed.tools.contains_key(name) {
                return Err(RequestError::UnknownToolChoice { name: name.clone() });
            }
        }
        let mut needs = BTreeSet::from([Feature::RequestFields, Feature::Errors]);
        if parsed.system_or_context {
            needs.insert(Feature::SystemContextPreservation);
        }
        if !parsed.tools.is_empty() {
            needs.insert(Feature::ToolSchema);
        }
        if parsed.explicit_tool_choice {
            needs.insert(Feature::ToolChoice);
        }
        match kind {
            RequestKind::CountTokens => {
                needs.insert(Feature::TokenCounting);
            }
            RequestKind::Generate => {
                needs.insert(Feature::FinishReason);
                if !parsed.tools.is_empty()
                    && parsed.parallel_calls_allowed
                    && parsed.tool_choice != ToolChoice::Disabled
                {
                    needs.insert(Feature::ParallelCalls);
                }
                if parsed.streaming {
                    needs.insert(Feature::StreamingDeltas);
                }
                if parsed.usage_reported {
                    needs.insert(Feature::Usage);
                }
            }
        }
        Ok(Self {
            dialect,
            kind,
            needs,
            tools: parsed.tools,
            tool_choice: parsed.tool_choice,
            explicit_tool_choice: parsed.explicit_tool_choice,
            parallel_calls_allowed: parsed.parallel_calls_allowed,
            streaming: parsed.streaming,
        })
    }

    /// The dialect the request was read in.
    pub fn dialect(&self) -> Dialect {
        self.dialect
    }

    /// Generation or token counting.
    pub fn kind(&self) -> RequestKind {
        self.kind
    }

    /// The capability-row features this request uses.
    pub fn needs(&self) -> &BTreeSet<Feature> {
        &self.needs
    }

    /// The declared tool's schema, if `name` is declared.
    pub fn tool(&self, name: &str) -> Option<&ToolSchema> {
        self.tools.get(name)
    }

    /// Whether any tool was declared.
    pub fn has_tools(&self) -> bool {
        !self.tools.is_empty()
    }

    /// The declared tool choice; [`ToolChoice::Auto`] when none was set.
    pub fn tool_choice(&self) -> &ToolChoice {
        &self.tool_choice
    }

    /// Whether the request set a tool choice explicitly.
    pub fn explicit_tool_choice(&self) -> bool {
        self.explicit_tool_choice
    }

    /// Whether several calls may come in one turn; every dialect defaults to yes.
    pub fn parallel_calls_allowed(&self) -> bool {
        self.parallel_calls_allowed
    }

    /// Whether the response is streamed.
    pub fn streaming(&self) -> bool {
        self.streaming
    }
}

/// A present, non-null field.
fn field<'a>(body: &'a Map<String, Value>, name: &str) -> Option<&'a Value> {
    body.get(name).filter(|value| !value.is_null())
}

fn non_empty_text<'a>(value: Option<&'a Value>, name: &str) -> Result<&'a str, RequestError> {
    let value = value.ok_or_else(|| RequestError::MissingField {
        field: name.to_owned(),
    })?;
    match value.as_str() {
        Some(text) if !text.is_empty() => Ok(text),
        _ => Err(RequestError::WrongType {
            field: name.to_owned(),
            expected: "a non-empty string",
        }),
    }
}

fn optional_bool(body: &Map<String, Value>, name: &str) -> Result<Option<bool>, RequestError> {
    field(body, name)
        .map(|value| {
            value.as_bool().ok_or_else(|| RequestError::WrongType {
                field: name.to_owned(),
                expected: "a boolean",
            })
        })
        .transpose()
}

fn required_array<'a>(
    body: &'a Map<String, Value>,
    name: &str,
) -> Result<&'a Vec<Value>, RequestError> {
    let values = field(body, name)
        .ok_or_else(|| RequestError::MissingField {
            field: name.to_owned(),
        })?
        .as_array()
        .ok_or_else(|| RequestError::WrongType {
            field: name.to_owned(),
            expected: "an array",
        })?;
    if values.is_empty() {
        return Err(RequestError::InvalidValue {
            field: name.to_owned(),
            detail: "must not be empty".to_owned(),
        });
    }
    Ok(values)
}

fn object_at<'a>(value: &'a Value, path: &str) -> Result<&'a Map<String, Value>, RequestError> {
    value.as_object().ok_or_else(|| RequestError::WrongType {
        field: path.to_owned(),
        expected: "an object",
    })
}

/// Collects `(name, parameters)` pairs into checked schemas, refusing repeated names.
fn declare_tools(
    declared: Vec<(String, Option<&Value>)>,
) -> Result<BTreeMap<String, ToolSchema>, RequestError> {
    let mut tools = BTreeMap::new();
    for (name, parameters) in declared {
        let schema = match parameters {
            Some(schema) => ToolSchema::parse(schema).map_err(|error| RequestError::Schema {
                tool: name.clone(),
                error,
            })?,
            None => ToolSchema::empty_object(),
        };
        if tools.insert(name.clone(), schema).is_some() {
            return Err(RequestError::DuplicateToolName { name });
        }
    }
    Ok(tools)
}

fn tools_array<'a>(body: &'a Map<String, Value>) -> Result<&'a [Value], RequestError> {
    match field(body, "tools") {
        None => Ok(&[]),
        Some(Value::Array(tools)) => Ok(tools),
        Some(_) => Err(RequestError::WrongType {
            field: "tools".to_owned(),
            expected: "an array",
        }),
    }
}

/// OpenAI's string tool choices, or `None` for an object.
fn openai_choice_word(choice: &Value) -> Result<Option<ToolChoice>, RequestError> {
    match choice.as_str() {
        Some("auto") => Ok(Some(ToolChoice::Auto)),
        Some("none") => Ok(Some(ToolChoice::Disabled)),
        Some("required") => Ok(Some(ToolChoice::Required)),
        Some(other) => Err(RequestError::InvalidValue {
            field: "tool_choice".to_owned(),
            detail: format!("unknown choice {other:?}"),
        }),
        None => Ok(None),
    }
}

fn chat_completions(body: &Map<String, Value>) -> Result<Parsed, RequestError> {
    non_empty_text(field(body, "model"), "model")?;
    let mut system_or_context = false;
    for (index, message) in required_array(body, "messages")?.iter().enumerate() {
        let path = format!("messages[{index}]");
        let message = object_at(message, &path)?;
        match non_empty_text(field(message, "role"), &format!("{path}.role"))? {
            "system" | "developer" | "assistant" | "tool" => system_or_context = true,
            "user" => {}
            other => {
                return Err(RequestError::InvalidValue {
                    field: format!("{path}.role"),
                    detail: format!("unknown role {other:?}"),
                })
            }
        }
    }
    let mut declared = Vec::new();
    for (index, tool) in tools_array(body)?.iter().enumerate() {
        let path = format!("tools[{index}]");
        let tool = object_at(tool, &path)?;
        let kind = non_empty_text(field(tool, "type"), &format!("{path}.type"))?;
        if kind != "function" {
            return Err(RequestError::UnsupportedToolType {
                index,
                kind: kind.to_owned(),
            });
        }
        let function = object_at(
            field(tool, "function").ok_or_else(|| RequestError::MissingField {
                field: format!("{path}.function"),
            })?,
            &format!("{path}.function"),
        )?;
        let name = non_empty_text(field(function, "name"), &format!("{path}.function.name"))?;
        declared.push((name.to_owned(), field(function, "parameters")));
    }
    let tools = declare_tools(declared)?;
    let (tool_choice, explicit_tool_choice) = match field(body, "tool_choice") {
        None => (ToolChoice::Auto, false),
        Some(choice) => match openai_choice_word(choice)? {
            Some(choice) => (choice, true),
            None => {
                let choice = object_at(choice, "tool_choice")?;
                let function =
                    field(choice, "function").ok_or_else(|| RequestError::MissingField {
                        field: "tool_choice.function".to_owned(),
                    })?;
                let function = object_at(function, "tool_choice.function")?;
                let name = non_empty_text(field(function, "name"), "tool_choice.function.name")?;
                (
                    ToolChoice::Named {
                        name: name.to_owned(),
                    },
                    true,
                )
            }
        },
    };
    let streaming = optional_bool(body, "stream")?.unwrap_or(false);
    let include_usage = match field(body, "stream_options") {
        None => false,
        Some(options) => {
            if !streaming {
                return Err(RequestError::InvalidValue {
                    field: "stream_options".to_owned(),
                    detail: "only allowed when stream is true".to_owned(),
                });
            }
            optional_bool(object_at(options, "stream_options")?, "include_usage")?.unwrap_or(false)
        }
    };
    Ok(Parsed {
        system_or_context,
        tools,
        tool_choice,
        explicit_tool_choice,
        parallel_calls_allowed: optional_bool(body, "parallel_tool_calls")?.unwrap_or(true),
        streaming,
        // A non-streamed completion always carries usage; a stream only when asked.
        usage_reported: !streaming || include_usage,
    })
}

fn responses(body: &Map<String, Value>) -> Result<Parsed, RequestError> {
    non_empty_text(field(body, "model"), "model")?;
    let mut system_or_context = false;
    if let Some(instructions) = field(body, "instructions") {
        if !instructions.is_string() {
            return Err(RequestError::WrongType {
                field: "instructions".to_owned(),
                expected: "a string",
            });
        }
        system_or_context = true;
    }
    if field(body, "previous_response_id").is_some() {
        system_or_context = true;
    }
    match field(body, "input") {
        None if system_or_context => {}
        None => {
            return Err(RequestError::MissingField {
                field: "input".to_owned(),
            })
        }
        Some(Value::String(_)) => {}
        Some(Value::Array(items)) => {
            for (index, item) in items.iter().enumerate() {
                let path = format!("input[{index}]");
                let item = object_at(item, &path)?;
                match field(item, "role").map(Value::as_str) {
                    Some(Some("user")) => {}
                    Some(Some("system" | "developer" | "assistant")) => system_or_context = true,
                    Some(_) => {
                        return Err(RequestError::InvalidValue {
                            field: format!("{path}.role"),
                            detail: "unknown role".to_owned(),
                        })
                    }
                    // Items without a role are earlier calls, outputs or reasoning.
                    None => system_or_context = true,
                }
            }
        }
        Some(_) => {
            return Err(RequestError::WrongType {
                field: "input".to_owned(),
                expected: "a string or an array",
            })
        }
    }
    let mut declared = Vec::new();
    for (index, tool) in tools_array(body)?.iter().enumerate() {
        let path = format!("tools[{index}]");
        let tool = object_at(tool, &path)?;
        let tool_kind = non_empty_text(field(tool, "type"), &format!("{path}.type"))?;
        if tool_kind != "function" {
            return Err(RequestError::UnsupportedToolType {
                index,
                kind: tool_kind.to_owned(),
            });
        }
        let name = non_empty_text(field(tool, "name"), &format!("{path}.name"))?;
        declared.push((name.to_owned(), field(tool, "parameters")));
    }
    let tools = declare_tools(declared)?;
    let (tool_choice, explicit_tool_choice) = match field(body, "tool_choice") {
        None => (ToolChoice::Auto, false),
        Some(choice) => match openai_choice_word(choice)? {
            Some(choice) => (choice, true),
            None => {
                let choice = object_at(choice, "tool_choice")?;
                let choice_kind = non_empty_text(field(choice, "type"), "tool_choice.type")?;
                if choice_kind != "function" {
                    return Err(RequestError::InvalidValue {
                        field: "tool_choice.type".to_owned(),
                        detail: format!("unsupported choice type {choice_kind:?}"),
                    });
                }
                let name = non_empty_text(field(choice, "name"), "tool_choice.name")?;
                (
                    ToolChoice::Named {
                        name: name.to_owned(),
                    },
                    true,
                )
            }
        },
    };
    Ok(Parsed {
        system_or_context,
        tools,
        tool_choice,
        explicit_tool_choice,
        parallel_calls_allowed: optional_bool(body, "parallel_tool_calls")?.unwrap_or(true),
        streaming: optional_bool(body, "stream")?.unwrap_or(false),
        // A response object always carries usage.
        usage_reported: true,
    })
}

fn messages(body: &Map<String, Value>, kind: RequestKind) -> Result<Parsed, RequestError> {
    non_empty_text(field(body, "model"), "model")?;
    if kind == RequestKind::Generate {
        let max_tokens = field(body, "max_tokens").ok_or_else(|| RequestError::MissingField {
            field: "max_tokens".to_owned(),
        })?;
        if !max_tokens.as_u64().is_some_and(|tokens| tokens > 0) {
            return Err(RequestError::WrongType {
                field: "max_tokens".to_owned(),
                expected: "a positive integer",
            });
        }
    }
    let mut system_or_context = match field(body, "system") {
        None => false,
        Some(Value::String(_) | Value::Array(_)) => true,
        Some(_) => {
            return Err(RequestError::WrongType {
                field: "system".to_owned(),
                expected: "a string or an array",
            })
        }
    };
    for (index, message) in required_array(body, "messages")?.iter().enumerate() {
        let path = format!("messages[{index}]");
        let message = object_at(message, &path)?;
        match non_empty_text(field(message, "role"), &format!("{path}.role"))? {
            "user" => {}
            "assistant" => system_or_context = true,
            other => {
                return Err(RequestError::InvalidValue {
                    field: format!("{path}.role"),
                    detail: format!("unknown role {other:?}"),
                })
            }
        }
    }
    let mut declared = Vec::new();
    for (index, tool) in tools_array(body)?.iter().enumerate() {
        let path = format!("tools[{index}]");
        let tool = object_at(tool, &path)?;
        if let Some(tool_kind) = field(tool, "type") {
            if tool_kind.as_str() != Some("custom") {
                return Err(RequestError::UnsupportedToolType {
                    index,
                    kind: tool_kind.as_str().unwrap_or("non-string").to_owned(),
                });
            }
        }
        let name = non_empty_text(field(tool, "name"), &format!("{path}.name"))?;
        let schema = field(tool, "input_schema").ok_or_else(|| RequestError::MissingField {
            field: format!("{path}.input_schema"),
        })?;
        declared.push((name.to_owned(), Some(schema)));
    }
    let tools = declare_tools(declared)?;
    let (tool_choice, explicit_tool_choice, parallel_calls_allowed) =
        match field(body, "tool_choice") {
            None => (ToolChoice::Auto, false, true),
            Some(choice) => {
                let choice = object_at(choice, "tool_choice")?;
                let tool_choice = match non_empty_text(field(choice, "type"), "tool_choice.type")? {
                    "auto" => ToolChoice::Auto,
                    "any" => ToolChoice::Required,
                    "none" => ToolChoice::Disabled,
                    "tool" => ToolChoice::Named {
                        name: non_empty_text(field(choice, "name"), "tool_choice.name")?.to_owned(),
                    },
                    other => {
                        return Err(RequestError::InvalidValue {
                            field: "tool_choice.type".to_owned(),
                            detail: format!("unknown choice {other:?}"),
                        })
                    }
                };
                let disable_parallel =
                    optional_bool(choice, "disable_parallel_tool_use")?.unwrap_or(false);
                (tool_choice, true, !disable_parallel)
            }
        };
    Ok(Parsed {
        system_or_context,
        tools,
        tool_choice,
        explicit_tool_choice,
        parallel_calls_allowed,
        streaming: optional_bool(body, "stream")?.unwrap_or(false),
        // A message always carries usage.
        usage_reported: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn needs(profile: &RequestProfile) -> Vec<Feature> {
        profile.needs().iter().copied().collect()
    }

    fn read_file() -> Value {
        json!({"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]})
    }

    #[test]
    fn chat_completions_needs_follow_the_fields() {
        let profile = RequestProfile::from_request(
            Dialect::OpenAiChatCompletions,
            &json!({
                "model": "synthetic-model",
                "stream": true,
                "stream_options": {"include_usage": true},
                "messages": [{"role": "system", "content": "synthetic"}, {"role": "user", "content": "synthetic"}],
                "tools": [{"type": "function", "function": {"name": "read_file", "parameters": read_file()}}],
                "tool_choice": "required"
            }),
        )
        .unwrap();
        assert_eq!(
            needs(&profile),
            vec![
                Feature::RequestFields,
                Feature::SystemContextPreservation,
                Feature::ToolSchema,
                Feature::ToolChoice,
                Feature::StreamingDeltas,
                Feature::ParallelCalls,
                Feature::FinishReason,
                Feature::Usage,
                Feature::Errors,
            ]
        );
        assert_eq!(profile.tool_choice(), &ToolChoice::Required);
        assert!(profile.tool("read_file").is_some() && profile.tool("other").is_none());

        // Parallel calls switched off, no usage asked of a stream, no system message.
        let profile = RequestProfile::from_request(
            Dialect::OpenAiChatCompletions,
            &json!({
                "model": "m", "stream": true, "parallel_tool_calls": false,
                "messages": [{"role": "user", "content": "synthetic"}],
                "tools": [{"type": "function", "function": {"name": "read_file"}}]
            }),
        )
        .unwrap();
        assert_eq!(
            needs(&profile),
            vec![
                Feature::RequestFields,
                Feature::ToolSchema,
                Feature::StreamingDeltas,
                Feature::FinishReason,
                Feature::Errors,
            ]
        );
        assert!(!profile.parallel_calls_allowed());
    }

    #[test]
    fn responses_and_messages_always_report_usage() {
        let profile = RequestProfile::from_request(
            Dialect::OpenAiResponses,
            &json!({"model": "m", "input": "synthetic", "instructions": "synthetic"}),
        )
        .unwrap();
        assert!(profile.needs().contains(&Feature::Usage));
        assert!(profile
            .needs()
            .contains(&Feature::SystemContextPreservation));
        assert!(!profile.needs().contains(&Feature::StreamingDeltas));

        let profile = RequestProfile::from_request(
            Dialect::AnthropicMessages,
            &json!({
                "model": "m", "max_tokens": 64, "stream": true,
                "messages": [{"role": "user", "content": "synthetic"}],
                "tools": [{"name": "read_file", "input_schema": read_file()}],
                "tool_choice": {"type": "tool", "name": "read_file", "disable_parallel_tool_use": true}
            }),
        )
        .unwrap();
        assert_eq!(
            profile.tool_choice(),
            &ToolChoice::Named {
                name: "read_file".to_owned()
            }
        );
        assert!(!profile.parallel_calls_allowed());
        assert!(!profile.needs().contains(&Feature::ParallelCalls));
        assert!(profile.needs().contains(&Feature::ToolChoice));
    }

    #[test]
    fn token_counting_needs_its_own_feature() {
        let body = json!({"model": "m", "messages": [{"role": "user", "content": "synthetic"}]});
        let profile =
            RequestProfile::from_token_count_request(Dialect::AnthropicMessages, &body).unwrap();
        assert_eq!(
            needs(&profile),
            vec![
                Feature::RequestFields,
                Feature::TokenCounting,
                Feature::Errors
            ]
        );
        assert_eq!(
            RequestProfile::from_token_count_request(Dialect::OpenAiChatCompletions, &body),
            Err(RequestError::FeatureNotInDialect {
                feature: Feature::TokenCounting
            })
        );
    }

    #[test]
    fn malformed_requests_are_refused() {
        let chat =
            |body: Value| RequestProfile::from_request(Dialect::OpenAiChatCompletions, &body);
        let user = json!([{"role": "user", "content": "synthetic"}]);
        assert_eq!(chat(json!([])), Err(RequestError::NotAnObject));
        assert!(matches!(
            chat(json!({"messages": user})),
            Err(RequestError::MissingField { .. })
        ));
        assert!(matches!(
            chat(
                json!({"model": "m", "messages": user, "stream_options": {"include_usage": true}})
            ),
            Err(RequestError::InvalidValue { .. })
        ));
        assert_eq!(
            chat(json!({"model": "m", "messages": user, "tool_choice": "auto"})),
            Err(RequestError::ToolChoiceWithoutTools)
        );
        let tool = json!({"type": "function", "function": {"name": "read_file"}});
        assert_eq!(
            chat(json!({"model": "m", "messages": user, "tools": [tool.clone(), tool.clone()]})),
            Err(RequestError::DuplicateToolName {
                name: "read_file".to_owned()
            })
        );
        assert_eq!(
            chat(json!({"model": "m", "messages": user, "tools": [tool],
                        "tool_choice": {"type": "function", "function": {"name": "other"}}})),
            Err(RequestError::UnknownToolChoice {
                name: "other".to_owned()
            })
        );
        assert!(matches!(
            chat(json!({"model": "m", "messages": user, "tools": [{"type": "web_search"}]})),
            Err(RequestError::UnsupportedToolType { index: 0, .. })
        ));
        assert!(matches!(
            chat(json!({"model": "m", "messages": user,
                        "tools": [{"type": "function", "function": {"name": "f", "parameters": {"type": "object", "properties": {"p": {"$ref": "#/x"}}}}}]})),
            Err(RequestError::Schema { .. })
        ));
        assert!(matches!(
            RequestProfile::from_request(
                Dialect::AnthropicMessages,
                &json!({"model": "m", "messages": [{"role": "user", "content": "synthetic"}]})
            ),
            Err(RequestError::MissingField { .. })
        ));
    }
}
