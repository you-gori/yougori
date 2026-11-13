//! The conversation: messages as the engine keeps (and stores) them, and as the relay takes
//! them. The wire form is always one a strict chat template accepts: one system message first,
//! user and assistant turns in order, every tool call answered right after the message that made
//! it, never two user messages in a row.
use crate::protocol::{Location, ToolContent, ToolKind, ToolStatus};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    User,
    Assistant,
    Tool,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Call {
    /// The id the model knows the call by.
    pub id: String,
    /// The id the screen knows the call by.
    #[serde(default)]
    pub event: String,
    pub name: String,
    /// The arguments as the model wrote them.
    #[serde(default)]
    pub arguments: String,
}

/// What the screen showed for a tool call, kept for replays.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Shown {
    pub title: String,
    pub kind: ToolKind,
    pub status: ToolStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub content: Vec<ToolContent>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub locations: Vec<Location>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Msg {
    pub role: Role,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub text: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reasoning: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub calls: Vec<Call>,
    /// A tool result: the call it answers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call: Option<String>,
    /// A tool result: what the screen showed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown: Option<Shown>,
    /// An assistant message: the screen's message id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// A user message: what the person typed, when the model got more (a mode note, the
    /// prompt behind a command).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typed: Option<String>,
}

impl Msg {
    pub fn user(text: impl Into<String>) -> Msg {
        Msg {
            role: Role::User,
            text: text.into(),
            reasoning: String::new(),
            calls: Vec::new(),
            call: None,
            shown: None,
            id: None,
            typed: None,
        }
    }

    pub fn assistant(id: &str, text: String, reasoning: String, calls: Vec<Call>) -> Msg {
        Msg { role: Role::Assistant, text, reasoning, calls, call: None, shown: None, id: Some(id.to_owned()), typed: None }
    }

    pub fn tool(call: &str, text: String, shown: Shown) -> Msg {
        Msg {
            role: Role::Tool,
            text,
            reasoning: String::new(),
            calls: Vec::new(),
            call: Some(call.to_owned()),
            shown: Some(shown),
            id: None,
            typed: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub seq: i64,
    pub msg: Msg,
}

/// What the model sees in place of an old tool output.
pub const TRIMMED: &str = "[This output was removed to save room. Run the tool again if you need it.]";
/// Outputs this short are never trimmed: they cost little and often matter.
pub const KEEP_SMALL: usize = 400;
/// What a tool call that never ran answers.
pub const NOT_RUN: &str = "Not run: the turn was stopped first.";

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Conversation {
    /// What compaction kept of older messages: the first user message the model sees.
    pub head: Option<String>,
    /// When the kept messages start inside a turn whose request was summarised: that request in
    /// the person's words (also at the end of `head`), so every later compaction keeps it too.
    pub request: Option<String>,
    pub entries: Vec<Entry>,
    /// Tool outputs of entries before this seq reach the model trimmed.
    pub trim_before: i64,
    pub next_seq: i64,
}

impl Conversation {
    pub fn push(&mut self, msg: Msg) -> i64 {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.entries.push(Entry { seq, msg });
        seq
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.head.is_none()
    }

    /// A tool result's text as the model sees it now.
    pub fn tool_text<'a>(&self, entry: &'a Entry) -> &'a str {
        if entry.seq < self.trim_before && entry.msg.text.len() > KEEP_SMALL {
            TRIMMED
        } else {
            &entry.msg.text
        }
    }

    /// The messages for the relay, after `system`.
    pub fn wire(&self, system: &str) -> Vec<Value> {
        let mut out = vec![json!({ "role": "system", "content": system })];
        let mut user: Option<String> = self.head.clone();
        let mut open: Vec<String> = Vec::new();
        for entry in &self.entries {
            let msg = &entry.msg;
            match msg.role {
                Role::User => {
                    answer_open(&mut out, &mut open);
                    user = Some(match user.take() {
                        Some(before) if !before.is_empty() => format!("{before}\n\n{}", msg.text),
                        _ => msg.text.clone(),
                    });
                }
                Role::Assistant => {
                    answer_open(&mut out, &mut open);
                    if msg.text.is_empty() && msg.calls.is_empty() {
                        continue;
                    }
                    if let Some(text) = user.take() {
                        out.push(json!({ "role": "user", "content": text }));
                    }
                    if out.len() == 1 {
                        // Templates want a user turn first; only reachable with damaged history.
                        out.push(json!({ "role": "user", "content": "Continue the work." }));
                    }
                    let mut message = json!({ "role": "assistant", "content": msg.text });
                    if !msg.calls.is_empty() {
                        message["tool_calls"] = msg
                            .calls
                            .iter()
                            .map(|call| {
                                json!({
                                    "id": call.id,
                                    "type": "function",
                                    "function": { "name": call.name, "arguments": wire_arguments(&call.arguments) },
                                })
                            })
                            .collect();
                        open = msg.calls.iter().map(|c| c.id.clone()).collect();
                    }
                    out.push(message);
                }
                Role::Tool => {
                    let Some(call) = &msg.call else { continue };
                    if let Some(at) = open.iter().position(|id| id == call) {
                        open.remove(at);
                        out.push(json!({ "role": "tool", "tool_call_id": call, "content": self.tool_text(entry) }));
                    }
                }
            }
        }
        answer_open(&mut out, &mut open);
        if let Some(text) = user.take() {
            out.push(json!({ "role": "user", "content": text }));
        }
        out
    }
}

/// Calls left without a result (a stopped turn) get one, so the history stays valid.
fn answer_open(out: &mut Vec<Value>, open: &mut Vec<String>) {
    for id in open.drain(..) {
        out.push(json!({ "role": "tool", "tool_call_id": id, "content": NOT_RUN }));
    }
}

/// Arguments as sent back to the relay: the model's own text when it is a JSON object, `{}`
/// otherwise (servers parse them, and a malformed one would fail every later request).
pub fn wire_arguments(raw: &str) -> String {
    match serde_json::from_str::<Value>(raw) {
        Ok(Value::Object(_)) => raw.trim().to_owned(),
        _ => "{}".to_owned(),
    }
}

/// Characters per token for the first estimate, before the server's counts calibrate it.
const CHARS_PER_TOKEN: f64 = 3.6;

/// Tokens a request of these messages and tools takes, uncalibrated.
pub fn estimate(messages: &[Value], tools: &[Value]) -> usize {
    let chars: usize = messages.iter().map(|m| json_len(m) + 12).sum::<usize>() + tools.iter().map(json_len).sum::<usize>();
    (chars as f64 / CHARS_PER_TOKEN).ceil() as usize
}

/// Tokens of plain text, uncalibrated.
pub fn estimate_text(text: &str) -> usize {
    (text.len() as f64 / CHARS_PER_TOKEN).ceil() as usize
}

fn json_len(value: &Value) -> usize {
    serde_json::to_string(value).map(|s| s.len()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shown() -> Shown {
        Shown { title: "t".into(), kind: ToolKind::Read, status: ToolStatus::Completed, content: Vec::new(), locations: Vec::new() }
    }

    fn call(id: &str) -> Call {
        Call { id: id.into(), event: format!("e{id}"), name: "read".into(), arguments: "{\"path\":\"a\"}".into() }
    }

    #[test]
    fn wire_merges_users_answers_open_calls_and_trims() {
        let mut conv = Conversation::default();
        conv.push(Msg::user("first"));
        conv.push(Msg::user("second"));
        conv.push(Msg::assistant("m1", String::new(), "thinking".into(), vec![call("a"), call("b")]));
        conv.push(Msg::tool("a", "x".repeat(KEEP_SMALL + 1), shown()));
        // "b" never got a result (the turn was stopped).
        conv.push(Msg::user("third"));
        conv.push(Msg::assistant("m2", "done".into(), String::new(), Vec::new()));
        conv.trim_before = 4;
        let wire = conv.wire("sys");
        let roles: Vec<&str> = wire.iter().map(|m| m["role"].as_str().unwrap()).collect();
        assert_eq!(roles, vec!["system", "user", "assistant", "tool", "tool", "user", "assistant"]);
        assert_eq!(wire[1]["content"], "first\n\nsecond");
        assert_eq!(wire[3]["content"], TRIMMED);
        assert_eq!(wire[4]["content"], NOT_RUN);
        assert_eq!(wire[4]["tool_call_id"], "b");
        assert!(wire[2].get("reasoning").is_none(), "reasoning is not sent back");
        assert_eq!(wire[2]["tool_calls"][0]["function"]["arguments"], "{\"path\":\"a\"}");
    }

    #[test]
    fn head_comes_first_and_bad_arguments_become_empty_objects() {
        let mut conv = Conversation { head: Some("Summary".into()), ..Default::default() };
        let mut bad = call("a");
        bad.arguments = "{\"path\": ".into();
        conv.push(Msg::assistant("m", String::new(), String::new(), vec![bad]));
        conv.push(Msg::tool("a", "Error".into(), shown()));
        let wire = conv.wire("sys");
        assert_eq!(wire[1], json!({"role": "user", "content": "Summary"}));
        assert_eq!(wire[2]["tool_calls"][0]["function"]["arguments"], "{}");
        assert!(estimate(&wire, &[]) > 0);
    }

    #[test]
    fn messages_round_trip_as_json() {
        let msg = Msg::tool("a", "out".into(), shown());
        let text = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<Msg>(&text).unwrap(), msg);
    }
}
