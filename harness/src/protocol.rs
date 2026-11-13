//! The one event model between an engine and the screen.
//!
//! Every engine the Yougori harness holds (our own agent, an ACP agent such as OpenCode, Codex's
//! app-server, Claude Code's stream-json, Pi's RPC mode, and the Python bridges for the rest)
//! turns what it does into these [`Event`]s, and takes these [`Command`]s from the screen. The
//! shape follows the Agent Client Protocol (ACP) so ACP agents map one to one; the additions
//! (findings, reports, progress, questions, usage) carry what coding and security harnesses report
//! beyond ACP. Everything serialises to JSON so a scripted engine and the tests can replay it.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::mpsc;

/// What an engine tells the screen.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    /// The engine is started and takes prompts. Sent once, and again after a restart.
    Ready(Ready),
    /// The model's reply, streamed. Chunks with the same `message` id form one message.
    Message {
        message: String,
        text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        parent: Option<String>,
    },
    /// The model's reasoning, streamed; the screen shows it folded.
    Reasoning {
        message: String,
        text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        parent: Option<String>,
    },
    /// A prompt as the engine records it (a replayed session, or text a bridge sent for the user).
    User { text: String },
    /// A tool call was announced or started.
    ToolCall(ToolCall),
    /// A tool call progressed or finished. Fields left out keep their value.
    ToolUpdate(ToolUpdate),
    /// The engine asks before it acts. Answer with [`Command::Permission`].
    Permission(PermissionRequest),
    /// The engine asks the person something. Answer with [`Command::Answer`].
    Question(QuestionRequest),
    /// The whole plan or to-do list, replacing the previous one.
    Plan { entries: Vec<PlanEntry> },
    /// A security finding.
    Finding(Finding),
    /// A report the harness saved (a security report, a patch, a run summary).
    Report(Report),
    /// Long work in phases or bytes (a scan phase, a pipeline stage, a download).
    Progress(Progress),
    /// Tokens: the context in use for the status line.
    Usage(Usage),
    /// The model in use is now this one.
    Model { model: String },
    /// The modes the engine offers (plan and build, ask and code, architect) and the current one.
    Modes { current: String, available: Vec<Mode> },
    /// The slash commands the engine offers.
    Commands { commands: Vec<SlashCommand> },
    /// The turn started by the last prompt ended.
    TurnEnd {
        reason: StopReason,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },
    /// Something for the person that is not model output.
    Notice { level: Level, text: String },
    /// The engine stopped and cannot take more prompts.
    Exit {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        code: Option<i32>,
        message: String,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Ready {
    /// Harness id, such as `opencode`.
    pub harness: String,
    /// Display name, such as `OpenCode`.
    pub name: String,
    pub model: String,
    /// Models the person may switch to (this inference's list).
    #[serde(default)]
    pub models: Vec<String>,
    pub model_switch: ModelSwitch,
    /// The engine's session id, when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    /// One line about the engine (version, mode), shown on the home screen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub info: Option<String>,
}

/// How a model change reaches the engine.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelSwitch {
    /// The engine switches in the same session.
    Live,
    /// The engine restarts with the new model; the conversation starts again.
    #[default]
    Restart,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    /// What the call does, in a few words: `Read src/main.rs`, `cargo test`.
    pub title: String,
    pub kind: ToolKind,
    pub status: ToolStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub locations: Vec<Location>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub content: Vec<ToolContent>,
    /// The task (subagent) call this call belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ToolUpdate {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<ToolStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Replaces the call's content when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<Vec<ToolContent>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locations: Option<Vec<Location>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<Value>,
}

/// ACP's tool kinds, plus `task` for a subagent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolKind {
    Read,
    Edit,
    Delete,
    Move,
    Search,
    Execute,
    Think,
    Fetch,
    Task,
    SwitchMode,
    #[default]
    Other,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolStatus {
    #[default]
    Pending,
    InProgress,
    Completed,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Location {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ToolContent {
    Text {
        text: String,
    },
    /// A file change. `old` is None for a new file.
    Diff {
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        old: Option<String>,
        new: String,
    },
    /// A command's output (the latest, bounded) and, once it ended, its exit code.
    Terminal {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        command: Option<String>,
        output: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exit_code: Option<i32>,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct PermissionRequest {
    /// Answer with this id.
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call: Option<String>,
    /// What is asked: `Run cargo test`, `Edit src/main.rs`.
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub options: Vec<PermissionOption>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PermissionOption {
    pub id: String,
    pub label: String,
    pub kind: PermissionKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionKind {
    AllowOnce,
    AllowAlways,
    RejectOnce,
    RejectAlways,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct QuestionRequest {
    pub id: String,
    pub question: String,
    /// Choices to pick from; empty for a typed answer.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub choices: Vec<String>,
    /// Several choices may be picked.
    #[serde(default)]
    pub multiple: bool,
    /// A typed answer is accepted besides the choices.
    #[serde(default)]
    pub allow_text: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PlanEntry {
    pub content: String,
    pub status: PlanStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<Priority>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanStatus {
    Pending,
    InProgress,
    Completed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    High,
    Medium,
    Low,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    /// Anything else the harness reports (CVSS, CWE, the endpoint).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    #[default]
    Info,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub title: String,
    /// Where the report is, inside the workspace when it should come back to the person.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Progress {
    /// Updates with the same id replace each other.
    pub id: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub done: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
    /// `bytes`, `steps`, `agents`... how to show done and total.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(default)]
    pub finished: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Usage {
    /// Tokens the conversation takes in the context window now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_window: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Mode {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SlashCommand {
    /// Without the slash.
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// What to type after the command, when it takes text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    EndTurn,
    MaxSteps,
    MaxTokens,
    Cancelled,
    Refused,
    Error,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    Info,
    Warn,
    Error,
}

/// What the screen asks of an engine.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Command {
    /// A prompt. A text starting with `/` is a slash command for engines that offer it.
    Prompt { text: String },
    /// Stop the current turn (Esc). The engine ends it with `TurnEnd { reason: Cancelled }`.
    Cancel,
    /// The answer to a [`PermissionRequest`]: one of its option ids, or None when dismissed.
    Permission { id: String, option: Option<String> },
    /// The answer to a [`QuestionRequest`]; None when dismissed.
    Answer { id: String, answer: Option<Vec<String>> },
    SetModel { model: String },
    SetMode { mode: String },
    /// End the engine, its child processes and services.
    Shutdown,
}

/// A running engine as the screen holds it.
pub struct EngineHandle {
    pub commands: mpsc::UnboundedSender<Command>,
    pub events: mpsc::UnboundedReceiver<Event>,
    /// Kept alive as long as the engine: child processes and services stop when it drops.
    pub keep: Vec<Box<dyn std::any::Any + Send>>,
}

impl EngineHandle {
    /// A handle and the engine's ends of its two channels.
    pub fn pair() -> (EngineHandle, mpsc::UnboundedReceiver<Command>, mpsc::UnboundedSender<Event>) {
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        (EngineHandle { commands: command_tx, events: event_rx, keep: Vec::new() }, command_rx, event_tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_round_trip_as_json() {
        let events = vec![
            Event::Ready(Ready {
                harness: "opencode".into(),
                name: "OpenCode".into(),
                model: "m".into(),
                models: vec!["m".into()],
                model_switch: ModelSwitch::Live,
                session: None,
                info: None,
            }),
            Event::Message { message: "1".into(), text: "Hello".into(), parent: None },
            Event::ToolCall(ToolCall {
                id: "t".into(),
                title: "Read a.rs".into(),
                kind: ToolKind::Read,
                status: ToolStatus::InProgress,
                ..Default::default()
            }),
            Event::ToolUpdate(ToolUpdate {
                id: "t".into(),
                status: Some(ToolStatus::Completed),
                content: Some(vec![ToolContent::Diff { path: "a.rs".into(), old: None, new: "x".into() }]),
                ..Default::default()
            }),
            Event::Finding(Finding { id: "f".into(), title: "SQL injection".into(), severity: Severity::High, ..Default::default() }),
            Event::TurnEnd { reason: StopReason::EndTurn, detail: None },
        ];
        for event in events {
            let text = serde_json::to_string(&event).unwrap();
            assert_eq!(serde_json::from_str::<Event>(&text).unwrap(), event, "{text}");
        }
        let command: Command = serde_json::from_str(r#"{"type":"permission","id":"p","option":"allow_once"}"#).unwrap();
        assert_eq!(command, Command::Permission { id: "p".into(), option: Some("allow_once".into()) });
    }
}
