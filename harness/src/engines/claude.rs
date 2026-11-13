//! Claude Code headless at 2.1.316: `claude -p --input-format stream-json --output-format
//! stream-json --verbose --include-partial-messages --permission-prompt-tool stdio`. Prompts go
//! in as `user` messages; the engine streams `stream_event` deltas, whole `assistant` and `user`
//! (tool result) messages and a `result` per turn; it asks before tools through `can_use_tool`
//! control requests, which also carry AskUserQuestion's questions. The control messages follow
//! the MIT Claude Agent SDK for Python (`initialize`, `interrupt`, `set_model`,
//! `set_permission_mode`); none of Claude Code's own text is used here.
use super::acp::Transport;
use super::codex::short_title;
use super::process::{self, Launch, LineWriter, ProcessGuard, Stdio2, Tail};
use crate::protocol::{
    Command, EngineHandle, Event, Level, Location, Mode, ModelSwitch, PermissionKind, PermissionOption, PermissionRequest,
    PlanEntry, PlanStatus, Progress, QuestionRequest, Ready, SlashCommand, StopReason, ToolCall, ToolContent, ToolKind,
    ToolStatus, ToolUpdate, Usage,
};
use crate::spec::EngineSpec;
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::time::Duration;
use tokio::sync::mpsc;

#[cfg(test)]
mod tests;

const START_LIMIT: Duration = Duration::from_secs(180);
/// Tool output shown in a call: the latest part.
const OUTPUT_LIMIT: usize = 64 * 1024;
/// A file read to show a write as a diff.
const DIFF_FILE_LIMIT: u64 = 2 * 1024 * 1024;
/// What a person is told was declined, in the engine's own conversation.
const DECLINED: &str = "The person declined this action.";
const STOPPED: &str = "The person stopped this action.";

pub async fn start(spec: &EngineSpec) -> anyhow::Result<EngineHandle> {
    let env = spec.environment();
    let spawned = process::spawn(Launch {
        name: &spec.name,
        log: &spec.harness,
        argv: &spec.argv,
        env: &env,
        cwd: &spec.cwd,
        state_dir: &spec.state_dir,
        stdio: Stdio2::Piped,
    })
    .await?;
    let (Some(stdin), Some(stdout)) = (spawned.stdin, spawned.stdout) else {
        anyhow::bail!("{} started without its pipes.", spec.name);
    };
    let noise = Tail::default();
    connect(
        spec.clone(),
        Transport { values: process::json_lines(stdout, noise.clone()), writer: LineWriter::new(stdin), guard: Some(spawned.guard), noise },
    )
    .await
}

pub(crate) async fn connect(spec: EngineSpec, transport: Transport) -> anyhow::Result<EngineHandle> {
    let Transport { mut values, writer, guard, noise } = transport;
    let mut backlog = VecDeque::new();
    writer.send(&json!({"type": "control_request", "request_id": "init", "request": {"subtype": "initialize", "hooks": null}}));
    let deadline = tokio::time::Instant::now() + START_LIMIT;
    let init = loop {
        match tokio::time::timeout_at(deadline, values.recv()).await {
            Err(_) => return Err(failed(&spec, guard.as_ref(), &noise, "it did not answer in time").await),
            Ok(None) => return Err(failed(&spec, guard.as_ref(), &noise, "it ended before answering").await),
            Ok(Some(message)) => {
                let response = &message["response"];
                if message["type"] == "control_response" && response["request_id"] == "init" {
                    if response["subtype"] == "error" {
                        let error = response["error"].as_str().unwrap_or("it refused to start").to_owned();
                        return Err(failed(&spec, guard.as_ref(), &noise, &error).await);
                    }
                    break response["response"].clone();
                }
                backlog.push_back(message);
            }
        }
    };
    let (mut handle, commands, events) = EngineHandle::pair();
    if let Some(guard) = guard.clone() {
        handle.keep.push(Box::new(guard));
    }
    let version = init["claude_code_version"].as_str().map(str::to_owned);
    let _ = events.send(Event::Ready(Ready {
        harness: spec.harness.clone(),
        name: spec.name.clone(),
        model: spec.model.clone(),
        models: spec.models.clone(),
        model_switch: if spec.model_switch == ModelSwitch::Live { ModelSwitch::Live } else { ModelSwitch::Restart },
        session: None,
        info: Some(match version {
            Some(v) => format!("Claude Code {v} · stream-json"),
            None => "Claude Code · stream-json".to_owned(),
        }),
    }));
    let mode = init["current_permission_mode"].as_str().unwrap_or("default").to_owned();
    let _ = events.send(Event::Modes { current: mode.clone(), available: modes() });
    let commands_offered: Vec<SlashCommand> = init["commands"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|c| {
            Some(SlashCommand {
                name: c["name"].as_str()?.to_owned(),
                description: c["description"].as_str().unwrap_or("").to_owned(),
                hint: c["argumentHint"].as_str().filter(|h| !h.is_empty()).map(str::to_owned),
            })
        })
        .collect();
    if !commands_offered.is_empty() {
        let _ = events.send(Event::Commands { commands: commands_offered });
    }
    let engine = Engine {
        model: spec.model.clone(),
        spec,
        writer,
        events,
        guard,
        noise,
        mode,
        session: None,
        turn: None,
        queue: VecDeque::new(),
        next_request: 0,
        pending: HashMap::new(),
        asked: HashMap::new(),
        asks: HashMap::new(),
        asking: HashMap::new(),
        tools: HashMap::new(),
        hidden: HashSet::new(),
        streamed: HashSet::new(),
        message: None,
        last_usage: None,
    };
    tokio::spawn(engine.run(values, backlog, commands));
    Ok(handle)
}

async fn failed(spec: &EngineSpec, guard: Option<&ProcessGuard>, noise: &Tail, why: &str) -> anyhow::Error {
    let mut text = format!("{} did not start: {why}.", spec.name);
    if let Some(guard) = guard {
        let _ = guard.wait_for(Duration::from_millis(800)).await;
        if let Some(status) = guard.status() {
            text = format!("{} did not start: it {}.", spec.name, process::describe(status));
        }
        let tail = guard.tail();
        if !tail.trim().is_empty() {
            text.push('\n');
            text.push_str(&tail);
        } else if !noise.is_empty() {
            text.push('\n');
            text.push_str(&noise.text());
        }
        guard.stop().await;
    }
    anyhow::anyhow!(text)
}

/// Claude Code's permission modes.
fn modes() -> Vec<Mode> {
    vec![
        Mode { id: "default".into(), name: "Ask".into(), description: Some("Asks before edits and commands".into()) },
        Mode { id: "acceptEdits".into(), name: "Accept edits".into(), description: Some("Edits without asking; asks before commands".into()) },
        Mode { id: "plan".into(), name: "Plan".into(), description: Some("Reads and plans; changes nothing".into()) },
        Mode { id: "bypassPermissions".into(), name: "Never ask".into(), description: Some("Runs everything without asking".into()) },
    ]
}

enum Pending {
    Interrupt,
    SetModel(String),
    SetMode(String),
}

struct Turn {
    cancelled: bool,
}

/// A tool permission shown to the person.
struct Asked {
    request: String,
    input: Value,
    suggestions: Value,
}

/// AskUserQuestion's questions, asked one after another, answered together.
struct Asks {
    request: String,
    input: Value,
    remaining: VecDeque<(String, QuestionRequest)>,
    answers: Map<String, Value>,
}

/// What a tool call is, to show its result.
struct Tool {
    name: String,
    command: Option<String>,
}

struct Engine {
    spec: EngineSpec,
    writer: LineWriter,
    events: mpsc::UnboundedSender<Event>,
    guard: Option<ProcessGuard>,
    noise: Tail,
    model: String,
    mode: String,
    session: Option<String>,
    turn: Option<Turn>,
    queue: VecDeque<String>,
    next_request: u64,
    pending: HashMap<String, Pending>,
    asked: HashMap<String, Asked>,
    asks: HashMap<String, Asks>,
    /// Shown question id -> its request.
    asking: HashMap<String, String>,
    tools: HashMap<String, Tool>,
    /// Calls not shown as calls (TodoWrite shows as the plan, AskUserQuestion as questions).
    hidden: HashSet<String>,
    /// Messages whose text and thinking arrived as deltas.
    streamed: HashSet<String>,
    /// The message the deltas belong to.
    message: Option<String>,
    last_usage: Option<Value>,
}

enum Flow {
    Go,
    Stop,
}

impl Engine {
    fn emit(&self, event: Event) {
        let _ = self.events.send(event);
    }

    fn notice(&self, level: Level, text: impl Into<String>) {
        self.emit(Event::Notice { level, text: text.into() });
    }

    fn control(&mut self, request: Value, pending: Pending) {
        self.next_request += 1;
        let id = format!("yh-{}", self.next_request);
        self.writer.send(&json!({"type": "control_request", "request_id": id, "request": request}));
        self.pending.insert(id, pending);
    }

    fn respond(&self, request: &str, response: Value) {
        self.writer.send(&json!({"type": "control_response", "response": {"subtype": "success", "request_id": request, "response": response}}));
    }

    fn refuse(&self, request: &str, error: &str) {
        self.writer.send(&json!({"type": "control_response", "response": {"subtype": "error", "request_id": request, "error": error}}));
    }

    async fn run(mut self, mut values: mpsc::UnboundedReceiver<Value>, mut backlog: VecDeque<Value>, mut commands: mpsc::UnboundedReceiver<Command>) {
        while let Some(message) = backlog.pop_front() {
            self.message_in(message);
        }
        let guard = self.guard.clone();
        let mut exited_at: Option<tokio::time::Instant> = None;
        loop {
            let wait_exit = async {
                match (&guard, exited_at) {
                    (Some(g), None) => {
                        g.wait().await;
                    }
                    _ => std::future::pending::<()>().await,
                }
            };
            let grace = async {
                match exited_at {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending::<()>().await,
                }
            };
            tokio::select! {
                command = commands.recv() => {
                    let flow = match command {
                        Some(command) => self.command(command).await,
                        None => {
                            self.shutdown().await;
                            Flow::Stop
                        }
                    };
                    if matches!(flow, Flow::Stop) {
                        break;
                    }
                }
                message = values.recv() => match message {
                    Some(message) => self.message_in(message),
                    None => {
                        self.ended().await;
                        break;
                    }
                },
                _ = wait_exit => exited_at = Some(tokio::time::Instant::now() + Duration::from_millis(1500)),
                _ = grace => {
                    self.ended().await;
                    break;
                }
            }
        }
    }

    async fn command(&mut self, command: Command) -> Flow {
        match command {
            Command::Prompt { text } => {
                if self.turn.is_some() {
                    self.queue.push_back(text);
                } else {
                    self.prompt(text);
                }
            }
            Command::Cancel => self.cancel(),
            Command::Permission { id, option } => {
                if let Some(asked) = self.asked.remove(&id) {
                    let response = match option.as_deref() {
                        Some("allow") => json!({"behavior": "allow", "updatedInput": asked.input}),
                        Some("always") => json!({"behavior": "allow", "updatedInput": asked.input, "updatedPermissions": asked.suggestions}),
                        Some(_) => json!({"behavior": "deny", "message": DECLINED}),
                        None => json!({"behavior": "deny", "message": STOPPED, "interrupt": true}),
                    };
                    self.respond(&asked.request, response);
                }
            }
            Command::Answer { id, answer } => self.answered(&id, answer),
            Command::SetModel { model } => {
                if self.spec.model_switch != ModelSwitch::Live {
                    self.notice(Level::Warn, format!("{} switches models by restarting.", self.spec.name));
                } else {
                    self.control(json!({"subtype": "set_model", "model": model}), Pending::SetModel(model));
                }
            }
            Command::SetMode { mode } => {
                if modes().iter().any(|m| m.id == mode) {
                    self.control(json!({"subtype": "set_permission_mode", "mode": mode}), Pending::SetMode(mode));
                } else {
                    self.notice(Level::Warn, format!("Claude Code has no mode {mode}."));
                }
            }
            Command::Shutdown => {
                self.shutdown().await;
                return Flow::Stop;
            }
        }
        Flow::Go
    }

    fn prompt(&mut self, text: String) {
        self.writer.send(&json!({"type": "user", "message": {"role": "user", "content": text}, "parent_tool_use_id": null,
                                 "session_id": self.session.clone().unwrap_or_default()}));
        self.turn = Some(Turn { cancelled: false });
    }

    fn cancel(&mut self) {
        self.queue.clear();
        let Some(turn) = self.turn.as_mut() else { return };
        if turn.cancelled {
            return;
        }
        turn.cancelled = true;
        self.control(json!({"subtype": "interrupt"}), Pending::Interrupt);
        self.close_asks();
    }

    /// Answers every open permission and question: the turn is over or stopping.
    fn close_asks(&mut self) {
        for (_, asked) in std::mem::take(&mut self.asked) {
            self.respond(&asked.request, json!({"behavior": "deny", "message": STOPPED, "interrupt": true}));
        }
        self.asking.clear();
        for (_, asks) in std::mem::take(&mut self.asks) {
            self.respond(&asks.request, json!({"behavior": "deny", "message": STOPPED, "interrupt": true}));
        }
    }

    fn message_in(&mut self, message: Value) {
        match message["type"].as_str().unwrap_or("") {
            "control_response" => self.control_response(&message["response"]),
            "control_request" => {
                let request = message["request_id"].as_str().unwrap_or("").to_owned();
                self.control_request(request, &message["request"]);
            }
            "control_cancel_request" => {
                // The engine withdrew a question it asked; its answer is no longer wanted.
                if let Some(request) = message["request_id"].as_str() {
                    self.asked.retain(|_, a| a.request != request);
                    self.asks.retain(|_, a| a.request != request);
                    let asks = &self.asks;
                    self.asking.retain(|_, r| asks.contains_key(r));
                }
            }
            "system" => self.system(&message),
            "stream_event" => self.stream_event(&message["event"], parent(&message)),
            "assistant" => self.assistant(&message),
            "user" => self.user(&message),
            "result" => self.result(&message),
            _ => {}
        }
    }

    fn control_response(&mut self, response: &Value) {
        let Some(id) = response["request_id"].as_str() else { return };
        let Some(pending) = self.pending.remove(id) else { return };
        let error = (response["subtype"] == "error").then(|| response["error"].as_str().unwrap_or("refused").to_owned());
        match (pending, error) {
            (Pending::SetModel(model), None) => {
                self.model = model.clone();
                self.emit(Event::Model { model });
            }
            (Pending::SetModel(model), Some(error)) => self.notice(Level::Error, format!("Could not switch to {model}: {error}")),
            (Pending::SetMode(mode), None) => {
                self.mode = mode.clone();
                self.emit(Event::Modes { current: mode, available: modes() });
            }
            (Pending::SetMode(mode), Some(error)) => self.notice(Level::Error, format!("Could not switch to the {mode} mode: {error}")),
            (Pending::Interrupt, Some(error)) => self.notice(Level::Warn, format!("Claude Code did not stop: {error}")),
            (Pending::Interrupt, None) => {}
        }
    }

    fn control_request(&mut self, request: String, body: &Value) {
        match body["subtype"].as_str() {
            Some("can_use_tool") => {
                let tool = body["tool_name"].as_str().unwrap_or("tool").to_owned();
                let input = body["input"].clone();
                let tool_use = body["tool_use_id"].as_str().map(str::to_owned);
                if self.turn.as_ref().map(|t| t.cancelled).unwrap_or(false) {
                    self.respond(&request, json!({"behavior": "deny", "message": STOPPED, "interrupt": true}));
                    return;
                }
                if tool == "AskUserQuestion" {
                    self.questions(request, input);
                    return;
                }
                if let Some(id) = &tool_use {
                    if !self.tools.contains_key(id) && !self.hidden.contains(id) {
                        self.tool_use(id, &tool, &input, None);
                    }
                }
                let title = body["title"].as_str().filter(|t| !t.is_empty()).map(str::to_owned).unwrap_or_else(|| asked_title(&tool, &input));
                let detail = body["description"]
                    .as_str()
                    .filter(|d| !d.is_empty() && *d != title)
                    .or(body["decision_reason"].as_str())
                    .map(str::to_owned);
                let suggestions = body["permission_suggestions"].clone();
                let mut options = vec![PermissionOption { id: "allow".into(), label: "Yes".into(), kind: PermissionKind::AllowOnce }];
                if suggestions.as_array().map(|s| !s.is_empty()).unwrap_or(false) {
                    options.push(PermissionOption { id: "always".into(), label: "Yes, and don't ask again".into(), kind: PermissionKind::AllowAlways });
                }
                options.push(PermissionOption { id: "deny".into(), label: "No".into(), kind: PermissionKind::RejectOnce });
                let ours = format!("claude-{request}");
                self.asked.insert(ours.clone(), Asked { request, input, suggestions });
                self.emit(Event::Permission(PermissionRequest { id: ours, tool_call: tool_use, title, detail, options }));
            }
            Some(other) => {
                let other = other.to_owned();
                self.refuse(&request, &format!("Yougori does not handle {other}."));
            }
            None => self.refuse(&request, "A control request needs a subtype."),
        }
    }

    fn questions(&mut self, request: String, input: Value) {
        let mut remaining = VecDeque::new();
        for (index, question) in input["questions"].as_array().into_iter().flatten().enumerate() {
            let text = question["question"].as_str().unwrap_or("").to_owned();
            let header = question["header"].as_str().unwrap_or("");
            let shown = QuestionRequest {
                id: format!("claude-q-{request}-{index}"),
                question: if header.is_empty() || text.starts_with(header) { text.clone() } else { format!("{header}: {text}") },
                choices: question["options"].as_array().into_iter().flatten().filter_map(|o| o["label"].as_str().map(str::to_owned)).collect(),
                multiple: question["multiSelect"].as_bool().unwrap_or(false),
                allow_text: true,
            };
            remaining.push_back((text, shown));
        }
        let key = format!("claude-q-{request}");
        self.asks.insert(key.clone(), Asks { request, input, remaining, answers: Map::new() });
        self.next_question(&key);
    }

    fn next_question(&mut self, key: &str) {
        let Some(asks) = self.asks.get(key) else { return };
        match asks.remaining.front() {
            Some((_, question)) => {
                self.asking.insert(question.id.clone(), key.to_owned());
                self.emit(Event::Question(question.clone()));
            }
            None => {
                let asks = self.asks.remove(key).expect("present");
                let mut input = asks.input;
                input["answers"] = Value::Object(asks.answers);
                self.respond(&asks.request, json!({"behavior": "allow", "updatedInput": input}));
            }
        }
    }

    fn answered(&mut self, shown: &str, answer: Option<Vec<String>>) {
        let Some(key) = self.asking.remove(shown) else { return };
        let Some(asks) = self.asks.get_mut(&key) else { return };
        let Some((question, _)) = asks.remaining.pop_front() else { return };
        match answer {
            Some(values) => {
                asks.answers.insert(question, json!(values.join(", ")));
                self.next_question(&key);
            }
            None => {
                let asks = self.asks.remove(&key).expect("present");
                self.respond(&asks.request, json!({"behavior": "deny", "message": "The person did not answer."}));
            }
        }
    }

    fn system(&mut self, message: &Value) {
        match message["subtype"].as_str() {
            Some("init") => {
                if let Some(session) = message["session_id"].as_str() {
                    self.session = Some(session.to_owned());
                }
                if let Some(model) = message["model"].as_str() {
                    if model != self.model {
                        self.model = model.to_owned();
                        self.emit(Event::Model { model: model.to_owned() });
                    }
                }
                self.mode_seen(message["permissionMode"].as_str());
            }
            Some("status") => {
                self.mode_seen(message["permissionMode"].as_str());
                if message["status"] == "compacting" {
                    self.emit(Event::Progress(Progress { id: "compaction".into(), label: "Compacting the conversation".into(), ..Default::default() }));
                }
            }
            Some("compact_boundary") => self.emit(Event::Progress(Progress {
                id: "compaction".into(),
                label: "Compacted the conversation".into(),
                finished: true,
                ..Default::default()
            })),
            Some("api_retry") => {
                let attempt = message["attempt"].as_u64().map(|a| format!(" (attempt {a})")).unwrap_or_default();
                self.notice(Level::Warn, format!("The model did not answer; Claude Code tries again{attempt}."));
            }
            // Announcements and task bookkeeping are not for this screen.
            _ => {}
        }
    }

    fn mode_seen(&mut self, mode: Option<&str>) {
        if let Some(mode) = mode {
            if mode != self.mode {
                self.mode = mode.to_owned();
                self.emit(Event::Modes { current: mode.to_owned(), available: modes() });
            }
        }
    }

    fn stream_event(&mut self, event: &Value, parent: Option<String>) {
        match event["type"].as_str() {
            Some("message_start") => {
                self.message = event["message"]["id"].as_str().map(str::to_owned);
                if let Some(usage) = event["message"].get("usage") {
                    self.last_usage = Some(usage.clone());
                }
            }
            Some("content_block_delta") => {
                let Some(message) = self.message.clone() else { return };
                let delta = &event["delta"];
                match delta["type"].as_str() {
                    Some("text_delta") => {
                        if let Some(text) = delta["text"].as_str().filter(|t| !t.is_empty()) {
                            self.streamed.insert(message.clone());
                            self.emit(Event::Message { message, text: text.to_owned(), parent });
                        }
                    }
                    Some("thinking_delta") => {
                        if let Some(text) = delta["thinking"].as_str().filter(|t| !t.is_empty()) {
                            self.streamed.insert(message.clone());
                            self.emit(Event::Reasoning { message: format!("{message}-thinking"), text: text.to_owned(), parent });
                        }
                    }
                    _ => {}
                }
            }
            Some("message_delta") => {
                if let (Some(usage), Some(last)) = (event.get("usage"), self.last_usage.as_mut()) {
                    if let Some(output) = usage["output_tokens"].as_u64() {
                        last["output_tokens"] = json!(output);
                    }
                }
            }
            _ => {}
        }
    }

    fn assistant(&mut self, message: &Value) {
        let parent = parent(message);
        let body = &message["message"];
        let id = body["id"].as_str().unwrap_or("").to_owned();
        let streamed = self.streamed.contains(&id);
        for block in body["content"].as_array().into_iter().flatten() {
            match block["type"].as_str() {
                Some("text") if !streamed => {
                    if let Some(text) = block["text"].as_str().filter(|t| !t.is_empty()) {
                        self.emit(Event::Message { message: id.clone(), text: text.to_owned(), parent: parent.clone() });
                    }
                }
                Some("thinking") if !streamed => {
                    if let Some(text) = block["thinking"].as_str().filter(|t| !t.is_empty()) {
                        self.emit(Event::Reasoning { message: format!("{id}-thinking"), text: text.to_owned(), parent: parent.clone() });
                    }
                }
                Some("tool_use") | Some("server_tool_use") => {
                    let Some(tool_id) = block["id"].as_str() else { continue };
                    if self.tools.contains_key(tool_id) || self.hidden.contains(tool_id) {
                        continue;
                    }
                    let name = block["name"].as_str().unwrap_or("tool");
                    self.tool_use(tool_id, name, &block["input"], parent.clone());
                }
                _ => {}
            }
        }
        if let Some(usage) = body.get("usage").filter(|u| u.is_object()) {
            let context = ["input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens", "output_tokens"]
                .iter()
                .filter_map(|k| usage[*k].as_u64())
                .sum::<u64>();
            if context > 0 {
                self.emit(Event::Usage(Usage {
                    context_tokens: Some(context),
                    context_window: Some(self.spec.context_window as u64),
                    ..Default::default()
                }));
            }
        }
    }

    /// Shows a tool call from its name and input.
    fn tool_use(&mut self, id: &str, name: &str, input: &Value, parent: Option<String>) {
        if name == "TodoWrite" {
            self.hidden.insert(id.to_owned());
            let entries = input["todos"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|todo| {
                    Some(PlanEntry {
                        content: todo["content"].as_str()?.to_owned(),
                        status: match todo["status"].as_str() {
                            Some("in_progress") => PlanStatus::InProgress,
                            Some("completed") => PlanStatus::Completed,
                            _ => PlanStatus::Pending,
                        },
                        priority: None,
                    })
                })
                .collect();
            self.emit(Event::Plan { entries });
            return;
        }
        if name == "AskUserQuestion" {
            self.hidden.insert(id.to_owned());
            return;
        }
        let (kind, title, content, locations) = describe_tool(name, input, &self.spec.cwd);
        let command = (name == "Bash").then(|| input["command"].as_str().unwrap_or("").to_owned());
        self.tools.insert(id.to_owned(), Tool { name: name.to_owned(), command });
        self.emit(Event::ToolCall(ToolCall {
            id: id.to_owned(),
            title,
            kind,
            status: ToolStatus::Pending,
            input: Some(input.clone()),
            locations,
            content,
            parent,
        }));
    }

    fn user(&mut self, message: &Value) {
        if message["isReplay"].as_bool().unwrap_or(false) {
            return;
        }
        let content = &message["message"]["content"];
        for block in content.as_array().into_iter().flatten() {
            if block["type"] != "tool_result" {
                continue;
            }
            let Some(id) = block["tool_use_id"].as_str() else { continue };
            if self.hidden.contains(id) {
                continue;
            }
            let Some(tool) = self.tools.get(id) else { continue };
            let failed = block["is_error"].as_bool().unwrap_or(false);
            let text = result_text(&block["content"]);
            let structured = &message["tool_use_result"];
            let content = match tool.name.as_str() {
                "Bash" => {
                    let mut output = match (structured["stdout"].as_str(), structured["stderr"].as_str()) {
                        (Some(out), Some(err)) if !err.is_empty() => format!("{out}\n{err}"),
                        (Some(out), _) => out.to_owned(),
                        _ => text.clone(),
                    };
                    if failed && output.trim().is_empty() {
                        output = text.clone();
                    }
                    process::keep_tail(&mut output, OUTPUT_LIMIT);
                    Some(vec![ToolContent::Terminal { command: tool.command.clone(), output, exit_code: None }])
                }
                // The diff shown with the call stays; a failure says why.
                "Edit" | "Write" | "MultiEdit" | "NotebookEdit" => failed.then(|| vec![ToolContent::Text { text: text.clone() }]),
                _ => {
                    let mut text = text.clone();
                    if text.chars().count() > 8000 {
                        text = text.chars().take(8000).chain("…".chars()).collect();
                    }
                    (!text.is_empty()).then(|| vec![ToolContent::Text { text }])
                }
            };
            self.emit(Event::ToolUpdate(ToolUpdate {
                id: id.to_owned(),
                status: Some(if failed { ToolStatus::Failed } else { ToolStatus::Completed }),
                content,
                output: (!structured.is_null()).then(|| structured.clone()),
                ..Default::default()
            }));
        }
    }

    fn result(&mut self, message: &Value) {
        let Some(turn) = self.turn.take() else { return };
        self.close_asks();
        let subtype = message["subtype"].as_str().unwrap_or("success");
        let is_error = message["is_error"].as_bool().unwrap_or(false);
        if let Some(usage) = message.get("usage").filter(|u| u.is_object()) {
            let input = ["input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens"].iter().filter_map(|k| usage[*k].as_u64()).sum();
            self.emit(Event::Usage(Usage { input_tokens: Some(input), output_tokens: usage["output_tokens"].as_u64(), ..Default::default() }));
        }
        let detail = || -> Option<String> {
            let errors: Vec<String> = message["errors"].as_array().into_iter().flatten().filter_map(|e| e.as_str().map(str::to_owned)).collect();
            if !errors.is_empty() {
                return Some(errors.join(" "));
            }
            message["result"].as_str().filter(|r| !r.trim().is_empty()).map(str::to_owned)
        };
        let (reason, detail) = if turn.cancelled {
            (StopReason::Cancelled, None)
        } else if subtype == "error_max_turns" {
            (StopReason::MaxSteps, None)
        } else if subtype != "success" || is_error {
            (StopReason::Error, detail())
        } else {
            match message["stop_reason"].as_str() {
                Some("max_tokens") => (StopReason::MaxTokens, None),
                Some("refusal") => (StopReason::Refused, None),
                _ => (StopReason::EndTurn, None),
            }
        };
        self.emit(Event::TurnEnd { reason, detail });
        if let Some(next) = self.queue.pop_front() {
            self.prompt(next);
        }
    }

    async fn ended(&mut self) {
        let mut code = None;
        let mut message = format!("{} closed its connection.", self.spec.name);
        if let Some(guard) = &self.guard {
            let _ = guard.wait_for(Duration::from_secs(2)).await;
            code = guard.code();
            message = guard.ended();
            if guard.tail().trim().is_empty() && !self.noise.is_empty() {
                message.push('\n');
                message.push_str(&self.noise.text());
            }
            guard.stop().await;
        } else if !self.noise.is_empty() {
            message.push('\n');
            message.push_str(&self.noise.text());
        }
        if self.turn.take().is_some() {
            self.emit(Event::TurnEnd { reason: StopReason::Error, detail: Some(format!("{} stopped.", self.spec.name)) });
        }
        self.emit(Event::Exit { code, message });
    }

    async fn shutdown(&mut self) {
        self.writer.close();
        if let Some(guard) = &self.guard {
            if guard.wait_for(Duration::from_secs(1)).await.is_none() {
                guard.stop().await;
            }
        }
        self.emit(Event::Exit { code: Some(0), message: String::new() });
    }
}

fn parent(message: &Value) -> Option<String> {
    message["parent_tool_use_id"].as_str().map(str::to_owned)
}

fn result_text(content: &Value) -> String {
    match content {
        Value::String(text) => text.clone(),
        Value::Array(blocks) => blocks.iter().filter_map(|b| b["text"].as_str()).collect::<Vec<_>>().join("\n"),
        _ => String::new(),
    }
}

/// What a permission asks, when Claude Code gives no title.
fn asked_title(tool: &str, input: &Value) -> String {
    let (_, title, _, _) = describe_tool(tool, input, Path::new(""));
    title
}

/// A tool's kind, title, content and locations from its name and input.
fn describe_tool(name: &str, input: &Value, cwd: &Path) -> (ToolKind, String, Vec<ToolContent>, Vec<Location>) {
    let path = input["file_path"].as_str().or(input["notebook_path"].as_str()).or(input["path"].as_str()).unwrap_or("");
    let at = |path: &str| if path.is_empty() { Vec::new() } else { vec![Location { path: path.to_owned(), line: None }] };
    match name {
        "Bash" => {
            let command = input["command"].as_str().unwrap_or("");
            (ToolKind::Execute, short_title(command), vec![ToolContent::Terminal { command: Some(command.to_owned()), output: String::new(), exit_code: None }], Vec::new())
        }
        "BashOutput" | "KillShell" | "KillBash" | "Monitor" | "TaskStop" => (ToolKind::Execute, name.to_owned(), Vec::new(), Vec::new()),
        "Read" => (ToolKind::Read, format!("Read {path}"), Vec::new(), at(path)),
        "Write" => {
            let full = if Path::new(path).is_absolute() { Path::new(path).to_path_buf() } else { cwd.join(path) };
            let old = std::fs::metadata(&full)
                .ok()
                .filter(|m| m.is_file() && m.len() <= DIFF_FILE_LIMIT)
                .and_then(|_| std::fs::read(&full).ok())
                .map(|b| String::from_utf8_lossy(&b).into_owned());
            let new = input["content"].as_str().unwrap_or("").to_owned();
            (ToolKind::Edit, format!("Write {path}"), vec![ToolContent::Diff { path: path.to_owned(), old, new }], at(path))
        }
        "Edit" => (
            ToolKind::Edit,
            format!("Edit {path}"),
            vec![ToolContent::Diff {
                path: path.to_owned(),
                old: Some(input["old_string"].as_str().unwrap_or("").to_owned()),
                new: input["new_string"].as_str().unwrap_or("").to_owned(),
            }],
            at(path),
        ),
        "MultiEdit" => (
            ToolKind::Edit,
            format!("Edit {path}"),
            input["edits"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|e| ToolContent::Diff {
                    path: path.to_owned(),
                    old: Some(e["old_string"].as_str().unwrap_or("").to_owned()),
                    new: e["new_string"].as_str().unwrap_or("").to_owned(),
                })
                .collect(),
            at(path),
        ),
        "NotebookEdit" => (ToolKind::Edit, format!("Edit {path}"), Vec::new(), at(path)),
        "Glob" => (ToolKind::Search, format!("Find {}", input["pattern"].as_str().unwrap_or("")), Vec::new(), at(path)),
        "Grep" => (ToolKind::Search, format!("Search for {}", input["pattern"].as_str().unwrap_or("")), Vec::new(), at(path)),
        "WebFetch" => (ToolKind::Fetch, format!("Fetch {}", input["url"].as_str().unwrap_or("")), Vec::new(), Vec::new()),
        "WebSearch" => (ToolKind::Fetch, format!("Search the web for {}", input["query"].as_str().unwrap_or("")), Vec::new(), Vec::new()),
        "Task" | "Agent" => {
            let title = input["description"].as_str().or(input["prompt"].as_str()).map(short_title).unwrap_or_else(|| "A subagent".to_owned());
            (ToolKind::Task, title, Vec::new(), Vec::new())
        }
        "ExitPlanMode" => {
            let plan = input["plan"].as_str().unwrap_or("").to_owned();
            let content = if plan.is_empty() { Vec::new() } else { vec![ToolContent::Text { text: plan }] };
            (ToolKind::SwitchMode, "Ready to leave the plan mode".to_owned(), content, Vec::new())
        }
        "EnterPlanMode" => (ToolKind::SwitchMode, "Plan first".to_owned(), Vec::new(), Vec::new()),
        other => {
            let title = match other.strip_prefix("mcp__") {
                Some(rest) => match rest.split_once("__") {
                    Some((server, tool)) => format!("{server}: {tool}"),
                    None => rest.to_owned(),
                },
                None => other.to_owned(),
            };
            (ToolKind::Other, title, Vec::new(), at(path))
        }
    }
}
