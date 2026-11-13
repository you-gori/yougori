//! Pi 0.73.1 in RPC mode (`pi --mode rpc`): commands as JSON lines with an `id`, a `response`
//! to each, and the agent's events (`agent_start` .. `agent_end`, `message_update` deltas,
//! `tool_execution_*`). Pi asks no permissions; its extensions' dialogs (`extension_ui_request`)
//! become questions. The model switches in the session (`set_model`).
use super::acp::Transport;
use super::codex::short_title;
use super::process::{self, Launch, LineWriter, ProcessGuard, Stdio2, Tail};
use crate::protocol::{
    Command, EngineHandle, Event, Level, Location, ModelSwitch, Progress, QuestionRequest, Ready, SlashCommand, StopReason,
    ToolCall, ToolContent, ToolKind, ToolStatus, ToolUpdate, Usage,
};
use crate::spec::EngineSpec;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::time::Duration;
use tokio::sync::mpsc;

#[cfg(test)]
mod tests;

const START_LIMIT: Duration = Duration::from_secs(180);
const OUTPUT_LIMIT: usize = 64 * 1024;
const DIFF_FILE_LIMIT: u64 = 2 * 1024 * 1024;

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

/// Sends a command and waits for its response, keeping the events that come first.
async fn call(
    writer: &LineWriter,
    values: &mut mpsc::UnboundedReceiver<Value>,
    backlog: &mut VecDeque<Value>,
    id: &str,
    command: Value,
) -> Result<Value, String> {
    let mut command = command;
    command["id"] = json!(id);
    writer.send(&command);
    let deadline = tokio::time::Instant::now() + START_LIMIT;
    loop {
        match tokio::time::timeout_at(deadline, values.recv()).await {
            Err(_) => return Err("it did not answer in time".into()),
            Ok(None) => return Err("it ended before answering".into()),
            Ok(Some(message)) => {
                if message["type"] == "response" && message["id"] == json!(id) {
                    if message["success"].as_bool().unwrap_or(false) {
                        return Ok(message["data"].clone());
                    }
                    return Err(message["error"].as_str().unwrap_or("it refused").to_owned());
                }
                backlog.push_back(message);
            }
        }
    }
}

pub(crate) async fn connect(spec: EngineSpec, transport: Transport) -> anyhow::Result<EngineHandle> {
    let Transport { mut values, writer, guard, noise } = transport;
    let mut backlog = VecDeque::new();
    let state = match call(&writer, &mut values, &mut backlog, "start-state", json!({"type": "get_state"})).await {
        Ok(state) => state,
        Err(why) => return Err(failed(&spec, guard.as_ref(), &noise, &why).await),
    };
    let available = call(&writer, &mut values, &mut backlog, "start-models", json!({"type": "get_available_models"}))
        .await
        .unwrap_or(Value::Null);
    let offered = call(&writer, &mut values, &mut backlog, "start-commands", json!({"type": "get_commands"}))
        .await
        .unwrap_or(Value::Null);
    let provider = state["model"]["provider"].as_str().unwrap_or("solver").to_owned();
    let listed: Vec<(String, String)> = available["models"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|m| Some((m["provider"].as_str()?.to_owned(), m["id"].as_str()?.to_owned())))
        .collect();
    let covers = spec.models.iter().chain([&spec.model]).all(|m| listed.iter().any(|(p, id)| *p == provider && id == m));
    let live = spec.model_switch == ModelSwitch::Live && covers;
    let (mut handle, commands, events) = EngineHandle::pair();
    if let Some(guard) = guard.clone() {
        handle.keep.push(Box::new(guard));
    }
    let _ = events.send(Event::Ready(Ready {
        harness: spec.harness.clone(),
        name: spec.name.clone(),
        model: spec.model.clone(),
        models: spec.models.clone(),
        model_switch: if live { ModelSwitch::Live } else { ModelSwitch::Restart },
        session: state["sessionId"].as_str().map(str::to_owned),
        info: Some("Pi · RPC".to_owned()),
    }));
    let commands_offered: Vec<SlashCommand> = offered["commands"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|c| {
            Some(SlashCommand { name: c["name"].as_str()?.to_owned(), description: c["description"].as_str().unwrap_or("").to_owned(), hint: None })
        })
        .collect();
    if !commands_offered.is_empty() {
        let _ = events.send(Event::Commands { commands: commands_offered });
    }
    let engine = Engine {
        context_window: state["model"]["contextWindow"].as_u64().unwrap_or(spec.context_window as u64),
        spec,
        writer,
        events,
        guard,
        noise,
        provider,
        live,
        turn: None,
        queue: VecDeque::new(),
        next: 0,
        pending: HashMap::new(),
        dialogs: HashMap::new(),
        messages: 0,
        tools: HashMap::new(),
        last_stop: None,
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

enum Pending {
    Prompt,
    SetModel(String),
    Stats,
}

struct Turn {
    cancelled: bool,
}

#[derive(Clone, Copy)]
enum Dialog {
    Select,
    Confirm,
    Text,
}

struct Tool {
    name: String,
    command: Option<String>,
    diffs: Vec<ToolContent>,
}

struct Engine {
    spec: EngineSpec,
    writer: LineWriter,
    events: mpsc::UnboundedSender<Event>,
    guard: Option<ProcessGuard>,
    noise: Tail,
    provider: String,
    live: bool,
    context_window: u64,
    turn: Option<Turn>,
    queue: VecDeque<String>,
    next: u64,
    pending: HashMap<String, Pending>,
    dialogs: HashMap<String, Dialog>,
    messages: u64,
    tools: HashMap<String, Tool>,
    /// The last assistant message's stop reason and error, for the turn's end.
    last_stop: Option<(String, Option<String>)>,
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

    fn send(&mut self, mut command: Value, pending: Pending) {
        self.next += 1;
        let id = format!("yh-{}", self.next);
        command["id"] = json!(id);
        self.writer.send(&command);
        self.pending.insert(id, pending);
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
            Command::Cancel => {
                self.queue.clear();
                if let Some(turn) = self.turn.as_mut() {
                    if !turn.cancelled {
                        turn.cancelled = true;
                        self.writer.send(&json!({"type": "abort"}));
                    }
                }
                self.close_dialogs();
            }
            // Pi asks no permissions.
            Command::Permission { .. } => {}
            Command::Answer { id, answer } => {
                if let Some(dialog) = self.dialogs.remove(&id) {
                    let response = match (dialog, answer) {
                        (_, None) => json!({"type": "extension_ui_response", "id": id, "cancelled": true}),
                        (Dialog::Confirm, Some(values)) => {
                            json!({"type": "extension_ui_response", "id": id, "confirmed": values.first().map(|v| v == "Yes").unwrap_or(false)})
                        }
                        (_, Some(values)) => json!({"type": "extension_ui_response", "id": id, "value": values.join(", ")}),
                    };
                    self.writer.send(&response);
                }
            }
            Command::SetModel { model } => {
                if !self.live {
                    self.notice(Level::Warn, format!("{} switches models by restarting.", self.spec.name));
                } else {
                    let provider = self.provider.clone();
                    self.send(json!({"type": "set_model", "provider": provider, "modelId": model}), Pending::SetModel(model));
                }
            }
            Command::SetMode { .. } => self.notice(Level::Warn, "Pi has no modes."),
            Command::Shutdown => {
                self.shutdown().await;
                return Flow::Stop;
            }
        }
        Flow::Go
    }

    fn prompt(&mut self, text: String) {
        self.turn = Some(Turn { cancelled: false });
        self.last_stop = None;
        self.send(json!({"type": "prompt", "message": text}), Pending::Prompt);
    }

    fn close_dialogs(&mut self) {
        for (id, _) in std::mem::take(&mut self.dialogs) {
            self.writer.send(&json!({"type": "extension_ui_response", "id": id, "cancelled": true}));
        }
    }

    fn end_turn(&mut self, reason: StopReason, detail: Option<String>) {
        let Some(turn) = self.turn.take() else { return };
        self.close_dialogs();
        let reason = if turn.cancelled { StopReason::Cancelled } else { reason };
        self.emit(Event::TurnEnd { reason, detail: if reason == StopReason::Error { detail } else { None } });
        // The context in use, as Pi counts it for its own compaction.
        self.send(json!({"type": "get_session_stats"}), Pending::Stats);
        if let Some(next) = self.queue.pop_front() {
            self.prompt(next);
        }
    }

    fn message_in(&mut self, message: Value) {
        match message["type"].as_str().unwrap_or("") {
            "response" => self.response(&message),
            "message_start" => {
                if message["message"]["role"] == "assistant" {
                    self.messages += 1;
                }
            }
            "message_update" => {
                let event = &message["assistantMessageEvent"];
                let id = format!("pi-{}", self.messages);
                match event["type"].as_str() {
                    Some("text_delta") => {
                        if let Some(text) = event["delta"].as_str().filter(|t| !t.is_empty()) {
                            self.emit(Event::Message { message: id, text: text.to_owned(), parent: None });
                        }
                    }
                    Some("thinking_delta") => {
                        if let Some(text) = event["delta"].as_str().filter(|t| !t.is_empty()) {
                            self.emit(Event::Reasoning { message: format!("{id}-thinking"), text: text.to_owned(), parent: None });
                        }
                    }
                    _ => {}
                }
            }
            "message_end" => {
                let body = &message["message"];
                if body["role"] == "assistant" {
                    self.last_stop = Some((
                        body["stopReason"].as_str().unwrap_or("stop").to_owned(),
                        body["errorMessage"].as_str().map(str::to_owned),
                    ));
                    let usage = &body["usage"];
                    if let Some(total) = usage["totalTokens"].as_u64().filter(|t| *t > 0) {
                        self.emit(Event::Usage(Usage { context_tokens: Some(total), context_window: Some(self.context_window), ..Default::default() }));
                    }
                }
            }
            "tool_execution_start" => {
                let id = message["toolCallId"].as_str().unwrap_or("").to_owned();
                let name = message["toolName"].as_str().unwrap_or("tool").to_owned();
                let args = message["args"].clone();
                let (kind, title, content, locations) = describe_tool(&name, &args, &self.spec.cwd);
                let diffs = content.iter().filter(|c| matches!(c, ToolContent::Diff { .. })).cloned().collect();
                let command = (name == "bash").then(|| args["command"].as_str().unwrap_or("").to_owned());
                self.tools.insert(id.clone(), Tool { name, command, diffs });
                self.emit(Event::ToolCall(ToolCall { id, title, kind, status: ToolStatus::InProgress, input: Some(args), locations, content, parent: None }));
            }
            "tool_execution_update" => {
                let id = message["toolCallId"].as_str().unwrap_or("").to_owned();
                if let Some(content) = self.result_content(&id, &message["partialResult"], false) {
                    self.emit(Event::ToolUpdate(ToolUpdate { id, content: Some(content), ..Default::default() }));
                }
            }
            "tool_execution_end" => {
                let id = message["toolCallId"].as_str().unwrap_or("").to_owned();
                let failed = message["isError"].as_bool().unwrap_or(false);
                let content = self.result_content(&id, &message["result"], failed);
                let details = message["result"]["details"].clone();
                self.tools.remove(&id);
                self.emit(Event::ToolUpdate(ToolUpdate {
                    id,
                    status: Some(if failed { ToolStatus::Failed } else { ToolStatus::Completed }),
                    content,
                    output: (!details.is_null()).then_some(details),
                    ..Default::default()
                }));
            }
            "agent_end" => {
                let (stop, error) = self.last_stop.take().unwrap_or(("stop".into(), None));
                let reason = match stop.as_str() {
                    "aborted" => StopReason::Cancelled,
                    "error" => StopReason::Error,
                    "length" => StopReason::MaxTokens,
                    _ => StopReason::EndTurn,
                };
                self.end_turn(reason, error);
            }
            "compaction_start" => self.emit(Event::Progress(Progress { id: "compaction".into(), label: "Compacting the conversation".into(), ..Default::default() })),
            "compaction_end" => {
                self.emit(Event::Progress(Progress { id: "compaction".into(), label: "Compacted the conversation".into(), finished: true, ..Default::default() }));
                if let Some(error) = message["errorMessage"].as_str() {
                    self.notice(Level::Warn, format!("Pi could not compact the conversation: {error}"));
                }
            }
            "auto_retry_start" => {
                let attempt = message["attempt"].as_u64().unwrap_or(1);
                let most = message["maxAttempts"].as_u64().unwrap_or(attempt);
                self.notice(Level::Warn, format!("The model did not answer; Pi tries again ({attempt} of {most})."));
            }
            "auto_retry_end" => {
                if message["success"] == json!(false) {
                    let error = message["finalError"].as_str().unwrap_or("the model kept failing");
                    self.notice(Level::Error, format!("Pi gave up: {error}"));
                }
            }
            "extension_error" => {
                let error = message["error"].as_str().unwrap_or("an extension failed");
                self.notice(Level::Warn, format!("A Pi extension failed: {error}"));
            }
            "extension_ui_request" => self.dialog(&message),
            _ => {}
        }
    }

    fn response(&mut self, message: &Value) {
        let Some(id) = message["id"].as_str() else { return };
        let Some(pending) = self.pending.remove(id) else { return };
        let ok = message["success"].as_bool().unwrap_or(false);
        let error = message["error"].as_str().unwrap_or("it refused").to_owned();
        match pending {
            Pending::Prompt if !ok => {
                self.last_stop = None;
                self.end_turn(StopReason::Error, Some(error));
            }
            Pending::Prompt => {}
            Pending::SetModel(model) if ok => self.emit(Event::Model { model }),
            Pending::SetModel(model) => self.notice(Level::Error, format!("Could not switch to {model}: {error}")),
            Pending::Stats if ok => {
                let data = &message["data"];
                let context = &data["contextUsage"];
                self.emit(Event::Usage(Usage {
                    context_tokens: context["tokens"].as_u64(),
                    context_window: context["contextWindow"].as_u64(),
                    input_tokens: data["tokens"]["input"].as_u64(),
                    output_tokens: data["tokens"]["output"].as_u64(),
                }));
            }
            Pending::Stats => {}
        }
    }

    fn dialog(&mut self, message: &Value) {
        let Some(id) = message["id"].as_str().map(str::to_owned) else { return };
        let title = message["title"].as_str().unwrap_or("");
        match message["method"].as_str() {
            Some("select") => {
                let choices = message["options"].as_array().into_iter().flatten().filter_map(|o| o.as_str().map(str::to_owned)).collect();
                self.ask(id, Dialog::Select, title.to_owned(), choices, false);
            }
            Some("confirm") => {
                let text = match message["message"].as_str() {
                    Some(m) if !m.is_empty() => format!("{title} {m}"),
                    _ => title.to_owned(),
                };
                self.ask(id, Dialog::Confirm, text, vec!["Yes".into(), "No".into()], false);
            }
            Some("input") | Some("editor") => {
                let mut text = title.to_owned();
                if let Some(prefill) = message["prefill"].as_str().filter(|p| !p.is_empty()) {
                    text.push_str(&format!("\n{prefill}"));
                }
                self.ask(id, Dialog::Text, text, Vec::new(), true);
            }
            Some("notify") => {
                let level = match message["notifyType"].as_str() {
                    Some("error") => Level::Error,
                    Some("warning") => Level::Warn,
                    _ => Level::Info,
                };
                if let Some(text) = message["message"].as_str() {
                    self.notice(level, text);
                }
            }
            // Status lines, widgets, titles and editor text belong to Pi's own screen.
            _ => {}
        }
    }

    fn ask(&mut self, id: String, dialog: Dialog, question: String, choices: Vec<String>, allow_text: bool) {
        if self.turn.as_ref().map(|t| t.cancelled).unwrap_or(false) {
            self.writer.send(&json!({"type": "extension_ui_response", "id": id, "cancelled": true}));
            return;
        }
        self.dialogs.insert(id.clone(), dialog);
        self.emit(Event::Question(QuestionRequest { id, question, choices, multiple: false, allow_text }));
    }

    /// A tool result as the call shows it: a command's output in its terminal, a change's diff,
    /// or the text.
    fn result_content(&self, id: &str, result: &Value, failed: bool) -> Option<Vec<ToolContent>> {
        let tool = self.tools.get(id)?;
        let mut text = result["content"].as_array().into_iter().flatten().filter_map(|b| b["text"].as_str()).collect::<Vec<_>>().join("\n");
        match tool.name.as_str() {
            "bash" => {
                process::keep_tail(&mut text, OUTPUT_LIMIT);
                Some(vec![ToolContent::Terminal { command: tool.command.clone(), output: text, exit_code: None }])
            }
            "edit" | "write" if !failed && !tool.diffs.is_empty() => Some(tool.diffs.clone()),
            _ if text.is_empty() => None,
            _ => {
                if text.chars().count() > 8000 {
                    text = text.chars().take(8000).chain("…".chars()).collect();
                }
                Some(vec![ToolContent::Text { text }])
            }
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

/// A Pi tool's kind, title, content and locations from its name and arguments.
fn describe_tool(name: &str, args: &Value, cwd: &Path) -> (ToolKind, String, Vec<ToolContent>, Vec<Location>) {
    let path = args["path"].as_str().unwrap_or("");
    let at = |path: &str| if path.is_empty() { Vec::new() } else { vec![Location { path: path.to_owned(), line: args["offset"].as_u64().map(|l| l as u32) }] };
    match name {
        "bash" => {
            let command = args["command"].as_str().unwrap_or("");
            (ToolKind::Execute, short_title(command), vec![ToolContent::Terminal { command: Some(command.to_owned()), output: String::new(), exit_code: None }], Vec::new())
        }
        "read" => (ToolKind::Read, format!("Read {path}"), Vec::new(), at(path)),
        "edit" => {
            let mut diffs: Vec<ToolContent> = args["edits"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|e| ToolContent::Diff {
                    path: path.to_owned(),
                    old: Some(e["oldText"].as_str().unwrap_or("").to_owned()),
                    new: e["newText"].as_str().unwrap_or("").to_owned(),
                })
                .collect();
            if diffs.is_empty() {
                if let (Some(old), Some(new)) = (args["oldText"].as_str(), args["newText"].as_str()) {
                    diffs.push(ToolContent::Diff { path: path.to_owned(), old: Some(old.to_owned()), new: new.to_owned() });
                }
            }
            (ToolKind::Edit, format!("Edit {path}"), diffs, at(path))
        }
        "write" => {
            let full = if Path::new(path).is_absolute() { Path::new(path).to_path_buf() } else { cwd.join(path) };
            let old = std::fs::metadata(&full)
                .ok()
                .filter(|m| m.is_file() && m.len() <= DIFF_FILE_LIMIT)
                .and_then(|_| std::fs::read(&full).ok())
                .map(|b| String::from_utf8_lossy(&b).into_owned());
            let new = args["content"].as_str().unwrap_or("").to_owned();
            (ToolKind::Edit, format!("Write {path}"), vec![ToolContent::Diff { path: path.to_owned(), old, new }], at(path))
        }
        "grep" | "find" => {
            let pattern = args["pattern"].as_str().unwrap_or("");
            (ToolKind::Search, format!("Search for {pattern}"), Vec::new(), at(path))
        }
        "ls" => (ToolKind::Search, format!("List {}", if path.is_empty() { "." } else { path }), Vec::new(), at(path)),
        other => (ToolKind::Other, other.to_owned(), Vec::new(), at(path)),
    }
}
