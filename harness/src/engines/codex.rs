//! Codex's app-server at 0.166.0: JSON-RPC over stdio without the `"jsonrpc"` member
//! (`codex app-server`, schema from `codex app-server generate-json-schema`). One thread per
//! engine, a turn per prompt; approvals for commands, file changes and extra permissions; the
//! request_user_input tool's questions and MCP elicitations as questions; the model and the
//! approval preset switch in the thread, taking effect from the next turn.
use super::acp::Transport;
use super::process::rpc::{self, CallError, Incoming, Message, Rpc, RpcError};
use super::process::{self, Launch, LineWriter, ProcessGuard, Stdio2, Tail};
use crate::protocol::{
    Command, EngineHandle, Event, Level, Location, Mode, ModelSwitch, PermissionKind, PermissionOption, PermissionRequest,
    PlanEntry, PlanStatus, Progress, QuestionRequest, Ready, SlashCommand, StopReason, ToolCall, ToolContent, ToolKind,
    ToolStatus, ToolUpdate, Usage,
};
use crate::spec::EngineSpec;
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::sync::mpsc;

#[cfg(test)]
mod tests;

const START_LIMIT: Duration = Duration::from_secs(180);
/// Command output shown in a tool call: the latest part.
const OUTPUT_LIMIT: usize = 64 * 1024;
/// Files read to show a change as a diff.
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

fn never(_: &Rpc, _: &Message) -> bool {
    false
}

pub(crate) async fn connect(spec: EngineSpec, transport: Transport) -> anyhow::Result<EngineHandle> {
    let Transport { values, writer, guard, noise } = transport;
    let rpc = Rpc::new(writer.clone(), true);
    let mut incoming = Incoming::new(values);
    let init = incoming
        .call(
            &rpc,
            "initialize",
            json!({"clientInfo": {"name": "yougori_harness", "title": "Yougori", "version": env!("CARGO_PKG_VERSION")},
                   "capabilities": {"experimentalApi": true}}),
            START_LIMIT,
            &mut never,
        )
        .await;
    let init = match init {
        Ok(init) => init,
        Err(error) => return Err(failed(&spec, guard.as_ref(), &noise, "initialize", error).await),
    };
    rpc.notify("initialized", Value::Null);
    let thread = incoming
        // Asks before every command it does not know to be safe (the "ask" mode); the config
        // decides the sandbox.
        .call(&rpc, "thread/start", json!({"cwd": spec.cwd, "model": spec.model, "approvalPolicy": "untrusted"}), START_LIMIT, &mut never)
        .await;
    let thread = match thread {
        Ok(thread) => thread,
        Err(error) => return Err(failed(&spec, guard.as_ref(), &noise, "start a thread", error).await),
    };
    let Some(thread_id) = thread["thread"]["id"].as_str().map(str::to_owned) else {
        writer.close();
        if let Some(guard) = &guard {
            guard.stop().await;
        }
        anyhow::bail!("{} started a thread without an id.", spec.name);
    };
    let preset = Preset::of(&thread["approvalPolicy"], &thread["sandbox"]);
    let version = init["userAgent"]
        .as_str()
        .and_then(|agent| agent.split(['/', ' ']).nth(1))
        .filter(|v| v.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false))
        .map(str::to_owned);
    let (mut handle, commands, events) = EngineHandle::pair();
    if let Some(guard) = guard.clone() {
        handle.keep.push(Box::new(guard));
    }
    let _ = events.send(Event::Ready(Ready {
        harness: spec.harness.clone(),
        name: spec.name.clone(),
        model: spec.model.clone(),
        models: spec.models.clone(),
        // A turn may name any model; it stays for the turns after it.
        model_switch: if spec.model_switch == ModelSwitch::Live { ModelSwitch::Live } else { ModelSwitch::Restart },
        session: Some(thread_id.clone()),
        info: Some(match version {
            Some(v) => format!("Codex {v} · app-server"),
            None => "Codex · app-server".to_owned(),
        }),
    }));
    let _ = events.send(Event::Modes { current: preset.map(Preset::id).unwrap_or("").to_owned(), available: Preset::modes() });
    let _ = events.send(Event::Commands {
        commands: vec![SlashCommand { name: "compact".into(), description: "Summarise the conversation to free the context".into(), hint: None }],
    });
    let engine = Engine {
        spec,
        rpc,
        writer,
        events,
        guard,
        noise,
        thread: thread_id,
        turn: None,
        queue: VecDeque::new(),
        next_model: None,
        next_preset: None,
        preset,
        pending: HashMap::new(),
        approvals: HashMap::new(),
        asks: HashMap::new(),
        asking: HashMap::new(),
        items: HashMap::new(),
        streamed: HashSet::new(),
        reasoning: HashMap::new(),
        dirty: HashSet::new(),
    };
    tokio::spawn(engine.run(incoming, commands));
    Ok(handle)
}

async fn failed(spec: &EngineSpec, guard: Option<&ProcessGuard>, noise: &Tail, what: &str, error: CallError) -> anyhow::Error {
    let mut text = format!("{} did not start: it could not {what}: {error}.", spec.name);
    if let Some(guard) = guard {
        let _ = guard.wait_for(Duration::from_millis(800)).await;
        if let Some(status) = guard.status() {
            text = format!("{} did not start: it {} while trying to {what}.", spec.name, process::describe(status));
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

/// How much Codex asks, offered as modes. The Sandbox VM is the boundary, so Codex's own sandbox
/// (bubblewrap) is not used: commands run unsandboxed and the approval policy decides what is
/// asked (the profile starts Codex with `-c sandbox_mode="danger-full-access"`; the thread starts
/// in the "ask" mode, which Codex takes only as a request parameter, not from its config).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Preset {
    /// Asks before every command it does not know to be safe, and before edits.
    Ask,
    /// Asks when the model asks for approval.
    Auto,
    /// Never asks.
    FullAccess,
}

impl Preset {
    fn id(self) -> &'static str {
        match self {
            Preset::Ask => "ask",
            Preset::Auto => "auto",
            Preset::FullAccess => "full-access",
        }
    }

    fn parse(id: &str) -> Option<Preset> {
        match id {
            "ask" => Some(Preset::Ask),
            "auto" => Some(Preset::Auto),
            "full-access" => Some(Preset::FullAccess),
            _ => None,
        }
    }

    fn modes() -> Vec<Mode> {
        vec![
            Mode { id: "ask".into(), name: "Ask".into(), description: Some("Asks before commands that are not known to be safe".into()) },
            Mode { id: "auto".into(), name: "Auto".into(), description: Some("Asks only when Codex asks for approval".into()) },
            Mode { id: "full-access".into(), name: "Full access".into(), description: Some("Runs and edits anything without asking".into()) },
        ]
    }

    /// The preset a thread's policy and sandbox amount to.
    fn of(policy: &Value, sandbox: &Value) -> Option<Preset> {
        let sandbox = sandbox["type"].as_str().or(sandbox.as_str())?;
        if !matches!(sandbox, "dangerFullAccess" | "danger-full-access") {
            return None;
        }
        match policy.as_str()? {
            "untrusted" => Some(Preset::Ask),
            "on-request" => Some(Preset::Auto),
            "never" => Some(Preset::FullAccess),
            _ => None,
        }
    }

    /// The turn/start overrides for this preset.
    fn overrides(self) -> (Value, Value) {
        let policy = match self {
            Preset::Ask => "untrusted",
            Preset::Auto => "on-request",
            Preset::FullAccess => "never",
        };
        (json!(policy), json!({"type": "dangerFullAccess"}))
    }
}

enum Pending {
    TurnStart,
    Interrupt,
    Compact,
}

struct Turn {
    /// The turn/start request while it is unanswered.
    request: Option<i64>,
    id: Option<String>,
    cancelled: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Approval {
    Command,
    FileChange,
    /// Extra permissions; the requested profile is granted back as it came.
    Permissions,
    /// Version 1 requests: `execCommandApproval`, `applyPatchApproval`.
    Legacy,
}

struct Asked {
    rpc_id: Value,
    kind: Approval,
    requested: Value,
}

/// Questions asked one after another for one request (request_user_input, an elicitation).
struct Asks {
    rpc_id: Value,
    kind: AskKind,
    /// (answer key, question) still to ask, in order.
    remaining: VecDeque<(String, QuestionRequest, Field)>,
    answers: Map<String, Value>,
    dismissed: bool,
}

#[derive(Clone, Copy)]
enum AskKind {
    UserInput,
    Elicitation,
}

/// How an elicitation field's answer is typed.
#[derive(Clone, Copy)]
enum Field {
    Text,
    Number,
    Integer,
    Boolean,
    Many,
}

enum Item {
    Command { command: String, output: String },
    Files { changes: Vec<Change> },
    Other,
}

struct Change {
    path: String,
    absolute: PathBuf,
    kind: String,
    diff: String,
    old: Option<String>,
}

struct Engine {
    spec: EngineSpec,
    rpc: Rpc,
    writer: LineWriter,
    events: mpsc::UnboundedSender<Event>,
    guard: Option<ProcessGuard>,
    noise: Tail,
    thread: String,
    turn: Option<Turn>,
    queue: VecDeque<String>,
    next_model: Option<String>,
    next_preset: Option<Preset>,
    preset: Option<Preset>,
    pending: HashMap<i64, Pending>,
    approvals: HashMap<String, Asked>,
    /// Question sets by request, and which set a shown question belongs to.
    asks: HashMap<String, Asks>,
    asking: HashMap<String, String>,
    items: HashMap<String, Item>,
    /// Items whose text arrived in deltas (their completed text is not shown again).
    streamed: HashSet<String>,
    /// Which reasoning stream an item uses: raw text or summary.
    reasoning: HashMap<String, bool>,
    dirty: HashSet<String>,
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

    async fn run(mut self, mut incoming: Incoming, mut commands: mpsc::UnboundedReceiver<Command>) {
        let mut flush = tokio::time::interval(Duration::from_millis(100));
        flush.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
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
                message = incoming.next() => match message {
                    Some(message) => self.message(message),
                    None => {
                        self.ended().await;
                        break;
                    }
                },
                _ = flush.tick(), if !self.dirty.is_empty() => self.flush(),
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
                } else if text.trim() == "/compact" {
                    let id = self.rpc.request("thread/compact/start", json!({"threadId": self.thread}));
                    self.pending.insert(id, Pending::Compact);
                } else {
                    self.start_turn(text);
                }
            }
            Command::Cancel => self.cancel(),
            Command::Permission { id, option } => {
                if let Some(asked) = self.approvals.remove(&id) {
                    let result = decision(&asked, option.as_deref());
                    self.rpc.respond(asked.rpc_id, result);
                }
            }
            Command::Answer { id, answer } => self.answered(&id, answer),
            Command::SetModel { model } => {
                if self.spec.model_switch != ModelSwitch::Live {
                    self.notice(Level::Warn, format!("{} switches models by restarting.", self.spec.name));
                } else {
                    // From the next turn on; turn/start carries it.
                    self.next_model = Some(model.clone());
                    self.emit(Event::Model { model });
                }
            }
            Command::SetMode { mode } => match Preset::parse(&mode) {
                Some(preset) => {
                    self.next_preset = Some(preset);
                    self.preset = Some(preset);
                    self.emit(Event::Modes { current: mode, available: Preset::modes() });
                }
                None => self.notice(Level::Warn, format!("Codex has no mode {mode}.")),
            },
            Command::Shutdown => {
                self.shutdown().await;
                return Flow::Stop;
            }
        }
        Flow::Go
    }

    fn start_turn(&mut self, text: String) {
        let mut params = json!({"threadId": self.thread, "input": [{"type": "text", "text": text, "text_elements": []}]});
        if let Some(model) = self.next_model.take() {
            params["model"] = json!(model);
        }
        if let Some(preset) = self.next_preset.take() {
            let (policy, sandbox) = preset.overrides();
            params["approvalPolicy"] = policy;
            params["sandboxPolicy"] = sandbox;
        }
        let id = self.rpc.request("turn/start", params);
        self.pending.insert(id, Pending::TurnStart);
        self.turn = Some(Turn { request: Some(id), id: None, cancelled: false });
    }

    fn cancel(&mut self) {
        self.queue.clear();
        let Some(turn) = self.turn.as_mut() else { return };
        if !turn.cancelled {
            turn.cancelled = true;
            if let Some(id) = turn.id.clone() {
                let request = self.rpc.request("turn/interrupt", json!({"threadId": self.thread, "turnId": id}));
                self.pending.insert(request, Pending::Interrupt);
            }
        }
        for (_, asked) in self.approvals.drain() {
            let result = decision(&asked, None);
            self.rpc.respond(asked.rpc_id, result);
        }
        self.asking.clear();
        for (_, asks) in self.asks.drain() {
            respond_asks(&self.rpc, asks, true);
        }
    }

    fn end_turn(&mut self, reason: StopReason, detail: Option<String>) {
        let Some(turn) = self.turn.take() else { return };
        let reason = if turn.cancelled && reason != StopReason::EndTurn { StopReason::Cancelled } else { reason };
        let reason = if turn.cancelled && reason == StopReason::EndTurn { StopReason::Cancelled } else { reason };
        for (_, asked) in self.approvals.drain() {
            let result = decision(&asked, None);
            self.rpc.respond(asked.rpc_id, result);
        }
        self.asking.clear();
        for (_, asks) in self.asks.drain() {
            respond_asks(&self.rpc, asks, true);
        }
        self.flush();
        self.emit(Event::TurnEnd { reason, detail: if reason == StopReason::Cancelled { None } else { detail } });
        if let Some(next) = self.queue.pop_front() {
            self.start_turn(next);
        }
    }

    fn message(&mut self, message: Message) {
        match message {
            Message::Response { id, outcome } => {
                let Some(id) = rpc::our_id(&id) else { return };
                match (self.pending.remove(&id), outcome) {
                    (Some(Pending::TurnStart), Ok(result)) => {
                        let turn_id = result["turn"]["id"].as_str().map(str::to_owned);
                        let mut interrupt = None;
                        if let Some(turn) = self.turn.as_mut().filter(|t| t.request == Some(id)) {
                            turn.request = None;
                            if turn.id.is_none() {
                                turn.id = turn_id.clone();
                            }
                            if turn.cancelled {
                                interrupt = turn.id.clone();
                            }
                        }
                        if let Some(turn_id) = interrupt {
                            let request = self.rpc.request("turn/interrupt", json!({"threadId": self.thread, "turnId": turn_id}));
                            self.pending.insert(request, Pending::Interrupt);
                        }
                    }
                    (Some(Pending::TurnStart), Err(error)) => {
                        if self.turn.as_ref().map(|t| t.request == Some(id)).unwrap_or(false) {
                            self.end_turn(StopReason::Error, Some(error.text()));
                        }
                    }
                    (Some(Pending::Interrupt), Err(error)) => {
                        self.notice(Level::Warn, format!("Codex did not stop the turn: {error}"));
                    }
                    (Some(Pending::Compact), Ok(_)) => self.notice(Level::Info, "Codex is compacting the conversation."),
                    (Some(Pending::Compact), Err(error)) => self.notice(Level::Error, format!("Codex could not compact: {error}")),
                    _ => {}
                }
            }
            Message::Notification { method, params } => self.notification(&method, &params),
            Message::Request { id, method, params } => self.request(id, &method, &params),
        }
    }

    fn notification(&mut self, method: &str, params: &Value) {
        match method {
            "turn/started" => {
                if let (Some(turn), Some(id)) = (self.turn.as_mut(), params["turn"]["id"].as_str()) {
                    if turn.id.is_none() {
                        turn.id = Some(id.to_owned());
                        if turn.cancelled {
                            let request = self.rpc.request("turn/interrupt", json!({"threadId": self.thread, "turnId": id}));
                            self.pending.insert(request, Pending::Interrupt);
                        }
                    }
                }
            }
            "turn/completed" => {
                let turn = &params["turn"];
                let ours = match (&self.turn, turn["id"].as_str()) {
                    (Some(active), Some(id)) => active.id.as_deref().map(|a| a == id).unwrap_or(true),
                    (Some(_), None) => true,
                    _ => false,
                };
                if !ours {
                    return;
                }
                let (reason, detail) = match turn["status"].as_str() {
                    Some("interrupted") => (StopReason::Cancelled, None),
                    Some("failed") => {
                        let error = &turn["error"];
                        let reason = if error["codexErrorInfo"] == json!("contextWindowExceeded") {
                            StopReason::MaxTokens
                        } else {
                            StopReason::Error
                        };
                        (reason, error["message"].as_str().map(str::to_owned))
                    }
                    _ => (StopReason::EndTurn, None),
                };
                self.end_turn(reason, detail);
            }
            "item/started" => self.item_started(&params["item"]),
            "item/completed" => self.item_completed(&params["item"]),
            "item/agentMessage/delta" => {
                if let (Some(item), Some(delta)) = (params["itemId"].as_str(), params["delta"].as_str()) {
                    self.streamed.insert(item.to_owned());
                    self.emit(Event::Message { message: item.to_owned(), text: delta.to_owned(), parent: None });
                }
            }
            "item/plan/delta" => {
                if let (Some(item), Some(delta)) = (params["itemId"].as_str(), params["delta"].as_str()) {
                    self.streamed.insert(item.to_owned());
                    self.emit(Event::Message { message: item.to_owned(), text: delta.to_owned(), parent: None });
                }
            }
            "item/reasoning/textDelta" | "item/reasoning/summaryTextDelta" => {
                let raw = method == "item/reasoning/textDelta";
                if let (Some(item), Some(delta)) = (params["itemId"].as_str(), params["delta"].as_str()) {
                    // One stream per item: raw reasoning when the model gives it, else its summary.
                    let chosen = *self.reasoning.entry(item.to_owned()).or_insert(raw);
                    if chosen == raw {
                        self.streamed.insert(item.to_owned());
                        self.emit(Event::Reasoning { message: item.to_owned(), text: delta.to_owned(), parent: None });
                    }
                }
            }
            "item/commandExecution/outputDelta" => {
                if let (Some(item), Some(delta)) = (params["itemId"].as_str(), params["delta"].as_str()) {
                    if let Some(Item::Command { output, .. }) = self.items.get_mut(item) {
                        output.push_str(delta);
                        process::keep_tail(output, OUTPUT_LIMIT);
                        self.dirty.insert(item.to_owned());
                    }
                }
            }
            "item/fileChange/patchUpdated" => {
                if let Some(item) = params["itemId"].as_str() {
                    let changes = self.changes(&params["changes"]);
                    self.items.insert(item.to_owned(), Item::Files { changes });
                    let content = self.proposed(item);
                    self.emit(Event::ToolUpdate(ToolUpdate { id: item.to_owned(), content: Some(content), ..Default::default() }));
                }
            }
            "turn/plan/updated" => {
                let entries = params["plan"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|step| {
                        Some(PlanEntry {
                            content: step["step"].as_str()?.to_owned(),
                            status: match step["status"].as_str() {
                                Some("inProgress") => PlanStatus::InProgress,
                                Some("completed") => PlanStatus::Completed,
                                _ => PlanStatus::Pending,
                            },
                            priority: None,
                        })
                    })
                    .collect();
                self.emit(Event::Plan { entries });
            }
            "thread/tokenUsage/updated" => {
                let usage = &params["tokenUsage"];
                let last = &usage["last"];
                let total = &usage["total"];
                self.emit(Event::Usage(Usage {
                    context_tokens: last["totalTokens"].as_u64().or_else(|| {
                        Some(last["inputTokens"].as_u64()? + last["outputTokens"].as_u64().unwrap_or(0))
                    }),
                    context_window: usage["modelContextWindow"].as_u64().or(Some(self.spec.context_window as u64)),
                    input_tokens: total["inputTokens"].as_u64(),
                    output_tokens: total["outputTokens"].as_u64(),
                }));
            }
            "error" => {
                let message = params["error"]["message"].as_str().unwrap_or("Codex reported an error.");
                if params["willRetry"].as_bool().unwrap_or(false) {
                    self.notice(Level::Warn, format!("{message} Codex tries again."));
                } else {
                    self.notice(Level::Error, message.to_owned());
                }
            }
            "warning" | "configWarning" | "deprecationNotice" | "guardianWarning" => {
                let text = params["message"].as_str().or(params["summary"].as_str()).map(str::to_owned);
                // Codex runs its bundled bubblewrap when the system has none, as in the VM:
                // nothing for the person to do.
                if let Some(text) = text.filter(|t| !t.contains("bubblewrap")) {
                    self.notice(Level::Warn, text);
                }
            }
            "thread/compacted" => self.emit(Event::Progress(Progress {
                id: "compaction".into(),
                label: "Compacted the conversation".into(),
                finished: true,
                ..Default::default()
            })),
            "model/rerouted" => {
                if let Some(model) = params["toModel"].as_str().or(params["model"].as_str()) {
                    self.notice(Level::Info, format!("Codex now uses {model}."));
                }
            }
            _ => {}
        }
    }

    fn item_started(&mut self, item: &Value) {
        let Some(id) = item["id"].as_str().map(str::to_owned) else { return };
        match item["type"].as_str().unwrap_or("") {
            "commandExecution" => {
                let command = shown_command(item);
                let (kind, locations) = command_kind(&item["commandActions"]);
                self.items.insert(id.clone(), Item::Command { command: command.clone(), output: String::new() });
                self.emit(Event::ToolCall(ToolCall {
                    id,
                    title: short_title(&command),
                    kind,
                    status: ToolStatus::InProgress,
                    input: Some(json!({"command": command, "cwd": item["cwd"]})),
                    locations,
                    content: vec![ToolContent::Terminal { command: Some(command), output: String::new(), exit_code: None }],
                    parent: None,
                }));
            }
            "fileChange" => {
                let changes = self.changes(&item["changes"]);
                let title = edit_title(&changes);
                let locations = changes.iter().map(|c| Location { path: c.path.clone(), line: None }).collect();
                self.items.insert(id.clone(), Item::Files { changes });
                let content = self.proposed(&id);
                self.emit(Event::ToolCall(ToolCall {
                    id,
                    title,
                    kind: ToolKind::Edit,
                    status: ToolStatus::Pending,
                    input: None,
                    locations,
                    content,
                    parent: None,
                }));
            }
            "mcpToolCall" | "dynamicToolCall" => {
                let tool = item["tool"].as_str().unwrap_or("tool");
                let title = match item["server"].as_str() {
                    Some(server) => format!("{server}: {tool}"),
                    None => tool.to_owned(),
                };
                self.items.insert(id.clone(), Item::Other);
                self.emit(Event::ToolCall(ToolCall {
                    id,
                    title,
                    kind: ToolKind::Other,
                    status: ToolStatus::InProgress,
                    input: item.get("arguments").filter(|a| !a.is_null()).cloned(),
                    ..Default::default()
                }));
            }
            "webSearch" => {
                self.items.insert(id.clone(), Item::Other);
                self.emit(Event::ToolCall(ToolCall {
                    id,
                    title: format!("Search the web: {}", item["query"].as_str().unwrap_or("")),
                    kind: ToolKind::Fetch,
                    status: ToolStatus::InProgress,
                    ..Default::default()
                }));
            }
            "collabAgentToolCall" | "subAgentActivity" => {
                self.items.insert(id.clone(), Item::Other);
                let title = item["prompt"]
                    .as_str()
                    .or(item["agentPath"].as_str())
                    .map(short_title)
                    .unwrap_or_else(|| "A subagent".to_owned());
                self.emit(Event::ToolCall(ToolCall { id, title, kind: ToolKind::Task, status: ToolStatus::InProgress, ..Default::default() }));
            }
            "imageView" => {
                self.items.insert(id.clone(), Item::Other);
                let path = item["path"].as_str().unwrap_or("").to_owned();
                self.emit(Event::ToolCall(ToolCall {
                    id,
                    title: format!("View {path}"),
                    kind: ToolKind::Read,
                    status: ToolStatus::InProgress,
                    locations: vec![Location { path, line: None }],
                    ..Default::default()
                }));
            }
            "contextCompaction" => self.emit(Event::Progress(Progress {
                id: "compaction".into(),
                label: "Compacting the conversation".into(),
                ..Default::default()
            })),
            _ => {}
        }
    }

    fn item_completed(&mut self, item: &Value) {
        let Some(id) = item["id"].as_str().map(str::to_owned) else { return };
        match item["type"].as_str().unwrap_or("") {
            "agentMessage" | "plan" => {
                if !self.streamed.remove(&id) {
                    if let Some(text) = item["text"].as_str().filter(|t| !t.is_empty()) {
                        self.emit(Event::Message { message: id, text: text.to_owned(), parent: None });
                    }
                }
            }
            "reasoning" => {
                self.reasoning.remove(&id);
                if !self.streamed.remove(&id) {
                    let parts = |key: &str| -> Vec<String> {
                        item[key].as_array().into_iter().flatten().filter_map(|p| p.as_str().map(str::to_owned)).collect()
                    };
                    let mut text = parts("content");
                    if text.is_empty() {
                        text = parts("summary");
                    }
                    let text = text.join("\n");
                    if !text.trim().is_empty() {
                        self.emit(Event::Reasoning { message: id, text, parent: None });
                    }
                }
            }
            "commandExecution" => {
                self.dirty.remove(&id);
                let command = shown_command(item);
                let mut output = match self.items.remove(&id) {
                    Some(Item::Command { output, .. }) => output,
                    _ => String::new(),
                };
                if let Some(all) = item["aggregatedOutput"].as_str() {
                    output = all.to_owned();
                }
                process::keep_tail(&mut output, OUTPUT_LIMIT);
                let exit_code = item["exitCode"].as_i64().map(|c| c as i32);
                let status = match item["status"].as_str() {
                    Some("completed") if exit_code.unwrap_or(0) == 0 => ToolStatus::Completed,
                    Some("completed") | Some("failed") | Some("declined") => ToolStatus::Failed,
                    _ => ToolStatus::Completed,
                };
                if !self.items.contains_key(&id) && command.is_empty() {
                    return;
                }
                self.emit(Event::ToolUpdate(ToolUpdate {
                    id,
                    status: Some(status),
                    content: Some(vec![ToolContent::Terminal { command: Some(command), output, exit_code }]),
                    ..Default::default()
                }));
            }
            "fileChange" => {
                let status = item["status"].as_str().unwrap_or("completed");
                let changes = match self.items.remove(&id) {
                    Some(Item::Files { changes }) => changes,
                    _ => self.changes(&item["changes"]),
                };
                let content = if status == "completed" {
                    changes.iter().map(applied).collect()
                } else {
                    changes.iter().map(proposed).collect()
                };
                self.emit(Event::ToolUpdate(ToolUpdate {
                    id,
                    status: Some(if status == "completed" { ToolStatus::Completed } else { ToolStatus::Failed }),
                    content: Some(content),
                    ..Default::default()
                }));
            }
            "mcpToolCall" | "dynamicToolCall" => {
                self.items.remove(&id);
                let failed = item["status"].as_str() == Some("failed") || item["success"] == json!(false);
                let mut content = Vec::new();
                let blocks = item["result"]["content"].as_array().or(item["contentItems"].as_array());
                for block in blocks.into_iter().flatten() {
                    if let Some(text) = block["text"].as_str() {
                        content.push(ToolContent::Text { text: text.to_owned() });
                    }
                }
                if let Some(error) = item["error"]["message"].as_str() {
                    content.push(ToolContent::Text { text: error.to_owned() });
                }
                self.emit(Event::ToolUpdate(ToolUpdate {
                    id,
                    status: Some(if failed { ToolStatus::Failed } else { ToolStatus::Completed }),
                    content: (!content.is_empty()).then_some(content),
                    output: item.get("result").filter(|r| !r.is_null()).cloned(),
                    ..Default::default()
                }));
            }
            "webSearch" | "collabAgentToolCall" | "subAgentActivity" | "imageView" => {
                if self.items.remove(&id).is_some() {
                    self.emit(Event::ToolUpdate(ToolUpdate { id, status: Some(ToolStatus::Completed), ..Default::default() }));
                }
            }
            "contextCompaction" => self.emit(Event::Progress(Progress {
                id: "compaction".into(),
                label: "Compacted the conversation".into(),
                finished: true,
                ..Default::default()
            })),
            "enteredReviewMode" | "exitedReviewMode" => {
                if let Some(review) = item["review"].as_str() {
                    self.emit(Event::Message { message: id, text: review.to_owned(), parent: None });
                }
            }
            _ => {}
        }
    }

    fn changes(&self, list: &Value) -> Vec<Change> {
        list.as_array()
            .into_iter()
            .flatten()
            .filter_map(|change| {
                let path = change["path"].as_str()?.to_owned();
                let absolute = if Path::new(&path).is_absolute() { PathBuf::from(&path) } else { self.spec.cwd.join(&path) };
                let kind = change["kind"]["type"].as_str().or(change["kind"].as_str()).unwrap_or("update").to_owned();
                let old = if kind == "add" { None } else { read_small(&absolute) };
                Some(Change { path, absolute, kind, diff: change["diff"].as_str().unwrap_or("").to_owned(), old })
            })
            .collect()
    }

    fn proposed(&self, item: &str) -> Vec<ToolContent> {
        match self.items.get(item) {
            Some(Item::Files { changes }) => changes.iter().map(proposed).collect(),
            _ => Vec::new(),
        }
    }

    fn flush(&mut self) {
        for id in std::mem::take(&mut self.dirty) {
            if let Some(Item::Command { command, output }) = self.items.get(&id) {
                self.emit(Event::ToolUpdate(ToolUpdate {
                    id: id.clone(),
                    content: Some(vec![ToolContent::Terminal { command: Some(command.clone()), output: output.clone(), exit_code: None }]),
                    ..Default::default()
                }));
            }
        }
    }

    fn request(&mut self, id: Value, method: &str, params: &Value) {
        match method {
            "item/commandExecution/requestApproval" | "execCommandApproval" => {
                let legacy = method == "execCommandApproval";
                let item = params["itemId"].as_str().or(params["callId"].as_str()).unwrap_or("").to_owned();
                let command = match &params["command"] {
                    Value::String(_) => shown_command(params),
                    Value::Array(parts) => parts.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(" "),
                    _ => match self.items.get(&item) {
                        Some(Item::Command { command, .. }) => command.clone(),
                        _ => String::new(),
                    },
                };
                let mut detail = params["reason"].as_str().map(str::to_owned);
                if let Some(host) = params["networkApprovalContext"]["host"].as_str() {
                    detail = Some(format!("{}It reaches {host}.", detail.map(|d| format!("{d} ")).unwrap_or_default()));
                }
                let title = if command.is_empty() { "Run a command".to_owned() } else { format!("Run {}", short_title(&command)) };
                self.ask(id, if legacy { Approval::Legacy } else { Approval::Command }, Some(item), title, detail, Value::Null);
            }
            "item/fileChange/requestApproval" | "applyPatchApproval" => {
                let legacy = method == "applyPatchApproval";
                let item = params["itemId"].as_str().or(params["callId"].as_str()).unwrap_or("").to_owned();
                let title = match self.items.get(&item) {
                    Some(Item::Files { changes }) => edit_title(changes),
                    _ => match params["fileChanges"].as_object() {
                        Some(files) => format!("Edit {}", files.keys().cloned().collect::<Vec<_>>().join(", ")),
                        None => "Edit files".to_owned(),
                    },
                };
                let detail = params["reason"].as_str().map(str::to_owned).or_else(|| {
                    params["grantRoot"].as_str().map(|root| format!("It also asks to write under {root} from now on."))
                });
                self.ask(id, if legacy { Approval::Legacy } else { Approval::FileChange }, Some(item), title, detail, Value::Null);
            }
            "item/permissions/requestApproval" => {
                let permissions = params["permissions"].clone();
                let mut wants = Vec::new();
                if permissions["network"]["enabled"] == json!(true) {
                    wants.push("network access".to_owned());
                }
                for key in ["write", "read"] {
                    for path in permissions["fileSystem"][key].as_array().into_iter().flatten().filter_map(Value::as_str) {
                        wants.push(format!("{key} {path}"));
                    }
                }
                let detail = match (params["reason"].as_str(), wants.is_empty()) {
                    (Some(reason), false) => Some(format!("{reason} ({})", wants.join(", "))),
                    (Some(reason), true) => Some(reason.to_owned()),
                    (None, false) => Some(wants.join(", ")),
                    (None, true) => None,
                };
                let item = params["itemId"].as_str().map(str::to_owned);
                self.ask(id, Approval::Permissions, item, "Allow more access".to_owned(), detail, permissions);
            }
            "item/tool/requestUserInput" => {
                let mut remaining = VecDeque::new();
                for (index, question) in params["questions"].as_array().into_iter().flatten().enumerate() {
                    let key = question["id"].as_str().map(str::to_owned).unwrap_or_else(|| format!("q{index}"));
                    let text = question["question"].as_str().unwrap_or("");
                    let header = question["header"].as_str().unwrap_or("");
                    let choices: Vec<String> = question["options"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|o| o["label"].as_str().map(str::to_owned))
                        .collect();
                    let request = QuestionRequest {
                        id: String::new(),
                        question: if header.is_empty() || text.starts_with(header) { text.to_owned() } else { format!("{header}: {text}") },
                        allow_text: choices.is_empty() || question["isOther"].as_bool().unwrap_or(false),
                        choices,
                        multiple: false,
                    };
                    remaining.push_back((key, request, Field::Many));
                }
                self.start_asks(id, AskKind::UserInput, remaining);
            }
            "mcpServer/elicitation/request" => {
                let server = params["serverName"].as_str().unwrap_or("an MCP server");
                let message = params["message"].as_str().unwrap_or("");
                if params["mode"].as_str() == Some("url") {
                    self.notice(Level::Warn, format!("{server} asks to open {}: {message} The VM has no browser.", params["url"].as_str().unwrap_or("a page")));
                    self.rpc.respond(id, json!({"action": "decline"}));
                    return;
                }
                let schema = &params["requestedSchema"];
                let mut remaining = VecDeque::new();
                for (name, field) in schema["properties"].as_object().into_iter().flatten() {
                    let title = field["title"].as_str().or(field["description"].as_str()).unwrap_or(name);
                    let (kind, choices) = match field["type"].as_str() {
                        Some("boolean") => (Field::Boolean, vec!["Yes".to_owned(), "No".to_owned()]),
                        Some("number") => (Field::Number, Vec::new()),
                        Some("integer") => (Field::Integer, Vec::new()),
                        Some("array") => (
                            Field::Many,
                            field["items"]["enum"].as_array().into_iter().flatten().filter_map(|c| c.as_str().map(str::to_owned)).collect(),
                        ),
                        _ => (Field::Text, field["enum"].as_array().into_iter().flatten().filter_map(|c| c.as_str().map(str::to_owned)).collect()),
                    };
                    let request = QuestionRequest {
                        id: String::new(),
                        question: if message.is_empty() { format!("{server}: {title}") } else { format!("{server}: {message} {title}") },
                        allow_text: choices.is_empty(),
                        multiple: matches!(kind, Field::Many) && !choices.is_empty(),
                        choices,
                    };
                    remaining.push_back((name.clone(), request, kind));
                }
                if remaining.is_empty() {
                    // Nothing to fill in: a confirmation.
                    remaining.push_back((
                        String::new(),
                        QuestionRequest {
                            id: String::new(),
                            question: format!("{server}: {message}"),
                            choices: vec!["Accept".into(), "Decline".into()],
                            ..Default::default()
                        },
                        Field::Text,
                    ));
                }
                self.start_asks(id, AskKind::Elicitation, remaining);
            }
            _ => {
                // Dynamic tools, ChatGPT tokens and attestations are not ours to answer.
                self.rpc.fail(id, RpcError::new(rpc::METHOD_NOT_FOUND, format!("Yougori does not handle {method}.")));
            }
        }
    }

    fn ask(&mut self, id: Value, kind: Approval, item: Option<String>, title: String, detail: Option<String>, requested: Value) {
        if self.turn.as_ref().map(|t| t.cancelled).unwrap_or(false) {
            let asked = Asked { rpc_id: id, kind, requested };
            let result = decision(&asked, None);
            self.rpc.respond(asked.rpc_id, result);
            return;
        }
        let our = format!("codex-{}", id_text(&id));
        let mut options = vec![
            PermissionOption { id: "accept".into(), label: "Yes".into(), kind: PermissionKind::AllowOnce },
            PermissionOption { id: "acceptForSession".into(), label: "Yes, for the rest of this session".into(), kind: PermissionKind::AllowAlways },
            PermissionOption { id: "decline".into(), label: "No".into(), kind: PermissionKind::RejectOnce },
        ];
        if kind == Approval::Permissions {
            options[0].label = "Yes, for this turn".into();
        }
        if let Some(item) = item.as_ref().filter(|i| !i.is_empty() && !self.items.contains_key(*i)) {
            // Asked before the item was announced: show what is asked about.
            self.items.insert(item.clone(), Item::Other);
            self.emit(Event::ToolCall(ToolCall {
                id: item.clone(),
                title: title.clone(),
                kind: if kind == Approval::FileChange { ToolKind::Edit } else { ToolKind::Execute },
                status: ToolStatus::Pending,
                ..Default::default()
            }));
        }
        self.approvals.insert(our.clone(), Asked { rpc_id: id, kind, requested });
        self.emit(Event::Permission(PermissionRequest {
            id: our,
            tool_call: item.filter(|i| !i.is_empty()),
            title,
            detail,
            options,
        }));
    }

    fn start_asks(&mut self, id: Value, kind: AskKind, remaining: VecDeque<(String, QuestionRequest, Field)>) {
        let key = format!("codex-q-{}", id_text(&id));
        let asks = Asks { rpc_id: id, kind, remaining, answers: Map::new(), dismissed: false };
        if self.turn.as_ref().map(|t| t.cancelled).unwrap_or(false) {
            respond_asks(&self.rpc, asks, true);
            return;
        }
        self.asks.insert(key.clone(), asks);
        self.next_question(&key);
    }

    /// Shows the set's next question, or answers the request when none is left.
    fn next_question(&mut self, key: &str) {
        let Some(asks) = self.asks.get_mut(key) else { return };
        match asks.remaining.front() {
            Some((field, question, _)) => {
                let shown = format!("{key}-{field}");
                let mut question = question.clone();
                question.id = shown.clone();
                self.asking.insert(shown, key.to_owned());
                self.emit(Event::Question(question));
            }
            None => {
                let asks = self.asks.remove(key).expect("present");
                respond_asks(&self.rpc, asks, false);
            }
        }
    }

    fn answered(&mut self, shown: &str, answer: Option<Vec<String>>) {
        let Some(key) = self.asking.remove(shown) else { return };
        let Some(asks) = self.asks.get_mut(&key) else { return };
        let Some((field, _, kind)) = asks.remaining.pop_front() else { return };
        match answer {
            None => {
                asks.dismissed = true;
                if matches!(asks.kind, AskKind::Elicitation) {
                    // A form left unfinished is declined as a whole.
                    asks.remaining.clear();
                } else {
                    asks.answers.insert(field, json!({"answers": []}));
                }
            }
            Some(values) => {
                let value = match (asks.kind, kind) {
                    (AskKind::UserInput, _) => json!({"answers": values}),
                    (AskKind::Elicitation, Field::Many) => json!(values),
                    (AskKind::Elicitation, Field::Boolean) => json!(values.first().map(|v| v == "Yes" || v == "true").unwrap_or(false)),
                    (AskKind::Elicitation, Field::Number) => {
                        values.first().and_then(|v| v.trim().parse::<f64>().ok()).map(|n| json!(n)).unwrap_or(json!(values.first()))
                    }
                    (AskKind::Elicitation, Field::Integer) => {
                        values.first().and_then(|v| v.trim().parse::<i64>().ok()).map(|n| json!(n)).unwrap_or(json!(values.first()))
                    }
                    (AskKind::Elicitation, Field::Text) => json!(values.join(", ")),
                };
                if field.is_empty() {
                    // A confirmation without fields.
                    if values.first().map(String::as_str) != Some("Accept") {
                        asks.dismissed = true;
                    }
                } else {
                    asks.answers.insert(field, value);
                }
            }
        }
        self.next_question(&key);
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

/// The answer to an approval: the option chosen, or None (dismissed, cancelled) which stops the
/// turn for commands and file changes and grants nothing for permissions.
fn decision(asked: &Asked, option: Option<&str>) -> Value {
    match asked.kind {
        Approval::Command | Approval::FileChange => json!({"decision": match option {
            Some("accept") => "accept",
            Some("acceptForSession") => "acceptForSession",
            Some("decline") => "decline",
            _ => "cancel",
        }}),
        Approval::Legacy => match option {
            Some("accept") => json!({"decision": "approved"}),
            Some("acceptForSession") => json!({"decision": "approved_for_session"}),
            Some("decline") => json!({"decision": {"denied": {"rejection": "The person declined."}}}),
            _ => json!({"decision": "abort"}),
        },
        Approval::Permissions => match option {
            Some("accept") => json!({"permissions": asked.requested, "scope": "turn"}),
            Some("acceptForSession") => json!({"permissions": asked.requested, "scope": "session"}),
            _ => json!({"permissions": {}}),
        },
    }
}

fn respond_asks(rpc: &Rpc, asks: Asks, cancelled: bool) {
    match asks.kind {
        AskKind::UserInput => {
            let mut answers = asks.answers;
            for (field, _, _) in asks.remaining {
                answers.insert(field, json!({"answers": []}));
            }
            rpc.respond(asks.rpc_id, json!({"answers": answers}));
        }
        AskKind::Elicitation => {
            if cancelled {
                rpc.respond(asks.rpc_id, json!({"action": "cancel"}));
            } else if asks.dismissed {
                rpc.respond(asks.rpc_id, json!({"action": "decline"}));
            } else {
                rpc.respond(asks.rpc_id, json!({"action": "accept", "content": asks.answers}));
            }
        }
    }
}

/// The command as the model wrote it: Codex runs it as `/bin/sh -lc '...'` and gives the
/// inner command in its one action.
fn shown_command(item: &Value) -> String {
    let full = item["command"].as_str().unwrap_or("");
    match item["commandActions"].as_array().map(Vec::as_slice) {
        Some([one]) => one["command"].as_str().filter(|c| !c.is_empty()).unwrap_or(full).to_owned(),
        _ => full.to_owned(),
    }
}

fn command_kind(actions: &Value) -> (ToolKind, Vec<Location>) {
    let list = actions.as_array().cloned().unwrap_or_default();
    if list.is_empty() {
        return (ToolKind::Execute, Vec::new());
    }
    let kinds: Vec<&str> = list.iter().filter_map(|a| a["type"].as_str()).collect();
    let locations = list
        .iter()
        .filter_map(|a| a["path"].as_str())
        .map(|p| Location { path: p.to_owned(), line: None })
        .collect();
    let kind = if kinds.iter().all(|k| *k == "read") {
        ToolKind::Read
    } else if kinds.iter().all(|k| matches!(*k, "search" | "listFiles")) {
        ToolKind::Search
    } else {
        ToolKind::Execute
    };
    (kind, locations)
}

/// The first line of a command, cut for a title.
pub(crate) fn short_title(text: &str) -> String {
    let line = text.lines().find(|l| !l.trim().is_empty()).unwrap_or("").trim();
    if line.chars().count() > 100 {
        line.chars().take(100).chain("…".chars()).collect()
    } else if text.trim().lines().count() > 1 {
        format!("{line} …")
    } else {
        line.to_owned()
    }
}

fn edit_title(changes: &[Change]) -> String {
    match changes {
        [] => "Edit files".to_owned(),
        [one] => format!(
            "{} {}",
            match one.kind.as_str() {
                "add" => "Create",
                "delete" => "Delete",
                _ => "Edit",
            },
            one.path
        ),
        many => format!("Edit {} files", many.len()),
    }
}

fn read_small(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > DIFF_FILE_LIMIT {
        return None;
    }
    std::fs::read(path).ok().map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

/// A change before it is applied: the file now and the file as the patch would leave it.
fn proposed(change: &Change) -> ToolContent {
    match change.kind.as_str() {
        "add" => ToolContent::Diff { path: change.path.clone(), old: None, new: added_text(&change.diff) },
        "delete" => ToolContent::Diff { path: change.path.clone(), old: change.old.clone().or(Some(String::new())), new: String::new() },
        _ => match change.old.as_deref().and_then(|old| apply_unified(old, &change.diff)) {
            Some(new) => ToolContent::Diff { path: change.path.clone(), old: change.old.clone(), new },
            None => ToolContent::Text { text: change.diff.clone() },
        },
    }
}

/// A change once applied: the file before and as it is now on disk.
fn applied(change: &Change) -> ToolContent {
    let now = read_small(&change.absolute);
    match (change.kind.as_str(), now) {
        ("delete", _) => ToolContent::Diff { path: change.path.clone(), old: change.old.clone().or(Some(String::new())), new: String::new() },
        (_, Some(now)) => ToolContent::Diff { path: change.path.clone(), old: change.old.clone(), new: now },
        (_, None) => proposed(change),
    }
}

/// A new file's text from its change: Codex gives either the text or a diff adding every line.
fn added_text(diff: &str) -> String {
    let is_diff = diff.lines().any(|l| l.starts_with("@@")) || diff.starts_with("--- ") || diff.starts_with("+++ ");
    if !is_diff {
        return diff.to_owned();
    }
    let mut text = String::new();
    for line in diff.lines() {
        if line.starts_with("+++") || line.starts_with("---") || line.starts_with("@@") {
            continue;
        }
        if let Some(added) = line.strip_prefix('+') {
            text.push_str(added);
            text.push('\n');
        }
    }
    text
}

/// Applies a unified diff to `old`; None when a hunk does not fit.
pub(crate) fn apply_unified(old: &str, diff: &str) -> Option<String> {
    let lines: Vec<&str> = old.split_inclusive('\n').collect();
    let mut out = String::new();
    let mut at = 0usize;
    let mut hunks = 0;
    let mut diff_lines = diff.lines().peekable();
    while let Some(line) = diff_lines.next() {
        if !line.starts_with("@@") {
            continue;
        }
        hunks += 1;
        let header = line.trim_start_matches('@').trim();
        let start = header.split_whitespace().next()?.strip_prefix('-')?.split(',').next()?.parse::<usize>().ok()?;
        let start = start.saturating_sub(1);
        if start < at || start > lines.len() {
            return None;
        }
        for kept in &lines[at..start] {
            out.push_str(kept);
        }
        at = start;
        let mut last = " ";
        while let Some(body) = diff_lines.peek() {
            if body.starts_with("@@") {
                break;
            }
            let body = diff_lines.next().unwrap();
            if body.starts_with("\\") {
                // "\ No newline at end of file": the line before it has none. Only a line of the
                // new file changes what is written.
                if last != "-" && out.ends_with('\n') {
                    out.pop();
                }
                continue;
            }
            let (mark, text) = body.split_at(body.len().min(1));
            last = mark;
            match mark {
                " " | "" => {
                    let original = lines.get(at)?;
                    if original.trim_end_matches(['\n', '\r']) != text {
                        return None;
                    }
                    out.push_str(original);
                    at += 1;
                }
                "-" => {
                    let original = lines.get(at)?;
                    if original.trim_end_matches(['\n', '\r']) != text {
                        return None;
                    }
                    at += 1;
                }
                "+" => {
                    out.push_str(text);
                    out.push('\n');
                }
                _ => return None,
            }
        }
    }
    if hunks == 0 {
        return None;
    }
    for kept in &lines[at.min(lines.len())..] {
        out.push_str(kept);
    }
    Some(out)
}

fn id_text(id: &Value) -> String {
    match id {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}
