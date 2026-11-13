//! The Agent Client Protocol (ACP, protocol version 1) over an agent's stdio, as the pinned
//! agents implement it: OpenCode, Kilo, Gemini CLI, Qwen Code, DeepSeek's dsh, Goose, OpenHands,
//! Cline and Grok, and our Python bridges (bridges/acp.py) for the harnesses that speak no
//! protocol of their own.
//!
//! The client offers file reads and writes and terminals; answers permission requests and our
//! `_yougori/question` request through the screen; switches models in the session when the agent
//! offers them (`configOptions` with the `model` category, or the older `session/set_model`); and
//! maps every session update to [`Event`]s. Our bridges also send `_yougori/finding`,
//! `_yougori/report`, `_yougori/progress` and `_yougori/usage` notifications.
use super::process::rpc::{self, CallError, Incoming, Message, Rpc, RpcError};
use super::process::{self, Launch, LineWriter, ProcessGuard, Stdio2, Tail};
use crate::protocol::{
    Command, EngineHandle, Event, Finding, Level, Location, Mode, ModelSwitch, PermissionKind, PermissionOption,
    PermissionRequest, PlanEntry, PlanStatus, Priority, Progress, QuestionRequest, Ready, Report, SlashCommand,
    StopReason, ToolCall, ToolContent, ToolKind, ToolStatus, ToolUpdate, Usage,
};
use crate::spec::EngineSpec;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::time::Duration;
use tokio::sync::mpsc;

mod terminals;
#[cfg(test)]
pub(crate) mod tests;

use terminals::{TermEvent, Terminals};

/// The ACP version we speak.
const PROTOCOL_VERSION: i64 = 1;
/// How long an agent may take to answer `initialize` and `session/new` (a first start in a fresh
/// VM compiles and caches a lot).
const START_LIMIT: Duration = Duration::from_secs(180);
/// The largest file `fs/read_text_file` returns.
const READ_LIMIT: u64 = 50 * 1024 * 1024;
/// Authentication methods that need no secret: the agent reads its key from the environment or
/// the configuration the profile wrote.
const SECRETLESS_AUTH: [&str; 7] = ["gemini-api-key", "openai", "openai-compatible", "use_openai", "api-key", "apikey", "env"];
/// How long a cancelled turn waits for the agent to answer its prompt (ACP: it must, with the
/// `cancelled` stop reason) before the screen ends the turn itself. Generous: an agent may take
/// a while to stop its commands (Plandex's bridge waits on its server, then its CLI).
const CANCEL_LIMIT: Duration = Duration::from_secs(30);

/// Starts the spec's agent and opens its ACP session.
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
    let transport = Transport {
        values: process::json_lines(stdout, noise.clone()),
        writer: LineWriter::new(stdin),
        guard: Some(spawned.guard),
        noise,
    };
    connect(spec.clone(), transport).await
}

/// An agent's two streams (and its process, when we started one).
pub(crate) struct Transport {
    pub values: mpsc::UnboundedReceiver<Value>,
    pub writer: LineWriter,
    pub guard: Option<ProcessGuard>,
    pub noise: Tail,
}

/// Initialises the agent and opens a session, then runs the engine loop in its own task.
pub(crate) async fn connect(spec: EngineSpec, transport: Transport) -> anyhow::Result<EngineHandle> {
    connect_limited(spec, transport, CANCEL_LIMIT).await
}

/// [`connect`] with the time a cancelled turn waits for the agent's answer.
async fn connect_limited(spec: EngineSpec, transport: Transport, cancel_limit: Duration) -> anyhow::Result<EngineHandle> {
    let Transport { values, writer, guard, noise } = transport;
    let rpc = Rpc::new(writer.clone(), false);
    let mut incoming = Incoming::new(values);

    let files = offers_files(&spec);
    let init_params = json!({
        "protocolVersion": PROTOCOL_VERSION,
        "clientCapabilities": {"fs": {"readTextFile": files, "writeTextFile": files}, "terminal": true},
        "clientInfo": {"name": "yougori-harness", "title": "Yougori", "version": env!("CARGO_PKG_VERSION")},
    });
    let init = match incoming.call(&rpc, "initialize", init_params, START_LIMIT, &mut early).await {
        Ok(init) => init,
        Err(error) => return Err(start_failed(&spec, guard.as_ref(), &noise, "initialize", error).await),
    };
    let version = init.get("protocolVersion").and_then(Value::as_i64).unwrap_or(PROTOCOL_VERSION);
    if version != PROTOCOL_VERSION {
        stop(guard.as_ref(), &writer).await;
        anyhow::bail!("{} speaks ACP version {version}; Yougori speaks version {PROTOCOL_VERSION}.", spec.name);
    }
    let agent = Agent::from_initialize(&init);
    let (servers, skipped) = mcp_servers(&spec, &agent);
    let session_params = json!({"cwd": spec.cwd, "mcpServers": servers});
    let session = match incoming.call(&rpc, "session/new", session_params.clone(), START_LIMIT, &mut early).await {
        Ok(session) => session,
        Err(CallError::Rpc(error)) if error.code == rpc::AUTH_REQUIRED => {
            let mut opened = None;
            for method in agent.secretless_auth(&spec) {
                let authenticated = incoming.call(&rpc, "authenticate", json!({"methodId": method}), START_LIMIT, &mut early).await;
                if authenticated.is_err() {
                    continue;
                }
                if let Ok(session) = incoming.call(&rpc, "session/new", session_params.clone(), START_LIMIT, &mut early).await {
                    opened = Some(session);
                    break;
                }
            }
            match opened {
                Some(session) => session,
                None => return Err(start_failed(&spec, guard.as_ref(), &noise, "open a session", CallError::Rpc(error)).await),
            }
        }
        Err(error) => return Err(start_failed(&spec, guard.as_ref(), &noise, "open a session", error).await),
    };
    let Some(session_id) = session.get("sessionId").and_then(Value::as_str).map(str::to_owned) else {
        stop(guard.as_ref(), &writer).await;
        anyhow::bail!("{} opened a session without an id.", spec.name);
    };

    let mut models = ModelControl::from_session(&session);
    let mut modes = ModeControl::from_session(&session);
    let mut notices = Vec::new();
    for name in skipped {
        notices.push(format!("{} cannot use the MCP server {name} (it takes no HTTP servers).", spec.name));
    }
    // An engine its profile switches in place starts on the chosen model even when the agent's
    // own default differs (Cline starts on its provider's default). The others were configured
    // for the model before they started, under names of their own (Grok's "solver").
    let live = spec.model_switch == ModelSwitch::Live && models.covers(&spec.models, &spec.model);
    if live {
        if let Some(choice) = models.choice(&spec.model) {
            if models.current_value().as_deref() != Some(choice.value.as_str()) {
                let (method, params) = choice.request(&session_id);
                match incoming.call(&rpc, method, params, START_LIMIT, &mut early).await {
                    Ok(result) => {
                        models.chose(&choice);
                        models.refresh(&result);
                        modes.refresh(&result);
                    }
                    Err(error) => notices.push(format!("{} could not select {}: {error}", spec.name, spec.model)),
                }
            }
        }
    }

    let (handle, commands, events) = EngineHandle::pair();
    let mut handle = handle;
    if let Some(guard) = guard.clone() {
        handle.keep.push(Box::new(guard));
    }
    let info = agent.info();
    let _ = events.send(Event::Ready(Ready {
        harness: spec.harness.clone(),
        name: spec.name.clone(),
        model: spec.model.clone(),
        models: spec.models.clone(),
        model_switch: if live { ModelSwitch::Live } else { ModelSwitch::Restart },
        session: Some(session_id.clone()),
        info: Some(info),
    }));
    if let Some(event) = modes.event() {
        let _ = events.send(event);
    }
    for text in notices {
        let _ = events.send(Event::Notice { level: Level::Warn, text });
    }
    let engine = Engine {
        model: spec.model.clone(),
        spec,
        rpc,
        writer,
        events,
        guard,
        noise,
        session: session_id,
        models,
        modes,
        live,
        pending: HashMap::new(),
        turn: None,
        turns: 0,
        queue: VecDeque::new(),
        permissions: HashMap::new(),
        questions: HashMap::new(),
        tools: HashMap::new(),
        terminals: Terminals::new(),
        ids: TextIds::default(),
        user_text: String::new(),
        cancel_limit,
    };
    tokio::spawn(engine.run(incoming, commands));
    Ok(handle)
}

/// Whether the client offers its file reads and writes. Gemini CLI 0.66.0 checks a file it is
/// about to create through `fs/read_text_file` and cannot read the error that says the file is
/// missing (its ACP SDK rejects with a plain object), so it never creates a file through a client
/// that offers them; it keeps its own file access, which is the same file system here.
fn offers_files(spec: &EngineSpec) -> bool {
    spec.harness != "gemini"
}

/// Requests answered during start-up, before the loop runs: an agent may read files while it
/// opens a session.
fn early(rpc: &Rpc, message: &Message) -> bool {
    let Message::Request { id, method, params } = message else { return false };
    let answer = match method.as_str() {
        "fs/read_text_file" => read_text_file(params),
        "fs/write_text_file" => write_text_file(params),
        _ => return false,
    };
    answer_with(rpc, id.clone(), answer);
    true
}

async fn start_failed(spec: &EngineSpec, guard: Option<&ProcessGuard>, noise: &Tail, what: &str, error: CallError) -> anyhow::Error {
    let mut text = format!("{} did not start: it could not {what}: {error}.", spec.name);
    if let Some(guard) = guard {
        // Its last words arrive a moment after it ends.
        let _ = guard.wait_for(Duration::from_millis(800)).await;
        let tail = guard.tail();
        if let Some(status) = guard.status() {
            text = format!("{} did not start: it {} while trying to {what}.", spec.name, process::describe(status));
        }
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

async fn stop(guard: Option<&ProcessGuard>, writer: &LineWriter) {
    writer.close();
    if let Some(guard) = guard {
        if guard.wait_for(Duration::from_secs(1)).await.is_none() {
            guard.stop().await;
        }
    }
}

/// What `initialize` told us about the agent.
struct Agent {
    name: String,
    version: Option<String>,
    mcp_http: bool,
    auth: Vec<Value>,
}

impl Agent {
    fn from_initialize(init: &Value) -> Agent {
        let info = &init["agentInfo"];
        let name = info["title"].as_str().or(info["name"].as_str()).unwrap_or("").to_owned();
        Agent {
            name,
            version: info["version"].as_str().map(str::to_owned),
            mcp_http: init["agentCapabilities"]["mcpCapabilities"]["http"].as_bool().unwrap_or(false),
            auth: init["authMethods"].as_array().cloned().unwrap_or_default(),
        }
    }

    fn info(&self) -> String {
        let mut parts = Vec::new();
        if !self.name.is_empty() {
            parts.push(match &self.version {
                Some(v) => format!("{} {v}", self.name),
                None => self.name.clone(),
            });
        }
        parts.push("ACP".to_owned());
        parts.join(" · ")
    }

    /// Authentication methods to try when the agent asks for one: only those that take their key
    /// from the environment, never a browser login or a typed secret.
    fn secretless_auth(&self, spec: &EngineSpec) -> Vec<String> {
        let env = spec.environment();
        self.auth
            .iter()
            .filter_map(|method| {
                let id = method["id"].as_str()?;
                let kind = method["type"].as_str().or(method["_meta"]["type"].as_str()).unwrap_or("agent");
                let fits = match kind {
                    "env_var" => {
                        let names: Vec<&str> = method["vars"]
                            .as_array()
                            .map(|vars| vars.iter().filter_map(|v| v["name"].as_str().or(v.as_str())).collect())
                            .or_else(|| method["varName"].as_str().map(|n| vec![n]))
                            .unwrap_or_default();
                        !names.is_empty() && names.iter().all(|n| env.contains_key(*n))
                    }
                    "terminal" => false,
                    _ => SECRETLESS_AUTH.contains(&id.to_ascii_lowercase().as_str()),
                };
                fits.then(|| id.to_owned())
            })
            .collect()
    }
}

/// The spec's MCP servers as ACP describes them; HTTP servers only when the agent takes them.
fn mcp_servers(spec: &EngineSpec, agent: &Agent) -> (Vec<Value>, Vec<String>) {
    let mut servers = Vec::new();
    let mut skipped = Vec::new();
    for server in &spec.mcp {
        if let Some(program) = server.command.first() {
            let env: Vec<Value> = server.env.iter().map(|(k, v)| json!({"name": k, "value": v})).collect();
            servers.push(json!({"name": server.name, "command": program, "args": &server.command[1..], "env": env}));
        } else if let Some(url) = &server.url {
            if agent.mcp_http {
                servers.push(json!({"type": "http", "name": server.name, "url": url, "headers": []}));
            } else {
                skipped.push(server.name.clone());
            }
        }
    }
    (servers, skipped)
}

/// How the agent switches models in a session: a `configOptions` entry with the `model`
/// category (`session/set_config_option`, values from its list), and/or the older `models` state
/// (`session/set_model`, which the pinned Gemini CLI and Cline take with any model id).
#[derive(Debug, Default)]
struct ModelControl {
    config: Option<ConfigModels>,
    listed: Option<ListedModels>,
}

#[derive(Debug)]
struct ConfigModels {
    id: String,
    current: Option<String>,
    values: Vec<(String, String)>,
}

#[derive(Debug)]
struct ListedModels {
    current: Option<String>,
    values: Vec<(String, String)>,
}

/// How one model is selected.
#[derive(Clone, Debug, PartialEq)]
struct Choice {
    /// Through the config option `Some(id)`, else `session/set_model`.
    config: Option<String>,
    value: String,
}

impl Choice {
    fn request(&self, session: &str) -> (&'static str, Value) {
        match &self.config {
            Some(id) => ("session/set_config_option", json!({"sessionId": session, "configId": id, "value": self.value})),
            None => ("session/set_model", json!({"sessionId": session, "modelId": self.value})),
        }
    }
}

impl ModelControl {
    fn from_session(session: &Value) -> ModelControl {
        let config = config_option(session, "model").map(|option| ConfigModels {
            id: option["id"].as_str().unwrap_or("model").to_owned(),
            current: option["currentValue"].as_str().map(str::to_owned),
            values: select_values(option),
        });
        let models = &session["models"];
        let listed = models["availableModels"].as_array().map(|available| ListedModels {
            current: models["currentModelId"].as_str().map(str::to_owned),
            values: available
                .iter()
                .filter_map(|m| {
                    let id = m["modelId"].as_str()?;
                    Some((id.to_owned(), m["name"].as_str().unwrap_or(id).to_owned()))
                })
                .collect(),
        });
        ModelControl { config, listed }
    }

    /// How to select one of our models: the config option when it lists it, else
    /// `session/set_model` with the listed id or the model itself.
    fn choice(&self, model: &str) -> Option<Choice> {
        if let Some(config) = &self.config {
            if let Some(value) = find_value(&config.values, model) {
                return Some(Choice { config: Some(config.id.clone()), value });
            }
        }
        let listed = self.listed.as_ref()?;
        Some(Choice { config: None, value: find_value(&listed.values, model).unwrap_or_else(|| model.to_owned()) })
    }

    fn current_value(&self) -> Option<String> {
        self.config.as_ref().and_then(|c| c.current.clone()).or_else(|| self.listed.as_ref().and_then(|l| l.current.clone()))
    }

    fn chose(&mut self, choice: &Choice) {
        match (&choice.config, self.config.as_mut(), self.listed.as_mut()) {
            (Some(_), Some(config), _) => config.current = Some(choice.value.clone()),
            (None, config, Some(listed)) => {
                listed.current = Some(choice.value.clone());
                // The config option, when there is one, no longer names the model in use.
                if let Some(config) = config {
                    config.current = None;
                }
            }
            _ => {}
        }
    }

    /// Our model for one of the agent's values.
    fn model_for(&self, value: &str, ours: &[String]) -> Option<String> {
        let names = self.config.iter().flat_map(|c| c.values.iter()).chain(self.listed.iter().flat_map(|l| l.values.iter()));
        let name = names.filter(|(v, _)| v == value).map(|(_, n)| n.as_str()).next().unwrap_or("");
        ours.iter().find(|m| m.as_str() == value).or_else(|| ours.iter().find(|m| same_model(m, value, name))).cloned()
    }

    /// Whether every model of this inference can be selected in the session.
    fn covers(&self, models: &[String], current: &str) -> bool {
        models.iter().map(String::as_str).chain([current]).all(|m| self.choice(m).is_some())
    }

    /// Takes the current value from a `configOptions` list (a response or an update).
    fn refresh(&mut self, holder: &Value) {
        let Some(config) = self.config.as_mut() else { return };
        if let Some(option) = holder["configOptions"].as_array().and_then(|list| list.iter().find(|o| o["id"] == json!(config.id))) {
            if let Some(value) = option["currentValue"].as_str() {
                config.current = Some(value.to_owned());
            }
            let fresh = select_values(option);
            if !fresh.is_empty() {
                config.values = fresh;
            }
        }
    }
}

/// The agent's value for one of our models in a list of (value, name).
fn find_value(values: &[(String, String)], model: &str) -> Option<String> {
    values
        .iter()
        .find(|(value, _)| value == model)
        .or_else(|| values.iter().find(|(value, name)| same_model(model, value, name)))
        .map(|(value, _)| value.clone())
}

/// Whether the agent's model value (or its display name) is our model: `solver/m` (OpenCode,
/// Kilo), `["solver","m"]` (dsh), `m(openai)` (Qwen Code), or the name.
fn same_model(model: &str, value: &str, name: &str) -> bool {
    if value == model || name == model {
        return true;
    }
    if value.len() > model.len() && value.ends_with(model) && value[..value.len() - model.len()].ends_with('/') {
        return true;
    }
    if let Ok(Value::Array(parts)) = serde_json::from_str::<Value>(value) {
        if parts.last().and_then(Value::as_str) == Some(model) {
            return true;
        }
    }
    if let Some(rest) = value.strip_prefix(model) {
        if rest.starts_with('(') && rest.ends_with(')') {
            return true;
        }
    }
    false
}

/// The first `configOptions` entry of a category.
fn config_option<'a>(holder: &'a Value, category: &str) -> Option<&'a Value> {
    holder["configOptions"]
        .as_array()?
        .iter()
        .find(|o| o["category"] == json!(category) && o["type"].as_str().unwrap_or("select") == "select")
}

/// A select option's values and names, grouped or not.
fn select_values(option: &Value) -> Vec<(String, String)> {
    let mut values = Vec::new();
    for entry in option["options"].as_array().into_iter().flatten() {
        if let Some(group) = entry["options"].as_array() {
            for item in group {
                if let Some(value) = item["value"].as_str() {
                    values.push((value.to_owned(), item["name"].as_str().unwrap_or(value).to_owned()));
                }
            }
        } else if let Some(value) = entry["value"].as_str() {
            values.push((value.to_owned(), entry["name"].as_str().unwrap_or(value).to_owned()));
        }
    }
    values
}

/// How the agent switches modes (plan, build, ask...).
#[derive(Debug)]
enum ModeControl {
    None,
    Modes { current: String, available: Vec<Mode> },
    Config { id: String, current: String, available: Vec<Mode> },
}

impl ModeControl {
    fn from_session(session: &Value) -> ModeControl {
        let modes = &session["modes"];
        if let Some(list) = modes["availableModes"].as_array() {
            let available: Vec<Mode> = list
                .iter()
                .filter_map(|m| {
                    let id = m["id"].as_str()?;
                    Some(Mode {
                        id: id.to_owned(),
                        name: m["name"].as_str().unwrap_or(id).to_owned(),
                        description: m["description"].as_str().map(str::to_owned),
                    })
                })
                .collect();
            if !available.is_empty() {
                let current = modes["currentModeId"].as_str().unwrap_or("").to_owned();
                return ModeControl::Modes { current, available };
            }
        }
        if let Some(option) = config_option(session, "mode") {
            let available: Vec<Mode> = select_values(option)
                .into_iter()
                .map(|(id, name)| Mode { id, name, description: None })
                .collect();
            if !available.is_empty() {
                return ModeControl::Config {
                    id: option["id"].as_str().unwrap_or("mode").to_owned(),
                    current: option["currentValue"].as_str().unwrap_or("").to_owned(),
                    available,
                };
            }
        }
        ModeControl::None
    }

    fn event(&self) -> Option<Event> {
        match self {
            ModeControl::None => None,
            ModeControl::Modes { current, available } | ModeControl::Config { current, available, .. } => {
                Some(Event::Modes { current: current.clone(), available: available.clone() })
            }
        }
    }

    fn set_current(&mut self, mode: &str) -> bool {
        match self {
            ModeControl::None => false,
            ModeControl::Modes { current, .. } | ModeControl::Config { current, .. } => {
                let changed = current != mode;
                *current = mode.to_owned();
                changed
            }
        }
    }

    fn refresh(&mut self, holder: &Value) -> bool {
        if let ModeControl::Config { id, .. } = self {
            let id = id.clone();
            if let Some(option) = holder["configOptions"].as_array().and_then(|l| l.iter().find(|o| o["id"] == json!(id))) {
                if let Some(value) = option["currentValue"].as_str() {
                    return self.set_current(value);
                }
            }
        }
        false
    }

    fn knows(&self, mode: &str) -> bool {
        match self {
            ModeControl::None => false,
            ModeControl::Modes { available, .. } | ModeControl::Config { available, .. } => available.iter().any(|m| m.id == mode),
        }
    }
}

/// Requests we sent and wait for in the loop.
enum Pending {
    Prompt,
    SetModel { model: String, choice: Choice },
    SetMode { mode: String },
}

struct Turn {
    id: i64,
    cancelled: bool,
    /// When a cancelled turn the agent has still not answered ends anyway.
    deadline: Option<tokio::time::Instant>,
}

struct AskedPermission {
    rpc_id: Value,
    options: Vec<String>,
}

/// A tool call's content as the agent last gave it; terminals are filled in from their output.
#[derive(Default)]
struct ToolState {
    title: String,
    kind: ToolKind,
    /// The command of an execute call, from its input.
    command: Option<String>,
    /// Its exit code, from its output.
    exit: Option<i32>,
    items: Vec<Item>,
}

enum Item {
    Plain(ToolContent),
    Terminal(String),
}

impl ToolState {
    /// Takes the command and exit code from an update's input and output.
    fn learn(&mut self, update: &Value) {
        if let Some(command) = command_of(update.get("rawInput")) {
            self.command = Some(command);
        }
        let output = &update["rawOutput"];
        let exit = output["metadata"]["exit"]
            .as_i64()
            .or(output["exit"].as_i64())
            .or(output["exitCode"].as_i64())
            .or(output["exit_code"].as_i64());
        if let Some(exit) = exit {
            self.exit = Some(exit as i32);
        }
    }

    fn shows_terminal(&self) -> bool {
        self.kind == ToolKind::Execute
            && self.command.is_some()
            && !self.items.is_empty()
            && self.items.iter().all(|item| matches!(item, Item::Plain(ToolContent::Text { .. })))
    }
}

/// The command a tool runs, from its input.
fn command_of(input: Option<&Value>) -> Option<String> {
    let input = input?;
    for key in ["command", "cmd"] {
        match input.get(key) {
            Some(Value::String(text)) if !text.is_empty() => return Some(text.clone()),
            Some(Value::Array(parts)) if !parts.is_empty() => {
                return Some(parts.iter().map(|p| p.as_str().map(str::to_owned).unwrap_or_else(|| p.to_string())).collect::<Vec<_>>().join(" "))
            }
            _ => {}
        }
    }
    None
}

/// Message ids for chunks that carry none: consecutive chunks of one kind form one message.
#[derive(Default)]
struct TextIds {
    turn: u64,
    seq: u64,
    last: Option<char>,
}

impl TextIds {
    fn next(&mut self, kind: char) -> String {
        if self.last != Some(kind) {
            self.seq += 1;
            self.last = Some(kind);
        }
        format!("t{}{kind}{}", self.turn, self.seq)
    }

    fn other(&mut self) {
        self.last = None;
    }

    fn new_turn(&mut self, turn: u64) {
        self.turn = turn;
        self.seq = 0;
        self.last = None;
    }
}

struct Engine {
    spec: EngineSpec,
    rpc: Rpc,
    writer: LineWriter,
    events: mpsc::UnboundedSender<Event>,
    guard: Option<ProcessGuard>,
    noise: Tail,
    session: String,
    models: ModelControl,
    modes: ModeControl,
    model: String,
    live: bool,
    pending: HashMap<i64, Pending>,
    turn: Option<Turn>,
    turns: u64,
    queue: VecDeque<String>,
    permissions: HashMap<String, AskedPermission>,
    questions: HashMap<String, Value>,
    tools: HashMap<String, ToolState>,
    terminals: Terminals,
    ids: TextIds,
    user_text: String,
    cancel_limit: Duration,
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
        let mut terminal_events = self.terminals.take_events();
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
            let deadline = self.turn.as_ref().and_then(|turn| turn.deadline);
            let unanswered = async move {
                match deadline {
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
                Some(event) = terminal_events.recv() => self.terminal_event(event),
                _ = flush.tick(), if self.terminals.has_dirty() => self.flush_terminals(),
                _ = wait_exit => {
                    // The process ended; its last output may still be on the way.
                    exited_at = Some(tokio::time::Instant::now() + Duration::from_millis(1500));
                }
                _ = grace => {
                    self.ended().await;
                    break;
                }
                _ = unanswered => self.abandon_turn(),
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
                if let Some(asked) = self.permissions.remove(&id) {
                    let outcome = match option.filter(|o| asked.options.contains(o)) {
                        Some(option) => json!({"outcome": "selected", "optionId": option}),
                        None => json!({"outcome": "cancelled"}),
                    };
                    self.rpc.respond(asked.rpc_id, json!({"outcome": outcome}));
                }
            }
            Command::Answer { id, answer } => {
                if let Some(rpc_id) = self.questions.remove(&id) {
                    self.rpc.respond(rpc_id, json!({"answer": answer}));
                }
            }
            Command::SetModel { model } => self.set_model(model),
            Command::SetMode { mode } => self.set_mode(mode),
            Command::Shutdown => {
                self.shutdown().await;
                return Flow::Stop;
            }
        }
        Flow::Go
    }

    fn prompt(&mut self, text: String) {
        self.flush_user();
        self.turns += 1;
        self.ids.new_turn(self.turns);
        let id = self.rpc.request(
            "session/prompt",
            json!({"sessionId": self.session, "prompt": [{"type": "text", "text": text}]}),
        );
        self.pending.insert(id, Pending::Prompt);
        self.turn = Some(Turn { id, cancelled: false, deadline: None });
    }

    fn cancel(&mut self) {
        self.queue.clear();
        let Some(turn) = self.turn.as_mut() else { return };
        if !turn.cancelled {
            turn.cancelled = true;
            turn.deadline = Some(tokio::time::Instant::now() + self.cancel_limit);
            self.rpc.notify("session/cancel", json!({"sessionId": self.session}));
        }
        // ACP: the client answers every open permission request as cancelled.
        for (_, asked) in self.permissions.drain() {
            self.rpc.respond(asked.rpc_id, json!({"outcome": {"outcome": "cancelled"}}));
        }
        for (_, rpc_id) in self.questions.drain() {
            self.rpc.respond(rpc_id, json!({"answer": null}));
        }
    }

    fn set_model(&mut self, model: String) {
        if !self.live {
            self.notice(Level::Warn, format!("{} switches models by restarting.", self.spec.name));
            return;
        }
        let Some(choice) = self.models.choice(&model) else {
            self.notice(Level::Warn, format!("{} does not offer {model}.", self.spec.name));
            return;
        };
        let (method, params) = choice.request(&self.session);
        let id = self.rpc.request(method, params);
        self.pending.insert(id, Pending::SetModel { model, choice });
    }

    fn set_mode(&mut self, mode: String) {
        if !self.modes.knows(&mode) {
            self.notice(Level::Warn, format!("{} has no mode {mode}.", self.spec.name));
            return;
        }
        let id = match &self.modes {
            ModeControl::Modes { .. } => {
                self.rpc.request("session/set_mode", json!({"sessionId": self.session, "modeId": mode}))
            }
            ModeControl::Config { id, .. } => self.rpc.request(
                "session/set_config_option",
                json!({"sessionId": self.session, "configId": id, "value": mode}),
            ),
            ModeControl::None => return,
        };
        self.pending.insert(id, Pending::SetMode { mode });
    }

    fn message(&mut self, message: Message) {
        match message {
            Message::Response { id, outcome } => {
                let Some(id) = rpc::our_id(&id) else { return };
                match self.pending.remove(&id) {
                    Some(Pending::Prompt) => self.prompt_done(id, outcome),
                    Some(Pending::SetModel { model, choice }) => match outcome {
                        Ok(result) => {
                            self.models.chose(&choice);
                            self.models.refresh(&result);
                            if self.modes.refresh(&result) {
                                if let Some(event) = self.modes.event() {
                                    self.emit(event);
                                }
                            }
                            self.model = model.clone();
                            self.emit(Event::Model { model });
                        }
                        Err(error) => self.notice(Level::Error, format!("Could not switch to {model}: {error}")),
                    },
                    Some(Pending::SetMode { mode }) => match outcome {
                        Ok(result) => {
                            self.models.refresh(&result);
                            self.modes.refresh(&result);
                            self.modes.set_current(&mode);
                            if let Some(event) = self.modes.event() {
                                self.emit(event);
                            }
                        }
                        Err(error) => self.notice(Level::Error, format!("Could not switch to the {mode} mode: {error}")),
                    },
                    None => {}
                }
            }
            Message::Notification { method, params } => self.notification(&method, params),
            Message::Request { id, method, params } => self.request(id, &method, params),
        }
    }

    fn prompt_done(&mut self, id: i64, outcome: Result<Value, RpcError>) {
        let Some(turn) = self.turn.take_if(|t| t.id == id) else { return };
        self.flush_user();
        // Anything still open belongs to the turn that ended.
        for (_, asked) in self.permissions.drain() {
            self.rpc.respond(asked.rpc_id, json!({"outcome": {"outcome": "cancelled"}}));
        }
        for (_, rpc_id) in self.questions.drain() {
            self.rpc.respond(rpc_id, json!({"answer": null}));
        }
        let (reason, detail) = match outcome {
            Ok(result) => {
                if let Some(usage) = result.get("usage").filter(|u| u.is_object()) {
                    self.emit(Event::Usage(Usage {
                        input_tokens: usage["inputTokens"].as_u64(),
                        output_tokens: usage["outputTokens"].as_u64(),
                        ..Default::default()
                    }));
                }
                let reason = match result["stopReason"].as_str().unwrap_or("end_turn") {
                    "max_tokens" => StopReason::MaxTokens,
                    "max_turn_requests" => StopReason::MaxSteps,
                    "refusal" => StopReason::Refused,
                    "cancelled" => StopReason::Cancelled,
                    _ => StopReason::EndTurn,
                };
                (if turn.cancelled { StopReason::Cancelled } else { reason }, None)
            }
            Err(_) if turn.cancelled => (StopReason::Cancelled, None),
            Err(error) => (StopReason::Error, Some(error.text())),
        };
        self.emit(Event::TurnEnd { reason, detail });
        if let Some(next) = self.queue.pop_front() {
            self.prompt(next);
        }
    }

    /// A cancelled turn the agent has not answered within the limit (a bridge whose turn died
    /// answers nothing): it ends here as cancelled, and the agent's answer, should it still come,
    /// belongs to no turn.
    fn abandon_turn(&mut self) {
        let Some(turn) = self.turn.take() else { return };
        self.pending.remove(&turn.id);
        self.flush_user();
        for (_, asked) in self.permissions.drain() {
            self.rpc.respond(asked.rpc_id, json!({"outcome": {"outcome": "cancelled"}}));
        }
        for (_, rpc_id) in self.questions.drain() {
            self.rpc.respond(rpc_id, json!({"answer": null}));
        }
        self.notice(
            Level::Warn,
            format!(
                "{} did not confirm the stop within {} s; the turn ends here. It may still be finishing: if your next message is refused, send it again in a moment.",
                self.spec.name,
                self.cancel_limit.as_secs_f64().ceil() as u64
            ),
        );
        self.emit(Event::TurnEnd { reason: StopReason::Cancelled, detail: None });
        if let Some(next) = self.queue.pop_front() {
            self.prompt(next);
        }
    }

    fn notification(&mut self, method: &str, params: Value) {
        match method {
            "session/update" => self.update(&params["update"]),
            "_yougori/finding" => match serde_json::from_value::<Finding>(params) {
                Ok(finding) => self.emit(Event::Finding(finding)),
                Err(error) => self.notice(Level::Warn, format!("{} sent an unreadable finding: {error}", self.spec.name)),
            },
            "_yougori/report" => match serde_json::from_value::<Report>(params) {
                Ok(report) => self.emit(Event::Report(report)),
                Err(error) => self.notice(Level::Warn, format!("{} sent an unreadable report: {error}", self.spec.name)),
            },
            "_yougori/progress" => {
                if let Ok(progress) = serde_json::from_value::<Progress>(params) {
                    self.emit(Event::Progress(progress));
                }
            }
            "_yougori/usage" => {
                if let Ok(usage) = serde_json::from_value::<Usage>(params) {
                    self.emit(Event::Usage(usage));
                }
            }
            "_yougori/notice" => {
                let level = match params["level"].as_str() {
                    Some("error") => Level::Error,
                    Some("warn") | Some("warning") => Level::Warn,
                    _ => Level::Info,
                };
                if let Some(text) = params["text"].as_str() {
                    self.notice(level, text);
                }
            }
            // Anything else (an agent's own extensions) is not for this screen.
            _ => {}
        }
    }

    fn update(&mut self, update: &Value) {
        let kind = update["sessionUpdate"].as_str().unwrap_or("");
        if kind != "user_message_chunk" {
            self.flush_user();
        }
        match kind {
            "user_message_chunk" => self.user_text.push_str(&block_text(&update["content"])),
            "agent_message_chunk" | "agent_thought_chunk" => {
                let text = block_text(&update["content"]);
                if text.is_empty() {
                    return;
                }
                let thought = kind == "agent_thought_chunk";
                let message = match update["messageId"].as_str() {
                    Some(id) => {
                        self.ids.other();
                        format!("{}-{id}", if thought { "r" } else { "m" })
                    }
                    None => self.ids.next(if thought { 'r' } else { 'm' }),
                };
                let parent = parent_of(update);
                self.emit(if thought { Event::Reasoning { message, text, parent } } else { Event::Message { message, text, parent } });
            }
            "tool_call" => {
                self.ids.other();
                let id = update["toolCallId"].as_str().unwrap_or("").to_owned();
                if id.is_empty() {
                    return;
                }
                if self.tools.contains_key(&id) {
                    self.tool_update(update);
                } else {
                    self.tool_call(&id, update);
                }
            }
            "tool_call_update" => {
                self.ids.other();
                self.tool_update(update);
            }
            "plan" => {
                self.ids.other();
                self.emit(Event::Plan { entries: plan_entries(&update["entries"]) });
            }
            "plan_update" => {
                self.ids.other();
                let plan = &update["plan"];
                let entries = match plan["type"].as_str() {
                    Some("items") => plan_entries(plan.get("items").or(plan.get("entries")).unwrap_or(&Value::Null)),
                    Some("markdown") => markdown_entries(plan["markdown"].as_str().or(plan["content"].as_str()).unwrap_or("")),
                    _ => return,
                };
                self.emit(Event::Plan { entries });
            }
            "plan_removed" => self.emit(Event::Plan { entries: Vec::new() }),
            "available_commands_update" => {
                let commands = update["availableCommands"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|c| {
                        Some(SlashCommand {
                            name: c["name"].as_str()?.trim_start_matches('/').to_owned(),
                            description: c["description"].as_str().unwrap_or("").to_owned(),
                            hint: c["input"]["hint"].as_str().map(str::to_owned),
                        })
                    })
                    .collect();
                self.emit(Event::Commands { commands });
            }
            "current_mode_update" => {
                if let Some(mode) = update["currentModeId"].as_str() {
                    if self.modes.set_current(mode) {
                        if let Some(event) = self.modes.event() {
                            self.emit(event);
                        }
                    }
                }
            }
            "config_option_update" => {
                let before = self.models.current_value();
                self.models.refresh(update);
                let after = self.models.current_value();
                if after != before {
                    if let Some(model) = after.and_then(|v| self.models.model_for(&v, &self.spec.models)) {
                        if model != self.model {
                            self.model = model.clone();
                            self.emit(Event::Model { model });
                        }
                    }
                }
                if self.modes.refresh(update) {
                    if let Some(event) = self.modes.event() {
                        self.emit(event);
                    }
                }
            }
            "usage_update" => {
                self.emit(Event::Usage(Usage {
                    context_tokens: update["used"].as_u64(),
                    context_window: update["size"].as_u64(),
                    ..Default::default()
                }));
            }
            "compaction_update" => {
                let status = update["status"].as_str().unwrap_or("");
                self.emit(Event::Progress(Progress {
                    id: "compaction".into(),
                    label: "Compacting the conversation".into(),
                    finished: matches!(status, "completed" | "failed" | "cancelled" | "done"),
                    ..Default::default()
                }));
            }
            _ => {}
        }
    }

    fn flush_user(&mut self) {
        if !self.user_text.is_empty() {
            let text = std::mem::take(&mut self.user_text);
            self.emit(Event::User { text });
        }
    }

    fn tool_call(&mut self, id: &str, update: &Value) {
        let items = self.items(id, update.get("content"));
        let title = update["title"].as_str().filter(|t| !t.is_empty()).map(str::to_owned).unwrap_or_else(|| tool_title(update));
        let kind = tool_kind(update["kind"].as_str());
        let mut state = ToolState { title: title.clone(), kind, items, ..Default::default() };
        state.learn(update);
        let content = self.render(&state);
        self.tools.insert(id.to_owned(), state);
        self.emit(Event::ToolCall(ToolCall {
            id: id.to_owned(),
            title,
            kind,
            status: tool_status(update["status"].as_str()).unwrap_or(ToolStatus::Pending),
            input: update.get("rawInput").filter(|v| !v.is_null()).cloned(),
            locations: locations(&update["locations"]).unwrap_or_default(),
            content,
            parent: parent_of(update),
        }));
    }

    fn tool_update(&mut self, update: &Value) {
        let id = update["toolCallId"].as_str().unwrap_or("").to_owned();
        if id.is_empty() {
            return;
        }
        if !self.tools.contains_key(&id) {
            // Some agents send updates for calls they never announced.
            self.tool_call(&id, update);
            return;
        }
        let had_exit = self.tools.get(&id).and_then(|s| s.exit);
        if let Some(state) = self.tools.get_mut(&id) {
            if let Some(kind) = update["kind"].as_str() {
                state.kind = tool_kind(Some(kind));
            }
            state.learn(update);
        }
        let content = match update.get("content") {
            Some(Value::Array(_)) => {
                let items = self.items(&id, update.get("content"));
                let state = self.tools.entry(id.clone()).or_default();
                state.items = items;
                let state = &self.tools[&id];
                Some(self.render(state))
            }
            // An exit code learned now shows in the command's output.
            _ if had_exit.is_none() && self.tools.get(&id).map(|s| s.exit.is_some() && s.shows_terminal()).unwrap_or(false) => {
                Some(self.render(&self.tools[&id]))
            }
            _ => None,
        };
        let title = update["title"].as_str().filter(|t| !t.is_empty()).map(str::to_owned);
        if let (Some(title), Some(state)) = (&title, self.tools.get_mut(&id)) {
            state.title = title.clone();
        }
        self.emit(Event::ToolUpdate(ToolUpdate {
            id,
            status: tool_status(update["status"].as_str()),
            title,
            content,
            locations: locations(&update["locations"]),
            output: update.get("rawOutput").filter(|v| !v.is_null()).cloned(),
        }));
    }

    /// A tool call's content items, noting which terminals it shows.
    fn items(&mut self, tool: &str, content: Option<&Value>) -> Vec<Item> {
        let mut items = Vec::new();
        for entry in content.and_then(Value::as_array).into_iter().flatten() {
            match entry["type"].as_str() {
                Some("diff") => items.push(Item::Plain(ToolContent::Diff {
                    path: entry["path"].as_str().unwrap_or("").to_owned(),
                    old: entry["oldText"].as_str().map(str::to_owned),
                    new: entry["newText"].as_str().unwrap_or("").to_owned(),
                })),
                Some("terminal") => {
                    if let Some(terminal) = entry["terminalId"].as_str() {
                        self.terminals.embed(terminal, tool);
                        items.push(Item::Terminal(terminal.to_owned()));
                    }
                }
                _ => {
                    let text = block_text(&entry["content"]);
                    if !text.is_empty() {
                        items.push(Item::Plain(ToolContent::Text { text }));
                    }
                }
            }
        }
        items
    }

    fn render(&self, state: &ToolState) -> Vec<ToolContent> {
        // A command whose output came as text shows as a terminal (OpenCode, Kilo, Goose, dsh).
        if state.shows_terminal() {
            let output: Vec<&str> = state
                .items
                .iter()
                .filter_map(|item| match item {
                    Item::Plain(ToolContent::Text { text }) => Some(text.as_str()),
                    _ => None,
                })
                .collect();
            let mut output = output.join("\n");
            process::keep_tail(&mut output, 64 * 1024);
            return vec![ToolContent::Terminal { command: state.command.clone(), output, exit_code: state.exit }];
        }
        state
            .items
            .iter()
            .filter_map(|item| match item {
                Item::Plain(content) => Some(content.clone()),
                Item::Terminal(id) => self.terminals.view(id),
            })
            .collect()
    }

    fn request(&mut self, id: Value, method: &str, params: Value) {
        match method {
            "session/request_permission" => self.permission(id, params),
            "_yougori/question" => self.question(id, params),
            "fs/read_text_file" | "fs/write_text_file" => {
                let rpc = self.rpc.clone();
                let write = method == "fs/write_text_file";
                tokio::task::spawn_blocking(move || {
                    let answer = if write { write_text_file(&params) } else { read_text_file(&params) };
                    answer_with(&rpc, id, answer);
                });
            }
            "terminal/create" => {
                let env = self.spec.environment();
                let created = self.terminals.create(&params, &env, &self.spec.cwd).map(|terminal| json!({"terminalId": terminal}));
                answer_with(&self.rpc, id, created);
            }
            "terminal/output" => {
                let output = self.terminals.output(params["terminalId"].as_str().unwrap_or(""));
                answer_with(&self.rpc, id, output);
            }
            "terminal/wait_for_exit" => {
                let terminal = params["terminalId"].as_str().unwrap_or("").to_owned();
                match self.terminals.wait(&terminal, id.clone()) {
                    Ok(Some(result)) => answer_with(&self.rpc, id, Ok(result)),
                    Ok(None) => {}
                    Err(error) => answer_with(&self.rpc, id, Err(error)),
                }
            }
            "terminal/kill" => {
                let killed = self.terminals.kill(params["terminalId"].as_str().unwrap_or("")).map(|()| json!({}));
                answer_with(&self.rpc, id, killed);
            }
            "terminal/release" => {
                let terminal = params["terminalId"].as_str().unwrap_or("").to_owned();
                for (waiter, result) in self.terminals.release(&terminal) {
                    self.rpc.respond(waiter, result);
                }
                self.rpc.respond(id, json!({}));
            }
            _ => {
                self.rpc.fail(id, RpcError::new(rpc::METHOD_NOT_FOUND, format!("Method not found: {method}")));
            }
        }
    }

    fn permission(&mut self, id: Value, params: Value) {
        let options: Vec<PermissionOption> = params["options"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|o| {
                let id = o["optionId"].as_str()?;
                Some(PermissionOption {
                    id: id.to_owned(),
                    label: o["name"].as_str().unwrap_or(id).to_owned(),
                    kind: match o["kind"].as_str() {
                        Some("allow_always") => PermissionKind::AllowAlways,
                        Some("reject_once") => PermissionKind::RejectOnce,
                        Some("reject_always") => PermissionKind::RejectAlways,
                        _ => PermissionKind::AllowOnce,
                    },
                })
            })
            .collect();
        let cancelled = self.turn.as_ref().map(|t| t.cancelled).unwrap_or(false);
        if options.is_empty() || cancelled {
            self.rpc.respond(id, json!({"outcome": {"outcome": "cancelled"}}));
            return;
        }
        let tool = &params["toolCall"];
        let tool_id = tool["toolCallId"].as_str().filter(|t| !t.is_empty()).map(str::to_owned);
        let mut title = tool["title"].as_str().filter(|t| !t.is_empty()).map(str::to_owned);
        if let Some(tool_id) = &tool_id {
            // Make sure the screen shows what is asked about.
            if !self.tools.contains_key(tool_id) {
                self.tool_call(tool_id, tool);
            } else if tool.get("content").is_some() || tool.get("title").is_some() {
                self.tool_update(tool);
            }
        }
        if title.is_none() {
            title = tool_id.as_ref().and_then(|t| self.tools.get(t)).map(|state| state.title.clone()).filter(|t| !t.is_empty());
        }
        if title.is_none() {
            title = Some(tool_title(tool));
        }
        let our_id = format!("acp-{}", id_text(&id));
        self.permissions.insert(our_id.clone(), AskedPermission { rpc_id: id, options: options.iter().map(|o| o.id.clone()).collect() });
        self.emit(Event::Permission(PermissionRequest {
            id: our_id,
            tool_call: tool_id,
            title: title.unwrap_or_else(|| "Allow this action?".into()),
            detail: input_summary(tool.get("rawInput")),
            options,
        }));
    }

    fn question(&mut self, id: Value, params: Value) {
        let cancelled = self.turn.as_ref().map(|t| t.cancelled).unwrap_or(false);
        let Some(question) = params["question"].as_str().filter(|q| !q.trim().is_empty()) else {
            self.rpc.fail(id, RpcError::new(rpc::INVALID_PARAMS, "A question needs its text."));
            return;
        };
        if cancelled {
            self.rpc.respond(id, json!({"answer": null}));
            return;
        }
        let our_id = format!("acp-q-{}", id_text(&id));
        let request = QuestionRequest {
            id: our_id.clone(),
            question: question.to_owned(),
            choices: params["choices"].as_array().into_iter().flatten().filter_map(|c| c.as_str().map(str::to_owned)).collect(),
            multiple: params["multiple"].as_bool().unwrap_or(false),
            allow_text: params["allow_text"].as_bool().unwrap_or(false),
        };
        self.questions.insert(our_id, id);
        self.emit(Event::Question(request));
    }

    fn terminal_event(&mut self, event: TermEvent) {
        match event {
            TermEvent::Output(id) => self.terminals.mark(&id),
            TermEvent::Exited(id, status) => {
                for (waiter, result) in self.terminals.exited(&id, status) {
                    self.rpc.respond(waiter, result);
                }
                self.terminals.mark(&id);
            }
        }
    }

    fn flush_terminals(&mut self) {
        for tool in self.terminals.take_dirty_tools() {
            if let Some(state) = self.tools.get(&tool) {
                let content = self.render(state);
                self.emit(Event::ToolUpdate(ToolUpdate { id: tool, content: Some(content), ..Default::default() }));
            }
        }
    }

    /// The agent's output ended: it stopped on its own or crashed.
    async fn ended(&mut self) {
        self.terminals.kill_all();
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
        // None (ended by a signal, or no process of ours) shows as a failure.
        self.emit(Event::Exit { code, message });
    }

    async fn shutdown(&mut self) {
        self.terminals.kill_all();
        stop(self.guard.as_ref(), &self.writer).await;
        self.emit(Event::Exit { code: Some(0), message: String::new() });
    }
}

fn answer_with(rpc: &Rpc, id: Value, answer: Result<Value, RpcError>) {
    match answer {
        Ok(result) => rpc.respond(id, result),
        Err(error) => rpc.fail(id, error),
    };
}

/// The text of a content block.
pub(crate) fn block_text(block: &Value) -> String {
    match block["type"].as_str() {
        Some("text") => block["text"].as_str().unwrap_or("").to_owned(),
        Some("resource_link") => {
            let name = block["title"].as_str().or(block["name"].as_str()).unwrap_or("");
            let uri = block["uri"].as_str().unwrap_or("");
            if name.is_empty() {
                uri.to_owned()
            } else {
                format!("{name} ({uri})")
            }
        }
        Some("resource") => {
            let resource = &block["resource"];
            match resource["text"].as_str() {
                Some(text) => text.to_owned(),
                None => format!("[{}]", resource["uri"].as_str().unwrap_or("resource")),
            }
        }
        Some("image") => "[image]".to_owned(),
        Some("audio") => "[audio]".to_owned(),
        _ => block.as_str().unwrap_or("").to_owned(),
    }
}

fn tool_kind(kind: Option<&str>) -> ToolKind {
    match kind {
        Some("read") => ToolKind::Read,
        Some("edit") => ToolKind::Edit,
        Some("delete") => ToolKind::Delete,
        Some("move") => ToolKind::Move,
        Some("search") => ToolKind::Search,
        Some("execute") => ToolKind::Execute,
        Some("think") => ToolKind::Think,
        Some("fetch") => ToolKind::Fetch,
        Some("switch_mode") => ToolKind::SwitchMode,
        Some("task") => ToolKind::Task,
        _ => ToolKind::Other,
    }
}

fn tool_status(status: Option<&str>) -> Option<ToolStatus> {
    match status? {
        "pending" => Some(ToolStatus::Pending),
        "in_progress" => Some(ToolStatus::InProgress),
        "completed" => Some(ToolStatus::Completed),
        "failed" => Some(ToolStatus::Failed),
        _ => None,
    }
}

fn locations(value: &Value) -> Option<Vec<Location>> {
    let list = value.as_array()?;
    Some(
        list.iter()
            .filter_map(|l| {
                Some(Location { path: l["path"].as_str()?.to_owned(), line: l["line"].as_u64().map(|n| n.min(u32::MAX as u64) as u32) })
            })
            .collect(),
    )
}

/// The subagent call an update belongs to, when our bridges say so.
fn parent_of(update: &Value) -> Option<String> {
    update["_meta"]["yougori"]["parent"].as_str().map(str::to_owned)
}

/// A title for a call that came without one.
fn tool_title(update: &Value) -> String {
    if let Some(summary) = input_summary(update.get("rawInput")) {
        if summary.len() <= 120 {
            return summary;
        }
    }
    update["name"].as_str().or(update["kind"].as_str()).unwrap_or("Tool").to_owned()
}

/// One line about what a tool is given: its command, else its path, else its arguments.
pub(crate) fn input_summary(input: Option<&Value>) -> Option<String> {
    let input = input.filter(|v| !v.is_null())?;
    let object = input.as_object()?;
    for key in ["command", "cmd"] {
        match object.get(key) {
            Some(Value::String(text)) if !text.is_empty() => return Some(text.clone()),
            Some(Value::Array(parts)) if !parts.is_empty() => {
                return Some(parts.iter().map(|p| p.as_str().map(str::to_owned).unwrap_or_else(|| p.to_string())).collect::<Vec<_>>().join(" "))
            }
            _ => {}
        }
    }
    for key in ["path", "file_path", "filePath", "file", "url", "pattern", "query"] {
        if let Some(Value::String(text)) = object.get(key) {
            if !text.is_empty() {
                return Some(text.clone());
            }
        }
    }
    if object.is_empty() {
        return None;
    }
    let mut text = input.to_string();
    if text.chars().count() > 400 {
        text = text.chars().take(400).chain("…".chars()).collect();
    }
    Some(text)
}

fn plan_entries(entries: &Value) -> Vec<PlanEntry> {
    entries
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|e| {
            Some(PlanEntry {
                content: e["content"].as_str()?.to_owned(),
                status: match e["status"].as_str() {
                    Some("in_progress") => PlanStatus::InProgress,
                    Some("completed") => PlanStatus::Completed,
                    _ => PlanStatus::Pending,
                },
                priority: match e["priority"].as_str() {
                    Some("high") => Some(Priority::High),
                    Some("medium") => Some(Priority::Medium),
                    Some("low") => Some(Priority::Low),
                    _ => None,
                },
            })
        })
        .collect()
}

/// A Markdown plan as entries: its list items, ticked ones completed.
fn markdown_entries(markdown: &str) -> Vec<PlanEntry> {
    markdown
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let item = line.strip_prefix("- ").or_else(|| line.strip_prefix("* "))?;
            let (status, content) = if let Some(rest) = item.strip_prefix("[x] ").or_else(|| item.strip_prefix("[X] ")) {
                (PlanStatus::Completed, rest)
            } else if let Some(rest) = item.strip_prefix("[ ] ") {
                (PlanStatus::Pending, rest)
            } else if let Some(rest) = item.strip_prefix("[-] ").or_else(|| item.strip_prefix("[~] ")) {
                (PlanStatus::InProgress, rest)
            } else {
                (PlanStatus::Pending, item)
            };
            Some(PlanEntry { content: content.to_owned(), status, priority: None })
        })
        .collect()
}

fn id_text(id: &Value) -> String {
    match id {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// `fs/read_text_file`: a whole file, or `limit` lines from line `line` (1-based).
fn read_text_file(params: &Value) -> Result<Value, RpcError> {
    let path = absolute(params)?;
    let size = std::fs::metadata(&path).map_err(|e| io_error(&path, e))?.len();
    if size > READ_LIMIT {
        return Err(RpcError::new(rpc::INVALID_PARAMS, format!("{} is too large to read ({size} bytes).", path.display())));
    }
    let bytes = std::fs::read(&path).map_err(|e| io_error(&path, e))?;
    let text = String::from_utf8_lossy(&bytes);
    let line = params["line"].as_u64().unwrap_or(1).max(1) as usize;
    let limit = params["limit"].as_u64().map(|l| l as usize);
    if line == 1 && limit.is_none() {
        return Ok(json!({"content": text}));
    }
    let content: String = text.split_inclusive('\n').skip(line - 1).take(limit.unwrap_or(usize::MAX)).collect();
    Ok(json!({"content": content}))
}

/// `fs/write_text_file`: the whole file, its folders created as needed.
fn write_text_file(params: &Value) -> Result<Value, RpcError> {
    let path = absolute(params)?;
    let content = params["content"]
        .as_str()
        .ok_or_else(|| RpcError::new(rpc::INVALID_PARAMS, "fs/write_text_file needs content."))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| io_error(parent, e))?;
    }
    std::fs::write(&path, content).map_err(|e| io_error(&path, e))?;
    Ok(json!({}))
}

fn absolute(params: &Value) -> Result<std::path::PathBuf, RpcError> {
    let path = params["path"].as_str().ok_or_else(|| RpcError::new(rpc::INVALID_PARAMS, "A path is needed."))?;
    let path = std::path::PathBuf::from(path);
    if !path.is_absolute() {
        return Err(RpcError::new(rpc::INVALID_PARAMS, format!("{} is not an absolute path.", path.display())));
    }
    Ok(path)
}

fn io_error(path: &std::path::Path, error: std::io::Error) -> RpcError {
    let code = if error.kind() == std::io::ErrorKind::NotFound { rpc::RESOURCE_NOT_FOUND } else { rpc::INTERNAL_ERROR };
    RpcError::new(code, format!("{}: {error}", path.display()))
}
