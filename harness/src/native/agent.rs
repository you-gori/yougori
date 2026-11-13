//! The agent loop: one model call per step, and the tools the model asks for run between steps,
//! until it answers without tools, reaches its step limit (then one closing reply without tools)
//! or the person stops it. The same loop runs the task tool's helpers, one level deep, with
//! their events carrying the task call's id as `parent`.
//!
//! Every tool call is checked before it runs: a malformed call (bad JSON, unknown tool) goes
//! back to the model as an error; the same call three times in a row asks the person whether to
//! go on; permission rules allow, deny or ask the person.
use super::cancel::Cancel;
use super::compaction::{self, Plan, Why};
use super::conversation::{estimate, Call, Conversation, Msg, Role, Shown};
use super::events::{Broker, Events, Stopped};
use super::llm::{CallError, Llm, Piece, Reply, Request};
use super::mcp::Mcp;
use super::permissions::{judge, Action, Rule, Subject, Vars};
use super::profiles::{Kind, Profile, Profiles};
use super::prompt;
use super::store::{self, Store};
use super::tools::{self, task::Task, Limits, Output, Tool, ToolCtx};
use super::util;
use crate::protocol::{
    Event, Location, PermissionKind, PermissionOption, PermissionRequest, PlanEntry, ToolCall, ToolContent, ToolKind,
    ToolStatus, ToolUpdate, Usage,
};
use crate::spec::EngineSpec;
use futures::future::BoxFuture;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

pub fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// The files an agent read, by the agent (None for the main agent, a helper's task call id) and
/// the file's real path: when each was last changed as the agent read it.
pub type ReadFiles = HashMap<(Option<String>, PathBuf), Option<SystemTime>>;

/// What every turn shares: the spec, the relay client, the screen, the person's answers.
pub struct Shared {
    pub spec: EngineSpec,
    /// The working folder.
    pub cwd: PathBuf,
    pub home: Option<PathBuf>,
    pub vars: Vars,
    pub llm: Llm,
    pub events: Events,
    pub broker: Broker,
    pub profiles: Profiles,
    /// Rules the person added this session with "always".
    pub rules: Mutex<Vec<Rule>>,
    pub model: Mutex<String>,
    /// The primary profile the person works in.
    pub mode: Mutex<String>,
    /// Server tokens per estimated token, once a reply reported its usage.
    pub ratio: Mutex<Option<f64>>,
    /// The environment commands run with.
    pub env: BTreeMap<String, String>,
    /// For webfetch and MCP over HTTP; None when the sandbox reaches only the inference.
    pub web: Option<reqwest::Client>,
    pub limits: Limits,
    /// Files each agent has read this session, and when they were last changed then.
    pub files: Mutex<ReadFiles>,
    pub todos: Mutex<Vec<PlanEntry>>,
    /// Ids handed out this run, so none repeats.
    ids: Mutex<HashSet<String>>,
}

/// The environment commands get: the spec's (or this process's without its secrets when the
/// spec gives none), the secret answers mapped in, and no pagers or prompts that would wait.
pub fn environment(spec: &EngineSpec) -> BTreeMap<String, String> {
    let mut env: BTreeMap<String, String> = if spec.env.is_empty() {
        std::env::vars().filter(|(name, _)| !name.starts_with("YOUGORI_SECRET_")).collect()
    } else {
        spec.env.clone()
    };
    for (name, id) in &spec.secret_env {
        if let Some(value) = crate::spec::secret(id) {
            env.insert(name.clone(), value);
        }
    }
    for (name, value) in [("GIT_PAGER", "cat"), ("PAGER", "cat"), ("GIT_TERMINAL_PROMPT", "0")] {
        env.entry(name.into()).or_insert_with(|| value.into());
    }
    // Git uses a bare repository only when told to (--git-dir), never one it comes upon: the
    // model may write the files that make a project folder look like one, settings that run
    // programs included (core.fsmonitor, textconv), and its git commands count as reading.
    let count = env.get("GIT_CONFIG_COUNT").and_then(|n| n.trim().parse::<usize>().ok()).unwrap_or(0);
    env.insert(format!("GIT_CONFIG_KEY_{count}"), "safe.bareRepository".into());
    env.insert(format!("GIT_CONFIG_VALUE_{count}"), "explicit".into());
    env.insert("GIT_CONFIG_COUNT".into(), (count + 1).to_string());
    // cmd.exe would otherwise run a git.bat (or any program) lying in the working folder before
    // the real one on PATH.
    if cfg!(windows) {
        env.retain(|name, _| !name.eq_ignore_ascii_case("NoDefaultCurrentDirectoryInExePath"));
        env.insert("NoDefaultCurrentDirectoryInExePath".into(), "1".into());
    }
    env
}

impl Shared {
    /// Everything a run needs from the spec; problems with profile files come back as warnings.
    pub fn new(spec: &EngineSpec, events: Events, mode: &str) -> anyhow::Result<(Shared, Vec<String>)> {
        let (profiles, warnings) = Profiles::load(&spec.state_dir.join("profiles"));
        profiles.mode(mode).map_err(|e| anyhow::anyhow!(e))?;
        let llm = Llm::new(&spec.base_url, &spec.api_key)?;
        let env = environment(spec);
        let mut warnings = warnings;
        let web = if spec.reach.web() {
            match tools::web::client(&env) {
                Ok(client) => Some(client),
                Err(e) => {
                    warnings.push(format!("Web pages cannot be fetched: {e}"));
                    None
                }
            }
        } else {
            None
        };
        let home = prompt::home();
        let vars = Vars {
            cwd: tools::slash(&tools::real(&spec.cwd)),
            state: tools::slash(&tools::real(&spec.state_dir)),
            home: home.as_deref().map(|h| tools::slash(&tools::real(h))).unwrap_or_default(),
        };
        Ok((
            Shared {
                cwd: spec.cwd.clone(),
                home,
                vars,
                llm,
                events,
                broker: Broker::default(),
                profiles,
                rules: Mutex::new(Vec::new()),
                model: Mutex::new(spec.model.clone()),
                mode: Mutex::new(mode.to_owned()),
                ratio: Mutex::new(None),
                env,
                web,
                limits: Limits::for_window(spec.context_window, spec.max_output),
                files: Mutex::new(HashMap::new()),
                todos: Mutex::new(Vec::new()),
                ids: Mutex::new(HashSet::new()),
                spec: spec.clone(),
            },
            warnings,
        ))
    }

    pub fn model(&self) -> String {
        lock(&self.model).clone()
    }

    pub fn mode(&self) -> String {
        lock(&self.mode).clone()
    }

    pub fn ratio(&self) -> f64 {
        lock(&self.ratio).unwrap_or(1.0)
    }

    pub fn rules(&self) -> Vec<Rule> {
        lock(&self.rules).clone()
    }

    /// Records an id as used; false when it was used before.
    pub fn claim(&self, id: &str) -> bool {
        lock(&self.ids).insert(id.to_owned())
    }

    /// A fresh id from `make` that was not handed out before.
    pub fn fresh(&self, make: impl Fn() -> String) -> String {
        loop {
            let id = make();
            if self.claim(&id) {
                return id;
            }
        }
    }

    fn calibrate(&self, estimated: usize, reported: u64) {
        if estimated < 200 || reported == 0 {
            return;
        }
        let seen = (reported as f64 / estimated as f64).clamp(0.4, 3.0);
        let mut ratio = lock(&self.ratio);
        *ratio = Some(match *ratio {
            Some(before) => before * 0.5 + seen * 0.5,
            None => seen,
        });
    }
}

/// One prompt's run: what it shares, its stop token and the MCP servers.
pub struct Turn {
    pub shared: Arc<Shared>,
    pub cancel: Cancel,
    pub mcp: Arc<Mcp>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Done,
    MaxSteps(u32),
    MaxTokens,
    /// Stopped by the person, with why when it was not their Esc.
    Cancelled(Option<String>),
    Failed(String),
}

/// Where the main agent's messages are stored.
pub struct Persist {
    pub store: Arc<Store>,
    pub session: String,
    warned: AtomicBool,
}

impl Persist {
    pub fn new(store: Arc<Store>, session: String) -> Persist {
        Persist { store, session, warned: AtomicBool::new(false) }
    }

    pub async fn row(&self, events: &Events, seq: i64, kind: &'static str, data: String) {
        let session = self.session.clone();
        let result = store::with(&self.store, move |s| s.append(&session, seq, kind, &data)).await;
        self.report(events, result);
    }

    pub async fn trim(&self, events: &Events, trim_before: i64) {
        let session = self.session.clone();
        let result = store::with(&self.store, move |s| s.set_trim(&session, trim_before)).await;
        self.report(events, result);
    }

    fn report(&self, events: &Events, result: Result<(), String>) {
        if let Err(error) = result {
            if !self.warned.swap(true, Ordering::SeqCst) {
                events.notice(crate::protocol::Level::Warn, format!("This session is not being saved: {error}"));
            }
        }
    }
}

/// Tool names small models use for ours.
const ALIASES: &[(&str, &str)] = &[
    ("read_file", "read"),
    ("view", "read"),
    ("cat", "read"),
    ("open", "read"),
    ("write_file", "write"),
    ("create_file", "write"),
    ("edit_file", "edit"),
    ("str_replace", "edit"),
    ("replace", "edit"),
    ("shell", "bash"),
    ("run", "bash"),
    ("execute", "bash"),
    ("run_command", "bash"),
    ("terminal", "bash"),
    ("find", "glob"),
    ("search", "grep"),
    ("ls", "list"),
    ("list_dir", "list"),
    ("list_directory", "list"),
    ("fetch", "webfetch"),
    ("todo", "todowrite"),
    ("todo_write", "todowrite"),
    ("ask", "question"),
];

const ALLOW_ONCE: &str = "allow_once";
const ALLOW_ALWAYS: &str = "allow_always";
const REJECT_ONCE: &str = "reject_once";
const REJECT_ALWAYS: &str = "reject_always";
const REJECTED: &str = "The person rejected this call. Do not make it again; go on another way, or ask them what they want.";
const REPEATED: &str = "Note: this is the third identical call in a row. If it does not get you what you need, change the approach instead of repeating it.";
const STOPPED: &str = "Not run: the person stopped the turn.";
const KEPT_REPEATING: &str = "Stopped because the model kept making the same call.";

#[derive(Default)]
struct Repeat {
    last: String,
    count: u32,
    quiet: bool,
}

enum Stop {
    Cancelled,
    Repeating,
}

enum Permit {
    Yes,
    No(String),
    Stopped,
}

/// A model reply and the screen ids it got.
struct Called {
    reply: Reply,
    /// Calls announced while the reply streamed: their place in the stream and screen id.
    announced: Vec<(usize, String)>,
    message: String,
}

pub struct Agent<'t> {
    turn: &'t Turn,
    pub profile: Arc<Profile>,
    parent: Option<String>,
    system: String,
    tools: Vec<Arc<dyn Tool>>,
    definitions: Vec<Value>,
    /// Worked on where it lives (the session's), never moved out, so whatever happens to the
    /// turn, even a panic, the session keeps every message added so far.
    pub conv: &'t mut Conversation,
    persist: Option<Persist>,
    repeat: Repeat,
}

/// The tools a profile offers: the built-in ones it names, its task tool, and MCP tools.
/// Helpers get no task tool (one level only) and no to-do list (the person's plan is the main
/// agent's).
fn tools_for(turn: &Turn, profile: &Profile, helper: bool) -> Vec<Arc<dyn Tool>> {
    let shared = &turn.shared;
    let mut all = tools::builtin(shared.web.is_some());
    if helper {
        all.retain(|tool| tool.name() != "todowrite");
    } else {
        let agents: Vec<(String, String)> = profile
            .subagents
            .iter()
            .filter_map(|name| shared.profiles.get(name))
            .filter(|p| p.mode == Kind::Subagent)
            .map(|p| (p.name.clone(), p.description.clone()))
            .collect();
        if !agents.is_empty() {
            all.push(Arc::new(Task { agents }));
        }
    }
    all.extend(turn.mcp.tools());
    all.into_iter().filter(|tool| profile.offers(tool.name())).collect()
}

impl<'t> Agent<'t> {
    pub fn new(turn: &'t Turn, profile: Profile, parent: Option<String>, conv: &'t mut Conversation, persist: Option<Persist>) -> Agent<'t> {
        let tools = tools_for(turn, &profile, parent.is_some());
        let definitions = tools.iter().map(|tool| tools::definition(tool.as_ref())).collect();
        let model = turn.shared.model();
        let mcp = turn.mcp.instructions();
        let setting = prompt::Setting { cwd: &turn.shared.cwd, model: &model, mcp: &mcp, home: turn.shared.home.as_deref() };
        let system = prompt::system(&profile, &setting);
        Agent { turn, profile: Arc::new(profile), parent, system, tools, definitions, conv, persist, repeat: Repeat::default() }
    }

    pub fn tool_names(&self) -> Vec<String> {
        self.tools.iter().map(|t| t.name().to_owned()).collect()
    }

    fn emit(&self, event: Event) {
        self.turn.shared.events.send(event);
    }

    /// Adds a message to the conversation (and the session store).
    pub async fn push(&mut self, msg: Msg) -> i64 {
        let data = self.persist.as_ref().map(|_| serde_json::to_string(&msg).unwrap_or_default());
        let seq = self.conv.push(msg);
        if let (Some(persist), Some(data)) = (&self.persist, data) {
            persist.row(&self.turn.shared.events, seq, store::MESSAGE, data).await;
        }
        seq
    }

    /// A note for the model at the end of the newest message.
    fn note(&mut self, text: &str) {
        if let Some(entry) = self.conv.entries.last_mut() {
            if !entry.msg.text.is_empty() {
                entry.msg.text.push_str("\n\n");
            }
            entry.msg.text.push_str(text);
        }
    }

    /// The text of the newest reply (a helper's report).
    pub fn last_reply(&self) -> String {
        self.conv
            .entries
            .iter()
            .rev()
            .find(|e| e.msg.role == Role::Assistant && !e.msg.text.trim().is_empty())
            .map(|e| e.msg.text.trim().to_owned())
            .unwrap_or_default()
    }

    pub async fn run(&mut self) -> Outcome {
        match self.steps().await {
            // Stopped by a helper's "Stop the turn", not by the person's Esc: say so.
            Outcome::Cancelled(None) => Outcome::Cancelled(self.turn.cancel.why()),
            outcome => outcome,
        }
    }

    async fn steps(&mut self) -> Outcome {
        let limit = self.profile.steps.max(1);
        let mut steps = 0u32;
        let mut nudged = false;
        loop {
            if self.turn.cancel.is_cancelled() {
                return Outcome::Cancelled(None);
            }
            let closing = steps >= limit;
            if closing {
                self.note(&format!(
                    "You have used all {limit} steps for this request, so no more tools can run now. Reply to the person: \
                     what you did, what is left, and how to go on."
                ));
            }
            let Called { reply, announced, message } = match self.call(closing).await {
                Ok(called) => called,
                Err(outcome) => return outcome,
            };
            steps += 1;
            if closing {
                self.close_announced(&announced, &[], "Not run: the step limit was reached.");
                self.push(Msg::assistant(&message, reply.text.clone(), reply.reasoning.clone(), Vec::new())).await;
                return Outcome::MaxSteps(limit);
            }
            if reply.calls.is_empty() {
                let after_tool = self.conv.entries.last().is_some_and(|e| e.msg.role == Role::Tool);
                if reply.text.is_empty() && after_tool && !nudged && !reply.cut_off() {
                    // Small models sometimes answer a tool result with nothing at all.
                    nudged = true;
                    self.note("Go on: make the next tool call, or reply to the person if the work is done.");
                    continue;
                }
                self.push(Msg::assistant(&message, reply.text.clone(), reply.reasoning.clone(), Vec::new())).await;
                return if reply.cut_off() { Outcome::MaxTokens } else { Outcome::Done };
            }
            let calls = self.name_calls(&reply, &announced);
            self.close_announced(&announced, &calls, "Not run.");
            self.push(Msg::assistant(&message, reply.text.clone(), reply.reasoning.clone(), calls.clone())).await;
            let cut_off = reply.cut_off();
            for (index, call) in calls.iter().enumerate() {
                let announced_call = announced.iter().any(|(_, id)| *id == call.event);
                let (result, stop) = self.run_call(call, cut_off, announced_call).await;
                self.push(result).await;
                if let Some(stop) = stop {
                    for rest in &calls[index + 1..] {
                        let shown_before = announced.iter().any(|(_, id)| *id == rest.event);
                        let result = self.fail(rest, shown_before, &rest.name, ToolKind::Other, STOPPED.into());
                        self.push(result).await;
                    }
                    return match stop {
                        Stop::Cancelled => Outcome::Cancelled(None),
                        Stop::Repeating => Outcome::Cancelled(Some(KEPT_REPEATING.into())),
                    };
                }
            }
        }
    }

    /// Ids for the reply's calls: the model's own when usable, ours otherwise.
    fn name_calls(&self, reply: &Reply, announced: &[(usize, String)]) -> Vec<Call> {
        let shared = &self.turn.shared;
        reply
            .calls
            .iter()
            .map(|raw| {
                let event = announced
                    .iter()
                    .find(|(index, _)| *index == raw.index)
                    .map(|(_, id)| id.clone())
                    .unwrap_or_else(|| shared.fresh(|| util::new_id("t")));
                let id = if !raw.id.trim().is_empty() && shared.claim(&raw.id) { raw.id.clone() } else { shared.fresh(util::call_id) };
                Call { id, event, name: raw.name.trim().to_owned(), arguments: raw.arguments.clone() }
            })
            .collect()
    }

    /// Calls the screen saw announced that will not run end as failed.
    fn close_announced(&self, announced: &[(usize, String)], calls: &[Call], why: &str) {
        for (_, id) in announced {
            if !calls.iter().any(|c| c.event == *id) {
                self.emit(Event::ToolUpdate(ToolUpdate {
                    id: id.clone(),
                    status: Some(ToolStatus::Failed),
                    content: Some(vec![ToolContent::Text { text: why.to_owned() }]),
                    ..ToolUpdate::default()
                }));
            }
        }
    }

    /// The token budget and what the system prompt and tools take of it.
    fn room(&self) -> (usize, usize) {
        let spec = &self.turn.shared.spec;
        let budget = compaction::budget(spec.context_window as usize, spec.max_output as usize);
        let fixed = estimate(&[json!({ "role": "system", "content": self.system })], &self.definitions);
        (budget, (fixed as f64 * self.turn.shared.ratio()).ceil() as usize)
    }

    /// Tokens the next request takes, calibrated.
    fn need(&self) -> usize {
        let raw = estimate(&self.conv.wire(&self.system), &self.definitions);
        (raw as f64 * self.turn.shared.ratio()).ceil() as usize
    }

    /// Compacts the conversation; true when something changed.
    pub async fn compact(&mut self, why: Why) -> Result<bool, Outcome> {
        let shared = self.turn.shared.clone();
        let (budget, fixed) = self.room();
        let plan = Plan {
            budget,
            fixed,
            ratio: shared.ratio(),
            window: shared.spec.context_window as usize,
            max_output: shared.spec.max_output as usize,
            why,
        };
        let model = shared.model();
        let trim_before = self.conv.trim_before;
        let events = self.parent.is_none().then_some(&shared.events);
        let result = compaction::compact(self.conv, &plan, &shared.llm, &model, &self.turn.cancel, events).await;
        let done = match result {
            Ok(done) => done,
            Err(compaction::Failure::Stopped) => return Err(Outcome::Cancelled(None)),
            Err(compaction::Failure::Failed(message)) => return Err(Outcome::Failed(message)),
        };
        if let Some(persist) = &self.persist {
            if self.conv.trim_before != trim_before {
                persist.trim(&shared.events, self.conv.trim_before).await;
            }
            if let Some((head, keep_from)) = &done.summary {
                let seq = self.conv.next_seq;
                self.conv.next_seq += 1;
                let data = json!({ "head": head, "keep_from": keep_from, "request": self.conv.request }).to_string();
                persist.row(&shared.events, seq, store::SUMMARY, data).await;
            }
        }
        if let Some(reason) = &done.fallback {
            shared.events.notice(
                crate::protocol::Level::Warn,
                format!("The model could not summarise older messages ({reason}); they were set aside with a short note."),
            );
        } else if done.summary.is_some() && why != Why::Asked && self.parent.is_none() {
            shared.events.notice(
                crate::protocol::Level::Info,
                format!("Older messages were summarised to stay within the {}K context.", shared.spec.context_window / 1024),
            );
        }
        if self.parent.is_none() {
            self.usage(None);
        }
        Ok(done.summary.is_some() || done.trimmed)
    }

    /// The Usage event: what the server reported, or the estimate.
    fn usage(&self, reported: Option<(u64, u64)>) {
        let spec = &self.turn.shared.spec;
        let (context, input, output) = match reported {
            Some((prompt, completion)) => (prompt + completion, Some(prompt), Some(completion)),
            None => (self.need() as u64, None, None),
        };
        self.emit(Event::Usage(Usage {
            context_tokens: Some(context),
            context_window: Some(spec.context_window as u64),
            input_tokens: input,
            output_tokens: output,
        }));
    }

    /// One model call, compacting first when the request would not fit.
    async fn call(&mut self, closing: bool) -> Result<Called, Outcome> {
        let mut overflowed = false;
        loop {
            let (budget, _) = self.room();
            if self.need() > budget {
                self.compact(Why::Auto).await?;
            }
            let shared = self.turn.shared.clone();
            let messages = self.conv.wire(&self.system);
            let estimated = estimate(&messages, &self.definitions);
            let model = shared.model();
            let request = Request {
                model: &model,
                messages: &messages,
                tools: &self.definitions,
                no_tools: closing,
                max_tokens: shared.spec.max_output,
                temperature: self.profile.temperature,
                top_p: self.profile.top_p,
            };
            let suffix = util::new_id("m");
            // The screen's id for the reply's text; a new one once a lone `</think>` showed the
            // text before it was reasoning, so the answer does not run on from it.
            let mut message = suffix.clone();
            let reasoning = format!("r{}", &suffix[1..]);
            let parent = self.parent.clone();
            let mut announced: Vec<(usize, String)> = Vec::new();
            let kinds: HashMap<String, ToolKind> = self.tools.iter().map(|t| (t.name().to_owned(), t.kind())).collect();
            let events = shared.events.clone();
            let ids = shared.clone();
            let mut on = |piece: Piece| match piece {
                Piece::Text(text) => events.send(Event::Message { message: message.clone(), text, parent: parent.clone() }),
                Piece::Reasoning(text) => events.send(Event::Reasoning { message: reasoning.clone(), text, parent: parent.clone() }),
                Piece::ToolStart { index, name } => {
                    let id = ids.fresh(|| util::new_id("t"));
                    events.send(Event::ToolCall(ToolCall {
                        id: id.clone(),
                        title: name.clone(),
                        kind: kinds.get(&name).copied().unwrap_or_default(),
                        status: ToolStatus::Pending,
                        parent: parent.clone(),
                        ..ToolCall::default()
                    }));
                    announced.push((index, id));
                }
                Piece::Wait(text) => events.notice(crate::protocol::Level::Warn, text),
                Piece::Rethink => message = ids.fresh(|| util::new_id("m")),
            };
            let result = shared.llm.chat(&request, &self.turn.cancel, &mut on).await;
            match result {
                Ok(reply) => {
                    if let Some(usage) = reply.usage {
                        shared.calibrate(estimated, usage.prompt);
                    }
                    if self.parent.is_none() {
                        self.usage(reply.usage.map(|u| (u.prompt, u.completion)));
                    }
                    return Ok(Called { reply, announced, message });
                }
                Err(CallError::Overflow(_)) if !overflowed => {
                    overflowed = true;
                    self.close_announced(&announced, &[], "Not run.");
                    // The server counts more than the estimate (or its window is smaller than the
                    // spec says): count this request as over the budget from now on, so the
                    // compaction below and later ones go far enough.
                    shared.calibrate(estimated, (budget as f64 * 1.15) as u64);
                    self.compact(Why::Overflow).await?;
                }
                Err(CallError::Overflow(message)) => {
                    return Err(Outcome::Failed(format!(
                        "The conversation does not fit the model's context window even after compacting it. {message}"
                    )))
                }
                Err(CallError::Cancelled(partial)) => {
                    self.close_announced(&announced, &[], "Stopped.");
                    self.keep_partial(&message, partial).await;
                    return Err(Outcome::Cancelled(None));
                }
                Err(CallError::Failed { message: why, partial }) => {
                    self.close_announced(&announced, &[], "The reply broke off.");
                    self.keep_partial(&message, partial).await;
                    return Err(Outcome::Failed(why));
                }
            }
        }
    }

    /// What the person saw of a reply that broke off stays in the conversation.
    async fn keep_partial(&mut self, id: &str, partial: Reply) {
        if !partial.text.is_empty() {
            self.push(Msg::assistant(id, partial.text, partial.reasoning, Vec::new())).await;
        }
    }

    fn lookup(&self, name: &str) -> Option<Arc<dyn Tool>> {
        let name = name.trim();
        let name = name.strip_prefix("functions.").or_else(|| name.strip_prefix("tools.")).unwrap_or(name);
        let find = |wanted: &str| {
            self.tools
                .iter()
                .find(|t| t.name() == wanted)
                .or_else(|| self.tools.iter().find(|t| t.name().eq_ignore_ascii_case(wanted)))
                .cloned()
        };
        find(name).or_else(|| ALIASES.iter().find(|(alias, _)| alias.eq_ignore_ascii_case(name)).and_then(|(_, real)| find(real)))
    }

    fn ctx<'c>(&self, call: &'c Call) -> ToolCtx<'c>
    where
        't: 'c,
    {
        ToolCtx { turn: self.turn, call: &call.event, parent: self.parent.clone() }
    }

    /// Runs one call; the result for the model, and whether the turn must stop.
    async fn run_call(&mut self, call: &Call, cut_off: bool, announced: bool) -> (Msg, Option<Stop>) {
        #[cfg(test)]
        if call.name == tests::PANIC_TOOL {
            panic!("a panic inside a turn, as the tests make one");
        }
        // Esc may land between two calls of one reply (while a result is stored): the next call
        // does not start.
        if self.turn.cancel.is_cancelled() {
            return (self.fail(call, announced, &call.name, ToolKind::Other, STOPPED.into()), Some(Stop::Cancelled));
        }
        let Some(tool) = self.lookup(&call.name) else {
            let message = if call.name.is_empty() {
                format!("The tool call has no tool name. The tools are: {}.", self.tool_names().join(", "))
            } else {
                format!("There is no tool named {}. The tools are: {}.", call.name, self.tool_names().join(", "))
            };
            let title = if call.name.is_empty() { "Unknown tool".to_owned() } else { call.name.clone() };
            return (self.fail(call, announced, &title, ToolKind::Other, message), None);
        };
        let args = match parse_arguments(&call.arguments, cut_off) {
            Ok(args) => args,
            Err(problem) => {
                let message = if cut_off {
                    format!(
                        "The reply reached the output limit ({} tokens) in the middle of this call, so its arguments are \
                         incomplete. Make the call again with less in it: write a long file in parts, adding the rest with edit.",
                        self.turn.shared.spec.max_output
                    )
                } else {
                    format!("The arguments are not valid JSON ({problem}). Send the call again with a JSON object of arguments.")
                };
                return (self.fail(call, announced, tool.name(), tool.kind(), message), None);
            }
        };
        let ctx = self.ctx(call);
        let title = tool.title(&args, &ctx);
        let locations = tool.locations(&args, &ctx);
        self.emit(Event::ToolCall(ToolCall {
            id: call.event.clone(),
            title: title.clone(),
            kind: tool.kind(),
            status: ToolStatus::Pending,
            input: Some(shown_input(&args)),
            locations: locations.clone(),
            content: Vec::new(),
            parent: self.parent.clone(),
        }));
        // The stuck-loop guard.
        let mut note = None;
        let signature = format!("{}\u{0}{}", tool.name(), util::canonical(&args));
        if signature == self.repeat.last {
            self.repeat.count += 1;
        } else {
            self.repeat = Repeat { last: signature, count: 1, quiet: self.repeat.quiet };
        }
        if self.repeat.count >= 3 && !self.repeat.quiet {
            match self.ask_repeating(call, &title).await {
                Err(Stopped) => return (self.finish(call, &title, tool.kind(), &locations, Err(STOPPED.into())), Some(Stop::Cancelled)),
                Ok(Some(option)) if option == "go" => {
                    self.repeat.count = 0;
                    note = Some(REPEATED);
                }
                Ok(Some(option)) if option == "go_quiet" => {
                    self.repeat.quiet = true;
                    note = Some(REPEATED);
                }
                Ok(_) => {
                    if self.parent.is_some() {
                        // The person stopped the turn, not only this helper: the agent that
                        // started it stops too.
                        self.turn.cancel.cancel_because(KEPT_REPEATING);
                    }
                    let message = "Not run: the person stopped the turn because this call kept repeating.".to_owned();
                    return (self.finish(call, &title, tool.kind(), &locations, Err(message)), Some(Stop::Repeating));
                }
            }
        }
        match self.permit(tool.as_ref(), &args, &ctx, call, &title).await {
            Permit::Yes => {}
            Permit::No(message) => return (self.finish(call, &title, tool.kind(), &locations, Err(message)), None),
            Permit::Stopped => return (self.finish(call, &title, tool.kind(), &locations, Err(STOPPED.into())), Some(Stop::Cancelled)),
        }
        if self.turn.cancel.is_cancelled() {
            return (self.finish(call, &title, tool.kind(), &locations, Err(STOPPED.into())), Some(Stop::Cancelled));
        }
        self.emit(Event::ToolUpdate(ToolUpdate { id: call.event.clone(), status: Some(ToolStatus::InProgress), ..ToolUpdate::default() }));
        let result = {
            let running = tool.run(args, &ctx);
            tokio::pin!(running);
            tokio::select! {
                result = &mut running => result,
                _ = self.turn.cancel.cancelled() => {
                    // Tools stop on a cancel themselves; give them a moment to clean up.
                    match tokio::time::timeout(Duration::from_secs(3), &mut running).await {
                        Ok(result) => result,
                        Err(_) => Err("Stopped.".to_owned()),
                    }
                }
            }
        };
        let stop = self.turn.cancel.is_cancelled().then_some(Stop::Cancelled);
        let mut msg = self.finish(call, &title, tool.kind(), &locations, result);
        if let Some(note) = note {
            msg.text.push_str("\n\n");
            msg.text.push_str(note);
        }
        (msg, stop)
    }

    async fn ask_repeating(&self, call: &Call, title: &str) -> Result<Option<String>, Stopped> {
        let shared = &self.turn.shared;
        let request = PermissionRequest {
            id: shared.fresh(|| util::new_id("p")),
            tool_call: Some(call.event.clone()),
            title: "The model is repeating itself".into(),
            detail: Some(format!("It has made the same call three times in a row: {title}. Let it go on?")),
            options: vec![
                PermissionOption { id: "go".into(), label: "Let it go on".into(), kind: PermissionKind::AllowOnce },
                PermissionOption {
                    id: "go_quiet".into(),
                    label: "Let it go on, and do not ask again this turn".into(),
                    kind: PermissionKind::AllowAlways,
                },
                PermissionOption { id: "stop".into(), label: "Stop the turn".into(), kind: PermissionKind::RejectOnce },
            ],
        };
        shared.broker.permission(&shared.events, request, Vec::new(), Vec::new(), &self.turn.cancel).await
    }

    async fn permit(&self, tool: &dyn Tool, args: &Value, ctx: &ToolCtx<'_>, call: &Call, title: &str) -> Permit {
        let subjects = match tool.subjects(args, ctx) {
            Ok(subjects) => subjects,
            Err(message) => return Permit::No(message),
        };
        if subjects.is_empty() {
            return Permit::Yes;
        }
        let shared = &self.turn.shared;
        let verdict = judge(&self.profile.permissions, &shared.rules(), &subjects, &shared.vars);
        match verdict.action {
            Action::Allow => Permit::Yes,
            Action::Deny => Permit::No(format!(
                "Not allowed in {} mode: {} {}. Do not try it again; go on another way or tell the person what you need.",
                self.profile.name,
                tool.name(),
                verdict.subjects[0].value
            )),
            Action::Ask => {
                let preview = tool.preview(args, ctx).await;
                if !preview.is_empty() {
                    self.emit(Event::ToolUpdate(ToolUpdate { id: call.event.clone(), content: Some(preview), ..ToolUpdate::default() }));
                }
                let mut patterns: Vec<String> = Vec::new();
                for subject in &verdict.subjects {
                    let shown = readable_pattern(&subject.always);
                    if !patterns.contains(&shown) {
                        patterns.push(shown);
                    }
                }
                let list = patterns.join(", ");
                let detail = if tool.kind() == ToolKind::Execute {
                    let command = tools::text_arg(args, &["command", "cmd"]).unwrap_or_default();
                    // Whichever name the folder came under, the person sees where it runs.
                    match tools::bash::folder(args, ctx).filter(|dir| tools::real(dir) != tools::real(ctx.cwd())) {
                        Some(dir) => format!("{command}\n(in {})", ctx.show(&dir)),
                        None => command,
                    }
                } else {
                    verdict.subjects.iter().map(|s| s.value.clone()).collect::<Vec<_>>().join("\n")
                };
                let request = PermissionRequest {
                    id: shared.fresh(|| util::new_id("p")),
                    tool_call: Some(call.event.clone()),
                    title: if tool.kind() == ToolKind::Execute { format!("Run {title}") } else { title.to_owned() },
                    detail: Some(detail),
                    options: vec![
                        PermissionOption { id: ALLOW_ONCE.into(), label: "Allow once".into(), kind: PermissionKind::AllowOnce },
                        PermissionOption { id: ALLOW_ALWAYS.into(), label: format!("Always allow {list}"), kind: PermissionKind::AllowAlways },
                        PermissionOption { id: REJECT_ONCE.into(), label: "Reject".into(), kind: PermissionKind::RejectOnce },
                        PermissionOption { id: REJECT_ALWAYS.into(), label: format!("Always reject {list}"), kind: PermissionKind::RejectAlways },
                    ],
                };
                let answer = shared
                    .broker
                    .permission(&shared.events, request, verdict.subjects.clone(), self.profile.permissions.clone(), &self.turn.cancel)
                    .await;
                match answer.as_ref().map(|a| a.as_deref()) {
                    Err(Stopped) => Permit::Stopped,
                    Ok(Some(ALLOW_ONCE)) => Permit::Yes,
                    Ok(Some(ALLOW_ALWAYS)) => {
                        self.remember(&verdict.subjects, Action::Allow);
                        Permit::Yes
                    }
                    Ok(Some(REJECT_ALWAYS)) => {
                        self.remember(&verdict.subjects, Action::Deny);
                        Permit::No(REJECTED.into())
                    }
                    Ok(Some(REJECT_ONCE)) | Ok(_) => Permit::No(REJECTED.into()),
                }
            }
        }
    }

    /// Adds the person's "always" answer as rules, and answers waiting requests they settle.
    fn remember(&self, subjects: &[Subject], action: Action) {
        let shared = &self.turn.shared;
        {
            let mut rules = lock(&shared.rules);
            for subject in subjects {
                let rule = Rule { tool: subject.tool.clone(), pattern: subject.always.clone(), action };
                if !rules.contains(&rule) {
                    rules.push(rule);
                }
            }
        }
        shared.broker.settle(&shared.rules(), &shared.vars);
    }

    /// The result of a call that ran (or was refused once it started).
    fn finish(&self, call: &Call, title: &str, kind: ToolKind, locations: &[Location], result: Result<Output, String>) -> Msg {
        let shared = &self.turn.shared;
        match result {
            Ok(out) => {
                let text = if out.bounded { out.text } else { tools::bound(&out.text, shared.limits, &shared.spec.state_dir, &call.event) };
                let status = if out.failed { ToolStatus::Failed } else { ToolStatus::Completed };
                let title = out.title.unwrap_or_else(|| title.to_owned());
                let locations = if out.locations.is_empty() { locations.to_vec() } else { out.locations };
                self.emit(Event::ToolUpdate(ToolUpdate {
                    id: call.event.clone(),
                    status: Some(status),
                    title: Some(title.clone()),
                    content: Some(out.content.clone()),
                    locations: Some(locations.clone()),
                    output: None,
                }));
                Msg::tool(&call.id, text, Shown { title, kind, status, content: out.content, locations })
            }
            Err(message) => {
                let content = vec![ToolContent::Text { text: message.clone() }];
                self.emit(Event::ToolUpdate(ToolUpdate {
                    id: call.event.clone(),
                    status: Some(ToolStatus::Failed),
                    title: Some(title.to_owned()),
                    content: Some(content.clone()),
                    ..ToolUpdate::default()
                }));
                Msg::tool(
                    &call.id,
                    format!("Error: {message}"),
                    Shown { title: title.to_owned(), kind, status: ToolStatus::Failed, content, locations: locations.to_vec() },
                )
            }
        }
    }

    /// The result of a call that never started (malformed, unknown, or not run).
    fn fail(&self, call: &Call, announced: bool, title: &str, kind: ToolKind, message: String) -> Msg {
        if !announced {
            self.emit(Event::ToolCall(ToolCall {
                id: call.event.clone(),
                title: title.to_owned(),
                kind,
                status: ToolStatus::Pending,
                parent: self.parent.clone(),
                ..ToolCall::default()
            }));
        }
        self.finish(call, title, kind, &[], Err(message))
    }
}

/// A call's input as the screen gets it: long strings (a whole file's content) shortened; the
/// change itself travels as a diff.
pub fn shown_input(args: &Value) -> Value {
    match args {
        Value::String(text) if text.len() > 2000 => {
            Value::String(format!("{}\u{2026} [{} KB in all]", util::cut(text, 2000), text.len().div_ceil(1024)))
        }
        Value::Object(map) => Value::Object(map.iter().map(|(key, value)| (key.clone(), shown_input(value))).collect()),
        Value::Array(items) => Value::Array(items.iter().map(shown_input).collect()),
        other => other.clone(),
    }
}

/// A pattern as the person reads it (escapes removed).
fn readable_pattern(pattern: &str) -> String {
    let mut out = String::new();
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(next) = chars.next() {
                out.push(next);
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Runs a helper agent for the task tool; its final reply is the report.
pub fn run_helper<'a>(turn: &'a Turn, profile: Profile, parent: String, prompt: String) -> BoxFuture<'a, Result<String, String>> {
    Box::pin(async move {
        let mut conv = Conversation::default();
        conv.push(Msg::user(prompt));
        let mut agent = Agent::new(turn, profile, Some(parent), &mut conv, None);
        let outcome = agent.run().await;
        let report = agent.last_reply();
        match outcome {
            Outcome::Done if report.is_empty() => Ok("The helper finished without a report.".into()),
            Outcome::Done => Ok(report),
            Outcome::MaxSteps(limit) => Ok(format!("{report}\n\n(The helper stopped at its limit of {limit} steps.)").trim().to_owned()),
            Outcome::MaxTokens => Ok(format!("{report}\n\n(The helper's reply was cut at the output limit.)").trim().to_owned()),
            Outcome::Cancelled(_) => Err("Stopped.".into()),
            Outcome::Failed(message) => Err(format!("The helper failed: {message}")),
        }
    })
}

/// A call's arguments as an object, mending what small models commonly get wrong (code fences,
/// a JSON string holding the object, trailing commas, unclosed brackets). A reply cut at the
/// output limit is never mended: its content would be incomplete.
pub fn parse_arguments(raw: &str, cut_off: bool) -> Result<Value, String> {
    let text = raw.trim();
    if text.is_empty() {
        return Ok(json!({}));
    }
    let text = text
        .strip_prefix("```json")
        .or_else(|| text.strip_prefix("```"))
        .map(|t| t.trim_end().trim_end_matches("```").trim())
        .unwrap_or(text);
    let first = match serde_json::from_str::<Value>(text) {
        Ok(value) => return object(value),
        Err(error) => error.to_string(),
    };
    if !cut_off {
        if let Some(mended) = mend(text) {
            if let Ok(value) = serde_json::from_str::<Value>(&mended) {
                return object(value);
            }
        }
    }
    Err(first)
}

fn object(value: Value) -> Result<Value, String> {
    match value {
        Value::Object(_) => Ok(value),
        Value::Null => Ok(json!({})),
        Value::String(inner) => match serde_json::from_str::<Value>(&inner) {
            Ok(value @ Value::Object(_)) => Ok(value),
            _ => Err("the arguments are a string, not an object".into()),
        },
        _ => Err("the arguments are not an object".into()),
    }
}

/// Trailing commas dropped and open strings and brackets closed.
fn mend(text: &str) -> Option<String> {
    let mut out = String::with_capacity(text.len() + 8);
    let mut stack = Vec::new();
    let mut in_string = false;
    let mut escaped = false;
    for c in text.chars() {
        if in_string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match c {
            '"' => in_string = true,
            '{' => stack.push('}'),
            '[' => stack.push(']'),
            '}' | ']' => {
                let trimmed = out.trim_end().trim_end_matches(',').len();
                out.truncate(trimmed);
                if stack.pop() != Some(c) {
                    return None;
                }
            }
            _ => {}
        }
        out.push(c);
    }
    if in_string {
        out.push('"');
    }
    while let Some(close) = stack.pop() {
        let trimmed = out.trim_end().trim_end_matches(',').len();
        out.truncate(trimmed);
        out.push(close);
    }
    (out != text).then_some(out)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::native::compaction::SUMMARY_PROMPT;
    use crate::native::testutil::{call, say, spec, sse_body, FakeServer, Reply};
    use crate::protocol::Command;
    use tokio::sync::mpsc;

    /// A call to this name makes the agent panic (tests only), as a bug in a tool would.
    pub const PANIC_TOOL: &str = "test_panic_inside_a_turn";

    struct Harness {
        turn: Turn,
        receiver: mpsc::UnboundedReceiver<Event>,
        work: PathBuf,
        _folder: tempfile::TempDir,
    }

    fn harness(server: &FakeServer, tweak: impl FnOnce(&mut EngineSpec)) -> Harness {
        let folder = tempfile::tempdir().unwrap();
        let work = folder.path().join("work");
        std::fs::create_dir_all(&work).unwrap();
        let mut spec = spec(&server.url, &work, &folder.path().join("state"));
        tweak(&mut spec);
        let (sender, receiver) = mpsc::unbounded_channel();
        let (mut shared, _) = Shared::new(&spec, Events::new(sender), "yougori").unwrap();
        shared.llm.retry.first = Duration::from_millis(10);
        let turn = Turn { shared: Arc::new(shared), cancel: Cancel::new(), mcp: Arc::new(Mcp::default()) };
        Harness { turn, receiver, work, _folder: folder }
    }

    fn yougori(h: &Harness, steps: Option<u32>) -> Profile {
        let mut profile = h.turn.shared.profiles.get("yougori").unwrap().clone();
        if let Some(steps) = steps {
            profile.steps = steps;
        }
        profile
    }

    fn ask(prompt: &str) -> Conversation {
        let mut conv = Conversation::default();
        conv.push(Msg::user(prompt));
        conv
    }

    /// Runs the agent while a scripted screen answers its events; the outcome, the conversation
    /// and every event it sent.
    async fn drive(
        h: &mut Harness,
        profile: Profile,
        mut conv: Conversation,
        mut answer: impl FnMut(&Event) -> Option<Command>,
    ) -> (Outcome, Conversation, Vec<Event>) {
        let mut agent = Agent::new(&h.turn, profile, None, &mut conv, None);
        let mut events = Vec::new();
        let outcome = {
            let run = agent.run();
            tokio::pin!(run);
            loop {
                tokio::select! {
                    outcome = &mut run => break outcome,
                    Some(event) = h.receiver.recv() => {
                        match answer(&event) {
                            Some(Command::Permission { id, option }) => {
                                h.turn.shared.broker.answer_permission(&id, option);
                            }
                            Some(Command::Answer { id, answer }) => {
                                h.turn.shared.broker.answer_question(&id, answer);
                            }
                            Some(Command::Cancel) => h.turn.cancel.cancel(),
                            _ => {}
                        }
                        events.push(event);
                    }
                }
            }
        };
        drop(agent);
        while let Ok(event) = h.receiver.try_recv() {
            events.push(event);
        }
        (outcome, conv, events)
    }

    fn tool_texts(conv: &Conversation) -> Vec<String> {
        conv.entries.iter().filter(|e| e.msg.role == Role::Tool).map(|e| e.msg.text.clone()).collect()
    }

    fn completed(events: &[Event]) -> usize {
        events.iter().filter(|e| matches!(e, Event::ToolUpdate(u) if u.status == Some(ToolStatus::Completed))).count()
    }

    fn history(turns: usize) -> Conversation {
        let mut conv = Conversation::default();
        for turn in 0..turns {
            conv.push(Msg::user(format!("question {turn}: {}", "tell me about the code ".repeat(12))));
            conv.push(Msg::assistant("m", format!("answer {turn}: {}", "the code does this ".repeat(14)), String::new(), Vec::new()));
        }
        conv.push(Msg::user("And now?"));
        conv
    }

    #[tokio::test]
    async fn the_step_limit_ends_with_a_closing_reply() {
        let server = FakeServer::start(|_, request| {
            if request.json()["tool_choice"] == "none" {
                say("I listed the folder twice; nothing else is left.")
            } else {
                call("list", json!({}))
            }
        })
        .await;
        let mut h = harness(&server, |_| {});
        let profile = yougori(&h, Some(2));
        let (outcome, conv, events) = drive(&mut h, profile, ask("look around"), |_| None).await;
        assert_eq!(outcome, Outcome::MaxSteps(2));
        let requests = server.requests();
        assert_eq!(requests.len(), 3);
        let last = requests[2].json();
        assert_eq!(last["tool_choice"], "none");
        let messages = last["messages"].as_array().unwrap();
        assert!(messages.last().unwrap()["content"].as_str().unwrap().contains("You have used all 2 steps"));
        assert_eq!(conv.entries.last().unwrap().msg.text, "I listed the folder twice; nothing else is left.");
        assert_eq!(completed(&events), 2);
        let usage: Vec<&Usage> = events.iter().filter_map(|e| if let Event::Usage(u) = e { Some(u) } else { None }).collect();
        assert_eq!(usage.len(), 3, "one Usage per model call");
        assert!(usage.iter().all(|u| u.context_window == Some(32768) && u.context_tokens.unwrap_or(0) > 0));
    }

    #[tokio::test]
    async fn the_same_call_three_times_asks_the_person_who_can_stop_it() {
        let server = FakeServer::start(|_, _| call("list", json!({"path": "."}))).await;
        let mut h = harness(&server, |_| {});
        let mut asked = Vec::new();
        let profile = yougori(&h, None);
        let (outcome, conv, events) = drive(&mut h, profile, ask("loop"), |event| match event {
            Event::Permission(p) => {
                asked.push((p.title.clone(), p.options.iter().map(|o| o.kind).collect::<Vec<_>>()));
                Some(Command::Permission { id: p.id.clone(), option: Some("stop".into()) })
            }
            _ => None,
        })
        .await;
        assert_eq!(outcome, Outcome::Cancelled(Some("Stopped because the model kept making the same call.".into())));
        assert_eq!(server.requests().len(), 3);
        assert_eq!(asked.len(), 1);
        assert_eq!(asked[0].0, "The model is repeating itself");
        assert_eq!(asked[0].1, vec![PermissionKind::AllowOnce, PermissionKind::AllowAlways, PermissionKind::RejectOnce]);
        let results = tool_texts(&conv);
        assert_eq!(results.len(), 3);
        assert!(results[2].contains("kept repeating"), "{}", results[2]);
        assert_eq!(completed(&events), 2);
    }

    #[tokio::test]
    async fn letting_a_repeated_call_go_on_tells_the_model() {
        let server = FakeServer::start(|index, _| if index < 3 { call("list", json!({})) } else { say("Done.") }).await;
        let mut h = harness(&server, |_| {});
        let profile = yougori(&h, None);
        let (outcome, conv, _) = drive(&mut h, profile, ask("loop"), |event| match event {
            Event::Permission(p) => Some(Command::Permission { id: p.id.clone(), option: Some("go".into()) }),
            _ => None,
        })
        .await;
        assert_eq!(outcome, Outcome::Done);
        let results = tool_texts(&conv);
        assert!(results[2].ends_with(REPEATED), "{}", results[2]);
        assert!(!results[1].contains("Note:"));
    }

    #[tokio::test]
    async fn cancel_stops_a_running_command_and_the_turn() {
        let command = if cfg!(windows) { "ping -n 30 127.0.0.1 > nul" } else { "sleep 30" };
        let server = FakeServer::start(move |_, _| call("bash", json!({"command": command}))).await;
        let mut h = harness(&server, |_| {});
        let profile = yougori(&h, None);
        let started = std::time::Instant::now();
        let (outcome, conv, events) = drive(&mut h, profile, ask("wait"), |event| match event {
            Event::Permission(p) => Some(Command::Permission { id: p.id.clone(), option: Some(ALLOW_ONCE.into()) }),
            Event::ToolUpdate(u) if u.status == Some(ToolStatus::InProgress) => Some(Command::Cancel),
            _ => None,
        })
        .await;
        assert_eq!(outcome, Outcome::Cancelled(None));
        assert!(started.elapsed() < Duration::from_secs(10), "{:?}", started.elapsed());
        assert!(tool_texts(&conv)[0].contains("Stopped by the person."), "{:?}", tool_texts(&conv));
        assert!(events.iter().any(|e| matches!(e, Event::ToolUpdate(u) if u.status == Some(ToolStatus::Failed))));
        assert_eq!(server.requests().len(), 1);
    }

    #[tokio::test]
    async fn cancel_while_the_model_streams_keeps_what_was_said() {
        let server = FakeServer::start(|_, _| {
            Reply::sse_slow(
                vec![
                    b"data: {\"choices\":[{\"delta\":{\"content\":\"Thinking about \"}}]}\n\n".to_vec(),
                    b"data: {\"choices\":[{\"delta\":{\"content\":\"it\"},\"finish_reason\":\"stop\"}]}\n\n".to_vec(),
                ],
                Duration::from_secs(10),
            )
        })
        .await;
        let mut h = harness(&server, |_| {});
        let profile = yougori(&h, None);
        let (outcome, conv, _) =
            drive(&mut h, profile, ask("think"), |event| matches!(event, Event::Message { .. }).then_some(Command::Cancel)).await;
        assert_eq!(outcome, Outcome::Cancelled(None));
        assert_eq!(conv.entries.last().unwrap().msg.text, "Thinking about");
    }

    #[tokio::test]
    async fn malformed_calls_go_back_to_the_model_as_errors() {
        let server = FakeServer::start(|index, _| match index {
            0 => Reply::sse(sse_body(&[json!({"choices": [{"delta": {"tool_calls": [
                {"index": 0, "id": "a", "function": {"name": "read", "arguments": "{\"path\": "}},
                {"index": 1, "id": "b", "function": {"name": "teleport", "arguments": "{}"}},
                {"index": 2, "id": "c", "function": {"name": "Read_File", "arguments": "{\"path\": \"missing.txt\"}"}}
            ]}, "finish_reason": "tool_calls"}]})])),
            _ => say("Sorry; fixed."),
        })
        .await;
        let mut h = harness(&server, |_| {});
        let profile = yougori(&h, None);
        let (outcome, _, _) = drive(&mut h, profile, ask("go"), |_| None).await;
        assert_eq!(outcome, Outcome::Done);
        let second = server.requests()[1].json();
        let results: Vec<String> = second["messages"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|m| m["role"] == "tool")
            .map(|m| m["content"].as_str().unwrap().to_owned())
            .collect();
        assert!(results[0].starts_with("Error: The arguments are not valid JSON"), "{results:?}");
        assert!(results[1].contains("There is no tool named teleport"), "{results:?}");
        assert!(results[2].contains("missing.txt does not exist"), "an alias reaches read: {results:?}");
        let calls = second["messages"][2]["tool_calls"].as_array().unwrap();
        assert_eq!(calls[0]["function"]["arguments"], "{}", "broken arguments are not sent back");
    }

    #[tokio::test]
    async fn permissions_ask_remember_always_and_reject_with_an_error() {
        let server = FakeServer::start(|index, _| match index {
            0 => call("bash", json!({"command": "mkdir first"})),
            1 => call("bash", json!({"command": "mkdir second"})),
            2 => call("bash", json!({"command": "rm -rf first"})),
            _ => say("done"),
        })
        .await;
        let mut h = harness(&server, |_| {});
        let profile = yougori(&h, None);
        let mut asked = Vec::new();
        let (outcome, conv, _) = drive(&mut h, profile, ask("make folders"), |event| match event {
            Event::Permission(p) => {
                asked.push((p.title.clone(), p.options[1].label.clone()));
                let option = if p.title.contains("mkdir") { ALLOW_ALWAYS } else { REJECT_ONCE };
                Some(Command::Permission { id: p.id.clone(), option: Some(option.into()) })
            }
            _ => None,
        })
        .await;
        assert_eq!(outcome, Outcome::Done);
        if cfg!(windows) {
            // cmd.exe lines are remembered only as written.
            assert_eq!(
                asked,
                vec![
                    ("Run mkdir first".to_owned(), "Always allow mkdir first".to_owned()),
                    ("Run mkdir second".to_owned(), "Always allow mkdir second".to_owned()),
                    ("Run rm -rf first".to_owned(), "Always allow rm -rf first".to_owned())
                ]
            );
        } else {
            assert_eq!(
                asked,
                vec![
                    ("Run mkdir first".to_owned(), "Always allow mkdir*".to_owned()),
                    ("Run rm -rf first".to_owned(), "Always allow rm -rf first".to_owned())
                ]
            );
            assert!(h.turn.shared.rules().contains(&Rule { tool: "bash".into(), pattern: "mkdir*".into(), action: Action::Allow }));
        }
        assert!(h.work.join("first").is_dir() && h.work.join("second").is_dir());
        assert!(tool_texts(&conv)[2].starts_with("Error: The person rejected this call"));
    }

    #[tokio::test]
    async fn a_command_in_another_folder_says_where_and_project_answers_do_not_cover_it() {
        let elsewhere = tempfile::tempdir().unwrap();
        let dir = tools::slash(elsewhere.path());
        let server = FakeServer::start(move |index, _| match index {
            0 => call("bash", json!({"command": "mkdir first"})),
            1 => call("bash", json!({"command": "mkdir second", "dir": dir})),
            _ => say("done"),
        })
        .await;
        let mut h = harness(&server, |_| {});
        let profile = yougori(&h, None);
        let mut asked = Vec::new();
        let (outcome, conv, _) = drive(&mut h, profile, ask("make folders"), |event| match event {
            Event::Permission(p) => {
                asked.push((p.title.clone(), p.detail.clone().unwrap_or_default(), p.options[1].label.clone()));
                let option = if asked.len() == 1 { ALLOW_ALWAYS } else { REJECT_ONCE };
                Some(Command::Permission { id: p.id.clone(), option: Some(option.into()) })
            }
            _ => None,
        })
        .await;
        assert_eq!(outcome, Outcome::Done);
        assert_eq!(asked.len(), 2, "the answer given in the project does not reach the other folder: {asked:?}");
        let there = tools::slash(&tools::real(elsewhere.path()));
        assert_eq!(asked[1].0, "Run mkdir second");
        assert!(asked[1].1.starts_with("mkdir second\n(in ") && asked[1].1.ends_with(')'), "{:?}", asked[1].1);
        assert!(asked[1].2.starts_with(&format!("Always allow (in {there}) mkdir")), "{:?}", asked[1].2);
        assert!(h.work.join("first").is_dir() && !elsewhere.path().join("second").exists());
        assert!(tool_texts(&conv)[1].starts_with("Error: The person rejected this call"));
    }

    #[tokio::test]
    async fn cd_moves_where_the_later_commands_of_a_line_are_judged() {
        let server = FakeServer::start(|_, _| say("unused")).await;
        let h = harness(&server, |_| {});
        let ctx = ToolCtx { turn: &h.turn, call: "t-1", parent: None };
        std::fs::create_dir_all(h.work.join("sub")).unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let there = tools::slash(&tools::real(elsewhere.path()));
        let work = tools::slash(&h.work);
        let values = |command: &str, args: Value| -> Vec<String> {
            tools::bash::posix_subjects(command, &args, &ctx).into_iter().map(|s| s.value).collect()
        };
        let plain = |command: &str| values(command, json!({ "command": command }));
        assert_eq!(plain("cd sub && cargo test"), vec!["cd sub", "cargo test"]);
        assert_eq!(plain(&format!("cd {there} && rm -rf build")), vec![format!("cd {there}"), format!("(in {there}) rm -rf build")]);
        assert_eq!(plain(&format!("cd {there}; cd {work} && make"))[2], "make", "back in the project");
        let unknown = "(in a folder that cannot be told before it runs) ";
        for command in ["cd \"$TARGET\" && make", "cd - && make", "builtin cd /tmp && make", "popd && make", "set -P; cd sub; make"] {
            assert!(plain(command).last().unwrap().starts_with(unknown), "{command}: {:?}", plain(command));
        }
        assert!(plain("cd .. && make")[1].starts_with("(in "), "the project's parent is elsewhere");
        // The folder the call names counts the same way, under any of its names.
        for name in ["workdir", "cwd", "directory", "dir"] {
            assert_eq!(values("make", json!({ "command": "make", name: there })), vec![format!("(in {there}) make")], "{name}");
        }
        assert_eq!(values("make", json!({ "command": "make", "dir": "sub" })), vec!["make"]);
    }

    #[tokio::test]
    async fn only_this_agents_own_reads_let_it_replace_a_file() {
        // (a) A helper's read of the file is not the main agent seeing it.
        let server = FakeServer::start(|_, request| {
            let body = request.json();
            let messages = body["messages"].as_array().unwrap();
            let system = messages[0]["content"].as_str().unwrap_or("").to_owned();
            let results = messages.iter().filter(|m| m["role"] == "tool").count();
            if system.starts_with("You are a search helper") {
                if results == 0 { call("read", json!({"path": "config.yaml"})) } else { say("config.yaml sets the port to 80.") }
            } else {
                match results {
                    0 => call("task", json!({"description": "summarise config", "prompt": "Summarise config.yaml.", "agent": "explore"})),
                    1 => call("write", json!({"path": "config.yaml", "content": "port: 81\n"})),
                    _ => say("done"),
                }
            }
        })
        .await;
        let mut h = harness(&server, |_| {});
        std::fs::write(h.work.join("config.yaml"), "port: 80\nname: keep me\n").unwrap();
        let profile = yougori(&h, None);
        let (outcome, conv, _) = drive(&mut h, profile, ask("set the port to 81"), |_| None).await;
        assert_eq!(outcome, Outcome::Done);
        let results = tool_texts(&conv);
        assert!(results[0].contains("port to 80"), "{results:?}");
        assert!(results[1].starts_with("Error: config.yaml already exists. Read it first"), "{results:?}");
        assert_eq!(std::fs::read_to_string(h.work.join("config.yaml")).unwrap(), "port: 80\nname: keep me\n");
        // (b) An edit shows only the lines around it: it does not count as reading the file,
        // unless the agent had read all of it before.
        let server = FakeServer::start(|index, _| match index {
            0 => call("edit", json!({"path": "a.txt", "old_string": "one", "new_string": "uno"})),
            1 => call("write", json!({"path": "a.txt", "content": "whole\n"})),
            2 => call("read", json!({"path": "b.txt"})),
            3 => call("edit", json!({"path": "b.txt", "old_string": "two", "new_string": "dos"})),
            4 => call("write", json!({"path": "b.txt", "content": "whole b\n"})),
            _ => say("done"),
        })
        .await;
        let mut h = harness(&server, |_| {});
        std::fs::write(h.work.join("a.txt"), "one\nmore\n").unwrap();
        std::fs::write(h.work.join("b.txt"), "two\nmore\n").unwrap();
        let profile = yougori(&h, None);
        let (outcome, conv, _) = drive(&mut h, profile, ask("rewrite them"), |_| None).await;
        assert_eq!(outcome, Outcome::Done);
        let results = tool_texts(&conv);
        assert!(results[1].starts_with("Error: a.txt already exists. Read it first"), "{results:?}");
        assert_eq!(std::fs::read_to_string(h.work.join("a.txt")).unwrap(), "uno\nmore\n");
        assert!(results[4].starts_with("Wrote b.txt"), "{results:?}");
        assert_eq!(std::fs::read_to_string(h.work.join("b.txt")).unwrap(), "whole b\n");
    }

    #[tokio::test]
    async fn plan_mode_refuses_commands_that_change_things() {
        let server = FakeServer::start(|index, _| if index == 0 { call("bash", json!({"command": "touch x"})) } else { say("ok") }).await;
        let mut h = harness(&server, |_| {});
        let plan = h.turn.shared.profiles.get("plan").unwrap().clone();
        let (outcome, conv, _) = drive(&mut h, plan, ask("try"), |_| None).await;
        assert_eq!(outcome, Outcome::Done);
        assert!(tool_texts(&conv)[0].starts_with("Error: Not allowed in plan mode: bash touch x"), "{:?}", tool_texts(&conv));
        let tools: Vec<String> = server.requests()[0].json()["tools"].as_array().unwrap().iter().map(|t| t["function"]["name"].as_str().unwrap().to_owned()).collect();
        assert!(!tools.contains(&"edit".to_owned()) && !tools.contains(&"write".to_owned()) && tools.contains(&"todowrite".to_owned()));
    }

    #[tokio::test]
    async fn a_call_that_would_not_fit_compacts_first() {
        let server = FakeServer::start(|_, request| {
            if request.json()["messages"][0]["content"] == SUMMARY_PROMPT {
                say("Requests: questions about the code.")
            } else {
                say("Answer.")
            }
        })
        .await;
        let mut h = harness(&server, |spec| {
            spec.context_window = 8192;
            spec.max_output = 1024;
        });
        let profile = yougori(&h, None);
        let (outcome, conv, events) = drive(&mut h, profile, history(40), |_| None).await;
        assert_eq!(outcome, Outcome::Done);
        let requests: Vec<Value> = server.requests().iter().map(|r| r.json()).collect();
        assert!(requests.len() >= 2);
        assert_eq!(requests[0]["messages"][0]["content"], SUMMARY_PROMPT, "the summary came first");
        let last = requests.last().unwrap();
        assert!(last["messages"][1]["content"].as_str().unwrap().starts_with("Summary of the conversation so far"));
        assert!(conv.head.is_some());
        assert!(events.iter().any(|e| matches!(e, Event::Progress(p) if p.finished)));
        assert!(events.iter().any(|e| matches!(e, Event::Notice { text, .. } if text.contains("summarised"))));
    }

    #[tokio::test]
    async fn an_overflow_compacts_and_tries_once_more() {
        let server = FakeServer::start(|index, request| {
            if request.json()["messages"][0]["content"] == SUMMARY_PROMPT {
                return say("Notes.");
            }
            if index == 0 {
                Reply::json(400, json!({"error": {"message": "This model's maximum context length is 32768 tokens. However, you requested 40000 tokens."}}))
            } else {
                say("Fits now.")
            }
        })
        .await;
        let mut h = harness(&server, |_| {});
        let profile = yougori(&h, None);
        let (outcome, conv, _) = drive(&mut h, profile, history(30), |_| None).await;
        assert_eq!(outcome, Outcome::Done);
        assert_eq!(conv.entries.last().unwrap().msg.text, "Fits now.");
        let requests: Vec<Value> = server.requests().iter().map(|r| r.json()).collect();
        assert_eq!(requests.len(), 3, "overflow, summary, retry");
        assert_eq!(requests[1]["messages"][0]["content"], SUMMARY_PROMPT);
        // A second overflow ends the turn plainly.
        let server = FakeServer::start(|_, request| {
            if request.json()["messages"][0]["content"] == SUMMARY_PROMPT {
                say("Notes.")
            } else {
                Reply::json(400, json!({"error": {"message": "the request exceeds the available context size"}}))
            }
        })
        .await;
        let mut h = harness(&server, |_| {});
        let profile = yougori(&h, None);
        let (outcome, _, _) = drive(&mut h, profile, history(30), |_| None).await;
        assert!(matches!(outcome, Outcome::Failed(ref m) if m.contains("even after compacting")), "{outcome:?}");
    }

    #[tokio::test]
    async fn a_helper_works_under_the_task_call_and_reports_back() {
        let server = FakeServer::start(|_, request| {
            let body = request.json();
            let system = body["messages"][0]["content"].as_str().unwrap_or("").to_owned();
            let last = body["messages"].as_array().unwrap().last().unwrap()["role"].as_str().unwrap().to_owned();
            if system.starts_with("You are a search helper") {
                say("Found it: src/lib.rs:3.")
            } else if last == "tool" {
                say("The helper found the parser in src/lib.rs.")
            } else {
                call("task", json!({"description": "find the parser", "prompt": "Find where the parser is.", "agent": "explore"}))
            }
        })
        .await;
        let mut h = harness(&server, |_| {});
        let profile = yougori(&h, None);
        let (outcome, conv, events) = drive(&mut h, profile, ask("Where is the parser?"), |_| None).await;
        assert_eq!(outcome, Outcome::Done);
        let task = events
            .iter()
            .find_map(|e| match e {
                Event::ToolCall(c) if c.kind == ToolKind::Task && c.input.is_some() => Some(c.clone()),
                _ => None,
            })
            .unwrap();
        assert_eq!(task.title, "Explore: find the parser");
        assert!(events.iter().any(|e| matches!(e, Event::Message { text, parent: Some(p), .. } if *p == task.id && text.contains("Found it"))));
        assert!(tool_texts(&conv)[0].contains("Found it: src/lib.rs:3."));
        let helper = server
            .requests()
            .iter()
            .map(|r| r.json())
            .find(|b| b["messages"][0]["content"].as_str().unwrap_or("").starts_with("You are a search helper"))
            .unwrap();
        let tools: Vec<String> = helper["tools"].as_array().unwrap().iter().map(|t| t["function"]["name"].as_str().unwrap().to_owned()).collect();
        assert!(!tools.iter().any(|t| t == "task" || t == "edit" || t == "write"), "{tools:?}");
        assert_eq!(helper["messages"][1]["content"], "Find where the parser is.");
    }

    #[tokio::test]
    async fn mcp_tools_are_offered_ask_first_and_answer() {
        let server = FakeServer::start(|index, _| if index == 0 { call("docs_echo", json!({"text": "hi"})) } else { say("It said hi.") }).await;
        let mut h = harness(&server, |_| {});
        h.turn.mcp = Arc::new(Mcp::with(vec![crate::native::mcp::tests::ready_server("docs", 3).await]));
        let profile = yougori(&h, None);
        let mut asked = Vec::new();
        let (outcome, conv, _) = drive(&mut h, profile, ask("echo hi"), |event| match event {
            Event::Permission(p) => {
                asked.push(p.title.clone());
                Some(Command::Permission { id: p.id.clone(), option: Some(ALLOW_ONCE.into()) })
            }
            _ => None,
        })
        .await;
        assert_eq!(outcome, Outcome::Done);
        assert_eq!(asked, vec!["docs: echo"]);
        assert_eq!(tool_texts(&conv)[0], "echo: hi");
        let first = server.requests()[0].json();
        let tools: Vec<String> = first["tools"].as_array().unwrap().iter().map(|t| t["function"]["name"].as_str().unwrap().to_owned()).collect();
        assert!(tools.contains(&"docs_echo".to_owned()) && tools.contains(&"docs_tool2".to_owned()), "{tools:?}");
        assert!(first["messages"][0]["content"].as_str().unwrap().contains("## docs\nUse echo to repeat."));
    }

    #[tokio::test]
    async fn the_question_tool_waits_for_the_answer() {
        let server = FakeServer::start(|index, _| {
            if index == 0 {
                call("question", json!({"question": "Which database?", "choices": ["Postgres", "SQLite"]}))
            } else {
                say("Using SQLite.")
            }
        })
        .await;
        let mut h = harness(&server, |_| {});
        let profile = yougori(&h, None);
        let (outcome, conv, _) = drive(&mut h, profile, ask("set up storage"), |event| match event {
            Event::Question(q) => {
                assert_eq!(q.choices, vec!["Postgres", "SQLite"]);
                Some(Command::Answer { id: q.id.clone(), answer: Some(vec!["SQLite".into()]) })
            }
            _ => None,
        })
        .await;
        assert_eq!(outcome, Outcome::Done);
        assert_eq!(tool_texts(&conv)[0], "The person answered: SQLite");
    }

    #[tokio::test]
    async fn an_empty_reply_after_a_tool_gets_one_nudge() {
        let server = FakeServer::start(|index, _| match index {
            0 => call("list", json!({})),
            1 => say(""),
            _ => say("Here is the folder."),
        })
        .await;
        let mut h = harness(&server, |_| {});
        let profile = yougori(&h, None);
        let (outcome, conv, _) = drive(&mut h, profile, ask("show"), |_| None).await;
        assert_eq!(outcome, Outcome::Done);
        assert_eq!(conv.entries.last().unwrap().msg.text, "Here is the folder.");
        assert!(tool_texts(&conv)[0].ends_with("reply to the person if the work is done."));
    }

    #[tokio::test]
    async fn stopping_a_helper_that_repeats_itself_stops_the_whole_turn() {
        let server = FakeServer::start(|_, request| {
            let body = request.json();
            let system = body["messages"][0]["content"].as_str().unwrap_or("").to_owned();
            let last = body["messages"].as_array().unwrap().last().unwrap()["role"].as_str().unwrap().to_owned();
            if system.starts_with("You are a search helper") {
                call("grep", json!({"pattern": "needle"}))
            } else if last == "tool" {
                say("The main agent went on after the person stopped the turn.")
            } else {
                call("task", json!({"description": "find it", "prompt": "Find the needle.", "agent": "explore"}))
            }
        })
        .await;
        let mut h = harness(&server, |_| {});
        let profile = yougori(&h, None);
        let mut asked = Vec::new();
        let (outcome, conv, _) = drive(&mut h, profile, ask("Where is the needle?"), |event| match event {
            Event::Permission(p) => {
                asked.push(p.title.clone());
                Some(Command::Permission { id: p.id.clone(), option: Some("stop".into()) })
            }
            _ => None,
        })
        .await;
        assert_eq!(asked, vec!["The model is repeating itself"]);
        assert_eq!(outcome, Outcome::Cancelled(Some(KEPT_REPEATING.into())));
        assert_eq!(server.requests().len(), 4, "the task call and the helper's three grep calls, then nothing");
        assert!(!conv.entries.iter().any(|e| e.msg.text.contains("went on")));
    }

    #[tokio::test]
    async fn a_call_does_not_start_once_the_turn_is_stopped() {
        let server = FakeServer::start(|_, _| say("unused")).await;
        let h = harness(&server, |_| {});
        let profile = yougori(&h, None);
        let mut conv = ask("write it");
        let mut agent = Agent::new(&h.turn, profile, None, &mut conv, None);
        let write = Call {
            id: "c1".into(),
            event: "t-1".into(),
            name: "write".into(),
            arguments: json!({"path": "after.txt", "content": "written after Esc\n"}).to_string(),
        };
        // Esc landed after the reply ended (or while the call before was stored).
        h.turn.cancel.cancel();
        let (result, stop) = agent.run_call(&write, false, true).await;
        assert!(matches!(stop, Some(Stop::Cancelled)));
        assert!(result.text.contains(STOPPED), "{}", result.text);
        assert!(!h.work.join("after.txt").exists(), "an allowed write does not run after Esc");
    }

    #[tokio::test]
    async fn the_answer_after_a_lone_think_close_is_a_message_of_its_own() {
        let body = sse_body(&[
            json!({"choices": [{"delta": {"content": "I should greet them.</think>"}}]}),
            json!({"choices": [{"delta": {"content": "\n\nHello!"}, "finish_reason": "stop"}]}),
        ]);
        let server = FakeServer::start(move |_, _| Reply::sse(body.clone())).await;
        let mut h = harness(&server, |_| {});
        let profile = yougori(&h, None);
        let (outcome, conv, events) = drive(&mut h, profile, ask("hi"), |_| None).await;
        assert_eq!(outcome, Outcome::Done);
        let mut shown: Vec<(String, String)> = Vec::new();
        for event in &events {
            if let Event::Message { message, text, .. } = event {
                match shown.last_mut() {
                    Some((id, joined)) if id == message => joined.push_str(text),
                    _ => shown.push((message.clone(), text.clone())),
                }
            }
        }
        assert_eq!(shown.len(), 2, "{shown:?}");
        assert_eq!((shown[0].1.as_str(), shown[1].1.as_str()), ("I should greet them.", "Hello!"));
        let reply = &conv.entries.last().unwrap().msg;
        assert_eq!((reply.text.as_str(), reply.reasoning.as_str()), ("Hello!", "I should greet them."));
        assert_eq!(reply.id.as_deref(), Some(shown[1].0.as_str()), "a replay shows the answer under its own id");
    }

    #[tokio::test]
    async fn git_never_uses_a_bare_repository_it_comes_upon() {
        let folder = tempfile::tempdir().unwrap();
        let mut spec = spec("http://127.0.0.1:9", folder.path(), &folder.path().join("state"));
        spec.env = std::env::vars().filter(|(name, _)| !name.starts_with("GIT_CONFIG")).collect();
        spec.env.insert("GIT_CONFIG_COUNT".into(), "1".into());
        spec.env.insert("GIT_CONFIG_KEY_0".into(), "user.name".into());
        spec.env.insert("GIT_CONFIG_VALUE_0".into(), "Kept".into());
        let env = environment(&spec);
        assert_eq!(env.get("GIT_CONFIG_COUNT").map(String::as_str), Some("2"));
        assert_eq!(env.get("GIT_CONFIG_KEY_0").map(String::as_str), Some("user.name"), "the spec's own settings stay");
        assert_eq!(env.get("GIT_CONFIG_KEY_1").map(String::as_str), Some("safe.bareRepository"));
        assert_eq!(env.get("GIT_CONFIG_VALUE_1").map(String::as_str), Some("explicit"));
        // A folder the model laid out as a bare repository, with a setting that runs a program.
        let run = |command: &str, env: &BTreeMap<String, String>| {
            let (command, env, cwd) = (command.to_owned(), env.clone(), folder.path().to_path_buf());
            async move { tools::bash::run(&command, &cwd, &env, Duration::from_secs(60), &Cancel::new(), &mut |_| {}).await.unwrap() }
        };
        if run("git init --bare -q planted", &spec.env).await.exit != Some(0) {
            eprintln!("git is not here, so only the environment was checked.");
            return;
        }
        let ask = "git -C planted rev-parse --is-bare-repository";
        let plain = run(ask, &spec.env).await;
        assert_eq!((plain.exit, String::from_utf8_lossy(&plain.output).trim()), (Some(0), "true"), "without the setting git uses it");
        let refused = run(ask, &env).await;
        assert_ne!(refused.exit, Some(0), "{}", String::from_utf8_lossy(&refused.output));
        // The project's own repository is unaffected.
        assert_eq!(run("git init -q mine && git -C mine rev-parse --is-inside-work-tree", &env).await.exit, Some(0));
    }

    #[test]
    fn arguments_are_mended_when_safe() {
        assert_eq!(parse_arguments("", false).unwrap(), json!({}));
        assert_eq!(parse_arguments("{\"path\": \"a\"}", false).unwrap(), json!({"path": "a"}));
        assert_eq!(parse_arguments("```json\n{\"path\": \"a\"}\n```", false).unwrap(), json!({"path": "a"}));
        assert_eq!(parse_arguments("\"{\\\"path\\\": \\\"a\\\"}\"", false).unwrap(), json!({"path": "a"}));
        assert_eq!(parse_arguments("{\"a\": [1, 2,], }", false).unwrap(), json!({"a": [1, 2]}));
        assert_eq!(parse_arguments("{\"path\": \"a\"", false).unwrap(), json!({"path": "a"}));
        assert!(parse_arguments("{\"content\": \"half a fi", true).is_err(), "a cut-off reply is never mended");
        assert!(parse_arguments("[1, 2]", false).is_err());
        assert!(parse_arguments("not json", false).is_err());
        assert_eq!(readable_pattern("rm -rf \\*.o"), "rm -rf *.o");
        let shown = shown_input(&json!({"path": "a", "content": "x".repeat(5000), "n": 1}));
        assert_eq!(shown["path"], "a");
        assert!(shown["content"].as_str().unwrap().ends_with("[5 KB in all]"));
    }
}
