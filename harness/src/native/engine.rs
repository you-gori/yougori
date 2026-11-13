//! The engine: takes the screen's commands, runs one prompt at a time (a prompt sent during a
//! turn waits for it), routes the person's answers, switches models and modes in place, and
//! keeps sessions with the slash commands `/new`, `/sessions`, `/compact` and `/init`.
use super::agent::{lock, Agent, Outcome, Persist, Shared, Turn};
use super::cancel::{Cancel, CancelOnDrop};
use super::compaction::Why;
use super::conversation::{estimate, Conversation, Msg, Role, Shown};
use super::events::Events;
use super::mcp::Mcp;
use super::store::{self, Store};
use super::tools;
use super::util;
use crate::protocol::{
    Command, EngineHandle, Event, Level, Mode, ModelSwitch, PlanEntry, QuestionRequest, Ready, SlashCommand, StopReason,
    ToolCall, ToolStatus, Usage,
};
use crate::spec::EngineSpec;
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch};

pub const INIT_PROMPT: &str = "Write an AGENTS.md file at the root of this project for coding agents that will work on it later.

1. Look around first: the README, the build and package files (such as package.json, Cargo.toml, pyproject.toml, go.mod or a Makefile), the folder layout, any CI configuration, and existing notes for contributors or agents.
2. Then write AGENTS.md in short sections: what the project is; how to install, build, test and run it, with the exact commands (including how to run a single test); how the code is laid out; and the conventions to follow that the code does not make obvious.
3. Keep it under about 80 lines and state only what you checked in the files. If an AGENTS.md exists already, improve it instead of starting over.";

const COMMANDS: [(&str, &str); 4] = [
    ("new", "Start a new session"),
    ("sessions", "Resume an earlier session in this folder"),
    ("compact", "Summarise the conversation to free room in the context"),
    ("init", "Write an AGENTS.md that tells agents how this project works"),
];

#[derive(Default)]
struct Session {
    /// None until the first prompt is stored.
    id: Option<String>,
    title: String,
    conv: Conversation,
    /// The mode the model worked in last, to tell it when the person switches.
    mode: Option<String>,
}

struct Core {
    shared: Arc<Shared>,
    store: Option<Arc<Store>>,
    mcp: watch::Receiver<Option<Arc<Mcp>>>,
}

pub async fn start(spec: &EngineSpec) -> anyhow::Result<EngineHandle> {
    let mode = spec.profile.clone().filter(|p| !p.trim().is_empty()).unwrap_or_else(|| "yougori".into());
    if !spec.cwd.is_dir() {
        anyhow::bail!("The working folder {} does not exist.", spec.cwd.display());
    }
    std::fs::create_dir_all(&spec.state_dir)
        .map_err(|e| anyhow::anyhow!("Cannot create the state folder {}: {e}", spec.state_dir.display()))?;
    let (mut handle, commands, sender) = EngineHandle::pair();
    let (shared, mut notes) = Shared::new(spec, Events::new(sender), &mode)?;
    let store = match Store::open(&spec.state_dir.join("sessions.db")) {
        Ok(store) => Some(Arc::new(store)),
        Err(error) => {
            notes.push(format!("Sessions will not be saved: {error}."));
            None
        }
    };
    let stop = Cancel::new();
    handle.keep.push(Box::new(CancelOnDrop(stop.clone())));
    tokio::spawn(run(Arc::new(shared), store, commands, stop, notes));
    Ok(handle)
}

fn send_modes(shared: &Shared) {
    let available = shared
        .profiles
        .primary()
        .iter()
        .map(|p| Mode { id: p.name.clone(), name: p.title(), description: Some(p.description.clone()) })
        .collect();
    shared.events.send(Event::Modes { current: shared.mode(), available });
}

async fn run(
    shared: Arc<Shared>,
    store: Option<Arc<Store>>,
    mut commands: mpsc::UnboundedReceiver<Command>,
    stop: Cancel,
    notes: Vec<String>,
) {
    let events = shared.events.clone();
    let spec = &shared.spec;
    events.send(Event::Ready(Ready {
        harness: spec.harness.clone(),
        name: spec.name.clone(),
        model: shared.model(),
        models: spec.models.clone(),
        model_switch: ModelSwitch::Live,
        session: None,
        info: Some(format!("Yougori agent {}, {} mode", env!("CARGO_PKG_VERSION"), shared.mode())),
    }));
    send_modes(&shared);
    events.send(Event::Commands {
        commands: COMMANDS
            .iter()
            .map(|(name, description)| SlashCommand {
                name: (*name).into(),
                description: (*description).into(),
                hint: (*name == "init").then(|| "what to focus on (optional)".into()),
            })
            .collect(),
    });
    for note in notes {
        events.notice(Level::Warn, note);
    }
    let state = spec.state_dir.clone();
    tokio::task::spawn_blocking(move || tools::cleanup_outputs(&state));
    // MCP servers start in the background; the first prompt waits for them.
    let (mcp_sender, mcp) = watch::channel(None);
    let starting = {
        let shared = shared.clone();
        tokio::spawn(async move {
            let mcp = Mcp::connect(&shared.spec.mcp, &shared.cwd, &shared.env, &shared.events).await;
            let _ = mcp_sender.send(Some(Arc::new(mcp)));
        })
    };
    {
        let shared = shared.clone();
        tokio::spawn(async move { check_model(&shared).await });
    }
    let core = Arc::new(Core { shared: shared.clone(), store, mcp });
    let session = Arc::new(tokio::sync::Mutex::new(Session::default()));
    let (done_sender, mut done) = mpsc::unbounded_channel::<()>();
    let mut queue: VecDeque<String> = VecDeque::new();
    let mut running: Option<(Cancel, tokio::task::JoinHandle<()>)> = None;
    loop {
        tokio::select! {
            _ = stop.cancelled() => break,
            Some(()) = done.recv() => {
                running = None;
                if let Some(text) = queue.pop_front() {
                    running = Some(begin(&core, &session, text, &done_sender));
                }
            }
            command = commands.recv() => match command {
                None | Some(Command::Shutdown) => break,
                Some(Command::Prompt { text }) => {
                    if running.is_some() {
                        queue.push_back(text);
                        events.notice(Level::Info, "Queued: it runs when the current turn ends.");
                    } else {
                        running = Some(begin(&core, &session, text, &done_sender));
                    }
                }
                Some(Command::Cancel) => {
                    if let Some((cancel, _)) = &running {
                        cancel.cancel();
                    }
                    for _ in queue.drain(..) {
                        events.send(Event::TurnEnd {
                            reason: StopReason::Cancelled,
                            detail: Some("Not run: the turn before it was stopped.".into()),
                        });
                    }
                }
                Some(Command::Permission { id, option }) => {
                    shared.broker.answer_permission(&id, option);
                }
                Some(Command::Answer { id, answer }) => {
                    shared.broker.answer_question(&id, answer);
                }
                Some(Command::SetModel { model }) => set_model(&shared, &model),
                Some(Command::SetMode { mode }) => set_mode(&shared, &mode, running.is_some()),
            }
        }
    }
    if let Some((cancel, task)) = running.take() {
        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    }
    starting.abort();
    let mcp = core.mcp.borrow().clone();
    if let Some(mcp) = mcp {
        mcp.close().await;
    }
    events.send(Event::Exit { code: Some(0), message: "Yougori stopped.".into() });
}

/// Starts a prompt's turn; a panic in it still ends the turn for the screen.
fn begin(
    core: &Arc<Core>,
    session: &Arc<tokio::sync::Mutex<Session>>,
    text: String,
    done: &mpsc::UnboundedSender<()>,
) -> (Cancel, tokio::task::JoinHandle<()>) {
    let cancel = Cancel::new();
    let (core, session, done, token) = (core.clone(), session.clone(), done.clone(), cancel.clone());
    let task = tokio::spawn(async move {
        let events = core.shared.events.clone();
        let inner = tokio::spawn(async move { prompt(&core, &session, text, &token).await });
        if let Err(error) = inner.await {
            if error.is_panic() {
                events.send(Event::TurnEnd {
                    reason: StopReason::Error,
                    detail: Some("The engine hit an internal error, so this turn stopped. The session is kept.".into()),
                });
            }
        }
        let _ = done.send(());
    });
    (cancel, task)
}

fn set_model(shared: &Shared, model: &str) {
    let model = model.trim();
    if model.is_empty() {
        return;
    }
    *lock(&shared.model) = model.to_owned();
    // Another model counts tokens its own way.
    *lock(&shared.ratio) = None;
    shared.events.send(Event::Model { model: model.to_owned() });
}

fn set_mode(shared: &Shared, mode: &str, busy: bool) {
    match shared.profiles.mode(mode.trim()) {
        Ok(profile) => {
            let title = profile.title();
            *lock(&shared.mode) = profile.name.clone();
            send_modes(shared);
            if busy {
                shared.events.notice(Level::Info, format!("{title} mode starts with your next message."));
            }
        }
        Err(error) => shared.events.notice(Level::Error, error),
    }
}

async fn check_model(shared: &Shared) {
    let Ok(models) = shared.llm.models().await else { return };
    let model = shared.model();
    if !models.is_empty() && !models.contains(&model) {
        let listed: Vec<&str> = models.iter().take(10).map(String::as_str).collect();
        shared.events.notice(
            Level::Warn,
            format!("The inference does not list the model {model}, so requests may fail. It lists: {}.", listed.join(", ")),
        );
    }
}

/// `/name rest` when the text is a command (a path such as `/usr/bin` is not).
fn slash(text: &str) -> Option<(&str, &str)> {
    let rest = text.trim_start().strip_prefix('/')?;
    let (name, args) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
    (!name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')).then_some((name, args.trim()))
}

async fn prompt(core: &Arc<Core>, session: &tokio::sync::Mutex<Session>, text: String, cancel: &Cancel) {
    let mut session = session.lock().await;
    let (reason, detail) = match slash(&text) {
        Some(("new", _)) => fresh(&core.shared, &mut session),
        Some(("sessions", _)) => resume(core, &mut session, cancel).await,
        Some(("compact", _)) => compact(core, &mut session, cancel).await,
        Some(("init", rest)) => {
            let rest = rest.to_owned();
            init(core, &mut session, &rest, cancel).await
        }
        Some((name, _)) => {
            let names: Vec<String> = COMMANDS.iter().map(|(n, _)| format!("/{n}")).collect();
            core.shared.events.notice(Level::Error, format!("There is no command /{name}. Commands: {}.", names.join(", ")));
            (StopReason::EndTurn, None)
        }
        None => turn(core, &mut session, text, None, cancel).await,
    };
    core.shared.events.send(Event::TurnEnd { reason, detail });
}

/// The MCP servers, once started; None when the person stopped the turn first.
async fn wait_mcp(core: &Core, cancel: &Cancel) -> Option<Arc<Mcp>> {
    let mut receiver = core.mcp.clone();
    tokio::select! {
        ready = receiver.wait_for(|m| m.is_some()) => {
            Some(ready.ok().and_then(|m| m.clone()).unwrap_or_default())
        }
        _ = cancel.cancelled() => None,
    }
}

fn ending(shared: &Shared, outcome: Outcome) -> (StopReason, Option<String>) {
    match outcome {
        Outcome::Done => (StopReason::EndTurn, None),
        Outcome::MaxSteps(limit) => {
            (StopReason::MaxSteps, Some(format!("Stopped after {limit} steps. Send a message to let it go on.")))
        }
        Outcome::MaxTokens => (
            StopReason::MaxTokens,
            Some(format!("The reply reached the output limit of {} tokens.", shared.spec.max_output)),
        ),
        Outcome::Cancelled(detail) => (StopReason::Cancelled, detail),
        Outcome::Failed(message) => {
            shared.events.notice(Level::Error, message.clone());
            (StopReason::Error, Some(message))
        }
    }
}

/// Creates the stored session at its first prompt, or records the model and mode in use.
async fn keep(core: &Core, session: &mut Session, first: &str, mode: &str) {
    let Some(store) = &core.store else { return };
    let model = core.shared.model();
    let mode = mode.to_owned();
    match session.id.clone() {
        Some(id) => {
            let _ = store::with(store, move |s| s.touch(&id, &model, &mode)).await;
        }
        None => {
            let id = core.shared.fresh(|| util::new_id("s"));
            let title = store::title(first);
            let cwd = core.shared.vars.cwd.clone();
            let (new_id, new_title) = (id.clone(), title.clone());
            match store::with(store, move |s| s.create(&new_id, &new_title, &cwd, &model, &mode)).await {
                Ok(()) => {
                    session.id = Some(id);
                    session.title = title;
                }
                Err(error) => core.shared.events.notice(Level::Warn, format!("This session is not being saved: {error}")),
            }
        }
    }
}

fn persist(core: &Core, session: &Session) -> Option<Persist> {
    match (&core.store, &session.id) {
        (Some(store), Some(id)) => Some(Persist::new(store.clone(), id.clone())),
        _ => None,
    }
}

/// One prompt to the model: `text` is what it gets, `typed` what the person typed when different.
async fn turn(core: &Arc<Core>, session: &mut Session, text: String, typed: Option<String>, cancel: &Cancel) -> (StopReason, Option<String>) {
    let shared = &core.shared;
    if text.trim().is_empty() {
        return (StopReason::EndTurn, None);
    }
    let Some(mcp) = wait_mcp(core, cancel).await else { return (StopReason::Cancelled, None) };
    // A server slow to list its changed tools does not hold up the person's Esc.
    mcp.refresh(&shared.events, cancel).await;
    if cancel.is_cancelled() {
        return (StopReason::Cancelled, None);
    }
    let mode = shared.mode();
    let profile = match shared.profiles.mode(&mode) {
        Ok(profile) => profile.clone(),
        Err(error) => return ending(shared, Outcome::Failed(error)),
    };
    let shown = typed.clone().unwrap_or_else(|| text.clone());
    keep(core, session, &shown, &mode).await;
    let mut message = Msg::user(text);
    message.typed = typed;
    if session.mode.as_ref().is_some_and(|before| *before != mode) {
        let change = if profile.offers("edit") || profile.offers("write") {
            format!("(The person switched to {} mode: you may change files and run commands again.)", profile.name)
        } else {
            format!("(The person switched to {} mode: do not change files now; study and plan instead.)", profile.name)
        };
        message.typed = Some(shown.clone());
        message.text = format!("{change}\n\n{}", message.text);
    }
    session.mode = Some(mode);
    let turn = Turn { shared: shared.clone(), cancel: cancel.clone(), mcp };
    let stored = persist(core, session);
    // The agent works on the session's own conversation: should the turn panic, the session
    // still holds every message it stored, and the next one goes after them.
    let mut agent = Agent::new(&turn, profile, None, &mut session.conv, stored);
    agent.push(message).await;
    let outcome = agent.run().await;
    ending(shared, outcome)
}

fn fresh(shared: &Shared, session: &mut Session) -> (StopReason, Option<String>) {
    *session = Session::default();
    lock(&shared.todos).clear();
    lock(&shared.files).clear();
    shared.events.send(Event::Plan { entries: Vec::new() });
    shared.events.send(Event::Usage(Usage {
        context_tokens: Some(0),
        context_window: Some(shared.spec.context_window as u64),
        ..Usage::default()
    }));
    shared.events.notice(Level::Info, "Started a new session.");
    (StopReason::EndTurn, None)
}

async fn compact(core: &Arc<Core>, session: &mut Session, cancel: &Cancel) -> (StopReason, Option<String>) {
    let shared = &core.shared;
    if session.conv.is_empty() {
        shared.events.notice(Level::Info, "There is nothing to compact yet.");
        return (StopReason::EndTurn, None);
    }
    let Some(mcp) = wait_mcp(core, cancel).await else { return (StopReason::Cancelled, None) };
    let profile = match shared.profiles.mode(&shared.mode()) {
        Ok(profile) => profile.clone(),
        Err(error) => return ending(shared, Outcome::Failed(error)),
    };
    let turn = Turn { shared: shared.clone(), cancel: cancel.clone(), mcp };
    let stored = persist(core, session);
    let mut agent = Agent::new(&turn, profile, None, &mut session.conv, stored);
    let result = agent.compact(Why::Asked).await;
    match result {
        Ok(true) => {
            shared.events.notice(Level::Info, "Summarised the conversation. The model now sees the summary and the latest message.");
            (StopReason::EndTurn, None)
        }
        Ok(false) => {
            shared.events.notice(Level::Info, "There is nothing to compact yet.");
            (StopReason::EndTurn, None)
        }
        Err(outcome) => ending(shared, outcome),
    }
}

async fn init(core: &Arc<Core>, session: &mut Session, rest: &str, cancel: &Cancel) -> (StopReason, Option<String>) {
    let shared = &core.shared;
    let mode = shared.mode();
    let can_write = shared.profiles.get(&mode).is_some_and(|p| p.offers("write") || p.offers("edit"));
    if !can_write {
        shared.events.notice(Level::Warn, format!("/init writes a file, which {mode} mode cannot do. Switch to yougori mode first."));
        return (StopReason::EndTurn, None);
    }
    let mut text = INIT_PROMPT.to_owned();
    if !rest.is_empty() {
        text.push_str(&format!("\n\nThe person adds: {rest}"));
    }
    let typed = format!("/init {rest}").trim().to_owned();
    turn(core, session, text, Some(typed), cancel).await
}

async fn resume(core: &Arc<Core>, session: &mut Session, cancel: &Cancel) -> (StopReason, Option<String>) {
    let shared = &core.shared;
    let Some(store) = core.store.clone() else {
        shared.events.notice(Level::Warn, "Sessions are not saved here, so there are none to resume.");
        return (StopReason::EndTurn, None);
    };
    let cwd = shared.vars.cwd.clone();
    let list = match store::with(&store, move |s| s.sessions(&cwd, 21)).await {
        Ok(list) => list,
        Err(error) => return ending(shared, Outcome::Failed(format!("The sessions could not be read: {error}"))),
    };
    let list: Vec<_> = list.into_iter().filter(|s| session.id.as_deref() != Some(s.id.as_str())).take(20).collect();
    if list.is_empty() {
        shared.events.notice(Level::Info, "There are no earlier sessions in this folder.");
        return (StopReason::EndTurn, None);
    }
    let choices: Vec<String> = list
        .iter()
        .enumerate()
        .map(|(n, s)| format!("{}. {} ({} UTC, {} messages)", n + 1, s.title, util::date_time(s.updated.max(0) as u64), s.messages))
        .collect();
    let request = QuestionRequest {
        id: shared.fresh(|| util::new_id("q")),
        question: "Which session should continue?".into(),
        choices: choices.clone(),
        multiple: false,
        allow_text: false,
    };
    let answer = match shared.broker.question(&shared.events, request, cancel).await {
        Ok(answer) => answer,
        Err(_) => return (StopReason::Cancelled, None),
    };
    let Some(picked) = answer.and_then(|a| a.into_iter().next()) else {
        shared.events.notice(Level::Info, "Kept the current session.");
        return (StopReason::EndTurn, None);
    };
    let index = choices
        .iter()
        .position(|c| *c == picked)
        .or_else(|| picked.trim().parse::<usize>().ok().and_then(|n| n.checked_sub(1)).filter(|n| *n < list.len()));
    let Some(index) = index else {
        shared.events.notice(Level::Warn, "That is not one of the sessions; kept the current one.");
        return (StopReason::EndTurn, None);
    };
    load(core, session, &store, &list[index].id).await
}

/// Opens a stored session: the model's context as compaction left it, the person's whole
/// history replayed on the screen, and the to-do list as it last stood.
async fn load(core: &Arc<Core>, session: &mut Session, store: &Arc<Store>, id: &str) -> (StopReason, Option<String>) {
    let shared = &core.shared;
    let wanted = id.to_owned();
    let (info, trim_before, rows) = match store::with(store, move |s| s.load(&wanted)).await {
        Ok(Some(found)) => found,
        Ok(None) => {
            shared.events.notice(Level::Warn, "That session no longer exists.");
            return (StopReason::EndTurn, None);
        }
        Err(error) => return ending(shared, Outcome::Failed(format!("The session could not be read: {error}"))),
    };
    let mut conv = Conversation { trim_before, ..Conversation::default() };
    let mut messages: Vec<Msg> = Vec::new();
    let mut summarised = false;
    let mut unreadable = 0;
    for row in &rows {
        conv.next_seq = conv.next_seq.max(row.seq + 1);
        match row.kind.as_str() {
            store::MESSAGE => match serde_json::from_str::<Msg>(&row.data) {
                Ok(msg) => {
                    for call in &msg.calls {
                        shared.claim(&call.id);
                        shared.claim(&call.event);
                    }
                    conv.entries.push(super::conversation::Entry { seq: row.seq, msg: msg.clone() });
                    messages.push(msg);
                }
                Err(_) => unreadable += 1,
            },
            store::SUMMARY => {
                let Ok(value) = serde_json::from_str::<Value>(&row.data) else { continue };
                if let (Some(head), Some(keep_from)) = (value["head"].as_str(), value["keep_from"].as_i64()) {
                    conv.entries.retain(|e| e.seq >= keep_from);
                    conv.head = Some(head.to_owned());
                    conv.request = value["request"].as_str().map(str::to_owned);
                    summarised = true;
                }
            }
            _ => {}
        }
    }
    let results: HashMap<String, Shown> = messages
        .iter()
        .filter(|m| m.role == Role::Tool)
        .filter_map(|m| Some((m.call.clone()?, m.shown.clone()?)))
        .collect();
    let mut plan: Vec<PlanEntry> = Vec::new();
    for msg in &messages {
        match msg.role {
            Role::User => shared.events.send(Event::User { text: msg.typed.clone().unwrap_or_else(|| msg.text.clone()) }),
            Role::Assistant => {
                let id = msg.id.clone().unwrap_or_else(|| util::new_id("m"));
                if !msg.reasoning.is_empty() {
                    let reasoning = format!("r{}", id.strip_prefix('m').unwrap_or(&id));
                    shared.events.send(Event::Reasoning { message: reasoning, text: msg.reasoning.clone(), parent: None });
                }
                if !msg.text.is_empty() {
                    shared.events.send(Event::Message { message: id.clone(), text: msg.text.clone(), parent: None });
                }
                for call in &msg.calls {
                    let shown = results.get(&call.id);
                    let input: Option<Value> = serde_json::from_str(&call.arguments).ok();
                    if call.name == "todowrite" {
                        if let Some(entries) = input.as_ref().and_then(|args| tools::todo::parse(args).ok()) {
                            plan = entries;
                        }
                    }
                    shared.events.send(Event::ToolCall(ToolCall {
                        id: if call.event.is_empty() { util::new_id("t") } else { call.event.clone() },
                        title: shown.map(|s| s.title.clone()).unwrap_or_else(|| call.name.clone()),
                        kind: shown.map(|s| s.kind).unwrap_or_default(),
                        status: shown.map(|s| s.status).unwrap_or(ToolStatus::Failed),
                        input: input.as_ref().map(super::agent::shown_input),
                        locations: shown.map(|s| s.locations.clone()).unwrap_or_default(),
                        content: shown.map(|s| s.content.clone()).unwrap_or_default(),
                        parent: None,
                    }));
                }
            }
            Role::Tool => {}
        }
    }
    *session = Session { id: Some(info.id.clone()), title: info.title.clone(), conv, mode: Some(info.profile.clone()) };
    lock(&shared.files).clear();
    *lock(&shared.todos) = plan.clone();
    shared.events.send(Event::Plan { entries: plan });
    let context = (estimate(&session.conv.wire(""), &[]) as f64 * shared.ratio()) as u64;
    shared.events.send(Event::Usage(Usage {
        context_tokens: Some(context),
        context_window: Some(shared.spec.context_window as u64),
        ..Usage::default()
    }));
    let mut note = format!("Resumed \u{201c}{}\u{201d}.", info.title);
    if summarised {
        note.push_str(" Its older messages were summarised; the model works from the summary.");
    }
    if unreadable > 0 {
        note.push_str(&format!(" {unreadable} stored messages could not be read and were left out."));
    }
    shared.events.notice(Level::Info, note);
    (StopReason::EndTurn, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::testutil::{call, say, spec, FakeServer};
    use crate::protocol::{ToolContent, ToolKind};
    use serde_json::json;

    async fn next(events: &mut mpsc::UnboundedReceiver<Event>, wanted: impl Fn(&Event) -> bool) -> Event {
        loop {
            let event = tokio::time::timeout(Duration::from_secs(20), events.recv()).await.expect("an event in time").expect("the engine runs");
            if wanted(&event) {
                return event;
            }
        }
    }

    async fn until_turn_end(events: &mut mpsc::UnboundedReceiver<Event>) -> Vec<Event> {
        let mut seen = Vec::new();
        loop {
            let event = tokio::time::timeout(Duration::from_secs(20), events.recv()).await.expect("an event in time").expect("the engine runs");
            let end = matches!(event, Event::TurnEnd { .. });
            seen.push(event);
            if end {
                return seen;
            }
        }
    }

    #[tokio::test]
    async fn unknown_profiles_and_missing_folders_fail_plainly() {
        let folder = tempfile::tempdir().unwrap();
        let mut bad = spec("http://127.0.0.1:9", folder.path(), &folder.path().join("state"));
        bad.profile = Some("pentestgpt".into());
        let error = start(&bad).await.err().unwrap().to_string();
        assert!(error.contains("no profile named pentestgpt") && error.contains("yougori, plan"), "{error}");
        bad.profile = Some("explore".into());
        assert!(start(&bad).await.err().unwrap().to_string().contains("helper"));
        bad.profile = Some("yougori".into());
        bad.cwd = folder.path().join("missing");
        assert!(start(&bad).await.err().unwrap().to_string().contains("does not exist"));
    }

    #[tokio::test]
    async fn a_prompt_runs_end_to_end_and_its_session_resumes() {
        let folder = tempfile::tempdir().unwrap();
        let work = folder.path().join("work");
        std::fs::create_dir_all(&work).unwrap();
        let server = FakeServer::start(|_, request| {
            let body = request.json();
            if request.path == "/models" {
                return crate::native::testutil::Reply::json(200, json!({"data": [{"id": "test-model"}]}));
            }
            let last = body["messages"].as_array().unwrap().last().unwrap().clone();
            if last["role"] == "tool" {
                say("Done: hello.txt is written.")
            } else {
                call("write", json!({"path": "hello.txt", "content": "hello\n"}))
            }
        })
        .await;
        let handle = start(&spec(&server.url, &work, &folder.path().join("state"))).await.unwrap();
        let mut events = handle.events;
        let commands = handle.commands;
        match next(&mut events, |e| matches!(e, Event::Ready(_))).await {
            Event::Ready(ready) => {
                assert_eq!(ready.model_switch, ModelSwitch::Live);
                assert_eq!(ready.harness, "yougori");
            }
            _ => unreachable!(),
        }
        match next(&mut events, |e| matches!(e, Event::Modes { .. })).await {
            Event::Modes { current, available } => {
                assert_eq!(current, "yougori");
                assert_eq!(available.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(), vec!["yougori", "plan"]);
            }
            _ => unreachable!(),
        }
        match next(&mut events, |e| matches!(e, Event::Commands { .. })).await {
            Event::Commands { commands } => assert_eq!(commands.len(), 4),
            _ => unreachable!(),
        }
        commands.send(Command::Prompt { text: "Write hello.txt".into() }).unwrap();
        let turn = until_turn_end(&mut events).await;
        assert!(matches!(turn.last(), Some(Event::TurnEnd { reason: StopReason::EndTurn, .. })), "{turn:?}");
        assert_eq!(std::fs::read_to_string(work.join("hello.txt")).unwrap(), "hello\n");
        let diff = turn.iter().any(|e| {
            matches!(e, Event::ToolUpdate(u) if u.status == Some(ToolStatus::Completed)
                && matches!(u.content.as_deref(), Some([ToolContent::Diff { old: None, .. }])))
        });
        assert!(diff, "{turn:?}");
        assert!(turn.iter().any(|e| matches!(e, Event::Message { text, .. } if text.contains("hello.txt is written"))));
        assert!(turn.iter().any(|e| matches!(e, Event::Usage(u) if u.context_window == Some(32768))));
        // A new session, then the first one back.
        commands.send(Command::Prompt { text: "/new".into() }).unwrap();
        let turn = until_turn_end(&mut events).await;
        assert!(turn.iter().any(|e| matches!(e, Event::Plan { entries } if entries.is_empty())));
        commands.send(Command::Prompt { text: "/sessions".into() }).unwrap();
        let question = match next(&mut events, |e| matches!(e, Event::Question(_))).await {
            Event::Question(question) => question,
            _ => unreachable!(),
        };
        assert!(question.choices[0].starts_with("1. Write hello.txt ("), "{:?}", question.choices);
        commands.send(Command::Answer { id: question.id.clone(), answer: Some(vec![question.choices[0].clone()]) }).unwrap();
        let replay = until_turn_end(&mut events).await;
        assert!(replay.iter().any(|e| matches!(e, Event::User { text } if text == "Write hello.txt")), "{replay:?}");
        assert!(replay.iter().any(|e| matches!(e, Event::ToolCall(c) if c.title == "Write hello.txt" && c.status == ToolStatus::Completed && c.kind == ToolKind::Edit)), "{replay:?}");
        assert!(replay.iter().any(|e| matches!(e, Event::Message { text, .. } if text.contains("is written"))));
        // The resumed session goes on with its history.
        commands.send(Command::Prompt { text: "And again".into() }).unwrap();
        until_turn_end(&mut events).await;
        let last = server.requests().into_iter().rfind(|r| r.path == "/chat/completions").unwrap().json();
        let contents: Vec<String> = last["messages"].as_array().unwrap().iter().map(|m| m["content"].as_str().unwrap_or("").to_owned()).collect();
        assert!(contents.iter().any(|c| c == "Write hello.txt"), "{contents:?}");
        commands.send(Command::Shutdown).unwrap();
        assert!(matches!(next(&mut events, |e| matches!(e, Event::Exit { .. })).await, Event::Exit { code: Some(0), .. }));
    }

    #[tokio::test]
    async fn modes_models_and_commands_switch_in_place() {
        let folder = tempfile::tempdir().unwrap();
        let server = FakeServer::start(|_, request| {
            let body = request.json();
            let system = body["messages"][0]["content"].as_str().unwrap_or("").to_owned();
            let user = body["messages"].as_array().map(|m| m.last().unwrap()["content"].as_str().unwrap_or("").to_owned()).unwrap_or_default();
            say(&format!("model={} plan={} switched={}", body["model"].as_str().unwrap_or(""), system.contains("plan mode"), user.contains("switched to plan mode")))
        })
        .await;
        let handle = start(&spec(&server.url, folder.path(), &folder.path().join("state"))).await.unwrap();
        let (commands, mut events) = (handle.commands, handle.events);
        commands.send(Command::Prompt { text: "first".into() }).unwrap();
        until_turn_end(&mut events).await;
        commands.send(Command::SetMode { mode: "plan".into() }).unwrap();
        assert!(matches!(next(&mut events, |e| matches!(e, Event::Modes { .. })).await, Event::Modes { current, .. } if current == "plan"));
        commands.send(Command::SetModel { model: "other-model".into() }).unwrap();
        assert!(matches!(next(&mut events, |e| matches!(e, Event::Model { .. })).await, Event::Model { model } if model == "other-model"));
        commands.send(Command::SetMode { mode: "nonsense".into() }).unwrap();
        assert!(matches!(next(&mut events, |e| matches!(e, Event::Notice { level: Level::Error, .. })).await, Event::Notice { .. }));
        commands.send(Command::Prompt { text: "second".into() }).unwrap();
        let turn = until_turn_end(&mut events).await;
        assert!(turn.iter().any(|e| matches!(e, Event::Message { text, .. } if text == "model=other-model plan=true switched=true")), "{turn:?}");
        commands.send(Command::Prompt { text: "/bogus".into() }).unwrap();
        let turn = until_turn_end(&mut events).await;
        assert!(turn.iter().any(|e| matches!(e, Event::Notice { text, .. } if text.contains("no command /bogus"))));
        commands.send(Command::Prompt { text: "/init".into() }).unwrap();
        let turn = until_turn_end(&mut events).await;
        assert!(turn.iter().any(|e| matches!(e, Event::Notice { text, .. } if text.contains("Switch to yougori mode"))), "{turn:?}");
        commands.send(Command::Prompt { text: "/compact".into() }).unwrap();
        let turn = until_turn_end(&mut events).await;
        assert!(matches!(turn.last(), Some(Event::TurnEnd { reason: StopReason::EndTurn, .. })));
        assert_eq!(slash("/usr/bin is broken"), None);
        assert_eq!(slash("/init  focus on tests "), Some(("init", "focus on tests")));
    }

    #[tokio::test]
    async fn prompts_wait_their_turn_and_cancel_drops_the_waiting_ones() {
        let folder = tempfile::tempdir().unwrap();
        let server = FakeServer::start(|_, _| {
            crate::native::testutil::Reply::sse_slow(
                vec![
                    b"data: {\"choices\":[{\"delta\":{\"content\":\"slow \"}}]}\n\n".to_vec(),
                    b"data: {\"choices\":[{\"delta\":{\"content\":\"reply\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n".to_vec(),
                ],
                Duration::from_secs(10),
            )
        })
        .await;
        let handle = start(&spec(&server.url, folder.path(), &folder.path().join("state"))).await.unwrap();
        let (commands, mut events) = (handle.commands, handle.events);
        commands.send(Command::Prompt { text: "one".into() }).unwrap();
        next(&mut events, |e| matches!(e, Event::Message { .. })).await;
        commands.send(Command::Prompt { text: "two".into() }).unwrap();
        commands.send(Command::Prompt { text: "three".into() }).unwrap();
        commands.send(Command::Cancel).unwrap();
        let mut ends = Vec::new();
        while ends.len() < 3 {
            if let Event::TurnEnd { reason, .. } = next(&mut events, |e| matches!(e, Event::TurnEnd { .. })).await {
                ends.push(reason);
            }
        }
        assert!(ends.iter().all(|r| *r == StopReason::Cancelled), "{ends:?}");
        // Dropping the handle stops the engine.
        drop(commands);
        assert!(matches!(next(&mut events, |e| matches!(e, Event::Exit { .. })).await, Event::Exit { .. }));
    }

    fn models_or(request: &crate::native::testutil::Recorded, reply: impl FnOnce(&str) -> crate::native::testutil::Reply) -> crate::native::testutil::Reply {
        if request.path == "/models" {
            return crate::native::testutil::Reply::json(200, json!({"data": [{"id": "test-model"}]}));
        }
        let body = request.json();
        let last = body["messages"].as_array().and_then(|m| m.last().cloned()).unwrap_or_default();
        reply(last["content"].as_str().unwrap_or(""))
    }

    #[tokio::test]
    async fn a_panic_in_a_turn_keeps_the_session_and_its_stored_messages() {
        let folder = tempfile::tempdir().unwrap();
        let work = folder.path().join("work");
        std::fs::create_dir_all(&work).unwrap();
        let server = FakeServer::start(|_, request| {
            models_or(request, |text| {
                if text == "second prompt" {
                    call(crate::native::agent::tests::PANIC_TOOL, json!({}))
                } else {
                    say(&format!("answer to: {text}"))
                }
            })
        })
        .await;
        let state = folder.path().join("state");
        let handle = start(&spec(&server.url, &work, &state)).await.unwrap();
        let (commands, mut events) = (handle.commands, handle.events);
        for text in ["first prompt", "second prompt", "third prompt"] {
            commands.send(Command::Prompt { text: text.into() }).unwrap();
            let turn = until_turn_end(&mut events).await;
            if text == "second prompt" {
                assert!(
                    matches!(turn.last(), Some(Event::TurnEnd { reason: StopReason::Error, detail: Some(d) }) if d.contains("internal error")),
                    "{turn:?}"
                );
            } else {
                assert!(matches!(turn.last(), Some(Event::TurnEnd { reason: StopReason::EndTurn, .. })), "{turn:?}");
            }
        }
        // The third prompt went to the model with the whole history.
        let last = server.requests().into_iter().rfind(|r| r.path == "/chat/completions").unwrap().json();
        let contents: Vec<String> = last["messages"].as_array().unwrap().iter().map(|m| m["content"].as_str().unwrap_or("").to_owned()).collect();
        for wanted in ["first prompt", "answer to: first prompt", "second prompt", "third prompt"] {
            assert!(contents.iter().any(|c| c == wanted), "{wanted} missing from {contents:?}");
        }
        commands.send(Command::Shutdown).unwrap();
        next(&mut events, |e| matches!(e, Event::Exit { .. })).await;
        // Nothing stored was overwritten: every message is there once, in order.
        let store = Store::open(&state.join("sessions.db")).unwrap();
        let sessions = store.sessions(&tools::slash(&tools::real(&work)), 10).unwrap();
        assert_eq!(sessions.len(), 1);
        let (_, _, rows) = store.load(&sessions[0].id).unwrap().unwrap();
        let texts: Vec<String> = rows.iter().map(|r| serde_json::from_str::<Msg>(&r.data).map(|m| m.text).unwrap_or_default()).collect();
        let at = |wanted: &str| texts.iter().position(|t| t == wanted).unwrap_or_else(|| panic!("{wanted} not stored: {texts:?}"));
        assert_eq!(at("first prompt"), 0);
        assert!(at("first prompt") < at("second prompt") && at("second prompt") < at("third prompt"), "{texts:?}");
        assert!(at("third prompt") < at("answer to: third prompt"), "{texts:?}");
    }

    /// Esc lands while the first call's result is being stored: the second call does not run.
    #[tokio::test(flavor = "current_thread")]
    async fn esc_between_two_calls_of_one_reply_stops_the_second() {
        for _ in 0..3 {
            let folder = tempfile::tempdir().unwrap();
            let work = folder.path().join("work");
            std::fs::create_dir_all(&work).unwrap();
            let chats = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let server = FakeServer::start(move |_, request| {
                models_or(request, |_| {
                    if chats.fetch_add(1, std::sync::atomic::Ordering::SeqCst) > 0 {
                        return say("done");
                    }
                    crate::native::testutil::Reply::sse(crate::native::testutil::sse_body(&[json!({"choices": [{"index": 0, "delta": {"tool_calls": [
                        {"index": 0, "id": "a", "type": "function", "function": {"name": "list", "arguments": "{}"}},
                        {"index": 1, "id": "b", "type": "function", "function": {"name": "write", "arguments": json!({"path": "after.txt", "content": "written after Esc\n"}).to_string()}}
                    ]}, "finish_reason": "tool_calls"}]})]))
                })
            })
            .await;
            let handle = start(&spec(&server.url, &work, &folder.path().join("state"))).await.unwrap();
            let (commands, mut events) = (handle.commands, handle.events);
            commands.send(Command::Prompt { text: "go".into() }).unwrap();
            next(&mut events, |e| matches!(e, Event::ToolUpdate(u) if u.status == Some(ToolStatus::Completed))).await;
            commands.send(Command::Cancel).unwrap();
            let end = next(&mut events, |e| matches!(e, Event::TurnEnd { .. })).await;
            assert!(matches!(end, Event::TurnEnd { reason: StopReason::Cancelled, .. }), "{end:?}");
            assert!(!work.join("after.txt").exists(), "the write ran after Esc");
            commands.send(Command::Shutdown).unwrap();
            next(&mut events, |e| matches!(e, Event::Exit { .. })).await;
        }
    }

    #[tokio::test]
    async fn esc_while_an_mcp_server_relists_its_tools_ends_the_turn_at_once() {
        let folder = tempfile::tempdir().unwrap();
        let server = FakeServer::start(|_, _| say("hello")).await;
        let (sender, mut events) = mpsc::unbounded_channel();
        let (shared, _) = Shared::new(&spec(&server.url, folder.path(), &folder.path().join("state")), Events::new(sender), "yougori").unwrap();
        let slow = crate::native::mcp::tests::changed_then_silent("slow").await;
        let (_starter, mcp) = watch::channel(Some(Arc::new(Mcp::with(vec![slow]))));
        let core = Arc::new(Core { shared: Arc::new(shared), store: None, mcp });
        let session = Arc::new(tokio::sync::Mutex::new(Session::default()));
        let (done, _finished) = mpsc::unbounded_channel();
        let (cancel, _task) = begin(&core, &session, "hi".into(), &done);
        tokio::time::sleep(Duration::from_millis(300)).await;
        let pressed = std::time::Instant::now();
        cancel.cancel();
        let end = next(&mut events, |e| matches!(e, Event::TurnEnd { .. })).await;
        assert!(matches!(end, Event::TurnEnd { reason: StopReason::Cancelled, .. }), "{end:?}");
        assert!(pressed.elapsed() < Duration::from_secs(5), "{:?}", pressed.elapsed());
        assert!(server.requests().is_empty(), "the model was never asked");
    }

    #[tokio::test]
    async fn a_resumed_session_keeps_the_request_its_summary_kept() {
        let folder = tempfile::tempdir().unwrap();
        let (sender, _events) = mpsc::unbounded_channel();
        let (shared, _) = Shared::new(&spec("http://127.0.0.1:9", folder.path(), &folder.path().join("state")), Events::new(sender), "yougori").unwrap();
        let store = Arc::new(Store::open(&folder.path().join("sessions.db")).unwrap());
        store.create("s1", "Port the parser", &shared.vars.cwd, "m", "yougori").unwrap();
        let rows = [
            (0, store::MESSAGE, serde_json::to_string(&Msg::user("Port the parser")).unwrap()),
            (1, store::MESSAGE, serde_json::to_string(&Msg::assistant("m-1", "step".into(), String::new(), Vec::new())).unwrap()),
            (2, store::SUMMARY, json!({"head": "Notes.", "keep_from": 1, "request": "Port the parser"}).to_string()),
        ];
        for (seq, kind, data) in rows {
            store.append("s1", seq, kind, &data).unwrap();
        }
        let (_starter, mcp) = watch::channel(None);
        let core = Arc::new(Core { shared: Arc::new(shared), store: Some(store.clone()), mcp });
        let mut session = Session::default();
        let (reason, _) = load(&core, &mut session, &store, "s1").await;
        assert_eq!(reason, StopReason::EndTurn);
        assert_eq!(session.conv.head.as_deref(), Some("Notes."));
        assert_eq!(session.conv.request.as_deref(), Some("Port the parser"));
        assert_eq!((session.conv.entries.len(), session.conv.next_seq), (1, 3));
    }
}
