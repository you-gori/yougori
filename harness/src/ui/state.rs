//! The screen's state and how engine events change it. Keys are in `keys.rs`, drawing in
//! `draw.rs`; the run loop (`mod.rs`) carries out the [`Effect`]s this state asks for.
use super::dialog::Dialog;
use super::input::{Editor, History};
use super::mask::Masker;
use super::overlay::{Action, Choice, Confirmable, Item, Outcome, Overlay, Which};
use super::text::clean;
use super::theme::Theme;
use super::transcript::{Key, Transcript};
use crate::protocol::{Command, Event, Level, Mode, ModelSwitch, PlanEntry, SlashCommand, StopReason, ToolCall, Usage};
use crate::spec::EngineSpec;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Ctrl+C twice within this quits.
pub const QUIT_WINDOW: Duration = Duration::from_secs(2);

#[derive(Clone, Debug, PartialEq)]
pub enum Phase {
    /// The engine is starting (first start, or again after it stopped).
    Starting {
        since: Instant,
    },
    Ready,
    /// Switching models by restarting the engine.
    Switching {
        model: String,
        since: Instant,
        step: String,
    },
    /// The engine stopped or could not start; the screen stays until the person quits.
    Stopped {
        title: String,
        message: String,
        failed: bool,
    },
    /// The person quit; the engine is being stopped.
    Quitting {
        since: Instant,
    },
}

/// What the run loop does for the state.
#[derive(Clone, Debug, PartialEq)]
pub enum Effect {
    Send(Command),
    /// Start the spec's engine (again).
    Start,
    /// Switch to this model by restarting the engine through the spec's `respec`.
    Restart(String),
    /// Paint the whole screen again.
    Redraw,
    Quit,
}

pub struct Turn {
    pub started: Instant,
    pub stopping: bool,
    /// The prompt that started it.
    pub prompt: String,
    /// A resumed session's history is being replayed into a cleared conversation.
    pub replaying: bool,
}

/// Whether a prompt asks to resume an earlier session (its history is then replayed).
fn resumes(prompt: &str) -> bool {
    let prompt = prompt.trim();
    prompt == "/sessions" || prompt.starts_with("/sessions ")
}

/// Where the conversation view is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scroll {
    /// Showing the newest lines as they come.
    Follow,
    /// Held at a line of an entry (None: the header).
    At { key: Option<Key>, offset: usize },
}

/// The conversation view as last drawn, for scrolling.
#[derive(Clone, Debug, Default)]
pub struct View {
    /// Each block's key (None for the header), first line and height.
    pub blocks: Vec<(Option<Key>, usize, usize)>,
    pub total: usize,
    pub height: usize,
    pub top: usize,
}

pub struct App {
    pub spec: EngineSpec,
    pub theme: Theme,
    pub masker: Masker,
    pub version: String,
    pub epoch: Instant,
    /// The screen started the engine itself (and can start it again).
    pub owns_engine: bool,

    pub phase: Phase,
    pub name: String,
    pub model: String,
    pub models: Vec<String>,
    pub model_switch: ModelSwitch,
    pub session: Option<String>,
    pub info: Option<String>,
    pub ready_once: bool,

    pub transcript: Transcript,
    pub plan: Vec<PlanEntry>,
    /// Findings by severity: critical, high, medium, low, info.
    pub findings: [usize; 5],
    pub usage: Usage,
    pub modes: Vec<Mode>,
    pub mode: Option<String>,
    pub commands: Vec<SlashCommand>,
    pub turn: Option<Turn>,
    /// Prompts sent in this conversation, and the one the plan was last updated in.
    pub turns: u64,
    pub plan_turn: u64,
    /// Something was said in this conversation (the keys line under the box goes away).
    pub conversed: bool,
    pub queued: VecDeque<String>,

    pub dialogs: VecDeque<Dialog>,
    pub overlay: Option<Overlay>,

    pub input: Editor,
    pub history: History,
    pub completion: usize,
    pub completion_closed: Option<String>,

    pub details: bool,
    pub scroll: Scroll,
    pub view: View,
    /// The prompt box's text width, from the last frame.
    pub input_width: usize,
    pub quit_armed: Option<Instant>,
    pub failed: bool,
    pub effects: Vec<Effect>,
    pub dirty: bool,
    /// Whether the terminal tells Shift+Enter from Enter; the keys line and the keys help then
    /// name it for a new line, else Ctrl+J.
    pub shift_enter: bool,
    /// The last prompt this screen sent, to drop an engine's echo of it.
    echo: Option<String>,
    /// While a restart switch is prepared: the phase to go back to if the new model cannot be.
    switch_from: Option<Phase>,
}

impl App {
    pub fn new(spec: EngineSpec, theme: Theme, masker: Masker, owns_engine: bool, now: Instant) -> App {
        let models = if spec.models.is_empty() { vec![spec.model.clone()] } else { spec.models.clone() };
        App {
            name: spec.name.clone(),
            model: spec.model.clone(),
            model_switch: spec.model_switch,
            models,
            spec,
            theme,
            masker,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            epoch: now,
            owns_engine,
            phase: Phase::Starting { since: now },
            session: None,
            info: None,
            ready_once: false,
            transcript: Transcript::default(),
            plan: Vec::new(),
            findings: [0; 5],
            usage: Usage::default(),
            modes: Vec::new(),
            mode: None,
            commands: Vec::new(),
            turn: None,
            turns: 0,
            plan_turn: 0,
            conversed: false,
            queued: VecDeque::new(),
            dialogs: VecDeque::new(),
            overlay: None,
            input: Editor::default(),
            history: History::default(),
            completion: 0,
            completion_closed: None,
            details: false,
            scroll: Scroll::Follow,
            view: View::default(),
            input_width: 60,
            quit_armed: None,
            failed: false,
            effects: Vec::new(),
            dirty: true,
            shift_enter: true,
            echo: None,
            switch_from: None,
        }
    }

    pub fn security(&self) -> bool {
        self.spec.category == "security"
    }

    /// Something runs: a turn, or tool calls and progress the engine started on its own.
    pub fn busy(&self) -> bool {
        self.turn.is_some() || self.transcript.live()
    }

    /// Since when the current work runs.
    pub fn busy_since(&self) -> Option<Instant> {
        self.turn.as_ref().map(|t| t.started).or_else(|| self.transcript.live_since())
    }

    pub fn stopped(&self) -> bool {
        matches!(self.phase, Phase::Stopped { .. })
    }

    /// Whether the screen changes by itself (spinners, clocks, the quit hint).
    pub fn animating(&self, now: Instant) -> bool {
        // The quit hint gets one more frame after it expires, to take it away.
        self.busy()
            || matches!(self.phase, Phase::Starting { .. } | Phase::Switching { .. } | Phase::Quitting { .. })
            || self
                .quit_armed
                .is_some_and(|t| now.saturating_duration_since(t) < QUIT_WINDOW + Duration::from_millis(300))
    }

    /// The first screen: nothing said yet in this conversation.
    pub fn first_screen(&self) -> bool {
        !self.conversed
    }

    /// How much of the context window the conversation takes, for the status line. The window
    /// is the smaller of the engine's and the model's. An engine that does not know the model
    /// reports its own default (Gemini CLI reports 1,048,576 tokens), but the model holds only
    /// the window in the spec.
    pub fn context_share(&self) -> Option<f64> {
        let tokens = self.usage.context_tokens?;
        let window = [self.usage.context_window, Some(u64::from(self.spec.context_window))]
            .into_iter()
            .flatten()
            .filter(|window| *window > 0)
            .min()?;
        Some(tokens as f64 / window as f64)
    }

    pub fn exit_code(&self) -> i32 {
        i32::from(self.failed)
    }

    pub fn send(&mut self, command: Command) {
        self.effects.push(Effect::Send(command));
    }

    /// Applies one engine event.
    pub fn apply(&mut self, event: Event, now: Instant) {
        self.dirty = true;
        match event {
            Event::Ready(ready) => {
                let again = self.ready_once;
                if !ready.name.trim().is_empty() {
                    self.name = ready.name;
                }
                if !ready.model.trim().is_empty() {
                    self.model = ready.model;
                }
                if !ready.models.is_empty() {
                    self.models = ready.models;
                }
                if !self.models.contains(&self.model) {
                    self.models.insert(0, self.model.clone());
                }
                self.model_switch = ready.model_switch;
                if again && ready.session.is_some() && self.session.is_some() && ready.session != self.session {
                    self.transcript.divider("A new session started");
                }
                self.session = ready.session;
                self.info = ready.info.map(|i| clean(&i).replace('\n', " ")).filter(|i| !i.trim().is_empty());
                self.phase = Phase::Ready;
                self.ready_once = true;
                self.failed = false;
                if self.turn.take().is_some() {
                    self.transcript.end_turn();
                }
                self.dialogs.clear();
                self.send_queued(now);
            }
            Event::Message { message, text, parent } => {
                self.conversed = true;
                self.replay_starts();
                self.transcript.message(&message, &text, parent.as_deref());
            }
            Event::Reasoning { message, text, parent } => {
                self.replay_starts();
                self.transcript.reasoning(&message, &text, parent.as_deref());
            }
            Event::User { text } => {
                let echoed = self.echo.as_deref().is_some_and(|sent| sent.trim() == text.trim())
                    && self.transcript.last_user_text().is_some_and(|last| last.trim() == clean(&text).trim());
                if echoed {
                    self.echo = None;
                } else {
                    self.conversed = true;
                    self.replay_starts();
                    self.transcript.user(&text);
                }
            }
            Event::ToolCall(call) => {
                self.replay_starts();
                self.transcript.tool_call(&call, now);
                self.settled(&call.id, Some(call.status), now);
            }
            Event::ToolUpdate(update) => {
                self.settled(&update.id, update.status, now);
                if !self.transcript.tool_update(&update, now) {
                    // An update for a call never announced: show it as a call of its own.
                    let call = ToolCall {
                        id: update.id.clone(),
                        title: update.title.clone().unwrap_or_else(|| "Tool call".into()),
                        status: update.status.unwrap_or_default(),
                        content: update.content.clone().unwrap_or_default(),
                        locations: update.locations.clone().unwrap_or_default(),
                        ..Default::default()
                    };
                    self.transcript.tool_call(&call, now);
                }
            }
            Event::Permission(request) => self.dialogs.push_back(Dialog::permission(request, now)),
            Event::Question(request) => self.dialogs.push_back(Dialog::question(request, now)),
            Event::Plan { entries } => {
                self.plan = entries;
                self.plan_turn = self.turns;
            }
            Event::Finding(finding) => {
                self.findings[finding.severity as usize] += 1;
                self.transcript.finding(&finding);
            }
            Event::Report(report) => self.transcript.report(&report),
            Event::Progress(progress) => self.transcript.progress(&progress, now),
            Event::Usage(usage) => {
                let u = &mut self.usage;
                u.context_tokens = usage.context_tokens.or(u.context_tokens);
                u.context_window = usage.context_window.or(u.context_window);
                u.input_tokens = usage.input_tokens.or(u.input_tokens);
                u.output_tokens = usage.output_tokens.or(u.output_tokens);
            }
            Event::Model { model } => {
                if !model.trim().is_empty() && model != self.model {
                    self.transcript.notice(Level::Info, &format!("Now using {model}."));
                    if !self.models.contains(&model) {
                        self.models.push(model.clone());
                    }
                    self.model = model;
                }
            }
            Event::Modes { current, available } => {
                self.mode = Some(current).filter(|m| !m.is_empty());
                self.modes = available;
            }
            Event::Commands { commands } => self.commands = commands,
            Event::TurnEnd { reason, detail } => self.turn_ended(reason, detail, now),
            Event::Notice { level, text } => self.transcript.notice(level, &text),
            Event::Exit { code, message } => {
                let failed = code != Some(0);
                let mut message = clean(&message).trim().to_owned();
                if failed && message.is_empty() {
                    if let Some(code) = code {
                        message = format!("Exit code {code}.");
                    }
                }
                let title = if failed { format!("{} stopped", self.name) } else { format!("{} ended", self.name) };
                self.stop(title, message, failed);
            }
        }
    }

    fn turn_ended(&mut self, reason: StopReason, detail: Option<String>, now: Instant) {
        self.transcript.end_turn();
        self.turn = None;
        self.dialogs.clear();
        // The engine's own words when it gives them, else a plain default.
        let detail = detail.map(|d| clean(&d).trim().to_owned()).filter(|d| !d.is_empty());
        let said = |default: &str| detail.clone().unwrap_or_else(|| default.to_owned());
        match reason {
            StopReason::EndTurn => {}
            StopReason::Cancelled => self.transcript.notice(Level::Info, &said("Stopped.")),
            StopReason::MaxSteps => {
                self.transcript.notice(Level::Warn, &said("Step limit reached. Send a message to continue."))
            }
            StopReason::MaxTokens => self.transcript.notice(Level::Warn, &said("The reply reached the output limit.")),
            StopReason::Refused => self.transcript.notice(Level::Warn, &said("The model declined.")),
            StopReason::Error => {
                // An engine that already said it in an error notice is not repeated.
                let shown = match &detail {
                    Some(d) => self.transcript.recent_notice(Level::Error, d),
                    None => false,
                };
                if !shown {
                    self.transcript.notice(Level::Error, &said("The turn failed."));
                }
            }
        }
        if matches!(reason, StopReason::Cancelled | StopReason::Error) {
            self.unqueue();
        } else {
            self.send_queued(now);
        }
    }

    /// A resumed session's history starts: the conversation shown is replaced by it.
    fn replay_starts(&mut self) {
        let starts = self.turn.as_ref().is_some_and(|t| resumes(&t.prompt) && !t.replaying);
        if starts {
            self.transcript.clear();
            self.plan.clear();
            self.findings = [0; 5];
            self.usage = Usage::default();
            self.scroll = Scroll::Follow;
            if let Some(turn) = self.turn.as_mut() {
                turn.replaying = true;
            }
        }
    }

    /// A tool call moved on: a permission still asked for it was settled by another answer
    /// (an "always" rule), so its dialog goes.
    fn settled(&mut self, tool: &str, status: Option<crate::protocol::ToolStatus>, now: Instant) {
        use crate::protocol::ToolStatus;
        if matches!(status, Some(ToolStatus::InProgress | ToolStatus::Completed | ToolStatus::Failed)) {
            let front = self.dialogs.front().map(|d| d.id().to_owned());
            self.dialogs.retain(
                |d| !matches!(d, Dialog::Permission { request, .. } if request.tool_call.as_deref() == Some(tool)),
            );
            if self.dialogs.front().map(Dialog::id) != front.as_deref() {
                self.front_shown(now);
            }
        }
    }

    /// The dialog at the front shows from now (it came forward, or what covered it closed): keys
    /// that answer wait its settle time, so a press meant for what was there before cannot
    /// answer a request the person has not seen.
    pub fn front_shown(&mut self, now: Instant) {
        if let Some(dialog) = self.dialogs.front_mut() {
            dialog.show(now);
        }
    }

    /// The engine stopped: what it said stays on screen until the person quits, and in the
    /// conversation after that.
    pub fn stop(&mut self, title: String, message: String, failed: bool) {
        self.dirty = true;
        if self.turn.take().is_some() || self.transcript.live() {
            self.transcript.end_turn();
        }
        self.dialogs.clear();
        let record = if message.is_empty() { format!("{title}.") } else { format!("{title}: {message}") };
        self.transcript.notice(if failed { Level::Error } else { Level::Info }, &record);
        self.failed = failed;
        self.phase = Phase::Stopped { title, message, failed };
        self.unqueue();
    }

    /// The engine's events ended without an Exit.
    pub fn engine_closed(&mut self) {
        if matches!(self.phase, Phase::Starting { .. } | Phase::Ready) {
            self.stop(format!("{} stopped", self.name), "It ended without saying why.".into(), true);
        }
    }

    pub fn start_failed(&mut self, error: &str) {
        self.stop(format!("{} could not start", self.name), clean(error).trim().to_owned(), true);
    }

    /// The engine's start began (again).
    pub fn starting(&mut self, now: Instant) {
        self.phase = Phase::Starting { since: now };
        self.dirty = true;
    }

    fn send_queued(&mut self, now: Instant) {
        if self.turn.is_none() && self.phase == Phase::Ready {
            if let Some(text) = self.queued.pop_front() {
                self.send_prompt(text, now);
            }
        }
    }

    /// Queued prompts go back into the box, to send again or change.
    fn unqueue(&mut self) {
        if self.queued.is_empty() {
            return;
        }
        let mut parts: Vec<String> = self.queued.drain(..).collect();
        if !self.input.is_empty() {
            parts.push(self.input.text().to_owned());
        }
        self.input.set(&parts.join("\n\n"));
    }

    fn offers(&self, command: &str) -> bool {
        self.commands.iter().any(|c| c.name == command)
    }

    pub fn send_prompt(&mut self, text: String, now: Instant) {
        if text.trim() == "/new" && self.offers("new") {
            self.transcript.clear();
            self.plan.clear();
            self.findings = [0; 5];
            self.usage = Usage::default();
            self.scroll = Scroll::Follow;
        }
        self.transcript.user(&text);
        self.echo = Some(text.clone());
        self.conversed = true;
        self.turns += 1;
        self.turn = Some(Turn { started: now, stopping: false, prompt: text.clone(), replaying: false });
        self.scroll = Scroll::Follow;
        self.send(Command::Prompt { text });
        self.dirty = true;
    }

    /// Enter in the prompt box.
    pub fn submit(&mut self, now: Instant) {
        let text = self.input.text().trim_end().to_owned();
        if text.trim().is_empty() {
            return;
        }
        self.history.push(&text);
        self.input.clear();
        self.completion_closed = None;
        match self.phase {
            Phase::Ready if self.turn.is_none() => self.send_prompt(text, now),
            Phase::Ready | Phase::Starting { .. } | Phase::Switching { .. } => {
                self.queued.push_back(text);
            }
            Phase::Stopped { .. } | Phase::Quitting { .. } => {
                self.input.set(&text);
            }
        }
        self.dirty = true;
    }

    /// Esc while work runs: asks the engine to stop the turn.
    pub fn cancel(&mut self) -> bool {
        // Only a turn stops: work the engine does on its own (starting its servers) goes on.
        if self.turn.is_none() || self.phase != Phase::Ready {
            return false;
        }
        if let Some(turn) = self.turn.as_mut() {
            turn.stopping = true;
        }
        self.send(Command::Cancel);
        self.unqueue();
        self.dirty = true;
        true
    }

    /// Quit, asking first while a turn runs.
    pub fn request_quit(&mut self) {
        if self.turn.is_some() && self.phase == Phase::Ready {
            self.overlay = Some(Overlay::Confirm {
                what: Confirmable::Quit,
                title: format!("Quit while {} is working?", self.name),
                detail: format!("The running turn stops and {} ends.", self.name),
                yes: "quit".into(),
            });
        } else {
            self.quit();
        }
    }

    pub fn quit(&mut self) {
        self.overlay = None;
        if !matches!(self.phase, Phase::Quitting { .. }) {
            self.effects.push(Effect::Quit);
        }
    }

    /// The command palette's entries for the engine's state.
    pub fn palette(&self) -> Vec<Item> {
        let not_offered = format!("not offered by {}", self.name);
        let slash = |name: &str, label: &str| Item {
            action: Action::Slash(name.into()),
            label: label.into(),
            hint: if self.offers(name) { format!("/{name}") } else { not_offered.clone() },
            enabled: self.offers(name) && self.phase == Phase::Ready,
        };
        let mode_name = self.mode_name().unwrap_or_default();
        let mut items = vec![
            Item {
                action: Action::Model,
                label: "Switch model".into(),
                hint: self.model.clone(),
                // Not while the engine starts or switches: wait for it.
                enabled: matches!(self.phase, Phase::Ready | Phase::Stopped { .. }),
            },
            Item {
                action: Action::Mode,
                label: "Switch mode".into(),
                hint: if self.modes.is_empty() { not_offered.clone() } else { mode_name },
                enabled: !self.modes.is_empty() && self.phase == Phase::Ready,
            },
            slash("new", "New session"),
            slash("sessions", "Sessions"),
            slash("compact", "Compact"),
            Item {
                action: Action::Details,
                label: if self.details { "Hide details".into() } else { "Show details".into() },
                hint: "thinking and full output · ctrl+o".into(),
                enabled: true,
            },
            Item { action: Action::Keys, label: "Keys".into(), hint: "every shortcut".into(), enabled: true },
        ];
        if self.stopped() && self.owns_engine {
            items.insert(
                0,
                Item {
                    action: Action::Restart,
                    label: "Start again".into(),
                    hint: format!("start {}", self.name),
                    enabled: true,
                },
            );
        }
        items.push(Item { action: Action::Quit, label: "Quit".into(), hint: "ctrl+c twice".into(), enabled: true });
        items
    }

    pub fn mode_name(&self) -> Option<String> {
        let current = self.mode.as_ref()?;
        Some(self.modes.iter().find(|m| &m.id == current).map(|m| m.name.clone()).unwrap_or_else(|| current.clone()))
    }

    pub fn model_picker(&self) -> Overlay {
        let choices = self
            .models
            .iter()
            .map(|m| Choice { id: m.clone(), label: m.clone(), hint: String::new(), current: *m == self.model })
            .collect();
        Overlay::picker(Which::Models, "Switch model", choices)
    }

    pub fn mode_picker(&self) -> Overlay {
        let choices = self
            .modes
            .iter()
            .map(|m| Choice {
                id: m.id.clone(),
                label: m.name.clone(),
                hint: m.description.clone().unwrap_or_default(),
                current: self.mode.as_deref() == Some(m.id.as_str()),
            })
            .collect();
        Overlay::picker(Which::Modes, "Switch mode", choices)
    }

    /// Switches to the next (or previous) mode the engine offers.
    pub fn cycle_mode(&mut self, back: bool) {
        if self.modes.is_empty() || self.phase != Phase::Ready {
            return;
        }
        let at = self.mode.as_ref().and_then(|m| self.modes.iter().position(|x| &x.id == m)).unwrap_or(0);
        let count = self.modes.len();
        let next = if back { (at + count - 1) % count } else { (at + 1) % count };
        let id = self.modes[next].id.clone();
        self.set_mode(id);
    }

    fn set_mode(&mut self, id: String) {
        self.mode = Some(id.clone());
        self.send(Command::SetMode { mode: id });
    }

    /// The person chose a model.
    pub fn choose_model(&mut self, model: String, now: Instant) {
        self.overlay = None;
        if !matches!(self.phase, Phase::Ready | Phase::Stopped { .. }) {
            self.transcript.notice(Level::Info, &format!("Wait until {} has started to switch models.", self.name));
            return;
        }
        if model == self.model && !self.stopped() {
            return;
        }
        if self.stopped() {
            if self.owns_engine {
                self.switch_by_restart(model, now);
            } else {
                self.transcript.notice(Level::Warn, &format!("{} cannot be started again from here.", self.name));
            }
            return;
        }
        match self.model_switch {
            // The engine answers with a Model event, which says "Now using …".
            ModelSwitch::Live => self.send(Command::SetModel { model }),
            ModelSwitch::Restart if self.owns_engine => {
                self.overlay = Some(Overlay::Confirm {
                    detail: format!("Switching to {model} restarts {}; this conversation starts again.", self.name),
                    title: format!("Switch to {model}?"),
                    what: Confirmable::SwitchModel(model),
                    yes: "switch".into(),
                });
            }
            ModelSwitch::Restart => {
                self.transcript.notice(
                    Level::Warn,
                    &format!("{} switches models by restarting, which this screen cannot do here.", self.name),
                );
            }
        }
    }

    /// Starts a switch by restarting. The running turn and its open requests stay with the engine
    /// that runs until it is stopped for the new one ([`App::switch_prepared`]); when the new model
    /// cannot be prepared they go on as before ([`App::switch_refused`]).
    fn switch_by_restart(&mut self, model: String, now: Instant) {
        self.switch_from = Some(self.phase.clone());
        self.phase = Phase::Switching { model: model.clone(), since: now, step: "Preparing".into() };
        self.effects.push(Effect::Restart(model));
    }

    pub fn outcome(&mut self, outcome: Outcome, now: Instant) {
        self.dirty = true;
        match outcome {
            Outcome::Stay => {}
            Outcome::Close => self.overlay = None,
            Outcome::Run(action) => {
                self.overlay = None;
                match action {
                    Action::Model => self.overlay = Some(self.model_picker()),
                    Action::Mode => self.overlay = Some(self.mode_picker()),
                    Action::Slash(name) => {
                        let text = format!("/{name}");
                        if self.turn.is_none() && self.phase == Phase::Ready {
                            self.history.push(&text);
                            self.send_prompt(text, now);
                        } else {
                            self.queued.push_back(text);
                        }
                    }
                    Action::Details => self.details = !self.details,
                    Action::Keys => self.overlay = Some(Overlay::Keys { keys: keys_help(self.shift_enter), scroll: 0 }),
                    Action::Quit => self.request_quit(),
                    Action::Restart => self.effects.push(Effect::Start),
                    Action::SendCtrlP => {}
                }
            }
            Outcome::Pick(Which::Models, model) => self.choose_model(model, now),
            Outcome::Pick(Which::Modes, mode) => {
                self.overlay = None;
                if self.mode.as_deref() != Some(mode.as_str()) {
                    self.set_mode(mode);
                }
            }
            Outcome::Confirmed(Confirmable::Quit) => self.quit(),
            Outcome::Confirmed(Confirmable::SwitchModel(model)) => {
                self.overlay = None;
                self.switch_by_restart(model, now);
            }
        }
    }

    /// The slash commands matching what is typed, while a command name is being typed.
    pub fn completions(&self) -> Vec<&SlashCommand> {
        let text = self.input.text();
        if !text.starts_with('/')
            || text.contains(char::is_whitespace)
            || self.completion_closed.as_deref() == Some(text)
        {
            return Vec::new();
        }
        let typed = text[1..].to_lowercase();
        let mut starts: Vec<&SlashCommand> =
            self.commands.iter().filter(|c| c.name.to_lowercase().starts_with(&typed)).collect();
        let contains = self
            .commands
            .iter()
            .filter(|c| !c.name.to_lowercase().starts_with(&typed) && c.name.to_lowercase().contains(&typed));
        starts.extend(contains);
        starts
    }

    // Restart progress, reported by the run loop.

    pub fn switch_step(&mut self, step: &str) {
        if let Phase::Switching { step: current, .. } = &mut self.phase {
            *current = step.to_owned();
        }
        self.dirty = true;
    }

    /// The new engine started with the new model; Ready follows from it.
    pub fn switched(&mut self, spec: EngineSpec, model: &str, now: Instant) {
        self.name = spec.name.clone();
        self.model = model.to_owned();
        self.spec = spec;
        self.session = None;
        self.usage = Usage::default();
        self.plan.clear();
        self.transcript.divider(&format!("{} restarted with {model}. The conversation starts again.", self.name));
        self.phase = Phase::Starting { since: now };
        self.dirty = true;
    }

    /// The new model is prepared and the engine that runs is being stopped for it: its turn and
    /// open requests end with it.
    pub fn switch_prepared(&mut self) {
        self.switch_from = None;
        if self.turn.take().is_some() || self.transcript.live() {
            self.transcript.end_turn();
        }
        self.dialogs.clear();
        self.switch_step(&format!("stopping {}", self.name));
    }

    /// The new model could not be prepared. Nothing was stopped: the screen goes back to how it
    /// was (an engine that runs keeps its turn and open requests; a stopped one stays stopped),
    /// and prompts typed meanwhile go when the engine can take them.
    pub fn switch_refused(&mut self, model: &str, error: &str, now: Instant) {
        self.transcript.notice(Level::Error, &format!("Could not switch to {model}: {}", clean(error).trim()));
        let before = self.switch_from.take();
        // The engine may have stopped meanwhile (its Exit says so): that stays.
        if matches!(self.phase, Phase::Switching { .. }) {
            self.phase = before.unwrap_or(if self.ready_once { Phase::Ready } else { Phase::Starting { since: now } });
        }
        self.send_queued(now);
        self.dirty = true;
    }

    /// The new engine did not start; the old one was started again.
    pub fn switch_reverted(&mut self, model: &str, error: &str, now: Instant) {
        self.transcript.notice(
            Level::Error,
            &format!("Could not start {} with {model}: {}. Back on {}.", self.name, clean(error).trim(), self.model),
        );
        self.phase = Phase::Starting { since: now };
        self.dirty = true;
    }

    /// Neither the new model nor the old one started.
    pub fn switch_failed(&mut self, model: &str, error: &str, again: &str) {
        let message = format!(
            "With {model}: {}. With {} again: {}. Press Enter to try again, or Ctrl+P to choose another model.",
            clean(error).trim(),
            self.model,
            clean(again).trim()
        );
        self.stop(format!("{} could not start", self.name), message, true);
    }
}

/// Every key, for the keys help. A terminal that does not tell Shift+Enter from Enter sends
/// the prompt on Shift+Enter, so Ctrl+J is named for a new line there.
pub fn keys_help(shift_enter: bool) -> Vec<(String, String)> {
    let new_line = if shift_enter {
        ("shift+enter", "new line (also alt+enter, ctrl+j)")
    } else {
        ("ctrl+j", "new line (also alt+enter)")
    };
    [
        ("enter", "send (while it works: queue for after)"),
        new_line,
        ("↑ ↓", "earlier prompts at the first or last line"),
        ("esc", "stop the turn"),
        ("ctrl+c", "clear the box or stop; twice to quit"),
        ("ctrl+p", "commands: model, mode, sessions, keys"),
        ("tab", "next mode (when the box is empty)"),
        ("/", "the engine's commands"),
        ("pgup pgdn", "scroll the conversation"),
        ("end", "follow the newest output again"),
        ("ctrl+o", "show or hide thinking and full output"),
        ("ctrl+l", "redraw the screen"),
        ("ctrl+a ctrl+e", "start or end of the line"),
        ("ctrl+u ctrl+k", "delete to the start or end of the line"),
        ("ctrl+w", "delete the word before"),
        ("alt+← alt+→", "move by word"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}
