//! The full-screen interface: one Yougori screen for whichever harness the person chose.
//!
//! Engines that speak the event model (`protocol.rs`) get the conversation screen (`state.rs`
//! for what it holds, `keys.rs`, `draw.rs`); a harness run as its own terminal client
//! (`Protocol::Terminal`) gets the terminal pane (`pane.rs`). Both redraw only when something
//! changed, at most about 30 times a second, and write only what changed (`screen.rs`), because
//! the screen reaches the person through the launcher's polling relay.
mod dialog;
mod draw;
mod highlight;
mod input;
mod keys;
mod markdown;
mod mask;
mod overlay;
mod pane;
mod screen;
mod state;
mod switcher;
mod term;
#[cfg(test)]
mod tests;
mod text;
mod theme;
mod transcript;

use crate::protocol::{Command, EngineHandle, Event, Level};
use crate::spec::{EngineSpec, Protocol};
use crossterm::event::{Event as TermEvent, EventStream};
use futures::future::{FutureExt, LocalBoxFuture};
use futures::stream::{FuturesUnordered, StreamExt};
use mask::Masker;
use pane::{Pane, PaneEffect, PanePhase};
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use screen::Screen;
use state::{App, Effect, Phase};
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use switcher::{Mode as Where, Pending, Switched, NEW_VM_EXIT, YOUGORI};
use term::Terminal;
use theme::{Depth, Theme};
use tokio::sync::{mpsc, oneshot};

/// The shortest time between two frames (about 30 a second).
const FRAME: Duration = Duration::from_millis(33);
/// How often spinners and clocks move.
const TICK: Duration = Duration::from_millis(80);
/// How long a quitting screen waits for the engine to stop by itself.
const STOP_WAIT: Duration = Duration::from_secs(3);
/// How long a model switch waits for the old engine to stop.
const SWITCH_WAIT: Duration = Duration::from_secs(10);
/// Engine events taken in one go before the screen looks at keys again.
const BATCH: usize = 512;

/// How a screen ended: the session is over (its exit code), or the person switched harness and
/// the next harness's screen takes over (/harness).
pub enum Ended {
    Exit(i32),
    Switch(Box<EngineSpec>, Box<Carry>),
}

/// What the next screen keeps of the one before after a switch: the conversation so far, the
/// prompts sent and queued, and the divider it starts under ("OpenCode · gemma-4").
#[derive(Default)]
pub struct Carry {
    pub transcript: Option<transcript::Transcript>,
    pub history: input::History,
    pub queued: VecDeque<String>,
    pub note: String,
}

/// Runs the screen until the person quits; returns the process exit code (0 after a normal
/// quit, 1 when the engine failed, [`NEW_VM_EXIT`] when the next harness starts in a new VM).
/// With `engine` None the screen starts the spec's engine itself (`crate::engines::start`), shows
/// its start-up and errors, restarts it to switch models (`crate::engines::respec`) and switches
/// harness (switcher.rs); a `Protocol::Terminal` harness runs in the terminal pane. A switch goes
/// on in the same terminal: the next harness's screen, conversation or pane, takes over.
pub async fn run(spec: EngineSpec, engine: Option<EngineHandle>) -> anyhow::Result<i32> {
    let theme = Theme::new(Depth::detect());
    highlight::warm();
    let mut terminal =
        Terminal::enter().map_err(|e| anyhow::anyhow!("The screen needs an interactive terminal: {e}"))?;
    let mut spec = spec;
    let mut engine = engine;
    let mut carry = Carry::default();
    let result = loop {
        // Secrets typed for the harness switched to are masked from its first frame.
        let masker = Masker::from_environment();
        let ended = if spec.protocol == Protocol::Terminal && engine.is_none() {
            run_pane(&mut terminal, spec, theme, masker, std::mem::take(&mut carry)).await
        } else {
            run_agent(&mut terminal, spec, engine.take(), theme, masker, std::mem::take(&mut carry)).await
        };
        match ended {
            Ok(Ended::Exit(code)) => break Ok(code),
            Ok(Ended::Switch(next, kept)) => {
                spec = *next;
                carry = *kept;
            }
            Err(error) => break Err(error),
        }
    };
    drop(terminal);
    result
}

/// The next progress line of the harness switch under way, if any.
async fn next_progress(progress: &mut Option<mpsc::UnboundedReceiver<String>>) -> Option<String> {
    match progress {
        Some(receiver) => receiver.recv().await,
        None => std::future::pending().await,
    }
}

/// What the terminal and the screen's timers do while the screen runs.
struct Io {
    screen: Screen,
    input: Option<EventStream>,
    detect: Option<tokio::sync::oneshot::Receiver<bool>>,
    last_frame: Option<Instant>,
}

impl Io {
    fn new() -> Io {
        let (width, height) = Terminal::size();
        // The keyboard question is asked before keys are read, so its answer is not taken for
        // typing; keys pressed meanwhile wait in the terminal's queue. It is asked on a thread of
        // its own, not the runtime's blocking pool, so a terminal that never answers cannot keep
        // the process from ending.
        let (answer, detect) = tokio::sync::oneshot::channel();
        let asked = std::thread::Builder::new()
            .name("yougori-keyboard".into())
            .spawn(move || {
                let _ = answer.send(Terminal::enhance_keyboard());
            })
            .is_ok();
        Io {
            screen: Screen::new(Rect::new(0, 0, width, height)),
            input: (!asked).then(EventStream::new),
            detect: asked.then_some(detect),
            last_frame: None,
        }
    }

    /// How long until a frame may be drawn.
    fn wait(&self, now: Instant) -> Duration {
        match self.last_frame {
            Some(at) => FRAME.saturating_sub(now.saturating_duration_since(at)),
            None => Duration::ZERO,
        }
    }

    fn resize(&mut self, width: u16, height: u16) {
        self.screen.resize(Rect::new(0, 0, width.max(1), height.max(1)));
    }
}

async fn next_input(input: &mut Option<EventStream>) -> Option<std::io::Result<TermEvent>> {
    match input {
        Some(stream) => stream.next().await,
        None => std::future::pending().await,
    }
}

async fn next_event(engine: &mut Option<EngineHandle>) -> Option<Event> {
    match engine {
        Some(handle) => handle.events.recv().await,
        None => std::future::pending().await,
    }
}

/// Whether the terminal reports Shift+Enter apart from Enter, once it answered.
async fn detected(detect: &mut Option<tokio::sync::oneshot::Receiver<bool>>) -> bool {
    match detect {
        Some(answer) => answer.await.unwrap_or(false),
        None => std::future::pending().await,
    }
}

#[cfg(unix)]
struct Signals {
    terminate: Option<tokio::signal::unix::Signal>,
    hangup: Option<tokio::signal::unix::Signal>,
}

#[cfg(unix)]
impl Signals {
    fn new() -> Signals {
        use tokio::signal::unix::{signal, SignalKind};
        Signals { terminate: signal(SignalKind::terminate()).ok(), hangup: signal(SignalKind::hangup()).ok() }
    }

    async fn next(&mut self) {
        let terminate = async {
            match self.terminate.as_mut() {
                Some(s) => {
                    s.recv().await;
                }
                None => std::future::pending().await,
            }
        };
        let hangup = async {
            match self.hangup.as_mut() {
                Some(s) => {
                    s.recv().await;
                }
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            _ = terminate => {}
            _ = hangup => {}
        }
    }
}

#[cfg(not(unix))]
struct Signals;

#[cfg(not(unix))]
impl Signals {
    fn new() -> Signals {
        Signals
    }

    async fn next(&mut self) {
        std::future::pending::<()>().await
    }
}

/// Work the conversation screen waits for besides events and keys.
enum Job {
    Started(anyhow::Result<EngineHandle>),
    Respecced(String, anyhow::Result<EngineSpec>),
    OldStopped(String, EngineSpec),
    Switched(String, EngineSpec, anyhow::Result<EngineHandle>),
    Reverted(String, String, anyhow::Result<EngineHandle>),
    /// A harness switch ended (/harness).
    Changed(Switched),
}

fn start_job(spec: EngineSpec) -> LocalBoxFuture<'static, Job> {
    async move { Job::Started(crate::engines::start(&spec).await) }.boxed_local()
}

async fn wait_closed(engine: &mut EngineHandle, limit: Duration) {
    let _ = tokio::time::timeout(limit, async { while engine.events.recv().await.is_some() {} }).await;
}

/// The terminal can no longer be written to: the engine is stopped and the screen ends.
async fn terminal_lost(engine: &mut Option<EngineHandle>, error: std::io::Error) -> anyhow::Error {
    if let Some(mut handle) = engine.take() {
        let _ = handle.commands.send(Command::Shutdown);
        wait_closed(&mut handle, STOP_WAIT).await;
    }
    anyhow::anyhow!("The terminal closed: {error}")
}

/// Carries out what a finished job means for the engine and the screen.
fn agent_job(
    job: Job,
    app: &mut App,
    engine: &mut Option<EngineHandle>,
    jobs: &FuturesUnordered<LocalBoxFuture<'static, Job>>,
    quitting: bool,
    now: Instant,
) {
    if quitting {
        // An engine that just started is stopped too; nothing new starts.
        if let Job::Started(Ok(handle)) | Job::Switched(_, _, Ok(handle)) | Job::Reverted(_, _, Ok(handle)) = job {
            let _ = handle.commands.send(Command::Shutdown);
            if engine.is_none() {
                *engine = Some(handle);
            }
        }
        return;
    }
    match job {
        Job::Started(Ok(handle)) => *engine = Some(handle),
        Job::Started(Err(error)) => app.start_failed(&format!("{error:#}")),
        Job::Respecced(model, Ok(next)) => {
            let old = engine.take();
            // The running turn and its open requests end with the engine.
            app.switch_prepared();
            jobs.push(
                async move {
                    if let Some(mut old) = old {
                        let _ = old.commands.send(Command::Shutdown);
                        wait_closed(&mut old, SWITCH_WAIT).await;
                    }
                    Job::OldStopped(model, next)
                }
                .boxed_local(),
            );
        }
        Job::Respecced(model, Err(error)) => {
            app.switch_refused(&model, &format!("{error:#}"), now);
            if engine.is_none() {
                // The engine's events ended while the new model was prepared: it is gone.
                app.engine_closed();
            }
        }
        Job::OldStopped(model, next) => {
            app.switch_step(&format!("starting {} with {model}", next.name));
            jobs.push(
                async move {
                    let result = crate::engines::start(&next).await;
                    Job::Switched(model, next, result)
                }
                .boxed_local(),
            );
        }
        Job::Switched(model, next, Ok(handle)) => {
            *engine = Some(handle);
            app.switched(next, &model, now);
        }
        Job::Switched(model, _, Err(error)) => {
            // The new model did not start: start the one before it again.
            let error = format!("{error:#}");
            app.switch_step(&format!("starting {} with {} again", app.name, app.model));
            let previous = app.spec.clone();
            jobs.push(
                async move {
                    let result = crate::engines::start(&previous).await;
                    Job::Reverted(model, error, result)
                }
                .boxed_local(),
            );
        }
        Job::Reverted(model, error, Ok(handle)) => {
            *engine = Some(handle);
            app.switch_reverted(&model, &error, now);
        }
        Job::Reverted(model, error, Err(again)) => app.switch_failed(&model, &error, &format!("{again:#}")),
        // Taken by the run loop before this.
        Job::Changed(_) => {}
    }
}

async fn run_agent(
    terminal: &mut Terminal,
    spec: EngineSpec,
    engine: Option<EngineHandle>,
    theme: Theme,
    masker: Masker,
    carry: Carry,
) -> anyhow::Result<Ended> {
    let now = Instant::now();
    let owns = engine.is_none();
    let mut app = App::new(spec, theme, masker, owns, now);
    app.carried(carry);
    // The harness switch under way: how to stop it, and its progress.
    let mut switch_cancel: Option<oneshot::Sender<()>> = None;
    let mut switch_progress: Option<mpsc::UnboundedReceiver<String>> = None;
    // Until the terminal says it reports Shift+Enter, it arrives as Enter (Windows reports it).
    app.shift_enter = cfg!(windows);
    let mut engine = engine;
    let mut jobs: FuturesUnordered<LocalBoxFuture<'static, Job>> = FuturesUnordered::new();
    if owns {
        jobs.push(start_job(app.spec.clone()));
    }
    let mut io = Io::new();
    let mut ticker = tokio::time::interval(TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut signals = Signals::new();
    let mut quitting: Option<Instant> = None;
    loop {
        let now = Instant::now();
        // A frame waits while the one before it is still being written.
        if app.dirty && !terminal.writing() && io.wait(now).is_zero() {
            let area = io.screen.area();
            let mut buffer = Buffer::empty(area);
            let frame = draw::draw(&mut app, area, &mut buffer, now);
            let bytes = io.screen.frame(&buffer, frame.cursor, frame.scroll);
            if let Err(error) = terminal.write(bytes) {
                return Err(terminal_lost(&mut engine, error).await);
            }
            app.dirty = false;
            io.last_frame = Some(now);
        }
        let wait = if app.dirty && !terminal.writing() { io.wait(now) } else { Duration::from_secs(3600) };
        tokio::select! {
            written = terminal.written() => {
                if let Err(error) = written {
                    return Err(terminal_lost(&mut engine, error).await);
                }
            }
            shift_enter = detected(&mut io.detect) => {
                io.detect = None;
                io.input = Some(EventStream::new());
                app.shift_enter = cfg!(windows) || shift_enter;
                app.dirty = true;
            }
            event = next_input(&mut io.input) => match event {
                Some(Ok(TermEvent::Key(key))) => app.key(key, Instant::now()),
                Some(Ok(TermEvent::Paste(text))) => app.paste(&text),
                Some(Ok(TermEvent::Resize(width, height))) => {
                    io.resize(width, height);
                    app.dirty = true;
                }
                Some(Ok(_)) => {}
                Some(Err(_)) | None => {
                    // No more keys can come: quit.
                    io.input = None;
                    app.quit();
                }
            },
            event = next_event(&mut engine) => match event {
                Some(event) => {
                    let now = Instant::now();
                    app.apply(event, now);
                    if let Some(handle) = engine.as_mut() {
                        for _ in 0..BATCH {
                            match handle.events.try_recv() {
                                Ok(event) => app.apply(event, now),
                                Err(_) => break,
                            }
                        }
                    }
                }
                None => {
                    engine = None;
                    if quitting.is_none() {
                        app.engine_closed();
                    }
                }
            },
            Some(step) = next_progress(&mut switch_progress) => app.change_step(&step),
            Some(job) = jobs.next(), if !jobs.is_empty() => {
                let now = Instant::now();
                match job {
                    Job::Changed(switched) if quitting.is_none() => {
                        switch_cancel = None;
                        switch_progress = None;
                        match switched {
                            Switched::InPlace(next) => {
                                let carry = app.carry(&next);
                                return Ok(Ended::Switch(next, Box::new(carry)));
                            }
                            Switched::NewVm => {
                                // The launcher starts the next VM once this screen has ended.
                                if let Some(mut handle) = engine.take() {
                                    let _ = handle.commands.send(Command::Shutdown);
                                    wait_closed(&mut handle, STOP_WAIT).await;
                                }
                                return Ok(Ended::Exit(NEW_VM_EXIT));
                            }
                            Switched::Failed { reason, kept } => {
                                let before = app.spec.harness == YOUGORI;
                                if app.change_failed(&reason, now) {
                                    if kept || before {
                                        engine = None;
                                        jobs.push(start_job(app.spec.clone()));
                                    } else {
                                        // The harness before is gone from the VM: Yougori's own
                                        // agent needs nothing to start.
                                        let back = Pending::yougori(&app.spec, &app.model);
                                        app.start_switch(back, now);
                                    }
                                }
                            }
                        }
                    }
                    job => agent_job(job, &mut app, &mut engine, &jobs, quitting.is_some(), now),
                }
            }
            _ = ticker.tick() => {
                let now = Instant::now();
                for panic in Terminal::panics() {
                    app.transcript.notice(Level::Error, &format!("Internal error: {panic}"));
                    app.dirty = true;
                }
                if app.animating(now) {
                    app.dirty = true;
                }
            }
            _ = tokio::time::sleep(wait), if app.dirty => {}
            _ = signals.next() => app.quit(),
        }
        let now = Instant::now();
        for effect in std::mem::take(&mut app.effects) {
            match effect {
                Effect::Send(command) => {
                    let sent = engine.as_ref().is_some_and(|handle| handle.commands.send(command).is_ok());
                    if !sent && quitting.is_none() && app.phase == Phase::Ready {
                        app.engine_closed();
                    }
                }
                Effect::Start => {
                    if owns && jobs.is_empty() && quitting.is_none() {
                        engine = None;
                        app.starting(now);
                        jobs.push(start_job(app.spec.clone()));
                    }
                }
                Effect::Restart(model) => {
                    let spec = app.spec.clone();
                    jobs.push(
                        async move {
                            let result = crate::engines::respec(&spec, &model).await;
                            Job::Respecced(model, result)
                        }
                        .boxed_local(),
                    );
                }
                Effect::Switch(pending) => {
                    // In place the engine stops before its pack can be replaced; a new VM's switch
                    // leaves it running until the launcher takes over.
                    let request = pending.request();
                    let old = if pending.mode == Where::InPlace { engine.take() } else { None };
                    let (progress, received) = mpsc::unbounded_channel();
                    let (cancel, cancelled) = oneshot::channel();
                    switch_progress = Some(received);
                    switch_cancel = Some(cancel);
                    let spec = app.spec.clone();
                    jobs.push(
                        async move {
                            if let Some(mut old) = old {
                                let _ = old.commands.send(Command::Shutdown);
                                wait_closed(&mut old, SWITCH_WAIT).await;
                            }
                            Job::Changed(switcher::run(spec, request, progress, cancelled).await)
                        }
                        .boxed_local(),
                    );
                }
                Effect::CancelSwitch => {
                    if let Some(cancel) = switch_cancel.take() {
                        let _ = cancel.send(());
                    }
                }
                Effect::Redraw => {
                    io.screen.invalidate();
                    app.dirty = true;
                }
                Effect::Quit => {
                    if quitting.is_none() {
                        quitting = Some(now);
                        app.phase = Phase::Quitting { since: now };
                        app.dirty = true;
                        if let Some(handle) = engine.as_ref() {
                            let _ = handle.commands.send(Command::Shutdown);
                        }
                        if let Some(cancel) = switch_cancel.take() {
                            let _ = cancel.send(());
                        }
                    }
                }
            }
        }
        if let Some(since) = quitting {
            if (engine.is_none() && jobs.is_empty()) || now.saturating_duration_since(since) >= STOP_WAIT {
                break;
            }
        }
    }
    // Dropping the handle stops whatever is left of the engine and its services.
    drop(engine);
    Ok(Ended::Exit(app.exit_code()))
}

/// A model switch in the terminal pane. There is at most one, so its size does not matter.
#[allow(clippy::large_enum_variant)]
enum Switch {
    /// Starting the new model's client; `previous` is what to go back to.
    Trying { model: String, previous: EngineSpec },
    /// The new one failed; the old one is starting again.
    Reverting { note: String },
}

/// Work the terminal pane waits for besides output and keys. A few at a time, so their size does
/// not matter.
#[allow(clippy::large_enum_variant)]
enum PaneJob {
    Started(u64, anyhow::Result<pane::Child>),
    Respecced(String, anyhow::Result<EngineSpec>),
    /// A harness switch ended (/harness).
    Changed(Switched),
}

fn pane_start(
    spec: EngineSpec,
    rows: u16,
    cols: u16,
    generation: u64,
    depth: Depth,
    tx: tokio::sync::mpsc::UnboundedSender<pane::Message>,
) -> LocalBoxFuture<'static, PaneJob> {
    async move {
        let result = async {
            let services = crate::engines::services::start(&spec).await?;
            pane::spawn(&spec, rows, cols, generation, Some(services), depth, tx)
        }
        .await;
        PaneJob::Started(generation, result)
    }
    .boxed_local()
}

async fn run_pane(
    terminal: &mut Terminal,
    spec: EngineSpec,
    theme: Theme,
    masker: Masker,
    carry: Carry,
) -> anyhow::Result<Ended> {
    let now = Instant::now();
    let mut io = Io::new();
    let size = io.screen.area();
    let mut pane = Pane::new(spec, theme, masker, size.width, size.height, now);
    if !carry.note.is_empty() {
        pane.note = Some((format!("Switched to {}", carry.note), now));
    }
    pane.kept = carry;
    // The harness switch under way: how to stop it, and its progress.
    let mut switch_cancel: Option<oneshot::Sender<()>> = None;
    let mut switch_progress: Option<mpsc::UnboundedReceiver<String>> = None;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<pane::Message>();
    let mut jobs: FuturesUnordered<LocalBoxFuture<'static, PaneJob>> = FuturesUnordered::new();
    let mut ticker = tokio::time::interval(TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut signals = Signals::new();
    let mut quitting: Option<Instant> = None;
    // A model switch in progress.
    let mut switching: Option<Switch> = None;
    let mut next_generation = 1u64;
    let mut last_second = 0u64;
    pane.effects.push(PaneEffect::Start);
    loop {
        let now = Instant::now();
        let mut start: Option<EngineSpec> = None;
        for effect in std::mem::take(&mut pane.effects) {
            match effect {
                PaneEffect::Start => {
                    if jobs.is_empty() && quitting.is_none() {
                        pane.child = None;
                        pane.phase = PanePhase::Starting { since: now };
                        start = Some(pane.spec.clone());
                    }
                }
                PaneEffect::Restart(model) => {
                    if quitting.is_none() && jobs.is_empty() {
                        pane.switch_preparing(&model, now);
                        let spec = pane.spec.clone();
                        jobs.push(
                            async move {
                                let result = crate::engines::respec(&spec, &model).await;
                                PaneJob::Respecced(model, result)
                            }
                            .boxed_local(),
                        );
                    } else if quitting.is_none() {
                        // A start or another switch is under way (the palette does not offer it then).
                        pane.wait_to_switch(now);
                    }
                }
                PaneEffect::Switch(pending) => {
                    // In place the client stops before its pack can be replaced (its services stop
                    // with it); a new VM's switch leaves it running until the launcher takes over.
                    if pending.mode == Where::InPlace {
                        if let Some(mut child) = pane.child.take() {
                            child.kill();
                        }
                    }
                    let request = pending.request();
                    let (progress, received) = mpsc::unbounded_channel();
                    let (cancel, cancelled) = oneshot::channel();
                    switch_progress = Some(received);
                    switch_cancel = Some(cancel);
                    let spec = pane.spec.clone();
                    jobs.push(
                        async move { PaneJob::Changed(switcher::run(spec, request, progress, cancelled).await) }
                            .boxed_local(),
                    );
                }
                PaneEffect::CancelSwitch => {
                    if let Some(cancel) = switch_cancel.take() {
                        let _ = cancel.send(());
                    }
                }
                PaneEffect::Redraw => io.screen.invalidate(),
                PaneEffect::Quit => {
                    if quitting.is_none() {
                        quitting = Some(now);
                        pane.phase = PanePhase::Quitting { since: now };
                        if let Some(child) = pane.child.as_mut() {
                            child.kill();
                        }
                        if let Some(cancel) = switch_cancel.take() {
                            let _ = cancel.send(());
                        }
                    }
                }
            }
            pane.dirty = true;
        }
        if let Some(spec) = start {
            let (rows, cols) = pane::pane_size(io.screen.area().width, io.screen.area().height);
            jobs.push(pane_start(spec, rows, cols, next_generation, pane.theme.depth, tx.clone()));
            pane.generation = next_generation;
            next_generation += 1;
        }
        if let Some(since) = quitting {
            if pane.child.is_none() || now.saturating_duration_since(since) >= pane::STOP_WAIT {
                break;
            }
        }
        // A frame waits while the one before it is still being written.
        if pane.dirty && !terminal.writing() && io.wait(now).is_zero() {
            let area = io.screen.area();
            let mut buffer = Buffer::empty(area);
            let frame = pane.draw(area, &mut buffer, now);
            let bytes = io.screen.frame(&buffer, frame.cursor, frame.scroll);
            if let Err(error) = terminal.write(bytes) {
                return Err(anyhow::anyhow!("The terminal closed: {error}"));
            }
            pane.dirty = false;
            io.last_frame = Some(now);
        }
        let wait = if pane.dirty && !terminal.writing() { io.wait(now) } else { Duration::from_secs(3600) };
        tokio::select! {
            written = terminal.written() => {
                if let Err(error) = written {
                    return Err(anyhow::anyhow!("The terminal closed: {error}"));
                }
            }
            _ = detected(&mut io.detect) => {
                io.detect = None;
                io.input = Some(EventStream::new());
            }
            event = next_input(&mut io.input) => match event {
                Some(Ok(TermEvent::Key(key))) => pane.key(key, Instant::now()),
                Some(Ok(TermEvent::Paste(text))) => pane.paste(&text),
                Some(Ok(TermEvent::Resize(width, height))) => {
                    io.resize(width, height);
                    pane.resize(width.max(1), height.max(1));
                }
                Some(Ok(_)) => {}
                Some(Err(_)) | None => {
                    io.input = None;
                    pane.effects.push(PaneEffect::Quit);
                }
            },
            Some(message) = rx.recv() => {
                let now = Instant::now();
                pane.message(message, now);
                for _ in 0..BATCH {
                    match rx.try_recv() {
                        Ok(message) => pane.message(message, now),
                        Err(_) => break,
                    }
                }
            }
            Some(step) = next_progress(&mut switch_progress) => pane.change_step(&step),
            Some(job) = jobs.next(), if !jobs.is_empty() => {
                let now = Instant::now();
                match job {
                    PaneJob::Changed(_) if quitting.is_some() => {}
                    PaneJob::Changed(switched) => {
                        switch_cancel = None;
                        switch_progress = None;
                        match switched {
                            Switched::InPlace(next) => {
                                drop(pane.child.take());
                                let mut carry = std::mem::take(&mut pane.kept);
                                carry.note = format!("{} · {}", next.name, next.model);
                                return Ok(Ended::Switch(next, Box::new(carry)));
                            }
                            Switched::NewVm => {
                                // The launcher starts the next VM once this screen has ended.
                                drop(pane.child.take());
                                return Ok(Ended::Exit(NEW_VM_EXIT));
                            }
                            Switched::Failed { reason, kept } => {
                                if pane.change_failed(&reason, now) {
                                    if kept {
                                        pane.effects.push(PaneEffect::Start);
                                    } else {
                                        // The harness before is gone from the VM: Yougori's own
                                        // agent needs nothing to start.
                                        let back = Pending::yougori(&pane.spec, &pane.spec.model);
                                        pane.start_switch(back, now);
                                    }
                                }
                            }
                        }
                    }
                    PaneJob::Started(generation, Ok(child)) => {
                        if quitting.is_some() || generation != pane.generation {
                            drop(child);
                        } else {
                            pane.started(child, now);
                            if let Some(Switch::Reverting { note }) = switching.take() {
                                pane.note = Some((note, now));
                            }
                        }
                    }
                    PaneJob::Started(_, Err(error)) => {
                        let error = format!("{error:#}");
                        match switching.take() {
                            Some(Switch::Trying { model, previous }) => {
                                // The new model's client did not start: go back to the old one.
                                let note = format!("Could not start {} with {model}: {error}. Back on {}.", pane.spec.name, previous.model);
                                pane.spec = previous.clone();
                                pane.phase = PanePhase::Switching { model: previous.model.clone(), since: now, step: "Starting again".into() };
                                let (rows, cols) = pane::pane_size(io.screen.area().width, io.screen.area().height);
                                jobs.push(pane_start(previous, rows, cols, next_generation, pane.theme.depth, tx.clone()));
                                pane.generation = next_generation;
                                next_generation += 1;
                                switching = Some(Switch::Reverting { note });
                            }
                            Some(Switch::Reverting { note }) => pane.start_failed(&format!("{note} Starting it again failed too: {error}")),
                            None => pane.start_failed(&error),
                        }
                    }
                    PaneJob::Respecced(model, Ok(next)) => {
                        // Stop the running client, then start the new one in a fresh screen.
                        if let Some(mut child) = pane.child.take() {
                            child.kill();
                        }
                        pane.switch_from = None;
                        switching = Some(Switch::Trying { model: model.clone(), previous: pane.spec.clone() });
                        pane.spec = next.clone();
                        pane.phase = PanePhase::Switching { model, since: now, step: "Starting".into() };
                        let (rows, cols) = pane::pane_size(io.screen.area().width, io.screen.area().height);
                        jobs.push(pane_start(next, rows, cols, next_generation, pane.theme.depth, tx.clone()));
                        pane.generation = next_generation;
                        next_generation += 1;
                    }
                    PaneJob::Respecced(model, Err(error)) => pane.switch_refused(&model, &format!("{error:#}"), now),
                }
                pane.dirty = true;
            }
            _ = ticker.tick() => {
                let now = Instant::now();
                let second = now.saturating_duration_since(pane.epoch).as_secs();
                if pane.animating() || pane.note_pending(now) || (pane.running() && second != last_second) {
                    pane.dirty = true;
                }
                last_second = second;
            }
            _ = tokio::time::sleep(wait), if pane.dirty => {}
            _ = signals.next() => pane.effects.push(PaneEffect::Quit),
        }
    }
    drop(pane.child.take());
    Ok(Ended::Exit(pane.exit_code()))
}
