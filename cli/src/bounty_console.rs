//! The live console over a worker's activity, laid out like a coding agent's chat: what you send
//! and what the worker does scroll by as a transcript, the model's answer streams in as it is
//! written, and a status line and a composer stay at the bottom. Keys are read and drawn at
//! once; the activity log is read in the background, so typing never waits for the engine.
//!
//! In a practice, typing (or Esc) stops the model's answer and the worker waits for your
//! message; a message after the practice ended starts a new one. While an accepted bounty is
//! worked on, messages go to its agent.
use crate::{
    bounty::{self, dispatch, safe},
    cli_ui as ui,
    composer::{Editor, Input},
};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// How often the console reads the worker's activity.
const POLL: Duration = Duration::from_millis(100);
/// How often keys are read and the screen is brought up to date.
const FRAME: Duration = Duration::from_millis(16);
/// Failed reads in a row after which the console gives up on the engine.
const FAILURES: u32 = 30;
const PLACEHOLDER: &str = "Your prompt here";

/// Opens the console over `worker`'s activity from event `after` on. `practice`: a practice
/// console, else the work on an accepted bounty. `nested`: opened from the waiting view, which
/// opens again when the console ends. `project`: the practice project's folder, for the header.
pub(crate) async fn console(worker: &str, practice: bool, nested: bool, after: u64, project: Option<&str>) -> Result<Value, String> {
    let raw = ui::Raw::on()?;
    let block = ui::block();
    let result = run(worker, practice, nested, after, project, &block).await;
    drop(block);
    drop(raw);
    match result? {
        Leave::Ended => {
            ui::info("Practice ended. Your worker is waiting for offers.");
            Ok(json!({"workerId":worker,"stopped":true}))
        }
        Leave::Stopped => Ok(json!({"workerId":worker,"stopped":true})),
        Leave::Finished(state) => Ok(json!({"workerId":worker,"state":state})),
        Leave::Detached => {
            if nested {
                ui::info(back_to_waiting_view(practice));
            } else {
                ui::info(&format!("Detached. {}", bounty::reconnect_line(worker).await));
            }
            Ok(json!({"workerId":worker,"detached":true}))
        }
    }
}

/// Why the console closed.
enum Leave {
    /// /endpractice or Ctrl+C ended the practice.
    Ended,
    /// The worker left the accepted bounty.
    Stopped,
    /// The worker stopped or failed while it was watched.
    Finished(String),
    /// Ctrl+]: the engine keeps working.
    Detached,
}

async fn run(worker: &str, practice: bool, nested: bool, mut after: u64, project: Option<&str>, block: &ui::Block) -> Result<Leave, String> {
    let mut view = View::new(practice);
    let mut editor = Editor::default();
    let messages = Messages::start();
    let mut poll: Option<tokio::task::JoinHandle<Result<Value, String>>> = None;
    let mut polled = Instant::now() - POLL;
    let mut failures = 0;
    let mut header = false;
    let mut shown: Vec<String> = Vec::new();
    loop {
        let columns = columns();
        if poll.as_ref().is_some_and(|poll| poll.is_finished()) {
            let read = poll.take().expect("a finished read").await.map_err(|error| error.to_string())?;
            polled = Instant::now();
            match read {
                Ok(log) => {
                    failures = 0;
                    let mut out = Vec::new();
                    if !header {
                        header = true;
                        out.extend(view.header(worker, &log["worker"], project, columns));
                    }
                    for event in log["events"].as_array().into_iter().flatten() {
                        if let Some(seq) = event["seq"].as_u64() {
                            after = seq;
                        }
                        view.event(event, &mut out, columns);
                    }
                    view.state = log["worker"]["state"].as_str().unwrap_or_default().to_owned();
                    if practice {
                        view.running(log["practicing"] == true);
                    }
                    ui::lines(out);
                    if !practice && matches!(view.state.as_str(), "stopped" | "failed") {
                        return Ok(Leave::Finished(view.state));
                    }
                }
                Err(error) => {
                    failures += 1;
                    if failures >= FAILURES {
                        return Err(error);
                    }
                }
            }
        }
        if poll.is_none() && polled.elapsed() >= POLL {
            let request = json!({"action":"activity","workerId":worker,"after":after});
            poll = Some(tokio::spawn(dispatch(request)));
        }
        while let Some(line) = messages.outcome() {
            ui::line(&line);
        }
        while event::poll(Duration::ZERO).map_err(|e| e.to_string())? {
            let key = match event::read().map_err(|e| e.to_string())? {
                Event::Key(key) if key.kind != KeyEventKind::Release => key,
                Event::Paste(text) => {
                    let typing = editor.text.is_empty();
                    editor.paste(&text);
                    if typing {
                        view.typing(worker, &messages);
                    }
                    continue;
                }
                Event::Resize(..) => {
                    ui::refresh();
                    continue;
                }
                _ => continue,
            };
            if let Some(leave) = view.key(worker, key, &mut editor, &messages, block).await? {
                return Ok(leave);
            }
        }
        let lines = view.frame(&editor, nested, columns, Instant::now());
        if lines != shown {
            block.set(lines.clone());
            shown = lines;
        }
        tokio::time::sleep(FRAME).await;
    }
}

fn columns() -> usize {
    crossterm::terminal::size().map(|(c, _)| usize::from(c)).unwrap_or(80).max(24)
}

/// Requests the console sends while you keep typing. They go to the engine one after another,
/// in the order they were made: stopping the model's answer always comes before the message.
struct Messages {
    send: mpsc::UnboundedSender<Value>,
    done: std::sync::Mutex<mpsc::UnboundedReceiver<(Value, Result<Value, String>)>>,
}

impl Messages {
    fn start() -> Self {
        let (send, mut requests) = mpsc::unbounded_channel::<Value>();
        let (finished, done) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(request) = requests.recv().await {
                let result = dispatch(request.clone()).await;
                if finished.send((request, result)).is_err() {
                    break;
                }
            }
        });
        Self { send, done: std::sync::Mutex::new(done) }
    }

    fn send(&self, request: Value) {
        let _ = self.send.send(request);
    }

    /// A line to show for a request that finished: a failed message, or how a message to the
    /// agent arrived. Stopping and resuming the model show nothing.
    fn outcome(&self) -> Option<String> {
        loop {
            let (request, result) = self.done.lock().unwrap_or_else(|p| p.into_inner()).try_recv().ok()?;
            let action = request["action"].as_str().unwrap_or_default();
            match result {
                Err(error) if matches!(action, "practiceInput" | "practiceStart" | "chat") => {
                    return Some(format!("{}  {}", ui::paint("▲", ui::AMBER), ui::paint(&safe(&error), ui::AMBER)));
                }
                Ok(result) if action == "chat" => {
                    return Some(note(if result["delivered"] == true {
                        "Your agent received the message."
                    } else {
                        "Saved; your agent handles it at a task checkpoint."
                    }));
                }
                _ => {}
            }
        }
    }
}

/// A quiet line under the item before it, indented under its text.
fn note(text: &str) -> String {
    format!("    {}", ui::muted(text))
}

/// What the console shows: the state the transcript is in and the live area's content.
struct View {
    practice: bool,
    answer: Answer,
    streamed: std::collections::BTreeMap<String, String>,
    /// The report's fields as the model writes them.
    arguments: String,
    /// A passing status such as loading the model, shown on the status line.
    status: Option<String>,
    /// When the current attempt or turn started.
    since: Instant,
    /// A practice runs in the engine.
    practicing: bool,
    /// The engine holds the practice for what you are typing.
    holding: bool,
    /// The worker's state.
    state: String,
}

impl View {
    fn new(practice: bool) -> Self {
        Self {
            practice,
            answer: Answer::default(),
            streamed: Default::default(),
            arguments: String::new(),
            status: None,
            since: Instant::now(),
            practicing: practice,
            holding: false,
            state: String::new(),
        }
    }

    /// The practice runs (`true`) or ended, as the engine last said.
    fn running(&mut self, practicing: bool) {
        if !practicing {
            self.holding = false;
        }
        self.practicing = practicing;
    }

    /// The card the console opens with.
    fn header(&self, worker: &str, view: &Value, project: Option<&str>, columns: usize) -> Vec<String> {
        // The worker as commands name it.
        let name = if view["id"].is_string() { bounty::typed_in_result(view) } else { bounty::worker_handle(worker) };
        let title = format!(
            "{}{}",
            ui::bold(if self.practice { "Practice bounty" } else { "Bounty work" }),
            ui::muted(&format!(" · {name}"))
        );
        let model = safe(view["model"].as_str().unwrap_or("—"));
        let mut rows = vec![("model", model_name(&model))];
        if self.practice {
            rows.push(("target", "Northstar Ledger · black-box, network only".into()));
            if let Some(project) = project {
                rows.push(("source", safe(project)));
            }
            rows.push(("reward", "0 PRACTICE · nothing is paid".into()));
        } else if let Some(bounty) = view["bountyId"].as_str() {
            rows.push(("bounty", safe(bounty)));
        }
        let mut lines = card(&title, &rows, columns);
        let intro = if self.practice {
            "Your worker investigates the live target over the network and writes up what it can prove from its own receipts. Type to talk to it: it stops and reads your message."
        } else {
            "Your agent works on the accepted bounty. Type to message it; it reads your message at its next checkpoint."
        };
        lines.push(String::new());
        lines.extend(indented(intro, "  ", "  ", columns, ui::muted));
        lines
    }

    /// One activity event, as transcript lines added to `out`.
    fn event(&mut self, event: &Value, out: &mut Vec<String>, columns: usize) {
        // Desktop readers replace full snapshots; terminal transcripts append
        // only the new suffix. Legacy practice events are already deltas.
        let mut delta;
        let event = if let Some(id) = event["streamId"].as_str() {
            let full = event["text"].as_str().unwrap_or_default();
            let previous = self.streamed.entry(id.to_owned()).or_default();
            let suffix = full.strip_prefix(previous.as_str()).unwrap_or(full).to_owned();
            *previous = full.to_owned();
            delta = event.clone();
            delta["text"] = suffix.into();
            &delta
        } else {
            if event["kind"] == "turn" { self.streamed.clear(); }
            event
        };
        let text = |key: &str| safe(event[key].as_str().unwrap_or_default());
        let kind = event["kind"].as_str().unwrap_or_default();
        match kind {
            "text" => {
                self.status = None;
                return self.answer.push(event["text"].as_str().unwrap_or_default(), out, columns);
            }
            "thinking" => {
                self.status = None;
                return self.answer.push_thinking(event["text"].as_str().unwrap_or_default(), out, columns);
            }
            "arguments" => {
                self.arguments.push_str(event["text"].as_str().unwrap_or_default());
                return;
            }
            // Shown when you send it.
            "input" => return,
            _ => {}
        }
        self.answer.finish(out, columns);
        let now = Instant::now();
        match kind {
            "practice" => {
                self.practicing = true;
                self.since = now;
                item(out, &ui::paint("•", ui::GREEN), &text("text"), columns, ui::bold);
            }
            "attempt" if event["attempt"].is_number() => {
                self.since = now;
                self.status = None;
                self.arguments.clear();
                out.push(String::new());
                out.push(rule(&format!("Attempt {}", event["attempt"]), columns));
            }
            "status" if event["live"] == true => self.status = Some(text("text")),
            "status" if event["tone"] == "warn" => {
                self.status = None;
                item(out, &ui::paint("•", ui::AMBER), &text("text"), columns, |row| ui::paint(row, ui::AMBER));
            }
            "status" => {
                self.status = None;
                out.push(note(&text("text")));
            }
            "tool" => {
                self.status = None;
                self.arguments.clear();
                item(out, &ui::paint("•", ui::SKY), &format!("Calling {}", text("name")), columns, ui::bold);
            }
            "request" => {
                self.status = None;
                out.push(String::new());
                out.push(ui::clip(&format!("{} {} {}", ui::paint("Request", ui::SKY), ui::bold(&text("method")), ui::muted(&text("path"))), columns.saturating_sub(1)));
                let body = text("body");
                if !body.trim().is_empty() {
                    out.extend(indented(&body, "    ", "    ", columns, ui::muted));
                }
            }
            "response" => {
                self.status = None;
                let status = event["status"].as_i64().unwrap_or(0);
                let tone = if (200..300).contains(&status) { ui::GREEN } else { ui::AMBER };
                out.push(if status == 0 {
                    ui::paint("No response", tone)
                } else {
                    format!("{} {}", ui::paint("Response", tone), ui::bold(&status.to_string()))
                });
                let body = text("body");
                if !body.trim().is_empty() {
                    out.extend(indented(&body, "    ", "    ", columns, ui::muted));
                }
            }
            "tried" => item(out, &ui::muted("•"), &format!("Tried: {}", text("text")), columns, ui::muted),
            "verdict" => {
                self.arguments.clear();
                out.extend(verdict(event, columns));
            }
            "feedback" => out.extend(indented(&format!("Hint: {}", text("text")), "    ", "    ", columns, ui::muted)),
            "practiceEnd" => {
                self.running(false);
                self.status = None;
                let tone = if event["outcome"] == "qualified" { ui::GREEN } else { ui::AMBER };
                item(out, &ui::paint("•", tone), &text("text"), columns, ui::bold);
                out.extend(indented("Type a message to practice again, or /endpractice to leave.", "  ", "  ", columns, ui::muted));
            }
            "work" | "turn" => {
                self.since = now;
                item(out, &ui::paint("•", ui::GREEN), &text("text"), columns, ui::bold);
            }
            "action" => {
                let failed = if event["status"] == "error" { ui::paint(" · failed", ui::AMBER) } else { String::new() };
                out.push(ui::clip(&format!("  {} {} {}{failed}", ui::muted("└"), ui::bold(&text("tool")), ui::muted(&text("target"))), columns.saturating_sub(1)));
            }
            "turnEnd" => out.push(note(&text("text"))),
            "attempt" | "check" | "report" => item(out, &ui::paint("•", ui::SKY), &text("text"), columns, plain),
            _ => {}
        }
    }

    /// You started typing: in a running practice the model's answer stops and the worker
    /// waits for your message.
    fn typing(&mut self, worker: &str, messages: &Messages) {
        if self.practice && self.practicing && !self.holding {
            self.interrupt(worker, messages);
        }
    }

    fn interrupt(&mut self, worker: &str, messages: &Messages) {
        self.holding = true;
        let mut out = Vec::new();
        self.answer.finish(&mut out, columns());
        self.arguments.clear();
        ui::lines(out);
        messages.send(json!({"action":"practiceInterrupt","workerId":worker}));
    }

    /// The worker goes on without a message.
    fn resume(&mut self, worker: &str, messages: &Messages) {
        if self.holding {
            self.holding = false;
            self.since = Instant::now();
            messages.send(json!({"action":"practiceResume","workerId":worker}));
        }
    }

    /// One key. Returns how the console closes, if this key closes it.
    async fn key(&mut self, worker: &str, key: KeyEvent, editor: &mut Editor, messages: &Messages, block: &ui::Block) -> Result<Option<Leave>, String> {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Char('c') if ctrl => {
                ui::take_interrupt();
                if self.practice {
                    return end_practice(worker).await.map(Some);
                }
                return self.stop(worker, block).await;
            }
            KeyCode::Char(']') if ctrl => {
                if self.holding {
                    let _ = dispatch(json!({"action":"practiceResume","workerId":worker})).await;
                }
                return Ok(Some(Leave::Detached));
            }
            KeyCode::Esc if !editor.text.is_empty() => {
                editor.set(String::new());
                self.resume(worker, messages);
            }
            KeyCode::Esc if self.holding => self.resume(worker, messages),
            KeyCode::Esc => self.typing(worker, messages),
            KeyCode::Enter => match editor.key(&key) {
                Input::Send(text) => return self.submit(worker, &text, messages, block).await,
                _ => self.resume(worker, messages),
            },
            _ => {
                let typing = editor.text.is_empty();
                editor.key(&key);
                if typing && !editor.text.is_empty() {
                    self.typing(worker, messages);
                }
            }
        }
        Ok(None)
    }

    /// A line you sent: a command, or a message for the worker.
    async fn submit(&mut self, worker: &str, text: &str, messages: &Messages, block: &ui::Block) -> Result<Option<Leave>, String> {
        let command = text.to_ascii_lowercase();
        match command.as_str() {
            "/endpractice" | "/stop" if self.practice => return end_practice(worker).await.map(Some),
            "/stop" => return self.stop(worker, block).await,
            "/help" => {
                ui::lines(help(self.practice));
                self.resume(worker, messages);
                return Ok(None);
            }
            "/clear" => {
                ui::clear();
                self.resume(worker, messages);
                return Ok(None);
            }
            _ if text.starts_with('/') => {
                ui::line(&note("Unknown command. Type /help for the commands."));
                self.resume(worker, messages);
                return Ok(None);
            }
            _ => {}
        }
        ui::lines(you(text, columns()));
        if !self.practice {
            messages.send(json!({"action":"chat","workerId":worker,"content":text}));
        } else if self.practicing {
            // The engine goes on as soon as it has your message.
            self.holding = false;
            self.since = Instant::now();
            messages.send(json!({"action":"practiceInput","workerId":worker,"content":text}));
        } else {
            self.running(true);
            self.since = Instant::now();
            messages.send(json!({"action":"practiceStart","workerId":worker,"content":text}));
        }
        Ok(None)
    }

    /// `/stop` or Ctrl+C while watching work: pause or leave the accepted bounty.
    async fn stop(&mut self, worker: &str, block: &ui::Block) -> Result<Option<Leave>, String> {
        block.set(Vec::new());
        Ok(bounty::console_stop(worker).await?.then_some(Leave::Stopped))
    }

    /// The live area: the row being written, the status line, the composer and its keys.
    fn frame(&self, editor: &Editor, nested: bool, columns: usize, now: Instant) -> Vec<String> {
        let mut lines = Vec::new();
        let mut live = self.answer.live(columns);
        if !self.arguments.trim().is_empty() {
            let shown: String = self.arguments.split_whitespace().collect::<Vec<_>>().join(" ");
            let room = columns.saturating_sub(7);
            let tail: String = shown.chars().rev().take(room).collect::<Vec<_>>().into_iter().rev().collect();
            live.push(format!("  {} {}", ui::muted("└"), ui::muted(&tail)));
        }
        if !live.is_empty() {
            lines.push(String::new());
            lines.extend(live);
        }
        lines.push(String::new());
        if let Some(status) = self.status_line(now) {
            lines.push(status);
        }
        lines.extend(composer(editor, if self.practice { PLACEHOLDER } else { "Message your agent" }, columns));
        lines.push(format!("  {}", ui::muted(hints(self.practice, nested))));
        // A live line never wraps: the painter could not erase it again.
        lines.into_iter().map(|line| ui::clip(&line, columns.saturating_sub(1))).collect()
    }

    fn status_line(&self, now: Instant) -> Option<String> {
        if self.holding {
            return Some(format!("{} {}", ui::paint("◦", ui::SKY), ui::muted("Waiting for your message · enter sends it · esc lets your worker go on")));
        }
        let label = if self.practice {
            if !self.practicing {
                return None;
            }
            self.status.clone().unwrap_or_else(|| "Working".into())
        } else {
            match self.state.as_str() {
                "running" | "working" => "Working".into(),
                "preparing_bounty" => "Preparing the bounty".into(),
                _ => return None,
            }
        };
        let elapsed = now.saturating_duration_since(self.since);
        let tick = (elapsed.as_millis() / 80) as usize;
        let detail = if self.practice { format!(" ({} • esc to interrupt)", seconds(elapsed)) } else { format!(" ({})", seconds(elapsed)) };
        Some(format!("{} {}{}", ui::paint(&ui::spinner(tick).to_string(), ui::SKY), ui::shimmer(&label, elapsed), ui::muted(&detail)))
    }
}

fn seconds(elapsed: Duration) -> String {
    if elapsed < Duration::from_secs(60) {
        format!("{}s", elapsed.as_secs())
    } else {
        ui::clock(elapsed)
    }
}

/// `/endpractice` or Ctrl+C in a practice console.
async fn end_practice(worker: &str) -> Result<Leave, String> {
    ui::take_interrupt();
    dispatch(json!({"action":"practiceStop","workerId":worker})).await?;
    Ok(Leave::Ended)
}

/// The model's streamed answer. Finished rows join the transcript; the row being written stays
/// in the live area. Reasoning models wrap their thinking in `<think>` tags, often empty ones:
/// thinking shows dimmed under a "Thinking" line, the tags never.
#[derive(Default)]
struct Answer {
    /// Text not yet sorted into thinking or answer, because it may end with part of a tag.
    pending: String,
    /// Inside `<think>`, or reading the model's separate reasoning.
    thinking: bool,
    /// The last text came through the model's separate reasoning.
    reasoning: bool,
    /// The paragraph being written.
    paragraph: String,
    /// What this answer has shown so far.
    shown: Shown,
    /// The answer's first row, with its bullet, is in the transcript.
    bulleted: bool,
    /// An empty line goes before the next row.
    blank: bool,
}

#[derive(Default, PartialEq, Clone, Copy)]
enum Shown {
    #[default]
    Nothing,
    Thinking,
    Answer,
}

const TAGS: [&str; 2] = ["<think>", "</think>"];

impl Answer {
    /// A piece of the model's answer, which may hold `<think>` tags.
    fn push(&mut self, piece: &str, out: &mut Vec<String>, columns: usize) {
        if self.reasoning {
            self.reasoning = false;
            self.switch(false, out, columns);
        }
        self.pending.push_str(&clean(piece));
        loop {
            let found = TAGS.iter().filter_map(|tag| self.pending.find(tag).map(|at| (at, *tag))).min();
            if let Some((at, tag)) = found {
                let before = self.pending[..at].to_owned();
                self.pending.drain(..at + tag.len());
                self.text(&before, out, columns);
                self.switch(tag == "<think>", out, columns);
                continue;
            }
            // Keep what may be the start of a tag until the next piece.
            let keep = (1..=self.pending.len().min(8))
                .rev()
                .find(|n| self.pending.is_char_boundary(self.pending.len() - n) && TAGS.iter().any(|tag| tag.starts_with(&self.pending[self.pending.len() - n..])))
                .unwrap_or(0);
            let ready: String = self.pending.drain(..self.pending.len() - keep).collect();
            self.text(&ready, out, columns);
            return;
        }
    }

    /// A piece of the model's separate reasoning.
    fn push_thinking(&mut self, piece: &str, out: &mut Vec<String>, columns: usize) {
        self.reasoning = true;
        self.switch(true, out, columns);
        self.text(&clean(piece), out, columns);
    }

    fn switch(&mut self, thinking: bool, out: &mut Vec<String>, columns: usize) {
        if self.thinking != thinking {
            self.end_paragraph(out, columns);
            self.thinking = thinking;
            self.blank = false;
        }
    }

    fn text(&mut self, text: &str, out: &mut Vec<String>, columns: usize) {
        for (i, part) in text.split('\n').enumerate() {
            if i > 0 {
                self.end_paragraph(out, columns);
            }
            self.paragraph.push_str(part);
        }
        self.flush(false, out, columns);
    }

    fn end_paragraph(&mut self, out: &mut Vec<String>, columns: usize) {
        if self.paragraph.trim().is_empty() {
            self.paragraph.clear();
            // Paragraphs keep one empty line between them, never before the first.
            self.blank = self.shown != Shown::Nothing;
            return;
        }
        self.flush(true, out, columns);
        self.paragraph.clear();
    }

    /// Commits the rows of the paragraph that can no longer change, all of them once `finished`.
    fn flush(&mut self, finished: bool, out: &mut Vec<String>, columns: usize) {
        let start = self.paragraph.len() - self.paragraph.trim_start().len();
        self.paragraph.drain(..start);
        if self.paragraph.is_empty() {
            return;
        }
        let rows = ui::wrap(&self.paragraph, Self::width(columns));
        let count = rows.len() - usize::from(!finished);
        let mut used = 0;
        for (row, bytes) in &rows[..count] {
            used += bytes;
            self.commit(row.trim_end(), out);
        }
        self.paragraph.drain(..used.min(self.paragraph.len()));
    }

    fn width(columns: usize) -> usize {
        columns.saturating_sub(4).max(12)
    }

    fn commit(&mut self, row: &str, out: &mut Vec<String>) {
        out.extend(self.lead());
        self.blank = false;
        out.push(self.row(row));
        self.bulleted |= !self.thinking;
    }

    /// The lines that open this answer's thinking or answer before its first row.
    fn lead(&mut self) -> Vec<String> {
        let now = if self.thinking { Shown::Thinking } else { Shown::Answer };
        if self.shown == now {
            return if self.blank { vec![String::new()] } else { Vec::new() };
        }
        self.shown = now;
        if self.thinking {
            vec![String::new(), format!("{} {}", ui::muted("•"), ui::muted(&ui::italic("Thinking")))]
        } else {
            vec![String::new()]
        }
    }

    /// A row as the transcript shows it: thinking dimmed, the answer's first row with a bullet.
    fn row(&self, row: &str) -> String {
        if self.thinking {
            format!("  {}", ui::muted(&ui::italic(row)))
        } else if self.bulleted {
            format!("  {row}")
        } else {
            format!("{} {row}", ui::paint("•", ui::SKY))
        }
    }

    /// The row being written, for the live area.
    fn live(&self, columns: usize) -> Vec<String> {
        let rest = self.paragraph.trim_start();
        let pending = if TAGS.iter().any(|tag| tag.starts_with(self.pending.as_str())) { "" } else { self.pending.as_str() };
        let text = format!("{rest}{pending}");
        if text.trim().is_empty() {
            return Vec::new();
        }
        let rows = ui::wrap(&text, Self::width(columns));
        let row = rows.last().map(|(row, _)| row.trim_end()).unwrap_or_default();
        if self.thinking && self.shown != Shown::Thinking {
            return vec![format!("{} {}", ui::muted("•"), ui::muted(&ui::italic("Thinking"))), self.row(row)];
        }
        vec![self.row(row)]
    }

    /// The answer is over: whatever is left joins the transcript.
    fn finish(&mut self, out: &mut Vec<String>, columns: usize) {
        let pending = std::mem::take(&mut self.pending);
        self.text(&pending, out, columns);
        self.end_paragraph(out, columns);
        *self = Self::default();
    }
}


/// Model text without control characters, which never reach the terminal; tabs become spaces.
fn clean(piece: &str) -> String {
    piece.replace('\t', "    ").split('\n').map(safe).collect::<Vec<_>>().join("\n")
}

/// An item of the transcript: an empty line, then `bullet text`, wrapped under itself.
fn item(out: &mut Vec<String>, bullet: &str, text: &str, columns: usize, style: impl Fn(&str) -> String) {
    out.push(String::new());
    out.extend(indented(text, &format!("{bullet} "), "  ", columns, style));
}

/// `text` wrapped to the terminal, its first row after `first` and the others after `rest`.
fn indented(text: &str, first: &str, rest: &str, columns: usize, style: impl Fn(&str) -> String) -> Vec<String> {
    let width = columns.saturating_sub(1 + ui::width(first).max(ui::width(rest))).max(12);
    ui::wrap(text, width)
        .into_iter()
        .enumerate()
        .map(|(i, (row, _))| format!("{}{}", if i == 0 { first } else { rest }, style(row.trim_end())))
        .collect()
}

fn plain(text: &str) -> String {
    text.to_owned()
}

/// A line across the transcript with `label` in it.
fn rule(label: &str, columns: usize) -> String {
    let fill = columns.saturating_sub(ui::width(label) + 4);
    ui::muted(&format!("─ {label} {}", "─".repeat(fill)))
}

/// A box of `title` and labelled `rows`, as wide as its content and the terminal allow.
fn card(title: &str, rows: &[(&str, String)], columns: usize) -> Vec<String> {
    let label = rows.iter().map(|(name, _)| name.len()).max().unwrap_or(0);
    let mut body = vec![title.to_owned(), String::new()];
    body.extend(rows.iter().map(|(name, value)| format!("{}  {value}", ui::muted(&format!("{name:<label$}")))));
    let inner = body.iter().map(|line| ui::width(line)).max().unwrap_or(0).clamp(10, columns.saturating_sub(5).max(10));
    boxed(body, inner)
}

/// `lines` in a rounded box `inner` columns wide.
fn boxed(lines: Vec<String>, inner: usize) -> Vec<String> {
    let mut out = vec![ui::muted(&format!("╭{}╮", "─".repeat(inner + 2)))];
    for line in lines {
        let line = ui::clip(&line, inner);
        let pad = " ".repeat(inner.saturating_sub(ui::width(&line)));
        out.push(format!("{} {line}{pad} {}", ui::muted("│"), ui::muted("│")));
    }
    out.push(ui::muted(&format!("╰{}╯", "─".repeat(inner + 2))));
    out
}

/// The box you type in.
fn composer(editor: &Editor, placeholder: &str, columns: usize) -> Vec<String> {
    let inner = columns.saturating_sub(5).max(12);
    let rows = editor
        .rows(placeholder, inner - 2)
        .into_iter()
        .enumerate()
        .map(|(i, row)| format!("{} {row}", if i == 0 { ui::paint("›", ui::SKY) } else { " ".into() }))
        .collect();
    boxed(rows, inner)
}

/// `hf.co/Owner/Name-GGUF:Q4_K_M` as `Name-GGUF:Q4_K_M`.
fn model_name(model: &str) -> String {
    model.rsplit('/').next().unwrap_or(model).to_owned()
}

/// How the practice's verifier judged a report.
fn verdict(event: &Value, columns: usize) -> Vec<String> {
    let text = |value: &Value| {
        let text = safe(value.as_str().unwrap_or("—"));
        if text.chars().count() > 600 { format!("{}…", text.chars().take(600).collect::<String>()) } else { text }
    };
    let good = event["qualifies"] == true;
    let finding = &event["finding"];
    let seconds = Duration::from_secs_f64(event["seconds"].as_f64().unwrap_or(0.0).max(0.0));
    let mut lines = vec![
        String::new(),
        format!(
            "{} {} {}",
            ui::paint("•", if good { ui::GREEN } else { ui::AMBER }),
            ui::bold(if good { "Flag captured — finding confirmed" } else { "Finding rejected" }),
            ui::muted(&format!("· {}", ui::clock(seconds)))
        ),
    ];
    let mut details = Vec::new();
    if finding.is_object() {
        details.push(text(&finding["title"]));
        if finding["technique"].is_string() {
            details.push(format!("Technique: {}", text(&finding["technique"])));
        }
        details.push(format!("Flag: {}", text(&finding["flag"])));
    }
    details.push(format!("Verification: {}", text(&event["reason"])));
    for (i, detail) in details.iter().enumerate() {
        let (first, style): (String, fn(&str) -> String) = if i == 0 { (format!("  {} ", ui::muted("└")), plain) } else { ("    ".into(), ui::muted) };
        lines.extend(indented(detail, &first, "    ", columns, style));
    }
    lines
}

/// Your message in the transcript.
fn you(text: &str, columns: usize) -> Vec<String> {
    let mut lines = vec![String::new()];
    lines.extend(indented(&safe(text), &format!("{} ", ui::paint("›", ui::SKY)), "  ", columns, ui::bold));
    lines
}

/// The keys under the composer. Opened from the waiting view (`nested`), Ctrl+] goes back to
/// it; opened on its own, Ctrl+] ends the command and leaves the engine working.
fn hints(practice: bool, nested: bool) -> &'static str {
    match (practice, nested) {
        (true, true) => "enter send · esc interrupt · /endpractice ends it · ctrl+] back · /help",
        (true, false) => "enter send · esc interrupt · /endpractice ends it · ctrl+] detach · /help",
        (false, true) => "enter message your agent · /stop pause or leave · ctrl+] back · /help",
        (false, false) => "enter message your agent · /stop pause or leave · ctrl+] detach · /help",
    }
}

fn help(practice: bool) -> Vec<String> {
    let mut rows = if practice {
        vec![
            ("/endpractice", "end the practice and leave (ctrl+c too)"),
            ("esc", "stop your worker's answer; esc again lets it go on"),
        ]
    } else {
        vec![("/stop", "pause or leave the bounty (ctrl+c too)")]
    };
    rows.extend([
        ("/clear", "clear the screen"),
        ("↑ ↓", "earlier messages"),
        ("ctrl+]", "leave the console; the engine keeps working"),
    ]);
    let mut lines = vec![String::new()];
    lines.extend(rows.into_iter().map(|(key, meaning)| format!("  {}  {}", ui::paint(&format!("{key:<12}"), ui::SKY), ui::muted(meaning))));
    lines
}

/// What Ctrl+] leaves on screen when the console returns to the waiting view.
pub(crate) fn back_to_waiting_view(practice: bool) -> &'static str {
    if practice {
        "Back to the waiting view; the practice keeps running in the engine."
    } else {
        "Back to the waiting view; your agent keeps working in the engine."
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_snapshots_append_only_new_text() {
        let mut view = View::new(false);
        let mut out = Vec::new();
        for text in ["Hello", "Hello world", "Hello world"] {
            view.event(&json!({"kind":"text", "streamId":"s:1", "text":text}), &mut out, 80);
        }
        view.answer.finish(&mut out, 80);
        let rendered = out.join("\n");
        assert_eq!(rendered.matches("Hello").count(), 1);
        assert!(rendered.contains("Hello world"));
    }

    fn streamed(pieces: &[&str], columns: usize) -> (Vec<String>, Answer) {
        let mut answer = Answer::default();
        let mut out = Vec::new();
        for piece in pieces {
            answer.push(piece, &mut out, columns);
        }
        (out, answer)
    }

    #[test]
    fn empty_thinking_never_shows_and_the_answer_streams_under_a_bullet() {
        let (out, mut answer) = streamed(&["<think>\n\n</think>\n\n", "The admin password"], 80);
        assert!(out.is_empty(), "{out:?}");
        let live = answer.live(80);
        assert_eq!(live.len(), 1);
        assert!(live[0].contains('•') && live[0].ends_with("The admin password"), "{live:?}");
        let mut out = Vec::new();
        answer.finish(&mut out, 80);
        assert_eq!(out.len(), 2);
        assert!(out[0].is_empty() && out[1].ends_with("The admin password"));
        assert!(answer.live(80).is_empty(), "a finished answer leaves the live area");
    }

    #[test]
    fn thinking_shows_dimmed_and_tags_split_across_pieces_never_show() {
        let (mut out, mut answer) = streamed(&["<thi", "nk>Look at auth", ".js</th", "ink>\n\nIt is hard", "coded.\nSecond line"], 80);
        answer.finish(&mut out, 80);
        let text = out.join("\n");
        for shown in ["Thinking", "Look at auth.js", "It is hardcoded.", "Second line"] {
            assert!(text.contains(shown), "{shown} in {text}");
        }
        assert!(!text.contains("think>") && !text.contains('<'), "{text}");
        let bullets = out.iter().filter(|line| line.contains('•')).count();
        assert_eq!(bullets, 2, "one for the thinking, one for the answer: {out:?}");
        // The model's separate reasoning reads the same way.
        let mut answer = Answer::default();
        let mut out = Vec::new();
        answer.push_thinking("Checking auth.js", &mut out, 80);
        answer.push("Line 3 holds it.", &mut out, 80);
        answer.finish(&mut out, 80);
        let text = out.join("\n");
        assert!(text.contains("Thinking") && text.contains("Checking auth.js") && text.contains("Line 3 holds it."), "{text}");
    }

    #[test]
    fn long_answers_commit_finished_rows_and_keep_the_row_being_written_live() {
        let words = "word ".repeat(60);
        let (out, answer) = streamed(&[&words], 40);
        assert!(out.len() > 2, "{out:?}");
        assert!(out.iter().all(|line| ui::width(line) <= 39), "{out:?}");
        assert_eq!(answer.live(40).len(), 1);
        // A lone `<` may start a tag: it waits for the next piece, then shows as text.
        let (out, mut answer) = streamed(&["a < b", " and <"], 80);
        assert!(out.is_empty());
        assert!(answer.live(80)[0].ends_with("a < b and"), "{:?}", answer.live(80));
        let mut out = Vec::new();
        answer.push("c", &mut out, 80);
        answer.finish(&mut out, 80);
        assert!(out.last().unwrap().ends_with("a < b and <c"), "{out:?}");
    }

    #[test]
    fn requests_responses_tries_and_the_captured_flag_show_in_the_transcript() {
        let mut view = View::new(true);
        let mut out = Vec::new();
        view.event(&json!({"kind":"request","method":"POST","path":"/login","body":"{\"user\":\"admin\",\"password\":\"admin\"}"}), &mut out, 80);
        view.event(&json!({"kind":"response","status":200,"body":"{\"ok\":true,\"token\":\"abc\"}"}), &mut out, 80);
        view.event(&json!({"kind":"tried","text":"default credentials admin/admin logged in"}), &mut out, 80);
        let text = out.join("\n");
        assert!(text.contains("Request") && text.contains("POST") && text.contains("/login") && text.contains("admin"), "{text}");
        assert!(text.contains("Response") && text.contains("200") && text.contains("token"), "{text}");
        assert!(!text.contains('→') && !text.contains('←'), "labels, not arrows: {text}");
        assert!(text.contains("Tried: default credentials"), "{text}");
        // A rejected finding and then a captured flag.
        let mut out = Vec::new();
        view.event(&json!({"kind":"verdict","attempt":1,"qualifies":false,"seconds":1.0,"reason":"That is not the flag.","finding":{"title":"Default creds","flag":"YGR{wrong}"}}), &mut out, 80);
        assert!(out.join("\n").contains("Finding rejected"), "{out:?}");
        let mut out = Vec::new();
        let finding = json!({"title":"Default admin credentials","technique":"admin/admin then GET /flag","flag":"YGR{abc123}"});
        view.event(&json!({"kind":"verdict","attempt":2,"qualifies":true,"seconds":4.5,"reason":"The reported flag matches.","finding":finding}), &mut out, 80);
        let text = out.join("\n");
        for shown in ["Flag captured", "Default admin credentials", "Technique: admin/admin", "Flag: YGR{abc123}", "Verification: The reported flag matches."] {
            assert!(text.contains(shown), "{shown} in {text}");
        }
        view.event(&json!({"kind":"practiceEnd","outcome":"qualified","text":"Your worker captured the flag after 1 try."}), &mut out, 80);
        assert!(!view.practicing);
        assert!(out.join("\n").contains("/endpractice"));
    }

    #[test]
    fn the_live_area_shows_the_work_the_composer_and_its_keys() {
        let editor = Editor::default();
        let start = Instant::now();
        let mut view = View::new(true);
        for columns in [24, 80, 200] {
            let frame = view.frame(&editor, true, columns, start);
            assert!(frame.iter().all(|line| ui::width(line) < columns), "{columns}: {frame:?}");
            for line in card("Practice bounty", &[("model", "x".repeat(300))], columns) {
                assert!(ui::width(&line) < columns, "{line}");
            }
        }
        let text = view.frame(&editor, true, 80, start).join("\n");
        assert!(text.contains("Working") && text.contains("esc to interrupt") && text.contains(PLACEHOLDER) && text.contains("/endpractice"), "{text}");
        view.holding = true;
        assert!(view.frame(&editor, true, 80, start).join("\n").contains("Waiting for your message"));
        view.running(false);
        let text = view.frame(&editor, false, 80, start).join("\n");
        assert!(!text.contains("Working") && !text.contains("Waiting") && text.contains("ctrl+] detach"), "{text}");
        let work = View::new(false).frame(&editor, true, 80, start).join("\n");
        assert!(work.contains("Message your agent") && work.contains("/stop"), "{work}");
    }

    #[test]
    fn leaving_inside_the_waiting_view_goes_back_to_it() {
        for practice in [true, false] {
            assert!(hints(practice, true).contains("ctrl+] back") && hints(practice, false).contains("ctrl+] detach"));
            let back = back_to_waiting_view(practice);
            assert!(back.starts_with("Back to the waiting view") && !back.contains("Reconnect"), "{back}");
        }
        assert!(back_to_waiting_view(true).contains("practice keeps running"));
        assert!(back_to_waiting_view(false).contains("agent keeps working"));
        assert_eq!(model_name("hf.co/Owner/Name-GGUF:Q4_K_M"), "Name-GGUF:Q4_K_M");
    }
}
