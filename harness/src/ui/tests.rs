//! The screen's tests: snapshots of every part at 100x30 and 60x20 (ratatui's TestBackend),
//! state transitions from events and keys, the scripted tours played through the state and
//! against the scripted engine, frame sizes, and the terminal pane.
use super::draw::{self, buffer_text};
use super::mask::Masker;
use super::overlay::Overlay;
use super::pane::{self, Pane, PanePhase};
use super::screen::Screen;
use super::state::{App, Effect, Phase, Scroll};
use super::theme::{Depth, Theme};
use crate::protocol::{Command, Event, ToolStatus};
use crate::spec::EngineSpec;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Color;
use ratatui::Terminal;
use std::time::{Duration, Instant};

const TOUR: &str = include_str!("../../tests/scripts/tour.jsonl");
const SECURITY_TOUR: &str = include_str!("../../tests/scripts/security-tour.jsonl");

fn spec(json: &str) -> EngineSpec {
    serde_json::from_str(json).expect("test spec")
}

fn coding_spec() -> EngineSpec {
    spec(
        r#"{"harness":"opencode","name":"OpenCode","category":"coding","protocol":"acp","argv":["opencode","acp"],
            "cwd":"/workspace","model":"qwen3-coder-30b","models":["qwen3-coder-30b","gemma-4-26B-A4B-it","gpt-oss-20b"],
            "model_switch":"restart","state_dir":"/home/node/.yougori"}"#,
    )
}

fn security_spec() -> EngineSpec {
    spec(
        r#"{"harness":"strix","name":"Strix","category":"security","protocol":"acp","argv":["strix-acp"],
            "cwd":"/workspace","model":"unsloth/gemma-4-26B-A4B-it-GGUF","models":["unsloth/gemma-4-26B-A4B-it-GGUF","qwen3-coder-30b"],
            "model_switch":"live","state_dir":"/s","answers":{"target":"https://shop.example.test","depth":"safe"},
            "reach":{"mode":"targets","targets":["shop.example.test:443"]}}"#,
    )
}

const READY: &str = r#"{"type":"ready","harness":"opencode","name":"OpenCode","model":"qwen3-coder-30b","models":["qwen3-coder-30b","gemma-4-26B-A4B-it","gpt-oss-20b"],"model_switch":"restart","info":"OpenCode 1.0 · build mode"}"#;
const MODES: &str = r#"{"type":"modes","current":"build","available":[{"id":"build","name":"Build"},{"id":"plan","name":"Plan","description":"Reads, changes nothing"}]}"#;
const COMMANDS: &str = r#"{"type":"commands","commands":[{"name":"new","description":"Start a new session"},{"name":"sessions","description":"Open an earlier session"},{"name":"compact","description":"Summarise the conversation"},{"name":"review","description":"Review the changes","hint":"what to review"}]}"#;

struct Rig {
    app: App,
    t0: Instant,
    now: Instant,
}

impl Rig {
    fn new(spec: EngineSpec) -> Rig {
        Rig::with(spec, Masker::default(), true)
    }

    fn with(spec: EngineSpec, masker: Masker, owns: bool) -> Rig {
        let t0 = Instant::now();
        let mut app = App::new(spec, Theme::new(Depth::True), masker, owns, t0);
        app.version = "1.0.0".into();
        Rig { app, t0, now: t0 }
    }

    /// The clock moves to `ms` after the start.
    fn at(&mut self, ms: u64) -> &mut Rig {
        self.now = self.t0 + Duration::from_millis(ms);
        self
    }

    fn event(&mut self, json: &str) -> &mut Rig {
        let event: Event = serde_json::from_str(json).unwrap_or_else(|e| panic!("{e}: {json}"));
        self.app.apply(event, self.now);
        self
    }

    fn ready(&mut self) -> &mut Rig {
        self.event(READY)
            .event(MODES)
            .event(COMMANDS)
            .event(r#"{"type":"usage","context_tokens":3277,"context_window":32768}"#)
    }

    fn key(&mut self, code: KeyCode, modifiers: KeyModifiers) -> &mut Rig {
        self.app.key(KeyEvent::new(code, modifiers), self.now);
        self
    }

    fn press(&mut self, code: KeyCode) -> &mut Rig {
        self.key(code, KeyModifiers::NONE)
    }

    fn ctrl(&mut self, c: char) -> &mut Rig {
        self.key(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    fn type_text(&mut self, text: &str) -> &mut Rig {
        for c in text.chars() {
            self.press(KeyCode::Char(c));
        }
        self
    }

    /// Types a prompt and sends it.
    fn prompt(&mut self, text: &str) -> &mut Rig {
        self.type_text(text).press(KeyCode::Enter)
    }

    fn effects(&mut self) -> Vec<Effect> {
        std::mem::take(&mut self.app.effects)
    }

    fn sent(&mut self) -> Vec<Command> {
        self.effects()
            .into_iter()
            .filter_map(|e| match e {
                Effect::Send(command) => Some(command),
                _ => None,
            })
            .collect()
    }

    fn buffer(&mut self, width: u16, height: u16) -> Buffer {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("test terminal");
        let now = self.now;
        let app = &mut self.app;
        terminal
            .draw(|frame| {
                let area = frame.area();
                let drawn = draw::draw(app, area, frame.buffer_mut(), now);
                if let Some(cursor) = drawn.cursor {
                    frame.set_cursor_position(cursor);
                }
            })
            .expect("draw");
        terminal.backend().buffer().clone()
    }

    fn render(&mut self, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("test terminal");
        let now = self.now;
        let app = &mut self.app;
        let mut cursor = None;
        terminal
            .draw(|frame| {
                let area = frame.area();
                let drawn = draw::draw(app, area, frame.buffer_mut(), now);
                cursor = drawn.cursor;
                if let Some(cursor) = drawn.cursor {
                    frame.set_cursor_position(cursor);
                }
            })
            .expect("draw");
        let mut text = buffer_text(terminal.backend().buffer());
        match cursor {
            Some(p) => text.push_str(&format!("[cursor {},{}]\n", p.x, p.y)),
            None => text.push_str("[no cursor]\n"),
        }
        text
    }

    /// Snapshots at both sizes.
    fn snap(&mut self, name: &str) {
        let wide = self.render(100, 30);
        insta::assert_snapshot!(format!("{name}_100x30"), wide);
        let narrow = self.render(60, 20);
        insta::assert_snapshot!(format!("{name}_60x20"), narrow);
    }
}

fn find_row(buffer: &Buffer, needle: &str) -> Option<u16> {
    let text = buffer_text(buffer);
    text.lines().position(|l| l.contains(needle)).map(|i| i as u16)
}

/// The colour of the first cell of `needle` on the screen.
fn color_of(buffer: &Buffer, needle: &str) -> Option<Color> {
    let row = find_row(buffer, needle)?;
    let line: String =
        (0..buffer.area.width).map(|x| buffer[(x, row)].symbol().to_owned()).collect::<Vec<_>>().concat();
    let at = line.find(needle)?;
    let column = line[..at].chars().count() as u16;
    Some(buffer[(column, row)].fg)
}

// ---- Snapshots ----

#[test]
fn home_coding() {
    let mut rig = Rig::new(coding_spec());
    rig.at(500).ready();
    rig.snap("home_coding");
}

#[test]
fn home_security() {
    let mut rig = Rig::new(security_spec());
    rig.at(500).event(r#"{"type":"ready","harness":"strix","name":"Strix","model":"unsloth/gemma-4-26B-A4B-it-GGUF","model_switch":"live","info":"Strix 0.4 · 3 agents"}"#);
    rig.snap("home_security");
}

#[test]
fn home_while_starting() {
    let mut rig = Rig::new(coding_spec());
    rig.at(2400);
    rig.snap("home_starting");
}

#[test]
fn streamed_message_with_code() {
    let mut rig = Rig::new(coding_spec());
    rig.ready().at(1000).prompt("Show me how to read a file in Rust");
    rig.at(1500)
        .event(r#"{"type":"message","message":"m1","text":"Use `std::fs::read_to_string`:\n\n```rust\nuse std::fs;\n\nfn main() -> std::io::Result<()> {\n"}"#)
        .event(r#"{"type":"message","message":"m1","text":"    let text = fs::read_to_string(\"notes.txt\")?;\n    println!(\"{text}\");\n    Ok(())\n}\n```\n\nIt returns an **error** when the file is missing."}"#);
    rig.at(4200);
    rig.snap("streamed_message_code");
    let buffer = rig.buffer(100, 30);
    assert_eq!(color_of(&buffer, "fn main"), Some(Color::Rgb(0x38, 0xbd, 0xf8)), "keywords are sky blue");
    assert_eq!(
        color_of(&buffer, "std::fs::read_to_string"),
        Some(Color::Rgb(0x9c, 0xc2, 0xff)),
        "inline code is pale blue"
    );
}

#[test]
fn reasoning_folded_and_open() {
    let mut rig = Rig::new(coding_spec());
    rig.ready().at(1000).prompt("Why does the build fail?");
    rig.event(r#"{"type":"reasoning","message":"r1","text":"The error mentions a missing feature flag. Cargo.toml enables "}"#)
        .event(r#"{"type":"reasoning","message":"r1","text":"tokio without the macros feature, so #[tokio::main] is not found."}"#)
        .event(r#"{"type":"message","message":"m1","text":"tokio is missing its `macros` feature."}"#)
        .event(r#"{"type":"turn_end","reason":"end_turn"}"#);
    rig.at(3000);
    rig.snap("reasoning_folded");
    rig.ctrl('o');
    rig.snap("reasoning_open");
}

#[test]
fn tool_row_with_a_diff() {
    let mut rig = Rig::new(coding_spec());
    rig.ready().at(1000).prompt("Fix the unwrap");
    rig.at(1200)
        .event(r#"{"type":"tool_call","id":"t1","title":"Edit src/parser.rs","kind":"edit","status":"in_progress"}"#);
    rig.at(1500).event(r#"{"type":"tool_update","id":"t1","status":"completed","content":[{"type":"diff","path":"src/parser.rs","old":"fn parse(input: &str) -> Option<Ast> {\n    let first = tokens(input).next().unwrap();\n    Some(Ast::new(first))\n}\n","new":"fn parse(input: &str) -> Option<Ast> {\n    let first = tokens(input).next()?;\n    Some(Ast::new(first))\n}\n"}]}"#);
    let long_old: String = (1..=40).map(|i| format!("line {i}\n")).collect();
    let long_new: String =
        (1..=40).map(|i| if i % 3 == 0 { format!("changed {i}\n") } else { format!("line {i}\n") }).collect();
    let call = serde_json::json!({"type":"tool_call","id":"t2","title":"Edit src/long.rs","kind":"edit","status":"completed","content":[{"type":"diff","path":"src/long.rs","old":long_old,"new":long_new}]});
    rig.at(1800).event(&call.to_string());
    rig.at(2000).event(r#"{"type":"turn_end","reason":"end_turn"}"#);
    rig.snap("tool_diff");
    let buffer = rig.buffer(100, 30);
    assert_eq!(color_of(&buffer, "let first = tokens(input).next().unwrap();"), Some(Color::Rgb(0xf8, 0x71, 0x71)));
    assert_eq!(color_of(&buffer, "let first = tokens(input).next()?;"), Some(Color::Rgb(0x4a, 0xde, 0x80)));
}

#[test]
fn running_terminal_tool() {
    let mut rig = Rig::new(coding_spec());
    rig.ready().at(1000).prompt("Run the tests");
    let output: String = (1..=30).map(|i| format!("test case_{i:02} ... ok\n")).collect();
    let call = serde_json::json!({"type":"tool_call","id":"t1","title":"cargo test","kind":"execute","status":"in_progress","content":[{"type":"terminal","command":"cargo test","output":output}]});
    rig.at(1100).event(&call.to_string());
    rig.at(4300);
    rig.snap("terminal_running");
}

#[test]
fn nested_subagent_rows() {
    let mut rig = Rig::new(coding_spec());
    rig.ready().at(1000).prompt("Find the callers");
    for line in [
        r#"{"type":"tool_call","id":"task","title":"Find the callers of parse()","kind":"task","status":"in_progress"}"#,
        r#"{"type":"tool_call","id":"a","title":"parse\\(","kind":"search","status":"completed","parent":"task"}"#,
        r#"{"type":"tool_call","id":"b","title":"src/cli.rs","kind":"read","status":"in_progress","parent":"task"}"#,
        r#"{"type":"message","message":"sub","text":"Two callers so far: src/lib.rs and src/cli.rs.","parent":"task"}"#,
    ] {
        rig.event(line);
    }
    rig.at(3500);
    rig.snap("nested_subagent");
}

const PERMISSION: &str = r#"{"type":"permission","id":"p1","tool_call":"t1","title":"Run cargo test --workspace","detail":"cargo test --workspace\nin /workspace","options":[{"id":"allow_once","label":"Allow once","kind":"allow_once"},{"id":"allow_always","label":"Always allow cargo test","kind":"allow_always"},{"id":"reject_once","label":"Reject","kind":"reject_once"},{"id":"reject_always","label":"Always reject","kind":"reject_always"}]}"#;

#[test]
fn permission_dialog() {
    let mut rig = Rig::new(coding_spec());
    rig.ready().at(1000).prompt("Test everything");
    rig.at(1100)
        .event(r#"{"type":"tool_call","id":"t1","title":"cargo test --workspace","kind":"execute","status":"pending"}"#)
        .event(PERMISSION);
    rig.at(1200);
    rig.snap("permission");
}

#[test]
fn question_with_choices() {
    let mut rig = Rig::new(coding_spec());
    rig.ready().at(1000).prompt("Add a database");
    rig.event(r#"{"type":"question","id":"q1","question":"Which database should the app use?","choices":["PostgreSQL","SQLite","MySQL"],"allow_text":true}"#);
    rig.at(2000).press(KeyCode::Down);
    rig.snap("question");
}

#[test]
fn plan_panel() {
    let mut rig = Rig::new(coding_spec());
    rig.ready().at(1000).prompt("Refactor the parser");
    rig.event(r#"{"type":"plan","entries":[{"content":"Read the parser","status":"completed"},{"content":"Split tokens from parsing","status":"in_progress","priority":"high"},{"content":"Update the callers","status":"pending"},{"content":"Run the tests","status":"pending"}]}"#);
    rig.event(r#"{"type":"message","message":"m1","text":"Splitting the tokenizer out of the parser."}"#);
    rig.at(9000);
    rig.snap("plan");
}

#[test]
fn findings_and_a_report() {
    let mut rig = Rig::new(security_spec());
    rig.event(r#"{"type":"ready","harness":"strix","name":"Strix","model":"unsloth/gemma-4-26B-A4B-it-GGUF","model_switch":"live"}"#);
    rig.at(1000).prompt("Start the assessment");
    for line in [
        r#"{"type":"finding","id":"f1","title":"Admin panel reachable without login","severity":"critical","target":"https://shop.example.test/admin","description":"The dashboard answers 200 without a session."}"#,
        r#"{"type":"finding","id":"f2","title":"SQL injection in the search","severity":"high","target":"https://shop.example.test/search?q=","description":"A single quote changes the result count."}"#,
        r#"{"type":"finding","id":"f3","title":"No rate limit on the login form","severity":"medium","target":"/login"}"#,
        r#"{"type":"finding","id":"f4","title":"Server version in the headers","severity":"low"}"#,
        r#"{"type":"report","title":"Assessment report","path":"reports/strix-shop.md","summary":"4 findings; fix the admin panel first."}"#,
        r#"{"type":"turn_end","reason":"end_turn"}"#,
    ] {
        rig.event(line);
    }
    rig.at(5000);
    rig.snap("findings_report");
    let buffer = rig.buffer(100, 30);
    assert_eq!(color_of(&buffer, "Critical"), Some(Color::Rgb(0xf8, 0x71, 0x71)));
    assert_eq!(color_of(&buffer, "Medium"), Some(Color::Rgb(0xfb, 0xbf, 0x24)));
    assert_eq!(rig.app.findings, [1, 1, 1, 1, 0]);
}

#[test]
fn progress_rows() {
    let mut rig = Rig::new(security_spec());
    rig.event(r#"{"type":"ready","harness":"strix","name":"Strix","model":"unsloth/gemma-4-26B-A4B-it-GGUF","model_switch":"live"}"#);
    rig.at(1000).prompt("Scan");
    rig.at(1000)
        .event(r#"{"type":"progress","id":"ports","label":"Port scan","done":412,"total":1000,"unit":"steps"}"#);
    rig.event(r#"{"type":"progress","id":"crawl","label":"Crawling the site","done":48,"unit":"pages"}"#);
    rig.event(r#"{"type":"progress","id":"list","label":"Downloading the wordlist","done":1258291,"total":5242880,"unit":"bytes"}"#);
    rig.at(3000).event(r#"{"type":"progress","id":"list","label":"Downloading the wordlist","done":5242880,"total":5242880,"unit":"bytes","finished":true}"#);
    rig.at(6500);
    rig.snap("progress");
}

#[test]
fn model_picker() {
    let mut rig = Rig::new(coding_spec());
    rig.ready().at(1000);
    rig.ctrl('p').press(KeyCode::Enter);
    assert!(matches!(rig.app.overlay, Some(Overlay::Picker { .. })));
    rig.snap("model_picker");
    rig.press(KeyCode::Down).press(KeyCode::Enter);
    rig.snap("model_restart_confirm");
}

#[test]
fn palette() {
    let mut rig = Rig::new(coding_spec());
    rig.ready().at(1000).ctrl('p');
    rig.snap("palette");
    rig.type_text("comp");
    rig.snap("palette_filtered");
}

#[test]
fn engine_error() {
    let mut rig = Rig::new(coding_spec());
    rig.at(1500);
    rig.app.start_failed("opencode: command not found (exit code 127)");
    rig.snap("engine_start_failed");
    let mut rig = Rig::new(coding_spec());
    rig.ready().at(1000).prompt("Go");
    rig.at(2000)
        .event(r#"{"type":"exit","code":1,"message":"OpenCode crashed: out of memory while loading the session"}"#);
    rig.snap("engine_exit");
    assert_eq!(rig.app.exit_code(), 1);
}

#[test]
fn keys_help_and_slash_completion() {
    let mut rig = Rig::new(coding_spec());
    rig.ready().at(1000).type_text("/");
    rig.snap("slash_completion");
    rig.app.input.clear();
    rig.ctrl('p').type_text("keys").press(KeyCode::Enter);
    rig.snap("keys_help");
}

// ---- State ----

#[test]
fn ready_sets_the_engine_and_queued_prompts_go_once_it_is_ready() {
    let mut rig = Rig::new(coding_spec());
    rig.prompt("early question");
    assert!(rig.sent().is_empty(), "nothing is sent before Ready");
    assert_eq!(rig.app.queued.len(), 1);
    rig.ready();
    assert_eq!(rig.app.phase, Phase::Ready);
    assert_eq!(rig.app.info.as_deref(), Some("OpenCode 1.0 · build mode"));
    assert_eq!(rig.sent(), [Command::Prompt { text: "early question".into() }]);
    assert!(rig.app.turn.is_some());
}

#[test]
fn prompts_while_working_are_queued_and_sent_after_the_turn() {
    let mut rig = Rig::new(coding_spec());
    rig.ready().prompt("first");
    assert_eq!(rig.sent(), [Command::Prompt { text: "first".into() }]);
    rig.prompt("second");
    assert!(rig.sent().is_empty());
    assert_eq!(rig.app.queued, ["second"]);
    rig.event(r#"{"type":"turn_end","reason":"end_turn"}"#);
    assert_eq!(rig.sent(), [Command::Prompt { text: "second".into() }]);
}

#[test]
fn esc_stops_the_turn_and_returns_queued_prompts_to_the_box() {
    let mut rig = Rig::new(coding_spec());
    rig.ready().prompt("long task").prompt("follow-up");
    rig.effects();
    rig.press(KeyCode::Esc);
    assert_eq!(rig.sent(), [Command::Cancel]);
    assert_eq!(rig.app.input.text(), "follow-up");
    assert!(rig.app.turn.as_ref().is_some_and(|t| t.stopping));
    rig.event(r#"{"type":"turn_end","reason":"cancelled"}"#);
    assert!(rig.app.turn.is_none());
    assert!(rig.sent().is_empty(), "a stopped turn sends nothing on its own");
}

#[test]
fn ctrl_c_clears_then_stops_then_quits_asking_while_working() {
    let mut rig = Rig::new(coding_spec());
    rig.ready().type_text("draft");
    rig.ctrl('c');
    assert!(rig.app.input.is_empty());
    rig.at(5000).ctrl('c');
    assert!(rig.effects().is_empty(), "one press only arms quitting");
    rig.at(6000).ctrl('c');
    assert_eq!(rig.effects(), [Effect::Quit]);

    let mut rig = Rig::new(coding_spec());
    rig.ready().prompt("work");
    rig.effects();
    rig.at(100).ctrl('c');
    assert_eq!(rig.sent(), [Command::Cancel]);
    rig.at(900).ctrl('c');
    assert!(matches!(rig.app.overlay, Some(Overlay::Confirm { .. })), "asks before quitting while a turn runs");
    rig.press(KeyCode::Enter);
    assert_eq!(rig.effects(), [Effect::Quit]);
}

#[test]
fn permission_and_question_answers_reach_the_engine() {
    let mut rig = Rig::new(coding_spec());
    rig.ready().prompt("x");
    rig.effects();
    rig.at(1000).event(PERMISSION);
    rig.at(1100).press(KeyCode::Char('2'));
    assert!(rig.sent().is_empty(), "too soon after the dialog opened");
    rig.at(1500).press(KeyCode::Char('2'));
    assert_eq!(rig.sent(), [Command::Permission { id: "p1".into(), option: Some("allow_always".into()) }]);
    rig.event(PERMISSION).at(3000).press(KeyCode::Esc);
    assert_eq!(rig.sent(), [Command::Permission { id: "p1".into(), option: None }]);
    rig.event(r#"{"type":"question","id":"q","question":"Name?"}"#);
    rig.at(4000).type_text("Ada").press(KeyCode::Enter);
    assert_eq!(rig.sent(), [Command::Answer { id: "q".into(), answer: Some(vec!["Ada".into()]) }]);
    rig.event(r#"{"type":"question","id":"q2","question":"Pick","choices":["a","b"]}"#);
    rig.at(5000).press(KeyCode::Esc);
    assert_eq!(rig.sent(), [Command::Answer { id: "q2".into(), answer: None }]);
}

#[test]
fn models_switch_live_or_by_restart_after_confirming() {
    let mut rig = Rig::new(security_spec());
    rig.event(r#"{"type":"ready","harness":"strix","name":"Strix","model":"unsloth/gemma-4-26B-A4B-it-GGUF","models":["unsloth/gemma-4-26B-A4B-it-GGUF","qwen3-coder-30b"],"model_switch":"live"}"#);
    rig.ctrl('p').press(KeyCode::Enter).press(KeyCode::Down).press(KeyCode::Enter);
    assert_eq!(rig.sent(), [Command::SetModel { model: "qwen3-coder-30b".into() }]);
    rig.event(r#"{"type":"model","model":"qwen3-coder-30b"}"#);
    assert_eq!(rig.app.model, "qwen3-coder-30b");

    let mut rig = Rig::new(coding_spec());
    rig.ready();
    rig.ctrl('p').press(KeyCode::Enter).press(KeyCode::Down).press(KeyCode::Enter);
    assert!(rig.effects().is_empty(), "a restart is confirmed first");
    rig.press(KeyCode::Enter);
    assert_eq!(rig.effects(), [Effect::Restart("gemma-4-26B-A4B-it".into())]);
    assert!(matches!(rig.app.phase, Phase::Switching { .. }));
    let next = {
        let mut s = coding_spec();
        s.model = "gemma-4-26B-A4B-it".into();
        s
    };
    rig.app.switched(next, "gemma-4-26B-A4B-it", rig.now);
    assert!(matches!(rig.app.phase, Phase::Starting { .. }));
    rig.event(r#"{"type":"ready","harness":"opencode","name":"OpenCode","model":"gemma-4-26B-A4B-it","model_switch":"restart"}"#);
    assert_eq!(rig.app.phase, Phase::Ready);
    assert_eq!(rig.app.model, "gemma-4-26B-A4B-it");
}

#[test]
fn a_failed_switch_keeps_or_restores_the_engine() {
    let mut rig = Rig::new(coding_spec());
    rig.ready();
    rig.app.switch_refused("gpt-oss-20b", "respec failed", rig.now);
    assert_eq!(rig.app.phase, Phase::Ready, "the running engine keeps running");
    rig.app.switch_reverted("gpt-oss-20b", "no such model", rig.now);
    assert!(matches!(rig.app.phase, Phase::Starting { .. }));
    rig.app.switch_failed("gpt-oss-20b", "no such model", "the port is taken");
    assert!(rig.app.stopped());
    assert_eq!(rig.app.exit_code(), 1);
    rig.press(KeyCode::Enter);
    assert_eq!(rig.effects(), [Effect::Start], "Enter starts the engine again");
}

#[test]
fn tab_switches_mode_and_slash_commands_complete() {
    let mut rig = Rig::new(coding_spec());
    rig.ready().press(KeyCode::Tab);
    assert_eq!(rig.sent(), [Command::SetMode { mode: "plan".into() }]);
    assert_eq!(rig.app.mode_name().as_deref(), Some("Plan"));
    rig.type_text("/co").press(KeyCode::Tab);
    assert_eq!(rig.app.completions().len(), 1);
    rig.press(KeyCode::Enter);
    assert_eq!(rig.sent(), [Command::Prompt { text: "/compact".into() }]);
    rig.event(r#"{"type":"turn_end","reason":"end_turn"}"#);
    rig.type_text("/rev").press(KeyCode::Enter);
    assert_eq!(rig.app.input.text(), "/review ", "a command that takes text waits for it");
    rig.type_text("the parser").press(KeyCode::Enter);
    assert_eq!(rig.sent(), [Command::Prompt { text: "/review the parser".into() }]);
}

#[test]
fn history_and_multi_line_input() {
    let mut rig = Rig::new(coding_spec());
    rig.ready().prompt("one");
    rig.event(r#"{"type":"turn_end","reason":"end_turn"}"#);
    rig.prompt("two");
    rig.event(r#"{"type":"turn_end","reason":"end_turn"}"#);
    rig.effects();
    rig.press(KeyCode::Up);
    assert_eq!(rig.app.input.text(), "two");
    rig.press(KeyCode::Up);
    assert_eq!(rig.app.input.text(), "one");
    rig.press(KeyCode::Down).press(KeyCode::Down);
    assert_eq!(rig.app.input.text(), "");
    rig.type_text("a").key(KeyCode::Enter, KeyModifiers::SHIFT).type_text("b").ctrl('j').type_text("c");
    rig.key(KeyCode::Enter, KeyModifiers::ALT).type_text("d");
    assert_eq!(rig.app.input.text(), "a\nb\nc\nd");
    rig.app.paste("pasted\r\nlines");
    assert_eq!(rig.app.input.text(), "a\nb\nc\ndpasted\nlines");
    rig.press(KeyCode::Enter);
    assert_eq!(rig.sent(), [Command::Prompt { text: "a\nb\nc\ndpasted\nlines".into() }]);
}

#[test]
fn turn_ends_are_said_plainly() {
    let mut rig = Rig::new(coding_spec());
    rig.ready();
    for (reason, detail, expected) in [
        ("cancelled", "", "Stopped."),
        ("max_steps", "", "Step limit reached. Send a message to continue."),
        ("max_steps", "Stopped after 40 steps.", "▲ Stopped after 40 steps."),
        ("max_tokens", "", "The reply reached the output limit."),
        ("refused", "", "The model declined."),
        ("error", "The relay closed the stream.", "■ The relay closed the stream."),
        ("error", "", "■ The turn failed."),
    ] {
        rig.prompt("go");
        let event = serde_json::json!({"type":"turn_end","reason":reason,"detail":if detail.is_empty() { None } else { Some(detail) }});
        rig.event(&event.to_string());
        let text = rig.render(100, 30);
        assert!(text.contains(expected), "{reason}: {text}");
    }
}

#[test]
fn the_engines_echo_of_a_prompt_is_not_shown_twice() {
    let mut rig = Rig::new(coding_spec());
    rig.ready().prompt("hello there");
    rig.event(r#"{"type":"user","text":"hello there"}"#);
    let text = rig.render(100, 30);
    assert_eq!(text.matches("hello there").count(), 1, "{text}");
    rig.event(r#"{"type":"user","text":"a prompt the bridge sent"}"#);
    assert!(rig.render(100, 30).contains("› a prompt the bridge sent"));
}

#[test]
fn secrets_are_masked_everywhere_drawn() {
    let masker = Masker::new(vec!["Sup3rS3cretPW".into()]);
    let mut rig = Rig::with(coding_spec(), masker, true);
    rig.ready().prompt("log in with Sup3rS3cretPW please");
    rig.event(r#"{"type":"message","message":"m","text":"Logging in as admin / Sup3rS3cretPW now."}"#)
        .event(r#"{"type":"tool_call","id":"t","title":"curl -u admin:Sup3rS3cretPW https://x","kind":"execute","status":"completed","content":[{"type":"terminal","output":"auth Sup3rS3cretPW ok","exit_code":0}]}"#)
        .event(r#"{"type":"message","message":"m2","text":"Typing Sup3r"}"#);
    rig.type_text("my Sup3rS3cretPW");
    let text = rig.render(100, 30);
    assert!(!text.contains("Sup3rS3cretPW"), "{text}");
    assert!(!text.contains("Typing Sup3r"), "the start of a secret still arriving is hidden: {text}");
    assert!(text.contains("••••"), "{text}");
    assert!(text.contains("my •••••••••••••"), "typed secrets show as dots: {text}");
}

#[test]
fn long_sessions_stay_bounded() {
    let mut rig = Rig::new(coding_spec());
    rig.ready();
    for i in 0..3000 {
        rig.event(&format!(
            r#"{{"type":"message","message":"m{i}","text":"line one of {i}\n\nline two\n\nline three\n\nline four"}}"#
        ));
        rig.event(&format!(
            r#"{{"type":"tool_call","id":"t{i}","title":"step {i}","kind":"read","status":"completed"}}"#
        ));
    }
    rig.render(100, 30);
    assert!(rig.app.transcript.trimmed > 0, "the oldest entries were dropped");
    assert!(rig.app.view.total <= super::transcript::TRIM_AT + 40, "{}", rig.app.view.total);
    let text = rig.render(100, 30);
    assert!(text.contains("step 2999"));
    rig.press(KeyCode::PageUp);
    let _ = rig.render(100, 30);
    rig.key(KeyCode::Home, KeyModifiers::CONTROL);
    assert!(rig.render(100, 30).contains("Earlier output was cleared to save memory."));
}

#[test]
fn scrolling_holds_the_view_and_end_follows_again() {
    let mut rig = Rig::new(coding_spec());
    rig.ready();
    for i in 0..60 {
        rig.event(&format!(r#"{{"type":"notice","level":"info","text":"notice {i}"}}"#));
    }
    assert!(rig.render(100, 30).contains("notice 59"));
    rig.press(KeyCode::PageUp);
    let held = rig.render(100, 30);
    assert!(!held.contains("notice 59"), "{held}");
    assert!(held.contains("more lines · end to follow"));
    rig.event(r#"{"type":"notice","level":"info","text":"notice 60"}"#);
    assert_eq!(rig.render(100, 30).lines().next(), held.lines().next(), "new output does not move a held view");
    rig.press(KeyCode::End);
    assert_eq!(rig.app.scroll, Scroll::Follow);
    assert!(rig.render(100, 30).contains("notice 60"));
}

#[test]
fn the_engine_ending_keeps_the_screen_until_the_person_quits() {
    let mut rig = Rig::new(coding_spec());
    rig.ready().event(r#"{"type":"exit","code":0,"message":"Session ended."}"#);
    assert!(rig.app.stopped());
    assert_eq!(rig.app.exit_code(), 0);
    rig.type_text("x");
    assert!(rig.effects().is_empty(), "typing does nothing once it ended");
    rig.press(KeyCode::Char('q'));
    assert_eq!(rig.effects(), [Effect::Quit]);
    let mut rig = Rig::new(coding_spec());
    rig.ready();
    rig.app.engine_closed();
    assert_eq!(rig.app.exit_code(), 1, "events ending without a word is a failure");
    rig.press(KeyCode::Esc);
    assert_eq!(rig.effects(), [Effect::Quit]);
}

/// Plays a tour's turns through the state, answering dialogs with keys.
fn play(rig: &mut Rig, script: &str, prompts: &[&str]) -> Vec<Command> {
    let turns = crate::engines::scripted::parse(script).expect("the tour parses");
    let mut commands = Vec::new();
    let mut clock = 0u64;
    let mut turns = turns.into_iter();
    for event in turns.next().expect("a first turn") {
        rig.app.apply(event, rig.now);
    }
    for (prompt, turn) in prompts.iter().zip(turns) {
        clock += 1000;
        rig.at(clock).prompt(prompt);
        commands.extend(rig.sent());
        for event in turn {
            clock += 50;
            rig.at(clock);
            let asks = matches!(event, Event::Permission(_) | Event::Question(_));
            rig.app.apply(event, rig.now);
            rig.render(100, 30);
            rig.render(60, 20);
            if asks {
                clock += 1000;
                rig.at(clock).press(KeyCode::Enter);
                let answered = rig.sent();
                assert_eq!(answered.len(), 1, "the dialog answered: {answered:?}");
                commands.extend(answered);
            }
        }
    }
    commands
}

#[test]
fn the_tour_plays_through_the_state() {
    let mut rig = Rig::new(coding_spec());
    let commands = play(
        &mut rig,
        TOUR,
        &["Fix the failing parser test", "Look for other callers", "Check the licenses", "Thanks"],
    );
    assert!(commands.contains(&Command::Permission { id: "p1".into(), option: Some("allow_once".into()) }));
    assert!(commands.contains(&Command::Answer { id: "q1".into(), answer: Some(vec!["Yes, both".into()]) }));
    let app = &rig.app;
    assert_eq!(app.name, "Yougori");
    assert_eq!(app.model, "gemma-4-26B-A4B-it", "the Model event switched it");
    assert_eq!(app.findings, [0, 0, 1, 0, 0]);
    assert!(app.plan.iter().all(|e| e.status == crate::protocol::PlanStatus::Completed));
    assert_eq!(app.transcript.tool("t2").map(|t| t.status), Some(ToolStatus::Failed));
    assert_eq!(app.transcript.tool("c1").map(|t| t.status), Some(ToolStatus::Completed));
    assert!(matches!(&app.phase, Phase::Stopped { failed: false, .. }));
    assert_eq!(app.exit_code(), 0);
    let text = rig.render(100, 30);
    assert!(text.contains("Yougori ended: Session ended."), "{text}");
}

#[test]
fn the_security_tour_plays_through_the_state() {
    let mut rig = Rig::new(security_spec());
    play(&mut rig, SECURITY_TOUR, &["Start the assessment"]);
    assert_eq!(rig.app.findings, [1, 1, 1, 1, 1]);
    assert!(!rig.app.busy());
    rig.snap("security_tour_end");
}

#[tokio::test]
async fn the_tour_plays_against_the_scripted_engine() {
    let turns = crate::engines::scripted::parse(TOUR).expect("the tour parses");
    let mut engine = crate::engines::scripted::start(turns);
    let mut rig = Rig::with(crate::spec::EngineSpec { ..coding_spec() }, Masker::default(), false);
    let mut prompts = ["Fix it", "Callers", "Licenses", "Bye"].into_iter();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut clock = 0u64;
    loop {
        // Answer dialogs, send the next prompt when the turn ended.
        clock += 400;
        rig.at(clock);
        if !rig.app.dialogs.is_empty() {
            rig.press(KeyCode::Enter);
        } else if rig.app.phase == Phase::Ready && rig.app.turn.is_none() && !rig.app.busy() {
            match prompts.next() {
                Some(prompt) => {
                    rig.prompt(prompt);
                }
                None => break,
            }
        }
        for effect in rig.effects() {
            if let Effect::Send(command) = effect {
                engine.commands.send(command).expect("the engine takes commands");
            }
        }
        let event = tokio::time::timeout_at(deadline, engine.events.recv()).await.expect("the tour keeps going");
        match event {
            Some(event) => rig.app.apply(event, rig.now),
            None => break,
        }
        while let Ok(event) = engine.events.try_recv() {
            rig.app.apply(event, rig.now);
        }
        if rig.app.stopped() {
            break;
        }
    }
    assert!(rig.app.stopped(), "the tour ends with the engine's exit");
    assert_eq!(rig.app.exit_code(), 0);
    assert_eq!(rig.app.findings[2], 1);
}

#[test]
fn streaming_into_a_full_screen_writes_little() {
    let mut rig = Rig::new(coding_spec());
    rig.ready().prompt("Write a long answer");
    let mut text = String::new();
    for i in 0..40 {
        text.push_str(&format!("Paragraph line {i} with enough words to look like prose.\n\n"));
    }
    rig.event(&serde_json::json!({"type":"message","message":"m","text":text}).to_string());
    let area = Rect::new(0, 0, 100, 30);
    let mut screen = Screen::new(area);
    let frame = |rig: &mut Rig, screen: &mut Screen| {
        let mut buffer = Buffer::empty(area);
        let drawn = draw::draw(&mut rig.app, area, &mut buffer, rig.now);
        screen.frame(&buffer, drawn.cursor, drawn.scroll)
    };
    let first = frame(&mut rig, &mut screen);
    assert!(first.len() > 1500, "the first frame paints everything ({} bytes)", first.len());
    rig.event(r#"{"type":"message","message":"m","text":"One more line arrives."}"#);
    let next = frame(&mut rig, &mut screen);
    let shown = String::from_utf8_lossy(&next);
    assert!(shown.contains("\x1b[1S") || shown.contains("\x1b[2S") || shown.contains("\x1b[3S"), "{shown:?}");
    assert!(next.len() < 400, "a streamed line costs few bytes ({} bytes): {shown:?}", next.len());
    let idle = frame(&mut rig, &mut screen);
    assert!(idle.len() < 64, "a frame with only the clock moving is tiny ({} bytes)", idle.len());
}

// ---- The terminal pane ----

fn pane_spec(argv: Vec<String>) -> EngineSpec {
    let mut spec = spec(
        r#"{"harness":"aider","name":"Aider","category":"coding","protocol":"terminal","argv":["aider"],
            "cwd":".","model":"qwen3-coder-30b","models":["qwen3-coder-30b","gpt-oss-20b"],"state_dir":"/s"}"#,
    );
    spec.argv = argv;
    spec.env = std::env::vars().collect();
    spec.cwd = std::env::temp_dir();
    spec
}

fn pane_text(pane: &mut Pane, width: u16, height: u16, now: Instant) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("test terminal");
    let mut cursor = None;
    terminal
        .draw(|frame| {
            let area = frame.area();
            cursor = pane.draw(area, frame.buffer_mut(), now).cursor;
        })
        .expect("draw");
    let mut text = buffer_text(terminal.backend().buffer());
    text.push_str(&match cursor {
        Some(p) => format!("[cursor {},{}]\n", p.x, p.y),
        None => "[no cursor]\n".into(),
    });
    text
}

#[test]
fn the_terminal_pane_draws_a_clients_screen_in_the_frame() {
    let t0 = Instant::now();
    for (width, height) in [(100u16, 30u16), (60, 20)] {
        let mut pane = Pane::new(
            pane_spec(vec!["aider".into()]),
            Theme::new(Depth::True),
            Masker::new(vec!["hunter2secret".into()]),
            width,
            height,
            t0,
        );
        pane.phase = PanePhase::Running { since: t0 };
        let script = "\x1b[2J\x1b[H\x1b[1;32mAider v0.86\x1b[0m\r\nModel: qwen3-coder-30b\r\nRepo: /workspace (12 files)\r\n\r\n\x1b[7m> \x1b[0m add a health check, password hunter2secret\r\n\x1b[33mApplied edit to app.py\x1b[0m\r\n> ";
        pane.message(pane::Message::Output(0, script.as_bytes().to_vec()), t0);
        let text = pane_text(&mut pane, width, height, t0 + Duration::from_secs(75));
        assert!(!text.contains("hunter2secret"), "{text}");
        insta::assert_snapshot!(format!("pane_running_{width}x{height}"), text);
        pane.message(pane::Message::Exited(0, Ok(portable_pty::ExitStatus::with_exit_code(2))), t0);
        assert_eq!(pane.exit_code(), 1);
        let text = pane_text(&mut pane, width, height, t0 + Duration::from_secs(80));
        insta::assert_snapshot!(format!("pane_ended_{width}x{height}"), text);
    }
}

#[test]
fn the_terminal_pane_keeps_ctrl_p_and_forwards_the_rest() {
    let t0 = Instant::now();
    let mut pane = Pane::new(pane_spec(vec!["aider".into()]), Theme::new(Depth::True), Masker::default(), 100, 30, t0);
    pane.phase = PanePhase::Ended { message: "Aider ended.".into(), failed: false };
    pane.key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::CONTROL), t0);
    assert!(matches!(pane.overlay, Some(Overlay::Palette { .. })));
    let text = pane_text(&mut pane, 100, 30, t0);
    assert!(text.contains("Switch model") && text.contains("Start again"), "{text}");
    pane.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE), t0);
    assert!(pane.overlay.is_none());
    pane.key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE), t0);
    assert_eq!(pane.effects, [pane::PaneEffect::Quit]);
}

#[test]
fn a_real_client_runs_in_the_pane() {
    let argv: Vec<String> = if cfg!(windows) {
        ["cmd", "/c", "echo yougori-pane-ok"].iter().map(|s| s.to_string()).collect()
    } else {
        ["sh", "-c", "printf 'yougori-pane-ok\\n'; exit 3"].iter().map(|s| s.to_string()).collect()
    };
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
    runtime.block_on(async move {
        let t0 = Instant::now();
        let spec = pane_spec(argv);
        let mut pane = Pane::new(spec.clone(), Theme::new(Depth::True), Masker::default(), 80, 24, t0);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let (rows, cols) = pane::pane_size(80, 24);
        let child = pane::spawn(&spec, rows, cols, 1, None, Depth::True, tx).expect("the client starts");
        pane.started(child, t0);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        while !matches!(pane.phase, PanePhase::Ended { .. }) {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(message)) => pane.message(message, Instant::now()),
                Ok(None) => break,
                Err(_) => panic!("the client did not end: {}", pane.parser.screen().contents()),
            }
        }
        // Output that arrives after the exit is still drawn.
        while let Ok(Some(message)) = tokio::time::timeout(Duration::from_millis(300), rx.recv()).await {
            pane.message(message, Instant::now());
        }
        let text = pane_text(&mut pane, 80, 24, Instant::now());
        assert!(text.contains("yougori-pane-ok"), "{text}");
        if cfg!(windows) {
            assert_eq!(pane.exit_code(), 0, "{text}");
        } else {
            assert_eq!(pane.exit_code(), 1, "exit 3 is a failure: {text}");
            assert!(text.contains("exit code 3"), "{text}");
        }
    });
}

#[test]
fn every_scene_draws_at_any_size() {
    let sizes = [(1u16, 1u16), (2, 2), (5, 3), (10, 4), (12, 6), (20, 6), (30, 8), (40, 10), (80, 12), (200, 60)];
    let mut rigs = Vec::new();
    let mut tour = Rig::new(coding_spec());
    play(&mut tour, TOUR, &["Fix it", "Callers", "Licenses"]);
    rigs.push(tour);
    let mut security = Rig::new(security_spec());
    play(&mut security, SECURITY_TOUR, &["Start"]);
    rigs.push(security);
    let mut dialog = Rig::new(coding_spec());
    dialog.ready().prompt("x").event(PERMISSION);
    rigs.push(dialog);
    let mut palette = Rig::new(coding_spec());
    palette.ready().ctrl('p');
    rigs.push(palette);
    let mut stopped = Rig::new(coding_spec());
    stopped.app.start_failed("no such command");
    rigs.push(stopped);
    for rig in &mut rigs {
        for (width, height) in sizes {
            rig.render(width, height);
            rig.app.details = !rig.app.details;
            rig.render(width, height);
        }
    }
    let t0 = Instant::now();
    for (width, height) in sizes {
        let mut pane =
            Pane::new(pane_spec(vec!["x".into()]), Theme::new(Depth::Ansi256), Masker::default(), width, height, t0);
        pane.message(pane::Message::Output(0, "日本語 \x1b[31mred\x1b[0m wide text".as_bytes().to_vec()), t0);
        pane_text(&mut pane, width, height, t0);
    }
}

#[test]
fn a_tasks_result_follows_its_nested_calls() {
    let mut rig = Rig::new(coding_spec());
    rig.ready().prompt("Find the callers");
    rig.event(r#"{"type":"tool_call","id":"task","title":"Find the callers","kind":"task","status":"in_progress"}"#)
        .event(r#"{"type":"tool_call","id":"a","title":"src/cli.rs","kind":"read","status":"completed","parent":"task"}"#)
        .event(r#"{"type":"tool_update","id":"task","status":"completed","content":[{"type":"text","text":"Both callers handle None."}]}"#);
    let text = rig.render(100, 30);
    let child = text.find("src/cli.rs").expect("the nested call");
    let result = text.find("Both callers handle None.").expect("the task's result");
    assert!(child < result, "{text}");
}

#[test]
fn the_quit_hint_goes_away_after_two_seconds() {
    let mut rig = Rig::new(coding_spec());
    rig.ready().at(1000).ctrl('c');
    assert!(rig.render(100, 30).contains("Press Ctrl+C again to quit"));
    rig.at(3100);
    assert!(rig.app.animating(rig.now), "one more frame takes the hint away");
    assert!(!rig.render(100, 30).contains("Press Ctrl+C again to quit"));
    rig.at(4000);
    assert!(!rig.app.animating(rig.now));
}

#[test]
fn a_finished_plan_is_not_pinned_in_the_next_turn() {
    let mut rig = Rig::new(coding_spec());
    rig.ready().prompt("first");
    rig.event(r#"{"type":"plan","entries":[{"content":"Only step","status":"completed"}]}"#);
    assert!(rig.render(100, 30).contains("Plan  1 of 1 done"), "shown while its turn runs");
    rig.event(r#"{"type":"turn_end","reason":"end_turn"}"#);
    assert!(!rig.render(100, 30).contains("Plan  1 of 1 done"));
    rig.prompt("second");
    assert!(!rig.render(100, 30).contains("Plan  1 of 1 done"), "an old finished plan stays away");
    rig.event(r#"{"type":"plan","entries":[{"content":"Next step","status":"in_progress"}]}"#);
    assert!(rig.render(100, 30).contains("Plan  0 of 1 done"));
}

#[test]
fn the_keys_line_stays_until_the_first_prompt() {
    let mut rig = Rig::new(coding_spec());
    rig.ready().event(r#"{"type":"notice","level":"info","text":"Read AGENTS.md."}"#);
    assert!(rig.render(100, 30).contains("enter send"), "a notice is not a conversation yet");
    rig.prompt("hello");
    assert!(!rig.render(100, 30).contains("enter send"));
}

// ---- How our own engine (native) emits events ----

#[test]
fn native_a_call_announced_twice_is_one_row_timed_from_its_start() {
    let mut rig = Rig::new(coding_spec());
    rig.ready().at(1000).prompt("Run the tests");
    // While the model streams the call: only the tool's name.
    rig.at(1100).event(r#"{"type":"tool_call","id":"t1","title":"bash","kind":"execute","status":"pending"}"#);
    assert!(rig.render(100, 30).contains("Run    bash"));
    // When it starts: the full title, its input (shortened strings) and locations.
    rig.at(1600).event(r#"{"type":"tool_call","id":"t1","title":"cargo test --workspace","kind":"execute","status":"pending","input":{"command":"cargo test --workspace","note":"a long text…"},"locations":[{"path":"/workspace"}]}"#);
    rig.at(2000).event(r#"{"type":"tool_update","id":"t1","status":"in_progress"}"#);
    rig.at(2500).event(r#"{"type":"tool_update","id":"t1","status":"completed","content":[{"type":"terminal","command":"cargo test --workspace","output":"ok","exit_code":0}]}"#);
    let text = rig.render(100, 30);
    assert_eq!(text.matches("◇ Run").count(), 1, "one row: {text}");
    assert!(!text.contains("bash"), "{text}");
    assert!(text.contains("done 0.5s"), "timed from in_progress, not from the first announcement: {text}");
    assert!(!text.contains("note"), "the input is not shown");
}

#[test]
fn native_one_turn_end_per_prompt_and_no_double_send() {
    let mut rig = Rig::new(coding_spec());
    rig.ready().prompt("one");
    assert_eq!(rig.sent(), [Command::Prompt { text: "one".into() }]);
    // Typed while it works: kept here, never sent to the engine's own queue.
    rig.prompt("two");
    assert!(rig.sent().is_empty());
    rig.press(KeyCode::Esc);
    assert_eq!(rig.sent(), [Command::Cancel]);
    rig.event(r#"{"type":"turn_end","reason":"cancelled"}"#);
    assert!(rig.app.turn.is_none());
    assert!(!rig.render(100, 30).contains("esc to stop"), "nothing left running");
    assert!(rig.sent().is_empty(), "a stopped turn does not send the queued prompt");
    assert_eq!(rig.app.input.text(), "two", "the queued prompt is back in the box");
    // A turn end for a prompt the engine had queued changes nothing here.
    rig.event(r#"{"type":"turn_end","reason":"cancelled","detail":"Not run: the turn before it was stopped."}"#);
    assert!(rig.app.turn.is_none() && rig.sent().is_empty());
    // Slash commands get their turn end too.
    rig.app.input.clear();
    rig.prompt("/compact");
    assert_eq!(rig.sent(), [Command::Prompt { text: "/compact".into() }]);
    assert!(rig.render(100, 30).contains("esc to stop"));
    rig.event(r#"{"type":"turn_end","reason":"end_turn"}"#);
    assert!(!rig.render(100, 30).contains("esc to stop"));
}

#[test]
fn native_an_error_is_shown_once() {
    let mut rig = Rig::new(coding_spec());
    rig.ready().prompt("go");
    rig.event(r#"{"type":"notice","level":"error","text":"The model server answered 500: overloaded."}"#)
        .event(r#"{"type":"turn_end","reason":"error","detail":"The model server answered 500: overloaded."}"#);
    let text = rig.render(100, 30);
    assert_eq!(text.matches("overloaded").count(), 1, "{text}");
    // Other endings use the engine's own words, not ours added to them.
    rig.prompt("again");
    rig.event(r#"{"type":"turn_end","reason":"max_steps","detail":"Stopped after 40 steps. Send a message to let it go on."}"#);
    let text = rig.render(100, 30);
    assert!(text.contains("▲ Stopped after 40 steps. Send a message to let it go on."), "{text}");
    assert!(!text.contains("Step limit reached"), "{text}");
}

#[test]
fn native_permission_options_and_dialogs_settled_by_another_answer() {
    let mut rig = Rig::new(coding_spec());
    rig.ready().prompt("edit both");
    let ask = |id: &str, tool: &str| {
        format!(
            r#"{{"type":"permission","id":"{id}","tool_call":"{tool}","title":"Edit {tool}.rs","options":[{{"id":"allow_once","label":"Allow once","kind":"allow_once"}},{{"id":"allow_always","label":"Always allow edits","kind":"allow_always"}},{{"id":"reject_once","label":"Reject","kind":"reject_once"}},{{"id":"reject_always","label":"Always reject edits","kind":"reject_always"}}]}}"#
        )
    };
    rig.event(r#"{"type":"tool_call","id":"a","title":"Edit a.rs","kind":"edit","status":"pending"}"#)
        .event(r#"{"type":"tool_call","id":"b","title":"Edit b.rs","kind":"edit","status":"pending"}"#)
        .event(&ask("p1", "a"))
        .event(&ask("p2", "b"));
    rig.effects();
    rig.at(1000).press(KeyCode::Char('2'));
    assert_eq!(rig.sent(), [Command::Permission { id: "p1".into(), option: Some("allow_always".into()) }]);
    assert_eq!(rig.app.dialogs.len(), 1, "the second request still shows");
    // The "always" answer settled the second request inside the engine: its call just goes on.
    rig.event(r#"{"type":"tool_update","id":"a","status":"in_progress"}"#)
        .event(r#"{"type":"tool_update","id":"b","status":"in_progress"}"#);
    assert!(rig.app.dialogs.is_empty(), "its dialog closed without an answer");
    assert!(rig.sent().is_empty(), "nothing is sent for a settled request");
    // The stuck-loop guard's own options.
    rig.event(r#"{"type":"tool_call","id":"c","title":"ls","kind":"execute","status":"pending"}"#)
        .event(r#"{"type":"permission","id":"p3","tool_call":"c","title":"The model is repeating itself","detail":"It has made the same call three times in a row: ls. Let it go on?","options":[{"id":"go","label":"Let it go on","kind":"allow_once"},{"id":"go_quiet","label":"Let it go on, and do not ask again this turn","kind":"allow_always"},{"id":"stop","label":"Stop the turn","kind":"reject_once"}]}"#);
    let text = rig.at(3000).render(100, 30);
    assert!(text.contains("○ 3  Stop the turn") && text.contains("1-3 choose"), "{text}");
    rig.press(KeyCode::Char('3'));
    assert_eq!(rig.sent(), [Command::Permission { id: "p3".into(), option: Some("stop".into()) }]);
}

#[test]
fn native_resuming_a_session_replays_it_without_running_timers() {
    let mut rig = Rig::new(coding_spec());
    rig.ready().prompt("the conversation before");
    rig.event(r#"{"type":"message","message":"m0","text":"An answer before."}"#)
        .event(r#"{"type":"turn_end","reason":"end_turn"}"#);
    rig.at(1000).prompt("/sessions");
    rig.event(r#"{"type":"question","id":"q1","question":"Which session should continue?","choices":["1. Fix the parser (2026-11-12 10:00 UTC, 6 messages)","2. Add tests (2026-11-11 18:20 UTC, 9 messages)"]}"#);
    let text = rig.render(100, 30);
    assert!(text.contains("● 1. Fix the parser") && !text.contains("1  1."), "numbered once: {text}");
    rig.effects();
    rig.at(2000).press(KeyCode::Enter);
    assert_eq!(
        rig.sent(),
        [Command::Answer {
            id: "q1".into(),
            answer: Some(vec!["1. Fix the parser (2026-11-12 10:00 UTC, 6 messages)".into()])
        }]
    );
    for line in [
        r#"{"type":"user","text":"Fix the parser"}"#,
        r#"{"type":"reasoning","message":"r1","text":"Read it first."}"#,
        r#"{"type":"message","message":"m1","text":"Fixed the early return."}"#,
        r#"{"type":"tool_call","id":"t1","title":"Edit src/parser.rs","kind":"edit","status":"completed","content":[{"type":"diff","path":"src/parser.rs","old":"a\n","new":"b\n"}]}"#,
        r#"{"type":"tool_call","id":"t2","title":"cargo test","kind":"execute","status":"failed"}"#,
        r#"{"type":"plan","entries":[{"content":"Fix the parser","status":"completed"},{"content":"Add a test","status":"pending"}]}"#,
        r#"{"type":"usage","context_tokens":6000,"context_window":32768}"#,
        r#"{"type":"notice","level":"info","text":"Resumed “Fix the parser”."}"#,
    ] {
        rig.event(line);
        let text = rig.render(100, 30);
        assert!(!text.contains("running"), "a replay has no running calls: {text}");
    }
    rig.event(r#"{"type":"turn_end","reason":"end_turn"}"#);
    let text = rig.at(9000).render(100, 30);
    assert!(
        !text.contains("the conversation before") && !text.contains("An answer before."),
        "replaced by the session: {text}"
    );
    assert!(text.contains("› Fix the parser") && text.contains("Fixed the early return."), "{text}");
    assert!(text.contains("Resumed “Fix the parser”."), "{text}");
    assert!(text.contains("◇ Edit   src/parser.rs  +1 -1"), "{text}");
    assert!(!text.contains("done 0") && !text.contains("failed 0"), "no times for replayed calls: {text}");
    assert!(!rig.app.busy() && !text.contains("esc to stop"));
    assert!(text.contains("Plan  1 of 2 done"), "the plan as it last stood: {text}");
    assert!(text.contains("18% context"), "{text}");
}

#[test]
fn native_model_and_mode_changes_are_confirmed_by_the_engine() {
    let mut rig = Rig::new(coding_spec());
    rig.ready();
    rig.app.model_switch = crate::protocol::ModelSwitch::Live;
    rig.ctrl('p').press(KeyCode::Enter).press(KeyCode::Down).press(KeyCode::Enter);
    assert_eq!(rig.sent(), [Command::SetModel { model: "gemma-4-26B-A4B-it".into() }]);
    rig.event(r#"{"type":"model","model":"gemma-4-26B-A4B-it"}"#);
    let text = rig.render(100, 30);
    assert_eq!(text.matches("Now using gemma-4-26B-A4B-it.").count(), 1, "said once: {text}");
    assert!(!text.contains("Switching to"), "{text}");
    // A mode chosen during a turn: the engine confirms it and says when it applies.
    rig.prompt("work");
    rig.effects();
    rig.press(KeyCode::Tab);
    assert_eq!(rig.sent(), [Command::SetMode { mode: "plan".into() }]);
    rig.event(
        r#"{"type":"modes","current":"plan","available":[{"id":"build","name":"Build"},{"id":"plan","name":"Plan"}]}"#,
    )
    .event(r#"{"type":"notice","level":"info","text":"Plan mode starts with your next message."}"#);
    let text = rig.render(100, 30);
    assert_eq!(text.matches("Plan mode starts with your next message.").count(), 1, "{text}");
    assert_eq!(rig.app.mode_name().as_deref(), Some("Plan"));
    assert!(text.lines().any(|l| l.contains("esc to stop") && l.contains("· Plan")), "{text}");
}

#[test]
fn native_helpers_nest_and_engine_progress_is_not_a_turn() {
    let mut rig = Rig::new(coding_spec());
    rig.ready();
    // The MCP servers start with the engine, before any prompt.
    rig.at(100).event(
        r#"{"type":"progress","id":"mcp-start","label":"Starting MCP servers","done":0,"total":2,"unit":"servers"}"#,
    );
    let text = rig.at(600).render(100, 30);
    assert!(text.contains("Starting MCP servers") && text.contains("0 / 2 servers"), "{text}");
    assert!(!text.contains("esc to stop"), "only a turn can be stopped: {text}");
    assert!(text.contains("enter send"), "still the first screen");
    rig.press(KeyCode::Esc);
    assert!(rig.sent().is_empty(), "Esc does not cancel the engine's own start-up");
    rig.event(r#"{"type":"progress","id":"mcp-start","label":"2 of 2 MCP servers ready","done":2,"total":2,"unit":"servers","finished":true}"#);
    assert!(rig.render(100, 30).contains("◇ 2 of 2 MCP servers ready"));
    // A helper's events carry the task call's id as parent.
    rig.prompt("Look into it");
    for line in [
        r#"{"type":"tool_call","id":"task1","title":"Explore the parser","kind":"task","status":"in_progress","input":{"prompt":"Explore…"}}"#,
        r#"{"type":"reasoning","message":"rh","text":"Search first.","parent":"task1"}"#,
        r#"{"type":"tool_call","id":"h1","title":"grep","kind":"search","status":"pending","parent":"task1"}"#,
        r#"{"type":"tool_call","id":"h1","title":"parse\\(","kind":"search","status":"pending","parent":"task1"}"#,
        r#"{"type":"tool_update","id":"h1","status":"completed"}"#,
        r#"{"type":"message","message":"mh","text":"Two callers.","parent":"task1"}"#,
        r#"{"type":"progress","id":"compact-1","label":"Summarising older messages to make room"}"#,
        r#"{"type":"progress","id":"compact-1","label":"Summarised older messages","finished":true}"#,
        r#"{"type":"progress","id":"compact-2","label":"Summarising older messages to make room"}"#,
    ] {
        rig.event(line);
    }
    let text = rig.render(100, 30);
    assert!(text.contains("│   ◇ Search parse\\("), "the helper's call nests under its task: {text}");
    assert!(text.contains("│   Two callers."), "{text}");
    assert_eq!(text.matches("◇ Search").count(), 1, "{text}");
    assert!(
        text.contains("◇ Summarised older messages") && text.contains("Summarising older messages to make room"),
        "{text}"
    );
}

// ---- Review fixes (12 Nov 2026) ----

/// Where a rendered screen puts the cursor.
fn cursor_of(text: &str) -> Option<(u16, u16)> {
    let at = text.rfind("[cursor ")?;
    let (x, y) = text[at + 8..].trim_end().trim_end_matches(']').split_once(',')?;
    Some((x.parse().ok()?, y.parse().ok()?))
}

fn permission(id: &str, title: &str, tool: Option<&str>) -> String {
    serde_json::json!({"type":"permission","id":id,"tool_call":tool,"title":title,"options":[
        {"id":"allow_once","label":"Allow once","kind":"allow_once"},
        {"id":"allow_always","label":"Always allow","kind":"allow_always"},
        {"id":"reject_once","label":"Reject","kind":"reject_once"}]})
    .to_string()
}

#[test]
fn a_typed_answer_holding_a_secret_draws_with_the_cursor_anywhere_in_it() {
    let masker = Masker::new(vec!["Sup3rS3cretPW".into()]);
    let mut rig = Rig::with(coding_spec(), masker, true);
    rig.ready().prompt("start");
    rig.effects();
    rig.at(1000).event(r#"{"type":"question","id":"q1","question":"Password for the test login?"}"#);
    rig.at(2000).type_text("my pw is Sup3rS3cretPW");
    let text = rig.render(100, 30);
    assert!(text.contains("› my pw is •••••••••••••"), "one dot per character, as in the prompt box: {text}");
    assert!(!text.contains("Sup3r"), "{text}");
    let row = find_row(&rig.buffer(100, 30), "› my pw is").expect("the answer row");
    // The cursor moved into the secret: drawing used to panic on a byte inside a dot.
    rig.press(KeyCode::Left).press(KeyCode::Left);
    let text = rig.render(100, 30);
    assert_eq!(cursor_of(&text), Some((3 + 2 + 9 + 11, row)), "dots are counted, not bytes: {text}");
    rig.press(KeyCode::Home).press(KeyCode::Right);
    assert_eq!(cursor_of(&rig.render(100, 30)), Some((3 + 2 + 1, row)));
    rig.press(KeyCode::Enter);
    assert_eq!(rig.sent(), [Command::Answer { id: "q1".into(), answer: Some(vec!["my pw is Sup3rS3cretPW".into()]) }]);
    // The typed answer beside choices.
    rig.at(3000).event(
        r#"{"type":"question","id":"q2","question":"Which login?","choices":["admin","guest"],"allow_text":true}"#,
    );
    rig.at(4000).type_text("Sup3rS3cretPW");
    rig.press(KeyCode::Home).press(KeyCode::Right);
    let text = rig.render(100, 30);
    assert!(text.contains("3  •••••••••••••") && !text.contains("Sup3r"), "{text}");
    let row = find_row(&rig.buffer(100, 30), "3  •••").expect("the typed row");
    assert_eq!(cursor_of(&text), Some((3 + 5 + 1, row)), "{text}");
}

#[test]
fn a_long_typed_answer_wraps_and_keeps_the_cursor_in_view() {
    let mut rig = Rig::new(coding_spec());
    rig.ready().prompt("start");
    rig.effects();
    rig.at(1000).event(r#"{"type":"question","id":"q1","question":"Describe the login flow"}"#);
    let answer = "The login page posts the email and password to /api/session and then redirects to the dashboard with a cookie set";
    rig.at(2000).type_text(answer);
    let text = rig.render(60, 20);
    assert!(text.contains("› The login page posts") && text.contains("a cookie set"), "{text}");
    let row = find_row(&rig.buffer(60, 20), "a cookie set").expect("the last row");
    let line = text.lines().nth(row as usize).unwrap_or_default();
    let end = line.chars().count() as u16;
    assert_eq!(cursor_of(&text), Some((end, row)), "the cursor follows the last character: {text}");
    // Past the rows a panel gives it, the answer scrolls with the cursor.
    rig.type_text(&" and more words".repeat(30));
    let text = rig.render(60, 20);
    assert!(text.contains("and more words"), "{text}");
    let (_, y) = cursor_of(&text).expect("a cursor");
    assert!(text.lines().nth(y as usize).is_some_and(|l| l.contains("words")), "{text}");
    rig.press(KeyCode::Home);
    let text = rig.render(60, 20);
    assert!(text.contains("› The login page posts"), "back at the start: {text}");
    rig.press(KeyCode::Enter);
    let sent = rig.sent();
    assert!(matches!(&sent[..], [Command::Answer { answer: Some(a), .. }] if a[0].starts_with(answer)), "{sent:?}");
}

#[test]
fn a_request_that_comes_forward_gets_its_own_settle_time() {
    let mut rig = Rig::new(coding_spec());
    rig.ready().prompt("edit both");
    rig.at(1000).event(&permission("p1", "Run npm test", None)).event(&permission("p2", "Run rm -rf build", None));
    rig.effects();
    let text = rig.at(1500).render(100, 30);
    assert!(text.contains("1 more waits"), "{text}");
    rig.at(2000).press(KeyCode::Char('1'));
    assert_eq!(rig.sent(), [Command::Permission { id: "p1".into(), option: Some("allow_once".into()) }]);
    // A double press: the second one does not answer the request that just came forward.
    rig.at(2020).press(KeyCode::Char('1'));
    assert!(rig.sent().is_empty(), "p2 was not seen yet");
    assert!(!rig.render(100, 30).contains("more wait"));
    rig.at(2400).press(KeyCode::Char('1'));
    assert_eq!(rig.sent(), [Command::Permission { id: "p2".into(), option: Some("allow_once".into()) }]);
    // Covered by the palette: it shows from when the palette closes.
    rig.at(3000).event(&permission("p3", "Run curl", None));
    rig.at(3100).ctrl('p');
    rig.at(4000).press(KeyCode::Esc);
    rig.at(4050).press(KeyCode::Char('1'));
    assert!(rig.sent().is_empty(), "the palette had covered it");
    rig.at(4400).press(KeyCode::Char('1'));
    assert_eq!(rig.sent(), [Command::Permission { id: "p3".into(), option: Some("allow_once".into()) }]);
    // Settled by the engine (its call went on): the request behind it comes forward.
    rig.event(r#"{"type":"tool_call","id":"a","title":"Edit a.rs","kind":"edit","status":"pending"}"#)
        .event(r#"{"type":"tool_call","id":"b","title":"Edit b.rs","kind":"edit","status":"pending"}"#)
        .event(&permission("p4", "Edit a.rs", Some("a")))
        .event(&permission("p5", "Edit b.rs", Some("b")));
    rig.at(6000).event(r#"{"type":"tool_update","id":"a","status":"in_progress"}"#);
    rig.at(6020).press(KeyCode::Char('1'));
    assert!(rig.sent().is_empty(), "p5 just came forward");
    rig.at(6400).press(KeyCode::Char('1'));
    assert_eq!(rig.sent(), [Command::Permission { id: "p5".into(), option: Some("allow_once".into()) }]);
}

#[test]
fn a_refused_restart_switch_leaves_the_turn_and_its_request_with_the_engine() {
    let mut rig = Rig::new(coding_spec());
    rig.ready().at(1000).prompt("run the whole test suite");
    rig.event(r#"{"type":"tool_call","id":"t1","title":"cargo test --workspace","kind":"execute","status":"pending"}"#)
        .event(PERMISSION);
    rig.effects();
    // Ctrl+P, Switch model, the next model, confirm.
    rig.at(3000).ctrl('p').press(KeyCode::Enter).press(KeyCode::Down).press(KeyCode::Enter).press(KeyCode::Enter);
    assert_eq!(rig.effects(), [Effect::Restart("gemma-4-26B-A4B-it".into())], "nothing is said to the engine yet");
    assert!(rig.app.turn.is_some() && rig.app.dialogs.len() == 1, "the engine still runs its turn");
    rig.app.switch_refused("gemma-4-26B-A4B-it", "the model left the catalog", rig.now);
    assert_eq!(rig.app.phase, Phase::Ready);
    assert!(rig.render(100, 30).contains("Could not switch to gemma-4-26B-A4B-it: the model left the catalog"));
    // The open request can still be answered (once it has shown long enough after the
    // confirmation that covered it), and the turn stopped.
    rig.at(3100).press(KeyCode::Char('1'));
    assert!(rig.sent().is_empty());
    rig.at(3400).press(KeyCode::Char('1'));
    assert_eq!(rig.sent(), [Command::Permission { id: "p1".into(), option: Some("allow_once".into()) }]);
    assert!(rig.render(100, 30).contains("esc to stop"));
    rig.press(KeyCode::Esc);
    assert_eq!(rig.sent(), [Command::Cancel]);

    // A prompt typed while the switch was prepared goes once the engine's turn ends.
    let mut rig = Rig::new(coding_spec());
    rig.ready().prompt("work");
    rig.effects();
    rig.ctrl('p').press(KeyCode::Enter).press(KeyCode::Down).press(KeyCode::Enter).press(KeyCode::Enter);
    rig.effects();
    rig.prompt("next step");
    assert_eq!(rig.app.queued, ["next step"]);
    rig.app.switch_refused("gemma-4-26B-A4B-it", "boom", rig.now);
    assert!(rig.sent().is_empty(), "the engine's turn still runs");
    rig.prompt("later prompt");
    rig.event(r#"{"type":"turn_end","reason":"end_turn"}"#);
    assert_eq!(rig.sent(), [Command::Prompt { text: "next step".into() }], "in the order typed");
    assert_eq!(rig.app.queued, ["later prompt"]);

    // Prepared: the engine is being stopped, and its turn and requests end with it.
    let mut rig = Rig::new(coding_spec());
    rig.ready().prompt("work");
    rig.event(PERMISSION);
    rig.app.choose_model("gpt-oss-20b".into(), rig.now);
    rig.press(KeyCode::Enter);
    rig.app.switch_prepared();
    assert!(rig.app.turn.is_none() && rig.app.dialogs.is_empty());
    assert!(matches!(&rig.app.phase, Phase::Switching { step, .. } if step == "stopping OpenCode"));
}

#[test]
fn a_refused_switch_from_a_stopped_engine_stays_stopped() {
    // The first start failed; the switch's preparation fails too.
    let mut rig = Rig::new(coding_spec());
    rig.app.start_failed("the service did not answer within 120 seconds");
    rig.app.choose_model("gpt-oss-20b".into(), rig.now);
    assert_eq!(rig.effects(), [Effect::Restart("gpt-oss-20b".into())]);
    rig.app.switch_refused("gpt-oss-20b", "the catalog is unreachable", rig.now);
    assert!(
        matches!(&rig.app.phase, Phase::Stopped { title, failed: true, .. } if title == "OpenCode could not start"),
        "{:?}",
        rig.app.phase
    );
    assert!(!rig.app.animating(rig.now + Duration::from_secs(600)), "nothing spins for ever");
    let palette = rig.app.palette();
    assert!(palette.iter().any(|i| i.label == "Start again" && i.enabled));
    assert!(palette.iter().any(|i| i.label == "Switch model" && i.enabled));
    rig.press(KeyCode::Enter);
    assert_eq!(rig.effects(), [Effect::Start]);
    // It ran, then ended.
    let mut rig = Rig::new(coding_spec());
    rig.ready().event(r#"{"type":"exit","code":1,"message":"OpenCode crashed"}"#);
    rig.app.choose_model("gpt-oss-20b".into(), rig.now);
    rig.effects();
    rig.app.switch_refused("gpt-oss-20b", "boom", rig.now);
    assert!(matches!(&rig.app.phase, Phase::Stopped { message, .. } if message == "OpenCode crashed"));
    assert_eq!(rig.app.exit_code(), 1);
    // An engine whose events ended meanwhile is not shown as ready (the run loop says so).
    let mut rig = Rig::new(coding_spec());
    rig.ready();
    rig.app.choose_model("gpt-oss-20b".into(), rig.now);
    rig.press(KeyCode::Enter);
    rig.app.switch_refused("gpt-oss-20b", "boom", rig.now);
    rig.app.engine_closed();
    assert!(rig.app.stopped());
}

#[test]
fn a_draft_survives_editing_a_recalled_prompt() {
    let mut rig = Rig::new(coding_spec());
    rig.ready().prompt("first");
    rig.event(r#"{"type":"turn_end","reason":"end_turn"}"#);
    rig.effects();
    rig.type_text("a long draft I was writing");
    rig.press(KeyCode::Up);
    assert_eq!(rig.app.input.text(), "first");
    rig.type_text("x");
    rig.press(KeyCode::Down);
    assert_eq!(rig.app.input.text(), "a long draft I was writing");
    rig.press(KeyCode::Up);
    assert_eq!(rig.app.input.text(), "firstx", "the change stays with the recalled prompt");
    rig.app.paste(" pasted");
    rig.press(KeyCode::Down);
    assert_eq!(rig.app.input.text(), "a long draft I was writing");
    // Clearing the box ends browsing: Up starts again from the prompt as sent.
    rig.ctrl('c');
    assert!(rig.app.input.is_empty());
    rig.press(KeyCode::Up);
    assert_eq!(rig.app.input.text(), "first");
}

#[test]
fn ctrl_c_that_clears_or_closes_something_does_not_count_towards_quitting() {
    let mut rig = Rig::new(coding_spec());
    rig.ready();
    rig.effects();
    rig.at(1000).type_text("a wrong paste");
    rig.ctrl('c');
    assert!(rig.app.input.is_empty());
    rig.at(1800).type_text("the real prompt I am writing");
    rig.at(2600).ctrl('c');
    assert!(rig.effects().is_empty(), "the second press cleared the new text");
    assert!(rig.app.input.is_empty());
    assert!(!rig.render(100, 30).contains("Press Ctrl+C again"));
    // Closing the palette does not count either.
    rig.at(3000).ctrl('p').ctrl('c');
    assert!(rig.app.overlay.is_none());
    rig.at(3200).ctrl('c');
    assert!(rig.effects().is_empty());
    assert!(rig.render(100, 30).contains("Press Ctrl+C again to quit"), "nothing to clear: it counts");
    // Any other key takes the count back.
    rig.at(3300).type_text("x");
    assert!(!rig.render(100, 30).contains("Press Ctrl+C again"));
    rig.at(3400).ctrl('c');
    assert!(rig.effects().is_empty() && rig.app.input.is_empty());
    rig.at(3500).ctrl('c');
    rig.at(3600).ctrl('c');
    assert_eq!(rig.effects(), [Effect::Quit]);
    // A dismissed request does not count.
    let mut rig = Rig::new(coding_spec());
    rig.ready().prompt("x");
    rig.event(PERMISSION);
    rig.effects();
    rig.at(1000).ctrl('c');
    assert_eq!(rig.sent(), [Command::Permission { id: "p1".into(), option: None }]);
    rig.at(1200).ctrl('c');
    assert_eq!(rig.sent(), [Command::Cancel], "the next press stops the turn, it does not quit");
}

#[test]
fn the_new_line_key_named_is_one_the_terminal_reports() {
    let mut rig = Rig::new(coding_spec());
    rig.ready();
    rig.app.shift_enter = false;
    let text = rig.render(100, 30);
    assert!(text.contains("ctrl+j new line") && !text.contains("shift+enter"), "{text}");
    rig.ctrl('p').type_text("keys").press(KeyCode::Enter);
    let text = rig.render(100, 30);
    assert!(text.contains("new line (also alt+enter)") && !text.contains("shift+enter"), "{text}");
    rig.press(KeyCode::Esc);
    rig.type_text("a").ctrl('j').type_text("b");
    assert_eq!(rig.app.input.text(), "a\nb");
    rig.app.shift_enter = true;
    rig.app.input.clear();
    assert!(rig.render(100, 30).contains("shift+enter new line"));
}

#[test]
fn encoded_secrets_are_masked_on_screen() {
    let masker = Masker::new(vec!["Winter@2026!".into()]);
    let mut rig = Rig::with(security_spec(), masker, true);
    rig.event(r#"{"type":"ready","harness":"strix","name":"Strix","model":"m","model_switch":"live"}"#);
    rig.prompt("log in");
    rig.event(r#"{"type":"tool_call","id":"t","title":"curl the login","kind":"execute","status":"completed","content":[{"type":"terminal","output":"POST /login email=a%40b.test&password=Winter%402026%21\n{\"password\":\"Winter@2026!\"}","exit_code":0}]}"#);
    let text = rig.render(100, 30);
    assert!(!text.contains("Winter"), "{text}");
    assert!(text.contains("password=••••"), "{text}");
}

fn long_running_client() -> Vec<String> {
    let argv: &[&str] = if cfg!(windows) { &["cmd"] } else { &["sh", "-c", "sleep 60"] };
    argv.iter().map(|s| s.to_string()).collect()
}

fn quick_client() -> Vec<String> {
    let argv: &[&str] = if cfg!(windows) { &["cmd", "/c", "echo bye"] } else { &["sh", "-c", "echo bye; exit 2"] };
    argv.iter().map(|s| s.to_string()).collect()
}

#[test]
fn a_client_that_ends_while_a_switch_is_prepared_is_not_shown_running() {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
    runtime.block_on(async move {
        let t0 = Instant::now();
        let spec = pane_spec(quick_client());
        let mut pane = Pane::new(spec.clone(), Theme::new(Depth::True), Masker::default(), 80, 24, t0);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let (rows, cols) = pane::pane_size(80, 24);
        let child = pane::spawn(&spec, rows, cols, 1, None, Depth::True, tx).expect("the client starts");
        pane.started(child, t0);
        pane.switch_preparing("gpt-oss-20b", t0);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(message)) => {
                    let exited = matches!(message, pane::Message::Exited(..));
                    pane.message(message, Instant::now());
                    if exited {
                        break;
                    }
                }
                other => panic!("the client did not end: {}", other.is_ok()),
            }
        }
        assert!(pane.child.is_none(), "the client is gone");
        assert!(matches!(pane.phase, PanePhase::Switching { .. }), "the switch goes on");
        let now = Instant::now();
        pane.switch_refused("gpt-oss-20b", "the catalog is unreachable", now);
        assert!(!pane.running());
        match &pane.phase {
            PanePhase::Ended { message, failed: true } => {
                assert!(message.contains("Aider ended"), "{message}");
                assert!(message.ends_with("Could not switch to gpt-oss-20b: the catalog is unreachable"), "{message}");
            }
            other => panic!("{other:?}"),
        }
        assert!(pane.overlay.is_none());
        pane.key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::CONTROL), now);
        let text = pane_text(&mut pane, 80, 24, now);
        assert!(text.contains("Start again"), "{text}");
        pane.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE), now);
        pane.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE), now);
        assert_eq!(pane.effects, [pane::PaneEffect::Start]);
    });
}

#[test]
fn a_refused_switch_leaves_a_running_client_its_keys() {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
    runtime.block_on(async move {
        let t0 = Instant::now();
        let spec = pane_spec(long_running_client());
        let mut pane = Pane::new(spec.clone(), Theme::new(Depth::True), Masker::default(), 80, 24, t0);
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let (rows, cols) = pane::pane_size(80, 24);
        let child = pane::spawn(&spec, rows, cols, 1, None, Depth::True, tx).expect("the client starts");
        pane.started(child, t0);
        // Ctrl+P, Switch model, the other model, confirm.
        for key in [
            KeyEvent::new(KeyCode::Char('p'), KeyModifiers::CONTROL),
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            KeyEvent::new(KeyCode::Down, KeyModifiers::NONE),
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
        ] {
            pane.key(key, t0);
        }
        assert_eq!(std::mem::take(&mut pane.effects), [pane::PaneEffect::Restart("gpt-oss-20b".into())]);
        let t1 = t0 + Duration::from_secs(5);
        pane.switch_preparing("gpt-oss-20b", t1);
        pane.switch_refused("gpt-oss-20b", "no such model", t1);
        assert!(pane.overlay.is_none(), "nothing takes the keys typed into the client");
        assert_eq!(pane.phase, PanePhase::Running { since: t0 }, "its clock goes on");
        let text = pane_text(&mut pane, 80, 24, t1);
        assert!(text.contains("Could not switch to gpt-oss-20b: no such model"), "{text}");
        // Typing goes to the client: a "y" answers nothing of ours.
        pane.key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE), t1);
        assert!(pane.effects.is_empty() && pane.overlay.is_none());
    });
}

#[test]
fn a_model_cannot_be_chosen_while_the_client_starts() {
    let t0 = Instant::now();
    let mut pane = Pane::new(pane_spec(vec!["aider".into()]), Theme::new(Depth::True), Masker::default(), 80, 24, t0);
    pane.key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::CONTROL), t0);
    match &pane.overlay {
        Some(Overlay::Palette { items, .. }) => {
            assert!(items.iter().any(|i| i.label == "Switch model" && !i.enabled), "not while it starts");
        }
        _ => panic!("the palette"),
    }
    pane.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE), t0);
    // A picker opened while it ran, answered once it had begun to start again: nothing is
    // switched, and the status line says why.
    pane.phase = PanePhase::Ended { message: "Aider ended.".into(), failed: false };
    pane.key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::CONTROL), t0);
    pane.key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE), t0);
    pane.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE), t0);
    assert!(matches!(pane.overlay, Some(Overlay::Picker { .. })));
    pane.phase = PanePhase::Starting { since: t0 };
    pane.key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE), t0);
    pane.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE), t0);
    assert!(pane.effects.is_empty(), "{:?}", pane.effects);
    let text = pane_text(&mut pane, 80, 24, t0);
    assert!(text.contains("Wait until Aider has started to switch models."), "{text}");
}

#[test]
fn a_resize_keeps_the_place_scrolled_back_to() {
    let t0 = Instant::now();
    let mut pane = Pane::new(pane_spec(vec!["x".into()]), Theme::new(Depth::True), Masker::default(), 80, 24, t0);
    pane.phase = PanePhase::Running { since: t0 };
    let output: String = (0..300).map(|i| format!("output line {i}\r\n")).collect();
    pane.message(pane::Message::Output(0, output.into_bytes()), t0);
    pane.key(KeyEvent::new(KeyCode::PageUp, KeyModifiers::SHIFT), t0);
    assert!(pane.scrollback > 0);
    pane.resize(100, 30);
    assert_eq!(pane.scrollback, pane.parser.screen().scrollback(), "the count follows the client's screen");
    assert!(pane.scrollback > 0, "still where the person was reading");
    let text = pane_text(&mut pane, 100, 30, t0);
    assert!(text.contains(&format!("{} rows back", pane.scrollback)), "{text}");
    pane.key(KeyEvent::new(KeyCode::PageUp, KeyModifiers::SHIFT), t0);
    assert_eq!(pane.scrollback, pane.parser.screen().scrollback());
    for _ in 0..10 {
        pane.key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::SHIFT), t0);
    }
    pane.resize(90, 26);
    assert_eq!((pane.scrollback, pane.parser.screen().scrollback()), (0, 0));
    assert!(pane_text(&mut pane, 90, 26, t0).contains("shift+pgup scroll back"));
}

#[test]
fn the_pane_hides_a_secret_its_client_wrapped_inside_a_frame_or_cut_short() {
    let t0 = Instant::now();
    let masker = Masker::new(vec!["Sup3rS3cretPW".into()]);
    let mut pane = Pane::new(pane_spec(vec!["x".into()]), Theme::new(Depth::True), masker, 40, 8, t0);
    pane.phase = PanePhase::Running { since: t0 };
    let row1 = format!("│{:<38}│", " curl -d password=Sup3rS3c");
    let row2 = format!("│{:<38}│", " retPW https://shop.test/login");
    let script = format!("\x1b[2J\x1b[H{row1}\r\n{row2}\r\nlogin as Sup3rS3cr…\r\n");
    pane.message(pane::Message::Output(0, script.into_bytes()), t0);
    let text = pane_text(&mut pane, 40, 8, t0);
    for piece in ["Sup3r", "retPW", "S3cr"] {
        assert!(!text.contains(piece), "{piece} shows:\n{text}");
    }
    assert!(text.contains("https://shop.test/login") && text.contains("login as"), "{text}");
}

#[test]
fn a_clients_scrolling_output_costs_a_few_bytes_a_line() {
    let t0 = Instant::now();
    let (width, height) = (100u16, 30u16);
    let mut pane =
        Pane::new(pane_spec(vec!["x".into()]), Theme::new(Depth::Ansi256), Masker::default(), width, height, t0);
    pane.phase = PanePhase::Running { since: t0 };
    let area = Rect::new(0, 0, width, height);
    let mut screen = Screen::new(area);
    fn frame(pane: &mut Pane, screen: &mut Screen, area: Rect, now: Instant) -> Vec<u8> {
        let mut buffer = Buffer::empty(area);
        let drawn = pane.draw(area, &mut buffer, now);
        screen.frame(&buffer, drawn.cursor, drawn.scroll)
    }
    let line =
        |i: usize| format!("\x1b[3{}m{i:>4}\x1b[0m GET /api/items?page={i} 200 in {} ms\r\n", 1 + i % 6, i * 7 % 300);
    let first: String = (0..40).map(line).collect();
    pane.message(pane::Message::Output(0, first.into_bytes()), t0);
    let painted = frame(&mut pane, &mut screen, area, t0).len();
    assert!(painted > 1500, "the first frame paints everything ({painted} bytes)");
    for i in 40..50 {
        pane.message(pane::Message::Output(0, line(i).into_bytes()), t0);
        let bytes = frame(&mut pane, &mut screen, area, t0);
        let shown = String::from_utf8_lossy(&bytes);
        assert!(shown.contains("\x1b[2;29r\x1b[1S\x1b[r"), "the rows are scrolled: {shown:?}");
        assert!(bytes.len() < 300, "a new line costs few bytes ({} bytes): {shown:?}", bytes.len());
    }
}

#[test]
fn a_client_is_told_when_the_screen_shows_no_colour() {
    let mut spec = pane_spec(vec!["x".into()]);
    spec.env =
        [("PATH", "/usr/bin"), ("COLORTERM", "truecolor")].into_iter().map(|(k, v)| (k.into(), v.into())).collect();
    let plain = pane::client_env(&spec, Depth::None);
    assert_eq!(plain.get("NO_COLOR").map(String::as_str), Some("1"));
    assert!(!plain.contains_key("COLORTERM"), "nor that it has 24-bit colour");
    assert_eq!(plain.get("TERM").map(String::as_str), Some("xterm-256color"));
    let coloured = pane::client_env(&spec, Depth::Ansi256);
    assert!(!coloured.contains_key("NO_COLOR"));
    assert_eq!(coloured.get("COLORTERM").map(String::as_str), Some("truecolor"));
    spec.env.remove("COLORTERM");
    assert_eq!(pane::client_env(&spec, Depth::True).get("COLORTERM").map(String::as_str), Some("truecolor"));
}

// ---- The context meter (the matrix run, 13 Nov 2026) ----

/// The model holds `window` tokens; the engine is ready and reports `usage`. Returns the screen,
/// its frame and the status line (the last row).
fn metered(window: u32, usage: &str) -> (Rig, Buffer, String) {
    let mut model = coding_spec();
    model.context_window = window;
    let mut rig = Rig::new(model);
    rig.event(READY).event(usage);
    let buffer = rig.buffer(100, 30);
    let status = buffer_text(&buffer).lines().last().unwrap_or_default().to_owned();
    (rig, buffer, status)
}

#[test]
fn the_context_meter_counts_against_the_models_window_when_the_engine_reports_a_larger_one() {
    // Engines that do not know the model report their own defaults. The matrix run's footers
    // showed 1%, 8% and 3%.
    for (usage, shown) in [
        // Gemini CLI.
        (r#"{"type":"usage","context_tokens":10782,"context_window":1048576}"#, " · 33% context"),
        // Qwen Code.
        (r#"{"type":"usage","context_tokens":16727,"context_window":200000}"#, " · 51% context"),
        // Goose.
        (r#"{"type":"usage","context_tokens":3343,"context_window":128000}"#, " · 10% context"),
    ] {
        let (_, _, status) = metered(32768, usage);
        assert!(status.contains(shown), "{usage}: {status}");
    }
    // The model's window is the spec's, whatever its size.
    let (_, _, status) = metered(8192, r#"{"type":"usage","context_tokens":4096,"context_window":32768}"#);
    assert!(status.contains(" · 50% context"), "{status}");
    // Near the model's window the meter turns red.
    let (rig, buffer, status) = metered(32768, r#"{"type":"usage","context_tokens":30000,"context_window":1048576}"#);
    assert!(status.contains(" · 92% context"), "{status}");
    assert_eq!(color_of(&buffer, "92% context"), rig.app.theme.bad().fg);
}

#[test]
fn the_context_meter_counts_against_the_engines_window_when_it_is_smaller() {
    // An engine that works within a smaller window than the model's fills that one first.
    let (rig, buffer, status) = metered(32768, r#"{"type":"usage","context_tokens":20000,"context_window":25000}"#);
    assert!(status.contains(" · 80% context"), "{status}");
    assert_eq!(color_of(&buffer, "80% context"), rig.app.theme.warn().fg);
    // Our own agent and Claude Code report the model's window itself.
    let (_, _, status) = metered(32768, r#"{"type":"usage","context_tokens":3277,"context_window":32768}"#);
    assert!(status.contains(" · 10% context"), "{status}");
}

#[test]
fn the_context_meter_counts_against_the_models_window_when_the_engine_reports_none() {
    let (mut rig, _, status) = metered(32768, r#"{"type":"usage","context_tokens":16384}"#);
    assert!(status.contains(" · 50% context"), "{status}");
    // A window of 0 is no window.
    rig.event(r#"{"type":"usage","context_tokens":8192,"context_window":0}"#);
    let status = buffer_text(&rig.buffer(100, 30)).lines().last().unwrap_or_default().to_owned();
    assert!(status.contains(" · 25% context"), "{status}");
    // Without tokens there is nothing to show.
    let (_, _, status) = metered(32768, r#"{"type":"usage","context_window":1048576}"#);
    assert!(!status.contains("context"), "{status}");
}
