//! Tests for the /harness panel and the switch command.
use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::io::Read;

/// The website's harness catalogue, whose questions the panel asks.
const CATALOG: &str = include_str!("../../../../examples/hub/inference-solver/site/harnesses.json");

fn catalog() -> Vec<Value> {
    serde_json::from_str(CATALOG).unwrap()
}

/// A Yougori session that may switch to a few harnesses, as runtime.py writes its spec.
fn spec() -> EngineSpec {
    let catalog = catalog();
    let questions = |id: &str| catalog.iter().find(|h| h["id"] == id).map(|h| h["questions"].clone()).unwrap_or(json!([]));
    let entry = |id: &str, name: &str, category: &str, base: &str, memory: u32, ready: bool| {
        json!({"id": id, "name": name, "category": category, "description": format!("{name} works here."),
               "questions": questions(id), "base": base, "memory": memory, "ready": ready,
               "reason": if ready { "" } else { "The administrator has not published it yet." }})
    };
    serde_json::from_value(json!({
        "harness": "yougori", "name": "Yougori", "protocol": "native", "profile": "yougori",
        "cwd": "/run/yougori/workspace", "model": "gemma", "models": ["gemma", "qwen"], "state_dir": "/home/node/.yougori",
        "harnesses": [entry("yougori", "Yougori", "coding", "base", 4, true), entry("opencode", "OpenCode", "coding", "base", 4, true),
                      entry("swe", "SWE-agent", "coding", "base", 4, true), entry("kilo", "Kilo Code", "coding", "base", 4, false),
                      entry("plandex", "Plandex", "coding", "postgres", 4, true), entry("strix", "Strix", "security", "base", 4, true),
                      entry("shannon", "Shannon", "security", "chromium", 6, true)],
        "switch": ["python3", "/opt/solver/runtime.py", "switch"], "vm_base": "base", "vm_memory": 4,
        "server": "https://argon.yougori.com"
    }))
    .unwrap()
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn typed(flow: &mut Flow, text: &str) {
    for c in text.chars() {
        assert_eq!(flow.key(key(KeyCode::Char(c))), FlowOutcome::Stay);
    }
}

/// What the panel shows, as plain text.
fn shown(flow: &Flow) -> String {
    let (lines, _) = flow.lines(&Theme::new(crate::ui::theme::Depth::None), 100, 30);
    lines.iter().map(|line| line.spans.iter().map(|s| s.content.as_ref()).collect::<String>()).collect::<Vec<_>>().join("\n")
}

fn started(outcome: FlowOutcome) -> Pending {
    match outcome {
        FlowOutcome::Start(pending) => *pending,
        other => panic!("the switch did not start: {other:?}"),
    }
}

#[test]
fn every_question_the_website_asks_can_be_asked_here() {
    for harness in catalog() {
        let asked = harness["questions"].as_array().cloned().unwrap_or_default();
        assert!(questions(&asked).is_ok(), "{}: {:?}", harness["id"], questions(&asked));
    }
    // The CLI's rules hold: a must-confirm is required, a target's default is refused.
    assert!(questions(&[json!({"id": "ok", "type": "confirm", "question": "Sure?", "must": true})]).is_err());
    assert!(questions(&[json!({"id": "t", "type": "target", "question": "What?", "default": "practice"})]).is_err());
    assert!(questions(&[json!({"id": "x", "type": "telepathy", "question": "Hm?"})]).is_err());
}

#[test]
fn a_harness_without_questions_comes_into_this_vm() {
    let (mut flow, outcome) = Flow::open(&spec(), "gemma", None).unwrap();
    assert_eq!(outcome, FlowOutcome::Stay);
    let list = shown(&flow);
    assert!(list.contains("◆  Switch harness") && list.contains("Strix (security)"), "{list}");
    assert!(list.contains("Yougori") && list.contains("running now"), "{list}");
    assert!(list.contains("The administrator has not published it yet."), "{list}");
    assert!(list.contains("Shannon works here. · new VM"), "{list}");
    // The harness running now is not chosen again.
    assert_eq!(flow.key(key(KeyCode::Enter)), FlowOutcome::Stay);
    assert!(shown(&flow).contains("Yougori is running now."));
    flow.key(key(KeyCode::Down));
    let pending = started(flow.key(key(KeyCode::Enter)));
    assert_eq!(pending.mode, Mode::InPlace);
    assert_eq!(pending.request(), json!({"harness": "opencode", "model": "gemma", "answers": {}, "mode": "in-place"}));
}

#[test]
fn typing_filters_and_one_not_ready_says_why() {
    let (mut flow, _) = Flow::open(&spec(), "gemma", None).unwrap();
    typed(&mut flow, "kilo");
    let list = shown(&flow);
    assert!(list.contains("Kilo Code") && !list.contains("OpenCode"), "{list}");
    assert_eq!(flow.key(key(KeyCode::Enter)), FlowOutcome::Stay);
    assert!(shown(&flow).contains("The administrator has not published it yet."));
    for _ in 0..4 {
        flow.key(key(KeyCode::Backspace));
    }
    typed(&mut flow, "zzz");
    assert!(shown(&flow).contains("Nothing matches."));
}

#[test]
fn a_harness_on_another_base_starts_in_a_new_vm_once_confirmed() {
    let (mut flow, outcome) = Flow::open(&spec(), "gemma", Some("plandex")).unwrap();
    assert_eq!(outcome, FlowOutcome::Stay);
    let confirm = shown(&flow);
    assert!(confirm.contains("Start Plandex in a new VM?") && confirm.contains("Plandex starts in a new VM (it needs PostgreSQL)."), "{confirm}");
    assert!(confirm.contains("Changes made so far stay in this VM's copy for review."), "{confirm}");
    let pending = started(flow.key(key(KeyCode::Enter)));
    assert_eq!(
        pending.request(),
        json!({"harness": "plandex", "model": "gemma", "answers": {}, "mode": "new-vm", "targets": [], "memory": 4, "secrets": {}})
    );
    // More memory than this VM has: a new VM too, with that memory.
    let (mut flow, _) = Flow::open(&spec(), "gemma", Some("Shannon")).unwrap();
    flow.key(key(KeyCode::Enter)); // the practice app
    for _ in 0..5 {
        if matches!(flow.step, Step::Confirm { .. }) {
            break;
        }
        flow.key(key(KeyCode::Enter));
    }
    assert!(shown(&flow).contains("Shannon starts in a new VM (it needs Chromium and 6 GB of memory)."), "{}", shown(&flow));
    let pending = started(flow.key(key(KeyCode::Char('y'))));
    assert_eq!(pending.request()["memory"], json!(6));
}

#[test]
fn a_security_harness_on_the_practice_app_stays_in_this_vm() {
    let (mut flow, outcome) = Flow::open(&spec(), "gemma", Some("strix")).unwrap();
    assert_eq!(outcome, FlowOutcome::Stay);
    let target = shown(&flow);
    assert!(target.contains("Strix · What should it test?") && target.contains("● A practice app inside the VM"), "{target}");
    // The practice app: no permission question; then off limits, depth (Test safely), a login,
    // the source and a focus, each skipped or kept as offered.
    assert_eq!(flow.key(key(KeyCode::Enter)), FlowOutcome::Stay);
    assert!(shown(&flow).contains("What is off limits?"));
    flow.key(key(KeyCode::Enter));
    assert!(shown(&flow).contains("● Test safely"));
    flow.key(key(KeyCode::Enter));
    assert!(shown(&flow).contains("Login for the test?"));
    flow.key(key(KeyCode::Enter));
    let source = shown(&flow);
    assert!(source.contains("This session's folder") && source.contains("● None"), "{source}");
    flow.key(key(KeyCode::Enter));
    let pending = started(flow.key(key(KeyCode::Enter)));
    assert_eq!(pending.mode, Mode::InPlace);
    assert_eq!(pending.request()["answers"], json!({"target": "practice", "depth": "safe"}));
}

#[test]
fn an_address_needs_the_permission_yes_and_a_new_vm_that_reaches_it() {
    let (mut flow, _) = Flow::open(&spec(), "gemma", Some("strix")).unwrap();
    flow.key(key(KeyCode::Down));
    flow.key(key(KeyCode::Enter));
    assert!(shown(&flow).contains("Website or address to test"));
    typed(&mut flow, "localhost:3000");
    flow.key(key(KeyCode::Enter));
    assert!(shown(&flow).contains("localhost:3000 is this computer"), "{}", shown(&flow));
    for _ in 0.."localhost:3000".len() {
        flow.key(key(KeyCode::Backspace));
    }
    typed(&mut flow, "https://staging.example.com");
    flow.key(key(KeyCode::Enter));
    // The permission question starts on No; No starts nothing.
    let permission = shown(&flow);
    assert!(permission.contains("written permission") && permission.contains("● No"), "{permission}");
    assert_eq!(flow.key(key(KeyCode::Enter)), FlowOutcome::Stay);
    assert!(shown(&flow).contains("Yougori tests only targets you own or have written permission to test."));
    flow.key(key(KeyCode::Up));
    flow.key(key(KeyCode::Enter));
    typed(&mut flow, "/billing");
    flow.key(key(KeyCode::Enter));
    flow.key(key(KeyCode::Enter)); // Test safely
    typed(&mut flow, "tester@example.com");
    flow.key(key(KeyCode::Enter));
    // The login's password: masked as typed.
    typed(&mut flow, "hunter22");
    let password = shown(&flow);
    assert!(password.contains("••••••••") && !password.contains("hunter22"), "{password}");
    flow.key(key(KeyCode::Enter));
    flow.key(key(KeyCode::Enter)); // no source
    flow.key(key(KeyCode::Enter)); // no focus
    let confirm = shown(&flow);
    assert!(confirm.contains("Strix starts in a new VM that reaches only staging.example.com:443 and this inference."), "{confirm}");
    let pending = started(flow.key(key(KeyCode::Enter)));
    let request = pending.request();
    assert_eq!(request["mode"], "new-vm");
    assert_eq!(request["targets"], json!(["staging.example.com:443"]));
    assert_eq!(request["secrets"], json!({"login_password": "hunter22"}));
    assert_eq!(
        request["answers"],
        json!({"target": ["https://staging.example.com"], "permission": true, "off_limits": ["/billing"], "depth": "safe",
               "login_user": "tester@example.com"})
    );
    // A secret is never in what the pending switch shows of itself, nor in place in the request.
    assert!(!format!("{pending:?}").contains("hunter22"));
    let here = Pending { mode: Mode::InPlace, ..pending };
    assert!(here.request().get("secrets").is_none());
}

#[test]
fn esc_goes_back_a_question_then_to_the_list_then_closes() {
    let (mut flow, _) = Flow::open(&spec(), "gemma", Some("swe")).unwrap();
    let issue = shown(&flow);
    assert!(issue.contains("What should SWE-agent fix?") && issue.contains("Such as"), "{issue}");
    assert_eq!(flow.key(key(KeyCode::Enter)), FlowOutcome::Stay);
    assert!(shown(&flow).contains("This question needs an answer."));
    typed(&mut flow, "Sign-in fails");
    assert_eq!(flow.key(key(KeyCode::Esc)), FlowOutcome::Stay);
    assert!(shown(&flow).contains("◆  Switch harness"));
    assert_eq!(flow.key(key(KeyCode::Esc)), FlowOutcome::Close);
    // Ctrl+C closes from anywhere.
    let (mut flow, _) = Flow::open(&spec(), "gemma", Some("swe")).unwrap();
    assert_eq!(flow.key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)), FlowOutcome::Close);
    // A pasted line goes into the field being typed.
    let (mut flow, _) = Flow::open(&spec(), "gemma", Some("swe")).unwrap();
    flow.paste("Fix the\nlogin");
    let pending = started(flow.key(key(KeyCode::Enter)));
    assert_eq!(pending.request()["answers"], json!({"issue": "Fix thelogin"}));
}

#[test]
fn a_session_that_cannot_switch_or_a_name_it_does_not_hold_says_so() {
    let mut older = spec();
    older.session = crate::spec::Session::default();
    assert_eq!(Flow::open(&older, "gemma", None).err().unwrap(), OLDER);
    assert_eq!(Flow::open(&spec(), "gemma", Some("nope")).err().unwrap(), "There is no harness nope here. /harness lists them.");
    assert_eq!(Flow::open(&spec(), "gemma", Some("kilo")).err().unwrap(), "The administrator has not published it yet.");
    assert_eq!(Flow::open(&spec(), "gemma", Some("yougori")).err().unwrap(), "Yougori is running now.");
    // A harness with no questions, named: it starts at once.
    let (_, outcome) = Flow::open(&spec(), "gemma", Some("OpenCode")).unwrap();
    assert_eq!(started(outcome).entry.id, "opencode");
}

#[test]
fn targets_the_vm_already_reaches_keep_the_harness_in_this_vm() {
    let mut spec = spec();
    let strix = spec.session.harnesses.iter().find(|entry| entry.id == "strix").unwrap().clone();
    let answers = BTreeMap::from([("target".to_owned(), Answer::Targets(target_entries("https://staging.example.com").unwrap()))]);
    assert!(matches!(mode(&spec, &strix, &answers), Mode::NewVm { .. }));
    spec.reach.mode = "targets".into();
    spec.reach.targets = vec!["staging.example.com:443".into()];
    assert_eq!(mode(&spec, &strix, &answers), Mode::InPlace);
    spec.reach.targets = vec!["staging.example.com".into()];
    assert_eq!(mode(&spec, &strix, &answers), Mode::InPlace, "a host alone is each of its ports");
    spec.reach.targets = vec!["other.example.com:443".into()];
    assert!(matches!(mode(&spec, &strix, &answers), Mode::NewVm { .. }));
    spec.reach = crate::spec::Reach { mode: "full".into(), ..Default::default() };
    assert_eq!(mode(&spec, &strix, &answers), Mode::InPlace);
    assert_eq!(mode(&spec, &strix, &BTreeMap::from([("target".to_owned(), Answer::Practice)])), Mode::InPlace);
}

#[test]
fn addresses_are_read_as_the_cli_reads_them() {
    assert_eq!(target_entries("https://Staging.Example.com, 10.0.0.5:8080").unwrap(), vec![
        ("https://Staging.Example.com".to_owned(), "staging.example.com:443".to_owned()),
        ("10.0.0.5:8080".to_owned(), "10.0.0.5:8080".to_owned()),
    ]);
    for bad in ["127.0.0.1", "localhost:80", "169.254.169.254:80", "jenkins", "x.com:0", "ftp://x.com", "https://user:pw@x.com", ""] {
        assert!(target_entries(bad).is_err(), "{bad}");
    }
}

// ---- the switch command, as runtime.py's

/// The switch command the tests run: this test binary again, acting as runtime.py's switch.
#[test]
fn fake_switch_command() {
    let Ok(mode) = std::env::var("YOUGORI_FAKE_SWITCH") else { return };
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).unwrap();
    let request: Value = serde_json::from_str(&input).unwrap();
    if let Ok(log) = std::env::var("YOUGORI_FAKE_SWITCH_LOG") {
        std::fs::write(log, json!({"request": request, "token": std::env::var(SWITCH_TOKEN).ok()}).to_string()).unwrap();
    }
    match mode.as_str() {
        "in-place" => {
            eprintln!("{}", json!({"progress": "Downloading Kilo: 50%"}));
            eprintln!("a line that is not JSON");
            eprintln!("{}", json!({"progress": "Installing Kilo: 100%"}));
            let next = json!({"harness": request["harness"], "name": "Kilo Code", "protocol": "acp", "argv": ["kilo", "acp"],
                              "cwd": "/w", "model": request["model"], "state_dir": "/s", "switch": ["x"],
                              "harnesses": [{"id": "yougori", "name": "Yougori"}]});
            println!("\n{next}");
        }
        "new-vm" => println!("\n{}", json!({"new_vm": true})),
        "fail-kept" => {
            eprintln!("{}", json!({"error": "Not published.", "kept": true}));
            std::process::exit(1);
        }
        "fail-gone" => {
            eprintln!("{}", json!({"error": "The pack could not be installed.", "kept": false}));
            std::process::exit(1);
        }
        "garbage" => println!("\nnot a spec"),
        "hang" => std::thread::sleep(Duration::from_secs(60)),
        _ => std::process::exit(9),
    }
    std::process::exit(0);
}

fn fake(dir: &std::path::Path, mode: &str) -> EngineSpec {
    let mut spec = spec();
    spec.cwd = dir.to_path_buf();
    spec.session.switch = vec![
        std::env::current_exe().unwrap().to_string_lossy().into_owned(),
        "--exact".into(),
        "ui::switcher::tests::fake_switch_command".into(),
        "--nocapture".into(),
        "--test-threads".into(),
        "1".into(),
        "-q".into(),
    ];
    spec.env.insert("YOUGORI_FAKE_SWITCH".into(), mode.into());
    spec.env.insert("YOUGORI_FAKE_SWITCH_LOG".into(), dir.join("asked.json").to_string_lossy().into_owned());
    for name in ["SystemRoot", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "PATH"] {
        if let Ok(value) = std::env::var(name) {
            spec.env.insert(name.into(), value);
        }
    }
    spec
}

async fn switch(spec: EngineSpec, request: Value, cancel_after: Option<Duration>) -> (Switched, Vec<String>) {
    let (progress, mut received) = tokio::sync::mpsc::unbounded_channel();
    let (cancel, cancelled) = tokio::sync::oneshot::channel();
    let canceller = tokio::spawn(async move {
        if let Some(after) = cancel_after {
            tokio::time::sleep(after).await;
            let _ = cancel.send(());
        } else {
            std::future::pending::<()>().await;
        }
    });
    let switched = tokio::time::timeout(Duration::from_secs(60), run(spec, request, progress, cancelled)).await.unwrap();
    canceller.abort();
    let mut said = Vec::new();
    while let Ok(line) = received.try_recv() {
        said.push(line);
    }
    (switched, said)
}

fn kilo() -> Value {
    json!({"harness": "kilo", "model": "gemma", "answers": {}, "mode": "in-place"})
}

#[tokio::test]
async fn in_place_the_next_spec_comes_back_with_its_progress() {
    let dir = tempfile::tempdir().unwrap();
    let (switched, said) = switch(fake(dir.path(), "in-place"), kilo(), None).await;
    let Switched::InPlace(next) = switched else { panic!("{switched:?}") };
    assert_eq!((next.harness.as_str(), next.model.as_str(), next.session.switch.as_slice()), ("kilo", "gemma", ["x".to_owned()].as_slice()));
    assert_eq!(said, ["Downloading Kilo: 50%", "Installing Kilo: 100%"]);
    let asked: Value = serde_json::from_str(&std::fs::read_to_string(dir.path().join("asked.json")).unwrap()).unwrap();
    assert_eq!(asked["request"], kilo());
}

#[tokio::test]
async fn a_new_vm_a_failure_and_a_mistake_each_say_so() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(switch(fake(dir.path(), "new-vm"), kilo(), None).await.0, Switched::NewVm);
    assert_eq!(switch(fake(dir.path(), "fail-kept"), kilo(), None).await.0, Switched::Failed { reason: "Not published.".into(), kept: true });
    assert_eq!(
        switch(fake(dir.path(), "fail-gone"), kilo(), None).await.0,
        Switched::Failed { reason: "The pack could not be installed.".into(), kept: false }
    );
    assert_eq!(
        switch(fake(dir.path(), "garbage"), kilo(), None).await.0,
        Switched::Failed { reason: "The switch printed no harness to start.".into(), kept: false }
    );
    let mut older = fake(dir.path(), "new-vm");
    older.session.switch.clear();
    assert_eq!(switch(older, kilo(), None).await.0, Switched::Failed { reason: OLDER.into(), kept: true });
}

#[tokio::test]
async fn esc_stops_a_switch_and_one_stopped_early_never_starts() {
    let dir = tempfile::tempdir().unwrap();
    let started = std::time::Instant::now();
    let (switched, _) = switch(fake(dir.path(), "hang"), kilo(), Some(Duration::from_millis(500))).await;
    assert!(matches!(switched, Switched::Failed { kept: true, .. }), "{switched:?}");
    assert!(started.elapsed() < Duration::from_secs(30));
    let other = tempfile::tempdir().unwrap();
    let (switched, _) = switch(fake(other.path(), "in-place"), kilo(), Some(Duration::ZERO)).await;
    // Cancelled before it started: the command never ran.
    if switched == (Switched::Failed { reason: "Cancelled.".into(), kept: true }) {
        assert!(!other.path().join("asked.json").exists());
    }
}

#[test]
fn only_the_switch_command_gets_the_switch_token() {
    let spec = fake(std::path::Path::new("/w"), "in-place");
    let command = switch_command(&spec, "runtime", &[], Some("t0ken".into()));
    let given: Vec<(String, String)> = command
        .as_std()
        .get_envs()
        .filter_map(|(name, value)| Some((name.to_string_lossy().into_owned(), value?.to_string_lossy().into_owned())))
        .collect();
    assert!(given.contains(&(SWITCH_TOKEN.to_owned(), "t0ken".to_owned())));
    assert!(!spec.environment().contains_key(SWITCH_TOKEN), "engines never get it");
    let without = switch_command(&spec, "runtime", &[], None);
    assert!(!without.as_std().get_envs().any(|(name, _)| name == SWITCH_TOKEN));
}
