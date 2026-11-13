//! The Codex adapter against a fake app-server over pipes, shaped like the 0.166.0 schema and
//! the probe of the real one.
use super::*;
use crate::engines::acp::tests::{pipes, spec as base_spec, Fake};

fn spec(dir: &Path) -> EngineSpec {
    let mut spec = base_spec(dir);
    spec.harness = "codex".into();
    spec.name = "Codex".into();
    spec.protocol = crate::spec::Protocol::CodexAppServer;
    spec.argv = vec!["codex".into(), "app-server".into()];
    spec.mcp.clear();
    spec
}

async fn next(engine: &mut EngineHandle) -> Event {
    tokio::time::timeout(Duration::from_secs(10), engine.events.recv()).await.expect("no event in time").expect("engine ended")
}

/// The next message from the client, which must be bare (no `jsonrpc` member).
async fn recv(fake: &mut Fake) -> Value {
    let message = fake.recv().await;
    assert!(message.get("jsonrpc").is_none(), "Codex messages carry no jsonrpc member: {message}");
    message
}

async fn request(fake: &mut Fake, method: &str) -> (Value, Value) {
    let message = recv(fake).await;
    assert_eq!(message["method"], json!(method), "{message}");
    (message["id"].clone(), message["params"].clone())
}

async fn reply(fake: &mut Fake, id: Value, result: Value) {
    fake.send(json!({"id": id, "result": result})).await;
}

async fn note(fake: &mut Fake, method: &str, params: Value) {
    fake.send(json!({"method": method, "params": params})).await;
}

async fn started(dir: &Path) -> (EngineHandle, Fake) {
    let (transport, mut fake) = pipes();
    let client = tokio::spawn(connect(spec(dir), transport));
    let (id, params) = request(&mut fake, "initialize").await;
    assert_eq!(params["clientInfo"]["name"], "yougori_harness");
    reply(&mut fake, id, json!({"userAgent": "codex_cli_rs/0.166.0 (Debian 13; x86_64)", "codexHome": "/home/node/.codex",
        "platformFamily": "unix", "platformOs": "linux"}))
    .await;
    let initialized = recv(&mut fake).await;
    assert_eq!(initialized, json!({"method": "initialized"}));
    let (id, params) = request(&mut fake, "thread/start").await;
    assert_eq!((params["model"].clone(), params["approvalPolicy"].clone()), (json!("m1"), json!("untrusted")));
    reply(&mut fake, id, json!({"thread": {"id": "th1"}, "model": "m1", "modelProvider": "solver", "cwd": dir,
        "approvalPolicy": "untrusted", "approvalsReviewer": "user", "sandbox": {"type": "dangerFullAccess"}}))
    .await;
    (client.await.unwrap().unwrap(), fake)
}

#[tokio::test]
async fn a_turn_streams_reasoning_text_commands_and_file_changes_with_approvals() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), "one\ntwo\n").unwrap();
    let (mut engine, mut fake) = started(dir.path()).await;
    let Event::Ready(ready) = next(&mut engine).await else { panic!() };
    assert_eq!((ready.session.as_deref(), ready.info.as_deref()), (Some("th1"), Some("Codex 0.166.0 · app-server")));
    assert_eq!(ready.model_switch, ModelSwitch::Live);
    let Event::Modes { current, available } = next(&mut engine).await else { panic!() };
    assert_eq!((current.as_str(), available.len()), ("ask", 3));
    assert!(matches!(next(&mut engine).await, Event::Commands { .. }));

    engine.commands.send(Command::Prompt { text: "run the tests".into() }).unwrap();
    let (id, params) = request(&mut fake, "turn/start").await;
    assert_eq!(params["input"], json!([{"type": "text", "text": "run the tests", "text_elements": []}]));
    assert!(params.get("model").is_none());
    reply(&mut fake, id, json!({"turn": {"id": "tu1", "status": "inProgress", "items": []}})).await;
    note(&mut fake, "turn/started", json!({"threadId": "th1", "turn": {"id": "tu1", "status": "inProgress", "items": []}})).await;
    note(&mut fake, "item/started", json!({"threadId": "th1", "turnId": "tu1", "startedAtMs": 1, "item": {"type": "reasoning", "id": "r1"}})).await;
    note(&mut fake, "item/reasoning/textDelta", json!({"threadId": "th1", "turnId": "tu1", "itemId": "r1", "contentIndex": 0, "delta": "Tests first."})).await;
    note(&mut fake, "item/reasoning/summaryTextDelta", json!({"threadId": "th1", "turnId": "tu1", "itemId": "r1", "summaryIndex": 0, "delta": "dup"})).await;
    note(&mut fake, "item/completed", json!({"threadId": "th1", "turnId": "tu1", "completedAtMs": 2, "item": {"type": "reasoning", "id": "r1", "content": ["Tests first."]}})).await;
    note(&mut fake, "item/agentMessage/delta", json!({"threadId": "th1", "turnId": "tu1", "itemId": "m1", "delta": "Running "})).await;
    note(&mut fake, "item/agentMessage/delta", json!({"threadId": "th1", "turnId": "tu1", "itemId": "m1", "delta": "them."})).await;
    note(&mut fake, "item/completed", json!({"threadId": "th1", "turnId": "tu1", "completedAtMs": 3, "item": {"type": "agentMessage", "id": "m1", "text": "Running them."}})).await;
    assert_eq!(next(&mut engine).await, Event::Reasoning { message: "r1".into(), text: "Tests first.".into(), parent: None });
    assert_eq!(next(&mut engine).await, Event::Message { message: "m1".into(), text: "Running ".into(), parent: None });
    assert_eq!(next(&mut engine).await, Event::Message { message: "m1".into(), text: "them.".into(), parent: None });

    // A command, approved, its output streamed.
    note(&mut fake, "item/started", json!({"threadId": "th1", "turnId": "tu1", "startedAtMs": 4, "item": {"type": "commandExecution", "id": "c1",
        "command": "cargo test", "cwd": dir.path(), "commandActions": [{"type": "unknown", "command": "cargo test"}], "status": "inProgress"}}))
    .await;
    let Event::ToolCall(call) = next(&mut engine).await else { panic!() };
    assert_eq!((call.id.as_str(), call.title.as_str(), call.kind), ("c1", "cargo test", ToolKind::Execute));
    fake.send(json!({"id": 90, "method": "item/commandExecution/requestApproval", "params": {"threadId": "th1", "turnId": "tu1", "itemId": "c1",
        "startedAtMs": 5, "command": "cargo test", "reason": "It needs the network."}}))
    .await;
    let Event::Permission(asked) = next(&mut engine).await else { panic!() };
    assert_eq!((asked.title.as_str(), asked.detail.as_deref(), asked.tool_call.as_deref()), ("Run cargo test", Some("It needs the network."), Some("c1")));
    assert_eq!(asked.options.iter().map(|o| o.kind).collect::<Vec<_>>(), vec![PermissionKind::AllowOnce, PermissionKind::AllowAlways, PermissionKind::RejectOnce]);
    engine.commands.send(Command::Permission { id: asked.id, option: Some("acceptForSession".into()) }).unwrap();
    let answer = recv(&mut fake).await;
    assert_eq!(answer, json!({"id": 90, "result": {"decision": "acceptForSession"}}));
    note(&mut fake, "item/commandExecution/outputDelta", json!({"threadId": "th1", "turnId": "tu1", "itemId": "c1", "delta": "running 3 tests\n"})).await;
    let Event::ToolUpdate(update) = next(&mut engine).await else { panic!() };
    assert_eq!(update.content, Some(vec![ToolContent::Terminal { command: Some("cargo test".into()), output: "running 3 tests\n".into(), exit_code: None }]));
    note(&mut fake, "item/completed", json!({"threadId": "th1", "turnId": "tu1", "completedAtMs": 6, "item": {"type": "commandExecution", "id": "c1",
        "command": "cargo test", "cwd": dir.path(), "commandActions": [], "status": "completed", "exitCode": 0,
        "aggregatedOutput": "running 3 tests\nok\n"}}))
    .await;
    let Event::ToolUpdate(done) = next(&mut engine).await else { panic!() };
    assert_eq!(done.status, Some(ToolStatus::Completed));
    assert_eq!(done.content, Some(vec![ToolContent::Terminal { command: Some("cargo test".into()), output: "running 3 tests\nok\n".into(), exit_code: Some(0) }]));

    // A file change: the diff from the file and the patch; dismissing its approval stops it.
    let change = json!([{"path": "a.txt", "kind": {"type": "update", "move_path": null}, "diff": "@@ -1,2 +1,2 @@\n one\n-two\n+three\n"}]);
    note(&mut fake, "item/started", json!({"threadId": "th1", "turnId": "tu1", "startedAtMs": 7, "item": {"type": "fileChange", "id": "f1", "changes": change, "status": "inProgress"}})).await;
    let Event::ToolCall(call) = next(&mut engine).await else { panic!() };
    assert_eq!((call.title.as_str(), call.kind), ("Edit a.txt", ToolKind::Edit));
    assert_eq!(call.content, vec![ToolContent::Diff { path: "a.txt".into(), old: Some("one\ntwo\n".into()), new: "one\nthree\n".into() }]);
    fake.send(json!({"id": 91, "method": "item/fileChange/requestApproval", "params": {"threadId": "th1", "turnId": "tu1", "itemId": "f1", "startedAtMs": 8}})).await;
    let Event::Permission(asked) = next(&mut engine).await else { panic!() };
    assert_eq!(asked.title, "Edit a.txt");
    engine.commands.send(Command::Permission { id: asked.id, option: Some("accept".into()) }).unwrap();
    assert_eq!(recv(&mut fake).await, json!({"id": 91, "result": {"decision": "accept"}}));
    std::fs::write(dir.path().join("a.txt"), "one\nthree\n").unwrap();
    note(&mut fake, "item/completed", json!({"threadId": "th1", "turnId": "tu1", "completedAtMs": 9, "item": {"type": "fileChange", "id": "f1", "changes": change, "status": "completed"}})).await;
    let Event::ToolUpdate(done) = next(&mut engine).await else { panic!() };
    assert_eq!(done.status, Some(ToolStatus::Completed));
    assert_eq!(done.content, Some(vec![ToolContent::Diff { path: "a.txt".into(), old: Some("one\ntwo\n".into()), new: "one\nthree\n".into() }]));

    // Extra permissions, dismissed: nothing is granted.
    fake.send(json!({"id": 92, "method": "item/permissions/requestApproval", "params": {"threadId": "th1", "turnId": "tu1", "itemId": "p1",
        "startedAtMs": 10, "cwd": dir.path(), "permissions": {"network": {"enabled": true}}, "reason": "Fetch a crate."}}))
    .await;
    let mut asked = None;
    while asked.is_none() {
        match next(&mut engine).await {
            Event::Permission(p) => asked = Some(p),
            Event::ToolCall(c) => assert_eq!(c.id, "p1"),
            other => panic!("{other:?}"),
        }
    }
    let asked = asked.unwrap();
    assert_eq!(asked.detail.as_deref(), Some("Fetch a crate. (network access)"));
    engine.commands.send(Command::Permission { id: asked.id, option: None }).unwrap();
    assert_eq!(recv(&mut fake).await, json!({"id": 92, "result": {"permissions": {}}}));

    // Questions from request_user_input, one after another.
    fake.send(json!({"id": 93, "method": "item/tool/requestUserInput", "params": {"threadId": "th1", "turnId": "tu1", "itemId": "q", "isBlocking": true,
        "questions": [{"id": "db", "header": "Database", "question": "Which database?", "options": [{"label": "Postgres", "description": ""}, {"label": "SQLite", "description": ""}]},
                      {"id": "name", "header": "Name", "question": "Name the table?", "isOther": true}]}}))
    .await;
    let Event::Question(first) = next(&mut engine).await else { panic!() };
    assert_eq!((first.question.as_str(), first.choices.len()), ("Database: Which database?", 2));
    engine.commands.send(Command::Answer { id: first.id, answer: Some(vec!["SQLite".into()]) }).unwrap();
    let Event::Question(second) = next(&mut engine).await else { panic!() };
    assert!(second.allow_text);
    engine.commands.send(Command::Answer { id: second.id, answer: None }).unwrap();
    assert_eq!(recv(&mut fake).await, json!({"id": 93, "result": {"answers": {"db": {"answers": ["SQLite"]}, "name": {"answers": []}}}}));

    fake.send(json!({"id": 94, "method": "item/tool/call", "params": {"threadId": "th1", "turnId": "tu1", "callId": "x", "tool": "t", "arguments": {}}})).await;
    let unknown = recv(&mut fake).await;
    assert_eq!(unknown["error"]["code"], rpc::METHOD_NOT_FOUND);

    note(&mut fake, "turn/plan/updated", json!({"threadId": "th1", "turnId": "tu1", "plan": [{"step": "Run tests", "status": "completed"}, {"step": "Fix", "status": "inProgress"}]})).await;
    let Event::Plan { entries } = next(&mut engine).await else { panic!() };
    assert_eq!(entries[1].status, PlanStatus::InProgress);
    note(&mut fake, "thread/tokenUsage/updated", json!({"threadId": "th1", "turnId": "tu1", "tokenUsage": {
        "last": {"totalTokens": 900, "inputTokens": 800, "cachedInputTokens": 0, "outputTokens": 100, "reasoningOutputTokens": 0},
        "total": {"totalTokens": 2000, "inputTokens": 1700, "cachedInputTokens": 0, "outputTokens": 300, "reasoningOutputTokens": 0},
        "modelContextWindow": 32768}}))
    .await;
    let Event::Usage(usage) = next(&mut engine).await else { panic!() };
    assert_eq!((usage.context_tokens, usage.context_window, usage.output_tokens), (Some(900), Some(32768), Some(300)));
    note(&mut fake, "turn/completed", json!({"threadId": "th1", "turn": {"id": "tu1", "status": "completed", "items": []}})).await;
    assert_eq!(next(&mut engine).await, Event::TurnEnd { reason: StopReason::EndTurn, detail: None });

    engine.commands.send(Command::Shutdown).unwrap();
    assert!(matches!(next(&mut engine).await, Event::Exit { code: Some(0), .. }));
}

#[tokio::test]
async fn models_and_presets_carry_to_the_next_turn_and_cancel_interrupts() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, mut fake) = started(dir.path()).await;
    for _ in 0..3 {
        next(&mut engine).await;
    }
    engine.commands.send(Command::SetModel { model: "m2".into() }).unwrap();
    assert_eq!(next(&mut engine).await, Event::Model { model: "m2".into() });
    engine.commands.send(Command::SetMode { mode: "auto".into() }).unwrap();
    let Event::Modes { current, .. } = next(&mut engine).await else { panic!() };
    assert_eq!(current, "auto");

    engine.commands.send(Command::Prompt { text: "look around".into() }).unwrap();
    let (id, params) = request(&mut fake, "turn/start").await;
    assert_eq!(params["model"], "m2");
    assert_eq!(params["approvalPolicy"], "on-request");
    assert_eq!(params["sandboxPolicy"], json!({"type": "dangerFullAccess"}));
    // Cancel before the turn's id is known: the interrupt follows its answer.
    engine.commands.send(Command::Cancel).unwrap();
    reply(&mut fake, id, json!({"turn": {"id": "tu2", "status": "inProgress", "items": []}})).await;
    let (id, params) = request(&mut fake, "turn/interrupt").await;
    assert_eq!(params, json!({"threadId": "th1", "turnId": "tu2"}));
    reply(&mut fake, id, json!({})).await;
    note(&mut fake, "turn/completed", json!({"threadId": "th1", "turn": {"id": "tu2", "status": "interrupted", "items": []}})).await;
    assert_eq!(next(&mut engine).await, Event::TurnEnd { reason: StopReason::Cancelled, detail: None });

    // The next turn takes no overrides again.
    engine.commands.send(Command::Prompt { text: "again".into() }).unwrap();
    let (id, params) = request(&mut fake, "turn/start").await;
    assert!(params.get("model").is_none() && params.get("sandboxPolicy").is_none(), "{params}");
    reply(&mut fake, id, json!({"turn": {"id": "tu3", "status": "inProgress", "items": []}})).await;
    note(&mut fake, "error", json!({"threadId": "th1", "turnId": "tu3", "willRetry": true, "error": {"message": "Reconnecting 1/5"}})).await;
    assert!(matches!(next(&mut engine).await, Event::Notice { level: Level::Warn, .. }));
    note(&mut fake, "turn/completed", json!({"threadId": "th1", "turn": {"id": "tu3", "status": "failed",
        "error": {"message": "The context window is full.", "codexErrorInfo": "contextWindowExceeded"}, "items": []}}))
    .await;
    assert_eq!(next(&mut engine).await, Event::TurnEnd { reason: StopReason::MaxTokens, detail: Some("The context window is full.".into()) });

    drop(fake);
    let Event::Exit { code, message } = next(&mut engine).await else { panic!() };
    assert_eq!(code, None);
    assert!(message.contains("closed its connection"));
}

#[test]
fn unified_diffs_apply_or_refuse() {
    let old = "a\nb\nc\nd\n";
    assert_eq!(apply_unified(old, "@@ -2,2 +2,3 @@\n b\n-c\n+C\n+c2\n").as_deref(), Some("a\nb\nC\nc2\nd\n"));
    assert_eq!(apply_unified(old, "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+A\n@@ -4 +4 @@\n-d\n+D\n").as_deref(), Some("A\nb\nc\nD\n"));
    assert_eq!(apply_unified(old, "@@ -2,1 +2,1 @@\n-x\n+y\n"), None, "context that does not match");
    assert_eq!(apply_unified(old, "no hunks"), None);
    assert_eq!(apply_unified("a\nb", "@@ -2 +2 @@\n-b\n\\ No newline at end of file\n+B\n\\ No newline at end of file\n").as_deref(), Some("a\nB"));
    assert_eq!(added_text("@@ -0,0 +1,2 @@\n+x\n+y\n"), "x\ny\n");
    assert_eq!(added_text("plain\n"), "plain\n");
    assert_eq!(Preset::of(&json!("never"), &json!({"type": "dangerFullAccess"})), Some(Preset::FullAccess));
    assert_eq!(short_title("cargo build\ncargo test"), "cargo build …");
}
