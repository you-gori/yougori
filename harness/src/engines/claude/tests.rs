//! The Claude Code adapter against a fake engine over pipes, shaped like the probe of 2.1.316.
use super::*;
use crate::engines::acp::tests::{pipes, spec as base_spec, Fake};
use serde_json::json;

fn spec(dir: &Path) -> EngineSpec {
    let mut spec = base_spec(dir);
    spec.harness = "claude".into();
    spec.name = "Claude Code".into();
    spec.protocol = crate::spec::Protocol::ClaudeStreamJson;
    spec.argv = vec!["claude".into(), "-p".into()];
    spec.mcp.clear();
    spec
}

async fn next(engine: &mut EngineHandle) -> Event {
    tokio::time::timeout(Duration::from_secs(10), engine.events.recv()).await.expect("no event in time").expect("engine ended")
}

async fn control(fake: &mut Fake, subtype: &str) -> (String, Value) {
    let message = fake.recv().await;
    assert_eq!(message["type"], "control_request", "{message}");
    assert_eq!(message["request"]["subtype"], json!(subtype), "{message}");
    (message["request_id"].as_str().unwrap().to_owned(), message["request"].clone())
}

async fn ok(fake: &mut Fake, request: &str, response: Value) {
    fake.send(json!({"type": "control_response", "response": {"subtype": "success", "request_id": request, "response": response}})).await;
}

async fn started(dir: &Path) -> (EngineHandle, Fake) {
    let (transport, mut fake) = pipes();
    let client = tokio::spawn(connect(spec(dir), transport));
    let (id, request) = control(&mut fake, "initialize").await;
    assert_eq!(request["hooks"], Value::Null);
    ok(&mut fake, &id, json!({"commands": [{"name": "compact", "description": "Compact", "argumentHint": "<focus>"}],
        "claude_code_version": "2.1.316", "current_permission_mode": "default"}))
    .await;
    (client.await.unwrap().unwrap(), fake)
}

fn sent_user(message: &Value) -> &str {
    assert_eq!(message["type"], "user", "{message}");
    message["message"]["content"].as_str().unwrap()
}

#[tokio::test]
async fn a_turn_streams_text_and_tools_with_permissions_and_questions() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, mut fake) = started(dir.path()).await;
    let Event::Ready(ready) = next(&mut engine).await else { panic!() };
    assert_eq!((ready.info.as_deref(), ready.model_switch), (Some("Claude Code 2.1.316 · stream-json"), ModelSwitch::Live));
    let Event::Modes { current, available } = next(&mut engine).await else { panic!() };
    assert_eq!((current.as_str(), available.len()), ("default", 4));
    let Event::Commands { commands } = next(&mut engine).await else { panic!() };
    assert_eq!(commands[0].hint.as_deref(), Some("<focus>"));

    engine.commands.send(Command::Prompt { text: "list files".into() }).unwrap();
    assert_eq!(sent_user(&fake.recv().await), "list files");
    fake.send(json!({"type": "system", "subtype": "init", "session_id": "cs1", "model": "m1", "permissionMode": "default"})).await;
    fake.send(json!({"type": "stream_event", "event": {"type": "message_start", "message": {"id": "msg1", "usage": {"input_tokens": 100}}}, "parent_tool_use_id": null})).await;
    fake.send(json!({"type": "stream_event", "event": {"type": "content_block_delta", "index": 0, "delta": {"type": "thinking_delta", "thinking": "Look."}}})).await;
    fake.send(json!({"type": "stream_event", "event": {"type": "content_block_delta", "index": 1, "delta": {"type": "text_delta", "text": "Hel"}}})).await;
    fake.send(json!({"type": "stream_event", "event": {"type": "content_block_delta", "index": 1, "delta": {"type": "text_delta", "text": "lo"}}})).await;
    fake.send(json!({"type": "assistant", "message": {"id": "msg1", "content": [{"type": "text", "text": "Hello"}],
        "usage": {"input_tokens": 100, "output_tokens": 0, "cache_read_input_tokens": 20, "cache_creation_input_tokens": 0}}, "parent_tool_use_id": null}))
    .await;
    assert_eq!(next(&mut engine).await, Event::Reasoning { message: "msg1-thinking".into(), text: "Look.".into(), parent: None });
    assert_eq!(next(&mut engine).await, Event::Message { message: "msg1".into(), text: "Hel".into(), parent: None });
    assert_eq!(next(&mut engine).await, Event::Message { message: "msg1".into(), text: "lo".into(), parent: None });
    let Event::Usage(usage) = next(&mut engine).await else { panic!("the full message is not shown again") };
    assert_eq!(usage.context_tokens, Some(120));

    // A command, allowed for good.
    fake.send(json!({"type": "assistant", "message": {"id": "msg2", "content": [{"type": "tool_use", "id": "t1", "name": "Bash",
        "input": {"command": "ls", "description": "List files"}}]}, "parent_tool_use_id": null}))
    .await;
    let Event::ToolCall(call) = next(&mut engine).await else { panic!() };
    assert_eq!((call.id.as_str(), call.title.as_str(), call.kind), ("t1", "ls", ToolKind::Execute));
    let suggestions = json!([{"type": "addRules", "rules": [{"toolName": "Bash", "ruleContent": "ls"}], "behavior": "allow", "destination": "localSettings"}]);
    fake.send(json!({"type": "control_request", "request_id": "p1", "request": {"subtype": "can_use_tool", "tool_name": "Bash",
        "input": {"command": "ls", "description": "List files"}, "description": "List files", "permission_suggestions": suggestions, "tool_use_id": "t1"}}))
    .await;
    let Event::Permission(asked) = next(&mut engine).await else { panic!() };
    assert_eq!((asked.title.as_str(), asked.detail.as_deref(), asked.tool_call.as_deref()), ("ls", Some("List files"), Some("t1")));
    assert_eq!(asked.options.iter().map(|o| o.id.as_str()).collect::<Vec<_>>(), vec!["allow", "always", "deny"]);
    engine.commands.send(Command::Permission { id: asked.id, option: Some("always".into()) }).unwrap();
    let answer = fake.recv().await;
    assert_eq!(answer["response"]["request_id"], "p1");
    assert_eq!(answer["response"]["response"], json!({"behavior": "allow", "updatedInput": {"command": "ls", "description": "List files"}, "updatedPermissions": suggestions}));
    fake.send(json!({"type": "user", "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "a.txt", "is_error": false}]},
        "tool_use_result": {"stdout": "a.txt", "stderr": "", "interrupted": false}}))
    .await;
    let Event::ToolUpdate(done) = next(&mut engine).await else { panic!() };
    assert_eq!(done.status, Some(ToolStatus::Completed));
    assert_eq!(done.content, Some(vec![ToolContent::Terminal { command: Some("ls".into()), output: "a.txt".into(), exit_code: None }]));

    // An edit, its permission dismissed: denied and the turn interrupted.
    fake.send(json!({"type": "assistant", "message": {"id": "msg3", "content": [{"type": "tool_use", "id": "t2", "name": "Edit",
        "input": {"file_path": "/w/a.rs", "old_string": "a", "new_string": "b"}}]}}))
    .await;
    let Event::ToolCall(call) = next(&mut engine).await else { panic!() };
    assert_eq!(call.content, vec![ToolContent::Diff { path: "/w/a.rs".into(), old: Some("a".into()), new: "b".into() }]);
    fake.send(json!({"type": "control_request", "request_id": "p2", "request": {"subtype": "can_use_tool", "tool_name": "Edit",
        "input": {"file_path": "/w/a.rs", "old_string": "a", "new_string": "b"}, "tool_use_id": "t2"}}))
    .await;
    let Event::Permission(asked) = next(&mut engine).await else { panic!() };
    assert_eq!(asked.title, "Edit /w/a.rs");
    assert_eq!(asked.options.len(), 2, "no 'always' without suggestions");
    engine.commands.send(Command::Permission { id: asked.id, option: None }).unwrap();
    let answer = fake.recv().await;
    assert_eq!(answer["response"]["response"]["behavior"], "deny");
    assert_eq!(answer["response"]["response"]["interrupt"], true);
    fake.send(json!({"type": "user", "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t2", "content": "Stopped.", "is_error": true}]}})).await;
    let Event::ToolUpdate(done) = next(&mut engine).await else { panic!() };
    assert_eq!(done.status, Some(ToolStatus::Failed));

    // AskUserQuestion: questions one after another, answered together; the call itself is not shown.
    let questions = json!([{"question": "Which colour?", "header": "Colour", "multiSelect": false, "options": [{"label": "Blue", "description": ""}, {"label": "Red", "description": ""}]},
                           {"question": "Which parts?", "header": "Parts", "multiSelect": true, "options": [{"label": "a", "description": ""}, {"label": "b", "description": ""}]}]);
    fake.send(json!({"type": "assistant", "message": {"id": "msg4", "content": [{"type": "tool_use", "id": "t3", "name": "AskUserQuestion", "input": {"questions": questions}}]}})).await;
    fake.send(json!({"type": "control_request", "request_id": "q1", "request": {"subtype": "can_use_tool", "tool_name": "AskUserQuestion",
        "input": {"questions": questions}, "tool_use_id": "t3"}}))
    .await;
    let Event::Question(first) = next(&mut engine).await else { panic!() };
    assert_eq!((first.question.as_str(), first.choices.len(), first.allow_text), ("Colour: Which colour?", 2, true));
    engine.commands.send(Command::Answer { id: first.id, answer: Some(vec!["Blue".into()]) }).unwrap();
    let Event::Question(second) = next(&mut engine).await else { panic!() };
    assert!(second.multiple);
    engine.commands.send(Command::Answer { id: second.id, answer: Some(vec!["a".into(), "b".into()]) }).unwrap();
    let answer = fake.recv().await;
    assert_eq!(answer["response"]["response"]["updatedInput"]["answers"], json!({"Which colour?": "Blue", "Which parts?": "a, b"}));
    fake.send(json!({"type": "user", "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t3", "content": "answered"}]}})).await;

    // TodoWrite shows as the plan.
    fake.send(json!({"type": "assistant", "message": {"id": "msg5", "content": [{"type": "tool_use", "id": "t4", "name": "TodoWrite",
        "input": {"todos": [{"content": "Fix", "status": "in_progress", "activeForm": "Fixing"}]}}]}}))
    .await;
    let Event::Plan { entries } = next(&mut engine).await else { panic!() };
    assert_eq!(entries[0].status, PlanStatus::InProgress);
    fake.send(json!({"type": "control_request", "request_id": "h1", "request": {"subtype": "hook_callback", "callback_id": "x"}})).await;
    let refused = fake.recv().await;
    assert_eq!(refused["response"]["subtype"], "error");
    fake.send(json!({"type": "user", "message": {"role": "user", "content": "<local-command-stdout>x</local-command-stdout>"}, "isReplay": true})).await;
    fake.send(json!({"type": "result", "subtype": "success", "is_error": false, "stop_reason": "end_turn", "result": "Done",
        "usage": {"input_tokens": 300, "cache_read_input_tokens": 50, "output_tokens": 40}}))
    .await;
    let Event::Usage(usage) = next(&mut engine).await else { panic!() };
    assert_eq!((usage.input_tokens, usage.output_tokens), (Some(350), Some(40)));
    assert_eq!(next(&mut engine).await, Event::TurnEnd { reason: StopReason::EndTurn, detail: None });

    engine.commands.send(Command::Shutdown).unwrap();
    assert!(matches!(next(&mut engine).await, Event::Exit { code: Some(0), .. }));
}

#[tokio::test]
async fn model_mode_and_cancel_go_through_control_requests() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, mut fake) = started(dir.path()).await;
    for _ in 0..3 {
        next(&mut engine).await;
    }
    engine.commands.send(Command::SetModel { model: "m2".into() }).unwrap();
    let (id, request) = control(&mut fake, "set_model").await;
    assert_eq!(request["model"], "m2");
    ok(&mut fake, &id, json!({"model": "m2"})).await;
    assert_eq!(next(&mut engine).await, Event::Model { model: "m2".into() });
    engine.commands.send(Command::SetMode { mode: "plan".into() }).unwrap();
    let (id, request) = control(&mut fake, "set_permission_mode").await;
    assert_eq!(request["mode"], "plan");
    ok(&mut fake, &id, json!({"mode": "plan"})).await;
    let Event::Modes { current, .. } = next(&mut engine).await else { panic!() };
    assert_eq!(current, "plan");

    engine.commands.send(Command::Prompt { text: "go".into() }).unwrap();
    sent_user(&fake.recv().await);
    fake.send(json!({"type": "control_request", "request_id": "p9", "request": {"subtype": "can_use_tool", "tool_name": "Bash", "input": {"command": "make"}, "tool_use_id": "t9"}})).await;
    let mut asked = false;
    while !asked {
        asked = matches!(next(&mut engine).await, Event::Permission(_));
    }
    engine.commands.send(Command::Cancel).unwrap();
    let (id, _) = control(&mut fake, "interrupt").await;
    let answer = fake.recv().await;
    assert_eq!((answer["response"]["request_id"].clone(), answer["response"]["response"]["interrupt"].clone()), (json!("p9"), json!(true)));
    ok(&mut fake, &id, json!({})).await;
    fake.send(json!({"type": "result", "subtype": "error_during_execution", "is_error": true, "errors": ["Interrupted"]})).await;
    assert_eq!(next(&mut engine).await, Event::TurnEnd { reason: StopReason::Cancelled, detail: None });

    engine.commands.send(Command::Prompt { text: "again".into() }).unwrap();
    sent_user(&fake.recv().await);
    fake.send(json!({"type": "result", "subtype": "error_during_execution", "is_error": true, "errors": ["API Error: 500 upstream"]})).await;
    assert_eq!(next(&mut engine).await, Event::TurnEnd { reason: StopReason::Error, detail: Some("API Error: 500 upstream".into()) });

    drop(fake);
    let Event::Exit { code, message } = next(&mut engine).await else { panic!() };
    assert_eq!(code, None);
    assert!(message.contains("closed its connection"));
}
