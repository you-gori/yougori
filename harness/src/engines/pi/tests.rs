//! The Pi adapter against a fake `pi --mode rpc` over pipes, shaped like the probe of 0.73.1.
use super::*;
use crate::engines::acp::tests::{pipes, spec as base_spec, Fake};

fn spec(dir: &Path) -> EngineSpec {
    let mut spec = base_spec(dir);
    spec.harness = "pi".into();
    spec.name = "Pi".into();
    spec.protocol = crate::spec::Protocol::PiRpc;
    spec.argv = vec!["pi".into(), "--mode".into(), "rpc".into()];
    spec.mcp.clear();
    spec
}

async fn next(engine: &mut EngineHandle) -> Event {
    tokio::time::timeout(Duration::from_secs(10), engine.events.recv()).await.expect("no event in time").expect("engine ended")
}

async fn command(fake: &mut Fake, kind: &str) -> Value {
    let message = fake.recv().await;
    assert_eq!(message["type"], json!(kind), "{message}");
    message
}

async fn respond(fake: &mut Fake, message: &Value, data: Value) {
    fake.send(json!({"id": message["id"], "type": "response", "command": message["type"], "success": true, "data": data})).await;
}

async fn started(dir: &Path) -> (EngineHandle, Fake) {
    let (transport, mut fake) = pipes();
    let client = tokio::spawn(connect(spec(dir), transport));
    let state = command(&mut fake, "get_state").await;
    respond(&mut fake, &state, json!({"model": {"id": "m1", "provider": "solver", "contextWindow": 32768}, "sessionId": "ps1", "isStreaming": false})).await;
    let models = command(&mut fake, "get_available_models").await;
    respond(&mut fake, &models, json!({"models": [{"id": "gpt-4", "provider": "openai"}, {"id": "m1", "provider": "solver"}, {"id": "m2", "provider": "solver"}]})).await;
    let commands = command(&mut fake, "get_commands").await;
    respond(&mut fake, &commands, json!({"commands": [{"name": "fix-tests", "description": "Fix failing tests", "source": "prompt"}]})).await;
    (client.await.unwrap().unwrap(), fake)
}

#[tokio::test]
async fn a_turn_streams_text_reasoning_and_tools_and_dialogs_become_questions() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, mut fake) = started(dir.path()).await;
    let Event::Ready(ready) = next(&mut engine).await else { panic!() };
    assert_eq!((ready.session.as_deref(), ready.model_switch), (Some("ps1"), ModelSwitch::Live));
    let Event::Commands { commands } = next(&mut engine).await else { panic!() };
    assert_eq!(commands[0].name, "fix-tests");

    engine.commands.send(Command::Prompt { text: "hi".into() }).unwrap();
    let prompt = command(&mut fake, "prompt").await;
    assert_eq!(prompt["message"], "hi");
    fake.send(json!({"id": prompt["id"], "type": "response", "command": "prompt", "success": true})).await;
    fake.send(json!({"type": "agent_start"})).await;
    fake.send(json!({"type": "message_start", "message": {"role": "user", "content": [{"type": "text", "text": "hi"}]}})).await;
    fake.send(json!({"type": "message_start", "message": {"role": "assistant", "content": []}})).await;
    fake.send(json!({"type": "message_update", "assistantMessageEvent": {"type": "thinking_delta", "contentIndex": 0, "delta": "Hmm."}})).await;
    fake.send(json!({"type": "message_update", "assistantMessageEvent": {"type": "text_delta", "contentIndex": 1, "delta": "Hello"}})).await;
    fake.send(json!({"type": "message_end", "message": {"role": "assistant", "stopReason": "toolUse", "usage": {"input": 120, "output": 12, "totalTokens": 132}}})).await;
    assert_eq!(next(&mut engine).await, Event::Reasoning { message: "pi-1-thinking".into(), text: "Hmm.".into(), parent: None });
    assert_eq!(next(&mut engine).await, Event::Message { message: "pi-1".into(), text: "Hello".into(), parent: None });
    let Event::Usage(usage) = next(&mut engine).await else { panic!() };
    assert_eq!((usage.context_tokens, usage.context_window), (Some(132), Some(32768)));

    fake.send(json!({"type": "tool_execution_start", "toolCallId": "b1", "toolName": "bash", "args": {"command": "ls"}})).await;
    fake.send(json!({"type": "tool_execution_update", "toolCallId": "b1", "toolName": "bash", "args": {"command": "ls"},
        "partialResult": {"content": [{"type": "text", "text": "a.txt\n"}]}}))
    .await;
    fake.send(json!({"type": "tool_execution_end", "toolCallId": "b1", "toolName": "bash", "result": {"content": [{"type": "text", "text": "a.txt\nb.txt\n"}]}, "isError": false})).await;
    let Event::ToolCall(call) = next(&mut engine).await else { panic!() };
    assert_eq!((call.title.as_str(), call.kind, call.status), ("ls", ToolKind::Execute, ToolStatus::InProgress));
    let Event::ToolUpdate(partial) = next(&mut engine).await else { panic!() };
    assert_eq!(partial.content, Some(vec![ToolContent::Terminal { command: Some("ls".into()), output: "a.txt\n".into(), exit_code: None }]));
    let Event::ToolUpdate(done) = next(&mut engine).await else { panic!() };
    assert_eq!(done.status, Some(ToolStatus::Completed));

    fake.send(json!({"type": "tool_execution_start", "toolCallId": "e1", "toolName": "edit", "args": {"path": "src/a.rs", "edits": [{"oldText": "a", "newText": "b"}]}})).await;
    let Event::ToolCall(call) = next(&mut engine).await else { panic!() };
    assert_eq!(call.content, vec![ToolContent::Diff { path: "src/a.rs".into(), old: Some("a".into()), new: "b".into() }]);
    fake.send(json!({"type": "tool_execution_end", "toolCallId": "e1", "toolName": "edit", "result": {"content": [{"type": "text", "text": "Edited"}], "details": {"diff": "-a\n+b"}}, "isError": false})).await;
    let Event::ToolUpdate(done) = next(&mut engine).await else { panic!() };
    assert_eq!(done.content, Some(vec![ToolContent::Diff { path: "src/a.rs".into(), old: Some("a".into()), new: "b".into() }]));
    assert_eq!(done.output, Some(json!({"diff": "-a\n+b"})));

    // An extension's dialogs.
    fake.send(json!({"type": "extension_ui_request", "id": "d1", "method": "select", "title": "Which target?", "options": ["staging", "prod"]})).await;
    let Event::Question(question) = next(&mut engine).await else { panic!() };
    assert_eq!(question.choices, vec!["staging".to_owned(), "prod".to_owned()]);
    engine.commands.send(Command::Answer { id: question.id, answer: Some(vec!["staging".into()]) }).unwrap();
    assert_eq!(fake.recv().await, json!({"type": "extension_ui_response", "id": "d1", "value": "staging"}));
    fake.send(json!({"type": "extension_ui_request", "id": "d2", "method": "confirm", "title": "Clear session?", "message": "All goes."})).await;
    let Event::Question(question) = next(&mut engine).await else { panic!() };
    assert_eq!(question.question, "Clear session? All goes.");
    engine.commands.send(Command::Answer { id: question.id, answer: Some(vec!["No".into()]) }).unwrap();
    assert_eq!(fake.recv().await, json!({"type": "extension_ui_response", "id": "d2", "confirmed": false}));
    fake.send(json!({"type": "extension_ui_request", "id": "d3", "method": "notify", "message": "Saved", "notifyType": "warning"})).await;
    assert_eq!(next(&mut engine).await, Event::Notice { level: Level::Warn, text: "Saved".into() });

    fake.send(json!({"type": "message_start", "message": {"role": "assistant", "content": []}})).await;
    fake.send(json!({"type": "message_end", "message": {"role": "assistant", "stopReason": "stop", "usage": {"totalTokens": 0}}})).await;
    fake.send(json!({"type": "agent_end", "messages": []})).await;
    assert_eq!(next(&mut engine).await, Event::TurnEnd { reason: StopReason::EndTurn, detail: None });
    let stats = command(&mut fake, "get_session_stats").await;
    respond(&mut fake, &stats, json!({"tokens": {"input": 720, "output": 72}, "contextUsage": {"tokens": 150, "contextWindow": 32768, "percent": 0.4}})).await;
    let Event::Usage(usage) = next(&mut engine).await else { panic!() };
    assert_eq!((usage.context_tokens, usage.input_tokens), (Some(150), Some(720)));

    engine.commands.send(Command::Shutdown).unwrap();
    assert!(matches!(next(&mut engine).await, Event::Exit { code: Some(0), .. }));
}

#[tokio::test]
async fn models_switch_in_place_abort_cancels_and_a_refused_prompt_fails() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, mut fake) = started(dir.path()).await;
    next(&mut engine).await;
    next(&mut engine).await;
    engine.commands.send(Command::SetModel { model: "m2".into() }).unwrap();
    let set = command(&mut fake, "set_model").await;
    assert_eq!((set["provider"].clone(), set["modelId"].clone()), (json!("solver"), json!("m2")));
    respond(&mut fake, &set, json!({"id": "m2", "provider": "solver"})).await;
    assert_eq!(next(&mut engine).await, Event::Model { model: "m2".into() });
    engine.commands.send(Command::SetMode { mode: "plan".into() }).unwrap();
    assert!(matches!(next(&mut engine).await, Event::Notice { level: Level::Warn, .. }));

    engine.commands.send(Command::Prompt { text: "slow".into() }).unwrap();
    let prompt = command(&mut fake, "prompt").await;
    fake.send(json!({"id": prompt["id"], "type": "response", "command": "prompt", "success": true})).await;
    fake.send(json!({"type": "extension_ui_request", "id": "d9", "method": "input", "title": "Name?"})).await;
    assert!(matches!(next(&mut engine).await, Event::Question(_)));
    engine.commands.send(Command::Cancel).unwrap();
    assert_eq!(command(&mut fake, "abort").await, json!({"type": "abort"}));
    assert_eq!(fake.recv().await, json!({"type": "extension_ui_response", "id": "d9", "cancelled": true}));
    fake.send(json!({"type": "message_start", "message": {"role": "assistant"}})).await;
    fake.send(json!({"type": "message_end", "message": {"role": "assistant", "stopReason": "aborted", "errorMessage": "Request was aborted"}})).await;
    fake.send(json!({"type": "agent_end", "messages": []})).await;
    assert_eq!(next(&mut engine).await, Event::TurnEnd { reason: StopReason::Cancelled, detail: None });
    let stats = command(&mut fake, "get_session_stats").await;
    fake.send(json!({"id": stats["id"], "type": "response", "command": "get_session_stats", "success": false, "error": "busy"})).await;

    engine.commands.send(Command::Prompt { text: "again".into() }).unwrap();
    let prompt = command(&mut fake, "prompt").await;
    fake.send(json!({"id": prompt["id"], "type": "response", "command": "prompt", "success": false, "error": "No model selected"})).await;
    assert_eq!(next(&mut engine).await, Event::TurnEnd { reason: StopReason::Error, detail: Some("No model selected".into()) });

    drop(fake);
    let mut exit = None;
    while exit.is_none() {
        if let Event::Exit { code, message } = next(&mut engine).await {
            exit = Some((code, message));
        }
    }
    assert!(exit.unwrap().1.contains("closed its connection"));
}
