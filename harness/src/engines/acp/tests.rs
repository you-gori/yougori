//! The ACP client against fake agents: one in this process over pipes, and this test binary run
//! again as a child process for crashes.
use super::*;
use crate::spec::{McpServer, Protocol};
use std::collections::BTreeMap;
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, Lines};

pub(crate) fn spec(dir: &std::path::Path) -> EngineSpec {
    EngineSpec {
        harness: "opencode".into(),
        name: "OpenCode".into(),
        category: "coding".into(),
        protocol: Protocol::Acp,
        argv: vec!["opencode".into(), "acp".into()],
        env: BTreeMap::from([("PATH".to_owned(), std::env::var("PATH").unwrap_or_default())]),
        secret_env: BTreeMap::new(),
        cwd: dir.to_path_buf(),
        model: "m1".into(),
        models: vec!["m1".into(), "m2".into()],
        model_switch: ModelSwitch::Live,
        respec: Vec::new(),
        profile: None,
        mcp: vec![McpServer { name: "tools".into(), command: vec!["tool-server".into(), "--stdio".into()], env: BTreeMap::new(), url: None }],
        services: Vec::new(),
        context_window: 32768,
        max_output: 4096,
        base_url: crate::spec::RELAY.into(),
        api_key: crate::spec::RELAY_KEY.into(),
        answers: Value::Null,
        reach: Default::default(),
        state_dir: dir.join("state"),
    }
}

/// The agent's side of the pipes.
pub(crate) struct Fake {
    lines: Lines<BufReader<DuplexStream>>,
    out: DuplexStream,
}

impl Fake {
    pub async fn recv(&mut self) -> Value {
        let line = tokio::time::timeout(Duration::from_secs(10), self.lines.next_line())
            .await
            .expect("the client sent nothing")
            .unwrap()
            .expect("the client closed");
        serde_json::from_str(&line).unwrap()
    }

    pub async fn send(&mut self, value: Value) {
        let mut line = serde_json::to_vec(&value).unwrap();
        line.push(b'\n');
        self.out.write_all(&line).await.unwrap();
    }

    /// The next message, which must be a request for `method`.
    pub async fn request(&mut self, method: &str) -> (Value, Value) {
        let message = self.recv().await;
        assert_eq!(message["method"], json!(method), "{message}");
        (message["id"].clone(), message["params"].clone())
    }

    pub async fn respond(&mut self, id: Value, result: Value) {
        self.send(json!({"jsonrpc": "2.0", "id": id, "result": result})).await;
    }

    pub async fn update(&mut self, update: Value) {
        self.send(json!({"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": "s1", "update": update}})).await;
    }

    /// Sends a request to the client and returns the answer.
    pub async fn ask(&mut self, id: i64, method: &str, params: Value) -> Value {
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})).await;
        let message = self.recv().await;
        assert!(
            message["id"] == json!(id) && message.get("method").is_none(),
            "expected the answer to {method}, got {message}"
        );
        message
    }
}

pub(crate) fn pipes() -> (Transport, Fake) {
    let (client_out, agent_in) = tokio::io::duplex(1 << 20);
    let (agent_out, client_in) = tokio::io::duplex(1 << 20);
    let noise = Tail::default();
    let transport = Transport {
        values: process::json_lines(client_in, noise.clone()),
        writer: LineWriter::new(client_out),
        guard: None,
        noise,
    };
    (transport, Fake { lines: BufReader::new(agent_in).lines(), out: agent_out })
}

async fn next(engine: &mut EngineHandle) -> Event {
    tokio::time::timeout(Duration::from_secs(10), engine.events.recv()).await.expect("no event in time").expect("engine ended")
}

/// The next event that is not a notice, nor a terminal's output redrawn in its call.
async fn next_real(engine: &mut EngineHandle) -> Event {
    loop {
        match next(engine).await {
            Event::Notice { .. } => continue,
            Event::ToolUpdate(ToolUpdate { status: None, title: None, locations: None, output: None, content: Some(content), .. })
                if content.iter().all(|c| matches!(c, ToolContent::Terminal { .. })) =>
            {
                continue
            }
            event => return event,
        }
    }
}

const SESSION: &str = r#"{"sessionId":"s1",
    "modes":{"currentModeId":"build","availableModes":[{"id":"build","name":"Build"},{"id":"plan","name":"Plan","description":"Think first"}]},
    "configOptions":[{"id":"model","name":"Model","category":"model","type":"select","currentValue":"solver/m1",
        "options":[{"value":"solver/m1","name":"m1"},{"value":"solver/m2","name":"m2"}]}]}"#;

/// Starts the client against the fake agent through `initialize` and `session/new`.
async fn started(dir: &std::path::Path) -> (EngineHandle, Fake) {
    started_limited(dir, CANCEL_LIMIT).await
}

/// [`started`] with the time a cancelled turn waits for the agent's answer.
async fn started_limited(dir: &std::path::Path, cancel_limit: Duration) -> (EngineHandle, Fake) {
    let (transport, mut fake) = pipes();
    let spec = spec(dir);
    let client = tokio::spawn(connect_limited(spec, transport, cancel_limit));
    let (id, params) = fake.request("initialize").await;
    assert_eq!(params["protocolVersion"], 1);
    assert_eq!(params["clientCapabilities"]["terminal"], true);
    assert_eq!(params["clientCapabilities"]["fs"]["writeTextFile"], true);
    fake.respond(id, json!({"protocolVersion": 1, "agentInfo": {"name": "fake", "title": "Fake Agent", "version": "9.1"}, "authMethods": []}))
        .await;
    let (id, params) = fake.request("session/new").await;
    assert_eq!(params["mcpServers"][0], json!({"name": "tools", "command": "tool-server", "args": ["--stdio"], "env": []}));
    assert!(params["cwd"].as_str().unwrap().len() > 1);
    fake.respond(id, serde_json::from_str(SESSION).unwrap()).await;
    let engine = client.await.unwrap().unwrap();
    (engine, fake)
}

#[tokio::test]
async fn a_turn_streams_text_reasoning_tools_terminals_and_permissions() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, mut fake) = started(dir.path()).await;
    let Event::Ready(ready) = next(&mut engine).await else { panic!("Ready first") };
    assert_eq!(ready.model_switch, ModelSwitch::Live);
    assert_eq!(ready.session.as_deref(), Some("s1"));
    assert_eq!(ready.info.as_deref(), Some("Fake Agent 9.1 · ACP"));
    let Event::Modes { current, available } = next(&mut engine).await else { panic!("modes") };
    assert_eq!((current.as_str(), available.len()), ("build", 2));

    engine.commands.send(Command::Prompt { text: "fix it".into() }).unwrap();
    let (prompt_id, params) = fake.request("session/prompt").await;
    assert_eq!(params["prompt"][0]["text"], "fix it");
    fake.update(json!({"sessionUpdate": "agent_thought_chunk", "content": {"type": "text", "text": "Let me look."}})).await;
    fake.update(json!({"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": "Hel"}})).await;
    fake.update(json!({"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": "lo"}})).await;
    let Event::Reasoning { message: thought, text, .. } = next(&mut engine).await else { panic!() };
    assert_eq!(text, "Let me look.");
    let Event::Message { message: first, text, .. } = next(&mut engine).await else { panic!() };
    assert_eq!(text, "Hel");
    let Event::Message { message: second, .. } = next(&mut engine).await else { panic!() };
    assert_eq!(first, second, "chunks of one message share an id");
    assert_ne!(first, thought);

    // An edit with a diff.
    fake.update(json!({"sessionUpdate": "tool_call", "toolCallId": "edit-1", "title": "Edit a.txt", "kind": "edit", "status": "pending",
        "locations": [{"path": "/w/a.txt", "line": 3}], "rawInput": {"filePath": "/w/a.txt"},
        "content": [{"type": "diff", "path": "/w/a.txt", "oldText": "old\n", "newText": "new\n"}]}))
    .await;
    let Event::ToolCall(call) = next(&mut engine).await else { panic!() };
    assert_eq!((call.id.as_str(), call.kind, call.status), ("edit-1", ToolKind::Edit, ToolStatus::Pending));
    assert_eq!(call.content, vec![ToolContent::Diff { path: "/w/a.txt".into(), old: Some("old\n".into()), new: "new\n".into() }]);
    assert_eq!(call.locations[0].line, Some(3));

    // The agent asks first; the person allows once.
    fake.send(json!({"jsonrpc": "2.0", "id": 50, "method": "session/request_permission", "params": {"sessionId": "s1",
        "toolCall": {"toolCallId": "edit-1"},
        "options": [{"optionId": "once", "name": "Allow", "kind": "allow_once"}, {"optionId": "always", "name": "Always", "kind": "allow_always"},
                    {"optionId": "reject", "name": "Reject", "kind": "reject_once"}]}}))
    .await;
    let Event::Permission(asked) = next(&mut engine).await else { panic!() };
    assert_eq!(asked.tool_call.as_deref(), Some("edit-1"));
    assert_eq!(asked.title, "Edit a.txt");
    assert_eq!(asked.options.len(), 3);
    assert_eq!(asked.options[1].kind, PermissionKind::AllowAlways);
    engine.commands.send(Command::Permission { id: asked.id.clone(), option: Some("once".into()) }).unwrap();
    let answer = fake.recv().await;
    assert_eq!(answer["id"], 50);
    assert_eq!(answer["result"]["outcome"], json!({"outcome": "selected", "optionId": "once"}));

    // A second request is dismissed.
    fake.send(json!({"jsonrpc": "2.0", "id": 51, "method": "session/request_permission", "params": {"sessionId": "s1",
        "toolCall": {"toolCallId": "edit-1", "title": "Edit b.txt"},
        "options": [{"optionId": "once", "name": "Allow", "kind": "allow_once"}]}}))
    .await;
    let mut asked = None;
    while asked.is_none() {
        match next(&mut engine).await {
            Event::Permission(p) => asked = Some(p),
            Event::ToolUpdate(u) => assert_eq!(u.title.as_deref(), Some("Edit b.txt")),
            other => panic!("{other:?}"),
        }
    }
    engine.commands.send(Command::Permission { id: asked.unwrap().id, option: None }).unwrap();
    let answer = fake.recv().await;
    assert_eq!(answer["result"]["outcome"], json!({"outcome": "cancelled"}));

    // The file system through the client.
    let file = dir.path().join("sub/notes.txt");
    let written = fake.ask(52, "fs/write_text_file", json!({"sessionId": "s1", "path": file, "content": "one\ntwo\nthree\n"})).await;
    assert_eq!(written["result"], json!({}));
    let read = fake.ask(53, "fs/read_text_file", json!({"sessionId": "s1", "path": file, "line": 2, "limit": 1})).await;
    assert_eq!(read["result"]["content"], "two\n");
    let relative = fake.ask(54, "fs/read_text_file", json!({"sessionId": "s1", "path": "notes.txt"})).await;
    assert_eq!(relative["error"]["code"], rpc::INVALID_PARAMS);

    // A command in a client terminal, its output streamed into the call that shows it.
    let script = if cfg!(windows) { "echo terminal says hi & exit 4" } else { "echo terminal says hi; exit 4" };
    let created = fake.ask(55, "terminal/create", json!({"sessionId": "s1", "command": script, "outputByteLimit": 4096})).await;
    let terminal = created["result"]["terminalId"].as_str().unwrap().to_owned();
    fake.update(json!({"sessionUpdate": "tool_call", "toolCallId": "run-1", "title": "Run the script", "kind": "execute", "status": "in_progress",
        "content": [{"type": "terminal", "terminalId": terminal}]}))
    .await;
    let exited = fake.ask(56, "terminal/wait_for_exit", json!({"sessionId": "s1", "terminalId": terminal})).await;
    assert_eq!(exited["result"]["exitCode"], 4);
    let output = fake.ask(57, "terminal/output", json!({"sessionId": "s1", "terminalId": terminal})).await;
    assert!(output["result"]["output"].as_str().unwrap().contains("terminal says hi"), "{output}");
    assert_eq!(output["result"]["exitStatus"]["exitCode"], 4);
    let mut saw_output = false;
    let mut saw_call = false;
    while !saw_output {
        match next(&mut engine).await {
            Event::ToolCall(call) => {
                assert_eq!(call.id, "run-1");
                saw_call = true;
                if let Some(ToolContent::Terminal { output, .. }) = call.content.first() {
                    saw_output = output.contains("terminal says hi");
                }
            }
            Event::ToolUpdate(update) => {
                assert_eq!(update.id, "run-1");
                if let Some(ToolContent::Terminal { output, exit_code, command }) = update.content.as_ref().and_then(|c| c.first()) {
                    assert!(command.as_deref().unwrap().contains("terminal says hi"));
                    saw_output = output.contains("terminal says hi") && *exit_code == Some(4);
                }
            }
            other => panic!("{other:?}"),
        }
    }
    assert!(saw_call);
    let released = fake.ask(58, "terminal/release", json!({"sessionId": "s1", "terminalId": terminal})).await;
    assert_eq!(released["result"], json!({}));
    let gone = fake.ask(59, "terminal/output", json!({"sessionId": "s1", "terminalId": terminal})).await;
    assert_eq!(gone["error"]["code"], rpc::RESOURCE_NOT_FOUND);

    fake.update(json!({"sessionUpdate": "tool_call_update", "toolCallId": "run-1", "status": "completed", "rawOutput": {"exit": 4}})).await;
    let Event::ToolUpdate(done) = next_real(&mut engine).await else { panic!() };
    assert_eq!((done.status, done.output), (Some(ToolStatus::Completed), Some(json!({"exit": 4}))));
    assert!(done.content.is_none(), "an update without content keeps the content");

    fake.update(json!({"sessionUpdate": "plan", "entries": [{"content": "Read", "status": "completed", "priority": "high"},
        {"content": "Fix", "status": "in_progress", "priority": "medium"}]}))
    .await;
    let Event::Plan { entries } = next_real(&mut engine).await else { panic!() };
    assert_eq!(entries[1].status, PlanStatus::InProgress);
    fake.update(json!({"sessionUpdate": "available_commands_update", "availableCommands": [{"name": "compact", "description": "Compact", "input": {"hint": "focus"}}]})).await;
    let Event::Commands { commands } = next_real(&mut engine).await else { panic!() };
    assert_eq!(commands[0].hint.as_deref(), Some("focus"));
    fake.update(json!({"sessionUpdate": "current_mode_update", "currentModeId": "plan"})).await;
    let Event::Modes { current, .. } = next_real(&mut engine).await else { panic!() };
    assert_eq!(current, "plan");
    fake.update(json!({"sessionUpdate": "usage_update", "used": 1200, "size": 32768})).await;
    let Event::Usage(usage) = next_real(&mut engine).await else { panic!() };
    assert_eq!((usage.context_tokens, usage.context_window), (Some(1200), Some(32768)));
    fake.update(json!({"sessionUpdate": "something_new", "x": 1})).await;
    fake.respond(prompt_id, json!({"stopReason": "end_turn", "usage": {"inputTokens": 10, "outputTokens": 5, "totalTokens": 15}})).await;
    let Event::Usage(usage) = next_real(&mut engine).await else { panic!() };
    assert_eq!(usage.output_tokens, Some(5));
    assert_eq!(next_real(&mut engine).await, Event::TurnEnd { reason: StopReason::EndTurn, detail: None });

    engine.commands.send(Command::Shutdown).unwrap();
    assert!(matches!(next_real(&mut engine).await, Event::Exit { code: Some(0), .. }));
}

#[tokio::test]
async fn models_and_modes_switch_in_the_session_and_cancel_ends_the_turn() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, mut fake) = started(dir.path()).await;
    let _ready = next(&mut engine).await;
    let _modes = next(&mut engine).await;

    engine.commands.send(Command::SetModel { model: "m2".into() }).unwrap();
    let (id, params) = fake.request("session/set_config_option").await;
    assert_eq!(params, json!({"sessionId": "s1", "configId": "model", "value": "solver/m2"}));
    fake.respond(id, json!({"configOptions": [{"id": "model", "category": "model", "type": "select", "currentValue": "solver/m2",
        "options": [{"value": "solver/m1", "name": "m1"}, {"value": "solver/m2", "name": "m2"}]}]}))
    .await;
    assert_eq!(next(&mut engine).await, Event::Model { model: "m2".into() });

    engine.commands.send(Command::SetMode { mode: "plan".into() }).unwrap();
    let (id, params) = fake.request("session/set_mode").await;
    assert_eq!(params["modeId"], "plan");
    fake.respond(id, json!({})).await;
    let Event::Modes { current, .. } = next(&mut engine).await else { panic!() };
    assert_eq!(current, "plan");

    // The agent changes the model itself.
    fake.update(json!({"sessionUpdate": "config_option_update", "configOptions": [{"id": "model", "category": "model", "type": "select",
        "currentValue": "solver/m1", "options": [{"value": "solver/m1", "name": "m1"}, {"value": "solver/m2", "name": "m2"}]}]}))
    .await;
    assert_eq!(next(&mut engine).await, Event::Model { model: "m1".into() });

    // Cancel: the session is cancelled, the open permission request answered as cancelled, and
    // the turn ends cancelled.
    engine.commands.send(Command::Prompt { text: "go on".into() }).unwrap();
    let (prompt_id, _) = fake.request("session/prompt").await;
    engine.commands.send(Command::Prompt { text: "queued".into() }).unwrap();
    fake.send(json!({"jsonrpc": "2.0", "id": 70, "method": "session/request_permission", "params": {"sessionId": "s1",
        "toolCall": {"toolCallId": "x", "title": "Run rm -rf build", "rawInput": {"command": "rm -rf build"}},
        "options": [{"optionId": "ok", "name": "Allow", "kind": "allow_once"}]}}))
    .await;
    let mut asked = None;
    while asked.is_none() {
        if let Event::Permission(p) = next(&mut engine).await {
            asked = Some(p);
        }
    }
    assert_eq!(asked.unwrap().detail.as_deref(), Some("rm -rf build"));
    engine.commands.send(Command::Cancel).unwrap();
    let cancel = fake.recv().await;
    assert_eq!(cancel["method"], "session/cancel");
    assert!(cancel.get("id").is_none(), "cancel is a notification");
    let answer = fake.recv().await;
    assert_eq!((answer["id"].clone(), answer["result"]["outcome"]["outcome"].clone()), (json!(70), json!("cancelled")));
    // Agents answer a cancelled prompt with an error or a stop reason; either ends it cancelled.
    fake.send(json!({"jsonrpc": "2.0", "id": prompt_id, "error": {"code": -32800, "message": "Request cancelled"}})).await;
    assert_eq!(next_real(&mut engine).await, Event::TurnEnd { reason: StopReason::Cancelled, detail: None });

    // The queued prompt was dropped by the cancel; a new one runs.
    engine.commands.send(Command::Prompt { text: "again".into() }).unwrap();
    let (prompt_id, params) = fake.request("session/prompt").await;
    assert_eq!(params["prompt"][0]["text"], "again");

    // Our extensions: a question answered through the screen, a finding.
    fake.send(json!({"jsonrpc": "2.0", "id": 80, "method": "_yougori/question", "params": {"question": "Which target?", "choices": ["a", "b"], "allow_text": true}})).await;
    let Event::Question(question) = next(&mut engine).await else { panic!() };
    assert_eq!((question.choices.len(), question.allow_text), (2, true));
    engine.commands.send(Command::Answer { id: question.id, answer: Some(vec!["b".into()]) }).unwrap();
    let answer = fake.recv().await;
    assert_eq!(answer["result"], json!({"answer": ["b"]}));
    fake.send(json!({"jsonrpc": "2.0", "method": "_yougori/finding", "params": {"id": "f1", "title": "SQL injection", "severity": "high", "target": "/login"}})).await;
    let Event::Finding(finding) = next(&mut engine).await else { panic!() };
    assert_eq!((finding.severity, finding.target.as_deref()), (crate::protocol::Severity::High, Some("/login")));
    fake.send(json!({"jsonrpc": "2.0", "method": "_yougori/progress", "params": {"id": "scan", "label": "Scanning", "done": 2, "total": 5}})).await;
    let Event::Progress(progress) = next(&mut engine).await else { panic!() };
    assert_eq!(progress.total, Some(5));
    fake.send(json!({"jsonrpc": "2.0", "method": "_vendor/unknown", "params": {}})).await;
    fake.send(json!({"jsonrpc": "2.0", "id": 81, "method": "vendor/unknown", "params": {}})).await;
    let unknown = fake.recv().await;
    assert_eq!(unknown["error"]["code"], rpc::METHOD_NOT_FOUND);
    fake.respond(prompt_id, json!({"stopReason": "max_turn_requests"})).await;
    assert_eq!(next(&mut engine).await, Event::TurnEnd { reason: StopReason::MaxSteps, detail: None });

    // The agent's output ends without a shutdown: the engine reports that it stopped.
    drop(fake);
    let Event::Exit { code, message } = next(&mut engine).await else { panic!() };
    assert_eq!(code, None);
    assert!(message.contains("closed its connection"), "{message}");
}

#[tokio::test]
async fn a_cancelled_turn_the_agent_never_answers_ends_after_the_limit() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, mut fake) = started_limited(dir.path(), Duration::from_millis(400)).await;
    let _ready = next(&mut engine).await;
    let _modes = next(&mut engine).await;

    engine.commands.send(Command::Prompt { text: "--help".into() }).unwrap();
    let (prompt_id, _) = fake.request("session/prompt").await;
    fake.send(json!({"jsonrpc": "2.0", "id": 90, "method": "_yougori/question", "params": {"question": "Which target?"}})).await;
    let Event::Question(_) = next_real(&mut engine).await else { panic!("expected the question") };
    let asked_at = tokio::time::Instant::now();
    engine.commands.send(Command::Cancel).unwrap();
    assert_eq!(fake.recv().await["method"], "session/cancel");
    assert_eq!(fake.recv().await["result"], json!({"answer": null}), "the open question is answered at the cancel");
    // A second Esc asks nothing more of the agent.
    engine.commands.send(Command::Cancel).unwrap();

    // The agent never answers the prompt: the turn ends anyway, after the limit, with a warning.
    let mut warned = false;
    loop {
        match next(&mut engine).await {
            Event::Notice { level: Level::Warn, text } => {
                assert!(text.contains("did not confirm the stop"), "{text}");
                warned = true;
            }
            Event::TurnEnd { reason, detail } => {
                assert_eq!((reason, detail), (StopReason::Cancelled, None));
                break;
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    assert!(warned);
    assert!(asked_at.elapsed() >= Duration::from_millis(350), "it waited for the agent first");

    // The agent's late answer belongs to no turn; the next prompt runs as usual.
    fake.respond(prompt_id, json!({"stopReason": "cancelled"})).await;
    engine.commands.send(Command::Prompt { text: "again".into() }).unwrap();
    let (again, params) = fake.request("session/prompt").await;
    assert_eq!(params["prompt"][0]["text"], "again");
    fake.respond(again, json!({"stopReason": "end_turn"})).await;
    assert_eq!(next_real(&mut engine).await, Event::TurnEnd { reason: StopReason::EndTurn, detail: None });

    // A cancelled turn the agent answers in time ends with its answer, before the limit.
    engine.commands.send(Command::Prompt { text: "stop me".into() }).unwrap();
    let (stopped, _) = fake.request("session/prompt").await;
    engine.commands.send(Command::Cancel).unwrap();
    assert_eq!(fake.recv().await["method"], "session/cancel");
    fake.respond(stopped, json!({"stopReason": "cancelled"})).await;
    assert_eq!(next_real(&mut engine).await, Event::TurnEnd { reason: StopReason::Cancelled, detail: None });
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(engine.events.try_recv().is_err(), "no second end once the deadline passes");
}

#[tokio::test]
async fn auth_needs_no_secret_and_listed_models_switch_with_any_id() {
    let dir = tempfile::tempdir().unwrap();
    let (transport, mut fake) = pipes();
    let mut spec = spec(dir.path());
    spec.mcp.clear();
    spec.harness = "gemini".into();
    let client = tokio::spawn(connect(spec, transport));
    let (id, params) = fake.request("initialize").await;
    assert_eq!(params["clientCapabilities"]["fs"]["readTextFile"], false, "Gemini keeps its own file access");
    fake.respond(id, json!({"protocolVersion": 1, "authMethods": [{"id": "oauth-personal", "name": "Google"}, {"id": "gemini-api-key", "name": "Key"}]})).await;
    let (id, _) = fake.request("session/new").await;
    fake.send(json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32000, "message": "Authentication required"}})).await;
    let (id, params) = fake.request("authenticate").await;
    assert_eq!(params["methodId"], "gemini-api-key", "never a browser login");
    fake.respond(id, json!({})).await;
    let (id, _) = fake.request("session/new").await;
    // The agent lists its own models; session/set_model takes this inference's ids (Gemini CLI,
    // Cline), so the chosen model is selected at once.
    fake.respond(id, json!({"sessionId": "s9", "models": {"currentModelId": "gemini-2.5-pro", "availableModels": [{"modelId": "gemini-2.5-pro", "name": "Gemini"}]},
        "configOptions": [{"id": "model", "category": "model", "type": "select", "currentValue": "gpt-4o", "options": [{"value": "gpt-4o", "name": "gpt-4o"}]}]}))
    .await;
    let (id, params) = fake.request("session/set_model").await;
    assert_eq!(params, json!({"sessionId": "s9", "modelId": "m1"}));
    fake.respond(id, json!({})).await;
    let mut engine = client.await.unwrap().unwrap();
    let Event::Ready(ready) = next(&mut engine).await else { panic!() };
    assert_eq!(ready.model_switch, ModelSwitch::Live);
    engine.commands.send(Command::SetModel { model: "m2".into() }).unwrap();
    let (id, params) = fake.request("session/set_model").await;
    assert_eq!(params["modelId"], "m2");
    fake.respond(id, json!({})).await;
    assert_eq!(next(&mut engine).await, Event::Model { model: "m2".into() });
    engine.commands.send(Command::Shutdown).unwrap();
    assert!(matches!(next(&mut engine).await, Event::Exit { code: Some(0), .. }));
}

#[tokio::test]
async fn a_profile_that_restarts_to_switch_leaves_the_agent_model_alone() {
    let dir = tempfile::tempdir().unwrap();
    let (transport, mut fake) = pipes();
    let mut spec = spec(dir.path());
    spec.mcp.clear();
    spec.model_switch = ModelSwitch::Restart;
    let client = tokio::spawn(connect(spec, transport));
    let (id, _) = fake.request("initialize").await;
    fake.respond(id, json!({"protocolVersion": 1})).await;
    let (id, _) = fake.request("session/new").await;
    // Grok names the configured model "solver".
    fake.respond(id, json!({"sessionId": "s2", "models": {"currentModelId": "solver", "availableModels": [{"modelId": "solver", "name": "solver"}]}})).await;
    let mut engine = client.await.unwrap().unwrap();
    let Event::Ready(ready) = next(&mut engine).await else { panic!() };
    assert_eq!(ready.model_switch, ModelSwitch::Restart);
    engine.commands.send(Command::SetModel { model: "m2".into() }).unwrap();
    assert!(matches!(next(&mut engine).await, Event::Notice { level: Level::Warn, .. }));
    // A command whose output comes as text shows as a terminal.
    engine.commands.send(Command::Prompt { text: "ls".into() }).unwrap();
    let (prompt, _) = fake.request("session/prompt").await;
    fake.update(json!({"sessionUpdate": "tool_call", "toolCallId": "b1", "title": "bash", "kind": "execute", "status": "pending", "rawInput": {}})).await;
    fake.update(json!({"sessionUpdate": "tool_call_update", "toolCallId": "b1", "status": "in_progress", "rawInput": {"command": "ls"}})).await;
    fake.update(json!({"sessionUpdate": "tool_call_update", "toolCallId": "b1", "status": "completed",
        "content": [{"type": "content", "content": {"type": "text", "text": "a.txt\n"}}], "rawOutput": {"output": "a.txt\n", "metadata": {"exit": 0}}}))
    .await;
    assert!(matches!(next(&mut engine).await, Event::ToolCall(_)));
    assert!(matches!(next(&mut engine).await, Event::ToolUpdate(_)));
    let Event::ToolUpdate(done) = next(&mut engine).await else { panic!() };
    assert_eq!(done.content, Some(vec![ToolContent::Terminal { command: Some("ls".into()), output: "a.txt\n".into(), exit_code: Some(0) }]));
    fake.respond(prompt, json!({"stopReason": "end_turn"})).await;
    assert_eq!(next(&mut engine).await, Event::TurnEnd { reason: StopReason::EndTurn, detail: None });
    engine.commands.send(Command::Shutdown).unwrap();
    assert!(matches!(next(&mut engine).await, Event::Exit { code: Some(0), .. }));
}

#[test]
fn model_values_of_each_agent_are_recognised() {
    assert!(same_model("qwen3", "solver/qwen3", ""));
    assert!(same_model("qwen3", r#"["solver","qwen3"]"#, ""));
    assert!(same_model("qwen3", "qwen3(openai)", ""));
    assert!(same_model("org/model", "solver/org/model", ""));
    assert!(same_model("qwen3", "x", "qwen3"));
    assert!(!same_model("qwen3", "solver/qwen3-coder", ""));
    assert!(!same_model("wen3", "solver/qwen3", ""));
    let grouped = json!({"configOptions": [{"id": "model", "category": "model", "type": "select", "currentValue": "[\"solver\",\"a\"]",
        "options": [{"group": "solver", "name": "Solver", "options": [{"value": "[\"solver\",\"a\"]", "name": "a"}, {"value": "[\"solver\",\"b\"]", "name": "b"}]}]}]});
    let control = ModelControl::from_session(&grouped);
    assert_eq!(control.choice("b").map(|c| c.value).as_deref(), Some("[\"solver\",\"b\"]"));
    assert!(control.covers(&["a".into(), "b".into()], "a"));
    assert!(!control.covers(&["a".into(), "c".into()], "a"));
    assert_eq!(markdown_entries("# Plan\n- [x] one\n- [ ] two\n* three").len(), 3);
}

/// Run as a child by the tests below (`YOUGORI_FAKE_AGENT` set): answers the handshake, then
/// fails on the first prompt the way a crashing agent does.
#[test]
fn fake_agent_process() {
    let Ok(mode) = std::env::var("YOUGORI_FAKE_AGENT") else { return };
    use std::io::{BufRead, Write};
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    if mode == "die-at-start" {
        eprintln!("fake agent: cannot read its configuration");
        std::process::exit(5);
    }
    let mut lines = stdin.lock().lines();
    for line in lines.by_ref() {
        let message: Value = serde_json::from_str(&line.unwrap()).unwrap();
        let id = message["id"].clone();
        match message["method"].as_str() {
            Some("initialize") => {
                writeln!(out, "{}", json!({"jsonrpc": "2.0", "id": id, "result": {"protocolVersion": 1}})).unwrap();
            }
            Some("session/new") => {
                writeln!(out, "{}", json!({"jsonrpc": "2.0", "id": id, "result": {"sessionId": "child"}})).unwrap();
            }
            Some("session/prompt") => {
                eprintln!("fatal: the model server went away");
                out.flush().unwrap();
                std::process::exit(7);
            }
            _ => {}
        }
        out.flush().unwrap();
    }
    std::process::exit(0);
}

fn child_spec(dir: &std::path::Path, mode: &str) -> EngineSpec {
    let mut spec = spec(dir);
    spec.mcp.clear();
    spec.argv = vec![
        std::env::current_exe().unwrap().to_string_lossy().into_owned(),
        "--exact".into(),
        "engines::acp::tests::fake_agent_process".into(),
        "--nocapture".into(),
        "--test-threads".into(),
        "1".into(),
        "-q".into(),
    ];
    spec.env.insert("YOUGORI_FAKE_AGENT".into(), mode.into());
    for key in ["SystemRoot", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"] {
        if let Ok(value) = std::env::var(key) {
            spec.env.insert(key.into(), value);
        }
    }
    spec
}

#[tokio::test]
async fn an_agent_that_crashes_mid_turn_ends_with_its_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = start(&child_spec(dir.path(), "crash")).await.unwrap();
    assert!(matches!(next(&mut engine).await, Event::Ready(_)));
    engine.commands.send(Command::Prompt { text: "hello".into() }).unwrap();
    let mut ended = None;
    let mut exit = None;
    while exit.is_none() {
        match next(&mut engine).await {
            Event::TurnEnd { reason, .. } => ended = Some(reason),
            Event::Exit { code, message } => exit = Some((code, message)),
            _ => {}
        }
    }
    assert_eq!(ended, Some(StopReason::Error));
    let (code, message) = exit.unwrap();
    assert_eq!(code, Some(7));
    assert!(message.contains("the model server went away"), "{message}");
    assert!(dir.path().join("state/opencode.stderr.log").exists());
}

#[tokio::test]
async fn an_agent_that_dies_at_start_fails_to_start_with_its_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let error = start(&child_spec(dir.path(), "die-at-start")).await.err().expect("no engine");
    let text = format!("{error:#}");
    assert!(text.contains("cannot read its configuration") && text.contains("exited with code 5"), "{text}");
    let missing = EngineSpec { argv: vec![PathBuf::from("no-such-agent-binary").to_string_lossy().into_owned()], ..spec(dir.path()) };
    let error = start(&missing).await.err().unwrap();
    assert!(format!("{error}").contains("not installed"), "{error}");
}

/// Drives a real engine from a spec file (`YOUGORI_REAL_SPEC`), for checks inside a harness's
/// VM image; does nothing otherwise. Prints every event as a JSON line, answers permissions with
/// their first allow option and questions with their first choice, switches to the spec's second
/// model when the engine switches in place, and cancels a slow turn.
#[tokio::test(flavor = "multi_thread")]
async fn real_engine_from_spec() {
    let Ok(path) = std::env::var("YOUGORI_REAL_SPEC") else { return };
    let spec = crate::spec::EngineSpec::load(std::path::Path::new(&path)).unwrap();
    let prompts: Vec<String> = std::env::var("YOUGORI_REAL_PROMPTS")
        .ok()
        .and_then(|p| serde_json::from_str(&p).ok())
        .unwrap_or_else(|| vec!["Say hello.".into(), "PROBE-SHELL run it.".into(), "PROBE-EDIT write it.".into()]);
    let mut engine = crate::engines::start(&spec).await.unwrap_or_else(|e| panic!("start: {e:#}"));
    let show = |event: &Event| println!("EVENT {}", serde_json::to_string(event).unwrap());
    async fn turn(engine: &mut EngineHandle, show: &dyn Fn(&Event), limit: u64) -> StopReason {
        loop {
            let event = tokio::time::timeout(Duration::from_secs(limit), engine.events.recv()).await.expect("turn timed out").expect("engine ended");
            show(&event);
            match event {
                Event::Permission(asked) => {
                    let option = asked.options.iter().find(|o| o.kind == PermissionKind::AllowOnce).map(|o| o.id.clone());
                    engine.commands.send(Command::Permission { id: asked.id, option }).unwrap();
                }
                Event::Question(question) => {
                    let answer = Some(vec![question.choices.first().cloned().unwrap_or_else(|| "yes".into())]);
                    engine.commands.send(Command::Answer { id: question.id, answer }).unwrap();
                }
                Event::TurnEnd { reason, .. } => return reason,
                Event::Exit { message, .. } => panic!("the engine stopped: {message}"),
                _ => {}
            }
        }
    }
    let first = tokio::time::timeout(Duration::from_secs(60), engine.events.recv()).await.unwrap().unwrap();
    show(&first);
    let Event::Ready(ready) = first else { panic!("Ready first") };
    for prompt in &prompts {
        engine.commands.send(Command::Prompt { text: prompt.clone() }).unwrap();
        let reason = turn(&mut engine, &show, 240).await;
        println!("TURN {prompt:?} -> {reason:?}");
    }
    if ready.model_switch == ModelSwitch::Live && spec.models.len() > 1 {
        engine.commands.send(Command::SetModel { model: spec.models[1].clone() }).unwrap();
        loop {
            let event = tokio::time::timeout(Duration::from_secs(60), engine.events.recv()).await.unwrap().unwrap();
            show(&event);
            if matches!(event, Event::Model { .. } | Event::Notice { level: Level::Error, .. }) {
                break;
            }
        }
        engine.commands.send(Command::Prompt { text: "Say hello.".into() }).unwrap();
        println!("TURN after switch -> {:?}", turn(&mut engine, &show, 240).await);
    }
    engine.commands.send(Command::Prompt { text: "PROBE-SLOW keep going.".into() }).unwrap();
    let canceller = engine.commands.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(4)).await;
        let _ = canceller.send(Command::Cancel);
    });
    let reason = turn(&mut engine, &show, 120).await;
    println!("TURN cancelled -> {reason:?}");
    assert_eq!(reason, StopReason::Cancelled);
    engine.commands.send(Command::Shutdown).unwrap();
    while let Ok(Some(event)) = tokio::time::timeout(Duration::from_secs(15), engine.events.recv()).await {
        show(&event);
    }
    println!("DONE");
}
