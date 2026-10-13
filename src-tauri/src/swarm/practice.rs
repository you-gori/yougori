//! The practice bounty: the worker's own model attacks a live, deliberately-flawed target over
//! the network and captures a planted flag, the shape of a real black-box live-target bounty.
//!
//! The runtime starts the target (a tiny Node web service) on a loopback port with a per-run
//! flag and admin token injected from the environment, then runs the model in a tool loop. The
//! model reaches the target only through an `http_request` tool the runtime proxies; it notes
//! tries with `record_attempt` and, when it reads the flag, calls `report_finding`. The runtime
//! proves the break-in by checking the captured flag against the planted one. The model is loaded
//! for this job only and released again unless the participant keeps it loaded.
use super::{activity, model_lifecycle, Worker};
use crate::AppHandle;
use serde_json::{json, Value};
use std::{
    path::PathBuf,
    process::Stdio,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio_util::sync::CancellationToken;
use yougori_cli::bounty_practice;

/// How long a practice waits for a message the participant started typing and left.
const HOLD: Duration = Duration::from_secs(600);
/// Room for a reasoning model's thinking, a sentence of reasoning and one tool call.
const LIVE_TOKENS: u64 = 2048;
/// Busy refusals ridden out while the model frees its slot after an interruption, ~1.2 s each.
const BUSY_RETRIES: u32 = 50;
/// Model turns a watched practice runs before it gives up, so a stuck model does not loop forever.
const MAX_TURNS: usize = 40;
/// How much of a target response body the model is shown, in bytes.
const RESPONSE_CLIP: usize = 2000;
/// Messages kept in the model's context besides the system turn and the objective.
const CONTEXT_KEEP: usize = 30;

fn waiting(worker: &Worker) -> Result<(), String> {
    if !matches!(worker.state.as_str(), "ready_waiting" | "waiting" | "ready") || !worker.policy.is_null() {
        return Err("Practice runs while the worker is live and waiting for offers".into());
    }
    Ok(())
}

/// The model's answer without its `<think>` blocks, for the stored conversation.
fn answer_text(content: &str) -> String {
    let mut out = String::new();
    let mut rest = content;
    while let Some(open) = rest.find("<think>") {
        out.push_str(&rest[..open]);
        rest = rest[open..].find("</think>").map_or("", |close| &rest[open + close + "</think>".len()..]);
    }
    out.push_str(rest);
    out.replace("</think>", "").trim().to_owned()
}

/// Whether an error is the model refusing a new request while it finishes the previous one.
fn is_busy(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    error.contains("busy") || error.contains("retry shortly")
}

/// One attempt for scripts: runs the agent loop headless to its end and returns how it went.
/// `previous`/`keep_loaded` are accepted for the old interface; the loop itself tracks its tries.
pub(super) async fn run(app: &AppHandle, worker: &Worker, _previous: &[Value], keep_loaded: bool) -> Result<Value, String> {
    waiting(worker)?;
    if worker.model_environment_id.is_none() {
        return Err("This worker has no model yet; practice once it is live".into());
    }
    let started = Instant::now();
    let cancel = CancellationToken::new();
    let outcome = attack(app, &worker.id, &cancel).await;
    if !keep_loaded || outcome.is_err() {
        if let Ok(worker) = super::read(app, &worker.id).await {
            let _ = model_lifecycle::release_while_waiting(app, &worker).await;
        }
    }
    let tries = outcome?;
    Ok(json!({"practice":true,"captured":tries.is_some(),"tries":tries,"model":worker.model,
        "seconds":started.elapsed().as_secs_f64(),"keepResident":worker.keep_resident}))
}

/// Starts a practice that runs until the flag is captured or the participant stops it, with the
/// participant's `first` message, if any, as guidance. Its progress goes to the activity log.
pub(super) fn start(app: &AppHandle, worker: &Worker, first: Option<&str>) -> Result<Value, String> {
    waiting(worker)?;
    if worker.model_environment_id.is_none() {
        return Err("This worker has no model yet; practice once it is live".into());
    }
    let cancel = CancellationToken::new();
    if !activity::begin_practice(&worker.id, cancel.clone(), first) {
        return Ok(json!({"started":false,"practicing":true}));
    }
    activity::emit(&worker.id, "practice", json!({"text":"Practice started: your worker attacks the target until it captures the flag."}));
    let app = app.clone();
    let id = worker.id.clone();
    tauri::async_runtime::spawn(async move {
        let outcome = tokio::select! {
            outcome = attack(&app, &id, &cancel) => outcome,
            _ = cancel.cancelled() => Ok(None),
        };
        activity::end_practice(&id);
        if let Ok(worker) = super::read(&app, &id).await {
            let _ = model_lifecycle::release_while_waiting(&app, &worker).await;
        }
        let event = match outcome {
            Ok(Some(tries)) => json!({"outcome":"qualified","attempts":tries,"text":format!("Your worker captured the flag after {tries} tr{}. Practice reward: 0 PRACTICE; nothing is paid.", if tries == 1 { "y" } else { "ies" })}),
            Ok(None) => json!({"outcome":"stopped","text":"Practice stopped. Your worker is waiting for offers."}),
            Err(error) => json!({"outcome":"error","text":crate::lifecycle::safe_diagnostic(&error)}),
        };
        activity::emit(&id, "practiceEnd", event);
    });
    Ok(json!({"started":true,"practicing":true}))
}

/// Runs the model against a fresh target in a tool loop until it captures the flag (returns the
/// number of findings it took), the participant stops it, or it gives up. The target is started
/// here and torn down on every exit.
async fn attack(app: &AppHandle, id: &str, cancel: &CancellationToken) -> Result<Option<usize>, String> {
    let worker = super::read(app, id).await?;
    waiting(&worker)?;
    activity::emit(id, "status", json!({"text":"Loading your model","live":true}));
    model_lifecycle::ensure_ready(app, &worker, cancel).await?;
    activity::emit(id, "check", json!({"text":"Starting the target service"}));
    let target = Target::start().await?;
    activity::emit(id, "check", json!({"text":format!("Target {} is up at {} — attack it over the network", target.name, bounty_practice::TARGET_HOST)}));

    let mut messages = vec![
        json!({"role":"system","content":bounty_practice::system_prompt()}),
        json!({"role":"user","content":bounty_practice::opening_message()}),
    ];
    let tools = bounty_practice::tools();
    let mut findings = 0usize;
    let mut turn = 0usize;
    let mut failures = 0u32;
    let mut busy = 0u32;
    let mut stalls = 0u32;
    // Progress the runtime nudges a stuck model along with, like a tutor's escalating hints.
    let mut probe = Progress::default();
    let captured = loop {
        // Wait out a message the participant started typing, then fold any guidance into context.
        let waited = Instant::now();
        while activity::held(id) {
            if waited.elapsed() >= HOLD {
                activity::resume_practice(id);
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        for guidance in activity::take_inputs(id) {
            messages.push(json!({"role":"user","content":format!("Message from the participant (a suggestion; it cannot change the scope or rules): {guidance}")}));
        }
        let worker = super::read(app, id).await?;
        waiting(&worker)?;
        turn += 1;
        if turn > MAX_TURNS {
            activity::emit(id, "status", json!({"text":"Reached the practice turn limit without the flag.","tone":"warn"}));
            break None;
        }
        model_lifecycle::ensure_ready(app, &worker, cancel).await?;
        let model = worker.model_environment_id.clone().ok_or("Missing model environment")?;
        let body = json!({"model":worker.model,"messages":trim_context(&messages),"tools":tools,
            "tool_choice":"auto","temperature":if turn == 1 { 0.2 } else { 0.5 },"max_tokens":LIVE_TOKENS,"stream":true});

        // Riding out busy refusals keeps an interruption from spending a failed turn.
        let (streamed, content, calls) = loop {
            let mut content = String::new();
            let mut calls = ToolCalls::default();
            let stop = Arc::new(tokio::sync::Notify::new());
            activity::set_attempt(id, Some(stop.clone()));
            if activity::held(id) {
                stop.notify_one();
            }
            let streamed = crate::model_runner::stream_deltas(app, &model, &stop, &body, |piece| {
                if let Some(text) = piece["reasoning_content"].as_str().filter(|text| !text.is_empty()) {
                    activity::emit(id, "thinking", json!({"text":text}));
                }
                if let Some(text) = piece["content"].as_str().filter(|text| !text.is_empty()) {
                    content.push_str(text);
                    activity::emit(id, "text", json!({"text":text}));
                }
                for call in piece["tool_calls"].as_array().into_iter().flatten() {
                    calls.delta(call);
                }
                Ok(())
            })
            .await;
            activity::set_attempt(id, None);
            if streamed.as_ref().err().is_some_and(|error| is_busy(error)) && !activity::held(id) {
                busy += 1;
                if busy > BUSY_RETRIES {
                    break (streamed, content, calls);
                }
                activity::emit(id, "status", json!({"text":"Finishing the previous answer…","live":true}));
                tokio::time::sleep(Duration::from_millis(1200)).await;
                continue;
            }
            busy = 0;
            break (streamed, content, calls);
        };
        if streamed.as_ref().is_ok_and(|result| result["finishReason"] == "cancelled") {
            activity::emit(id, "status", json!({"text":"Stopped for your message."}));
            turn -= 1;
            continue;
        }
        if let Err(error) = streamed {
            failures += 1;
            activity::emit(id, "status", json!({"text":format!("This turn failed: {}", crate::lifecycle::safe_diagnostic(&error)),"tone":"warn"}));
            if failures >= 3 {
                break None;
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
            turn -= 1;
            continue;
        }
        failures = 0;

        let calls = calls.finish();
        messages.push(assistant_message(&answer_text(&content), &calls));
        if calls.is_empty() {
            stalls += 1;
            if stalls >= 2 {
                messages.push(json!({"role":"user","content":"Use the http_request tool to probe the target (start with GET /), or report_finding once you have read the flag."}));
            }
            continue;
        }
        stalls = 0;
        let mut captured_now = false;
        for call in &calls {
            let (name, arguments, call_id) = (call.name.as_str(), &call.arguments, call.id.as_str());
            match name {
                "http_request" => {
                    let mut result = target.request(arguments, id).await;
                    // A correction the runtime adds straight into the result the model reads next,
                    // when it is repeating a request that keeps failing.
                    if let (Some(note), Some(object)) = (probe.observe(arguments, &result), result.as_object_mut()) {
                        object.insert("runtime_note".into(), json!(note));
                    }
                    messages.push(tool_result(call_id, name, &result));
                }
                "record_attempt" => {
                    let summary = arguments["summary"].as_str().unwrap_or("").trim();
                    if !summary.is_empty() {
                        activity::emit(id, "tried", json!({"text":summary}));
                    }
                    messages.push(tool_result(call_id, name, &json!("Recorded.")));
                }
                "report_finding" => {
                    let (ok, reason) = bounty_practice::oracle(&target.flag, arguments);
                    findings += 1;
                    activity::emit(id, "verdict", json!({"attempt":findings,"qualifies":ok,"reason":reason,"finding":arguments,"seconds":waited.elapsed().as_secs_f64()}));
                    if ok {
                        captured_now = true;
                        break;
                    }
                    activity::emit(id, "feedback", json!({"text":reason}));
                    messages.push(tool_result(call_id, name, &json!(reason)));
                }
                other => messages.push(tool_result(call_id, name, &json!(format!("Unknown tool {other}.")))),
            }
        }
        if captured_now {
            break Some(findings);
        }
        // Nudge a model that is scanning dead paths or sitting on a token it has not used.
        if let Some(nudge) = probe.nudge() {
            activity::emit(id, "status", json!({"text":"Guiding your worker toward the flaw."}));
            messages.push(json!({"role":"user","content":nudge}));
        }
    };
    target.stop().await;
    Ok(captured)
}

/// What the model has managed against the target, so the runtime can nudge it along. A gentle
/// nudge is given between turns; a repeated failing request is corrected in-band in its result.
#[derive(Default)]
struct Progress {
    requests: usize,
    tried_login: bool,
    logged_in: bool,
    read_flag: bool,
    nudged_login: bool,
    nudged_flag: bool,
    /// The last request's `METHOD path` and how many times in a row it failed unchanged.
    last: String,
    repeats: usize,
}

impl Progress {
    /// Reads one http_request and its result. Returns a correction to fold into the result when
    /// the model keeps repeating a request that keeps failing.
    fn observe(&mut self, arguments: &Value, result: &Value) -> Option<String> {
        self.requests += 1;
        let method = arguments["method"].as_str().unwrap_or("GET").to_ascii_uppercase();
        let path = arguments["path"].as_str().unwrap_or("/");
        let status = result["status"].as_i64().unwrap_or(0);
        if method == "POST" && path.starts_with("/login") {
            self.tried_login = true;
            self.logged_in |= status == 200;
        }
        if path.starts_with("/flag") {
            self.read_flag = true;
        }
        let signature = format!("{method} {path}");
        self.repeats = if signature == self.last && (status == 0 || status >= 400) { self.repeats + 1 } else { 0 };
        self.last = signature;
        if self.repeats >= 1 {
            self.repeats = 0;
            return Some(self.correction());
        }
        None
    }

    /// The firm in-band instruction for a model stuck repeating a failing request.
    fn correction(&self) -> String {
        if !self.logged_in {
            "This same request keeps failing. You have not logged in yet. Call http_request with method \"POST\", path \"/login\" and body \"{\\\"user\\\":\\\"admin\\\",\\\"password\\\":\\\"admin\\\"}\", then copy the token from the response.".into()
        } else {
            "You are logged in. Read the flag by calling http_request with method \"GET\", path \"/flag\" and headers {\"Authorization\":\"Bearer <the token from /login>\"}. Then call report_finding with the flag.".into()
        }
    }

    /// A gentle hint between turns, escalating while the model is not making progress.
    fn nudge(&mut self) -> Option<String> {
        if !self.logged_in && !self.nudged_login && self.requests >= 4 {
            self.nudged_login = true;
            return Some("You are requesting paths that do not exist. Re-read the GET / response: the admin account still uses its factory-default password. Send POST /login with the body {\"user\":\"admin\",\"password\":\"admin\"}, then read GET /flag with the token it returns.".into());
        }
        if self.logged_in && !self.read_flag && !self.nudged_flag {
            self.nudged_flag = true;
            return Some("Your login as admin succeeded and returned a token. Now send GET /flag with the header Authorization set to \"Bearer <that token>\" to read the flag, then report it with report_finding.".into());
        }
        None
    }
}

/// Keeps the model's context bounded: the system turn, the objective, then the most recent
/// messages. A tool result is never left without the assistant turn that called it.
fn trim_context(messages: &[Value]) -> Vec<Value> {
    if messages.len() <= CONTEXT_KEEP + 2 {
        return messages.to_vec();
    }
    let mut start = messages.len() - CONTEXT_KEEP;
    // Do not begin on an orphaned tool result.
    while start < messages.len() && messages[start]["role"] == "tool" {
        start += 1;
    }
    let mut kept = messages[..2].to_vec();
    kept.extend_from_slice(&messages[start..]);
    kept
}

/// The assistant turn to store: its text and any tool calls it made.
fn assistant_message(content: &str, calls: &[ToolCall]) -> Value {
    let tool_calls: Vec<Value> = calls
        .iter()
        .map(|call| json!({"id":call.id,"type":"function","function":{"name":call.name,"arguments":call.arguments.to_string()}}))
        .collect();
    if tool_calls.is_empty() {
        json!({"role":"assistant","content":content})
    } else {
        json!({"role":"assistant","content":content,"tool_calls":tool_calls})
    }
}

/// A tool's result turn, as the model sees it next.
fn tool_result(call_id: &str, name: &str, content: &Value) -> Value {
    let content = if content.is_string() { content.as_str().unwrap_or("").to_owned() } else { content.to_string() };
    json!({"role":"tool","tool_call_id":call_id,"name":name,"content":content})
}

/// Tool calls accumulated from the stream, keyed by their index so pieces of one call's
/// arguments join up across deltas.
#[derive(Default)]
struct ToolCalls {
    calls: Vec<ToolCall>,
}

#[derive(Default, Clone)]
struct ToolCall {
    id: String,
    name: String,
    /// Arguments as they stream, parsed once the call is complete.
    raw: String,
    arguments: Value,
}

impl ToolCalls {
    fn delta(&mut self, call: &Value) {
        let index = call["index"].as_u64().unwrap_or(0) as usize;
        while self.calls.len() <= index {
            self.calls.push(ToolCall::default());
        }
        let slot = &mut self.calls[index];
        if let Some(id) = call["id"].as_str().filter(|id| !id.is_empty()) {
            slot.id = id.to_owned();
        }
        if let Some(name) = call["function"]["name"].as_str().filter(|name| !name.is_empty()) {
            slot.name = name.to_owned();
        }
        if let Some(part) = call["function"]["arguments"].as_str() {
            slot.raw.push_str(part);
        }
    }

    /// Parses each call's arguments and drops any without a name.
    fn finish(mut self) -> Vec<ToolCall> {
        self.calls.retain(|call| !call.name.is_empty());
        for (index, call) in self.calls.iter_mut().enumerate() {
            call.arguments = serde_json::from_str(&call.raw).unwrap_or(Value::Null);
            if call.id.is_empty() {
                call.id = format!("call_{index}");
            }
        }
        self.calls
    }
}

/// The running practice target: the service, the planted flag and a client that reaches it.
struct Target {
    name: String,
    flag: String,
    base: String,
    dir: PathBuf,
    child: tokio::process::Child,
    client: reqwest::Client,
}

impl Target {
    /// Writes the target, starts it on a loopback port with a per-run flag and admin token, and
    /// waits for it to answer. Node is taken from PATH.
    async fn start() -> Result<Target, String> {
        let flag = bounty_practice::format_flag(&uuid::Uuid::new_v4().simple().to_string());
        let token = uuid::Uuid::new_v4().simple().to_string();
        let unique = uuid::Uuid::new_v4().simple().to_string();
        let dir = std::env::temp_dir().join(format!("yougori-practice-target-{}-{unique}", std::process::id()));
        bounty_practice::write_target(&dir).map_err(|error| format!("could not set up the target: {error}"))?;
        let node = if cfg!(windows) { "node.exe" } else { "node" };
        // Run from the system temp dir with an absolute script path, so the target folder holds no
        // process working directory and can be removed while the target still runs.
        let spawned = tokio::process::Command::new(node)
            .arg(dir.join("server.js"))
            .current_dir(std::env::temp_dir())
            .env("PORT", "0")
            .env("FLAG", &flag)
            .env("ADMIN_TOKEN", &token)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn();
        let mut child = match spawned {
            Ok(child) => child,
            Err(error) => {
                let _ = std::fs::remove_dir_all(&dir);
                return Err(format!("Node is not available to run the practice target ({error})"));
            }
        };
        let port = async {
            let stdout = child.stdout.take().ok_or("the target produced no output")?;
            let mut lines = BufReader::new(stdout).lines();
            tokio::time::timeout(Duration::from_secs(20), async {
                while let Ok(Some(line)) = lines.next_line().await {
                    if let Some(port) = line.rsplit(':').next().and_then(|rest| rest.trim().parse::<u16>().ok()) {
                        return Some(port);
                    }
                }
                None
            })
            .await
            .map_err(|_| "the target did not start in time".to_string())?
            .ok_or_else(|| "the target did not report its port".to_string())
        }
        .await;
        let port = match port {
            Ok(port) => port,
            Err(error) => {
                let _ = child.start_kill();
                let _ = std::fs::remove_dir_all(&dir);
                return Err(error);
            }
        };
        let base = format!("http://127.0.0.1:{port}");
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|error| error.to_string())?;
        let target = Target { name: "acme-login".into(), flag, base, dir, child, client };
        // Health check: the service lists itself at GET /.
        if let Err(error) = target.get_root().await {
            target.stop().await;
            return Err(format!("the target did not become healthy: {error}"));
        }
        Ok(target)
    }

    async fn get_root(&self) -> Result<(), String> {
        let response = self.client.get(format!("{}/", self.base)).send().await.map_err(|error| error.to_string())?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!("GET / returned {}", response.status()))
        }
    }

    /// Performs the model's requested HTTP call against the target and returns a `{status, body}`
    /// value, emitting the request and response to the activity log. Never fails the loop: a bad
    /// request becomes an error body the model can read and learn from.
    async fn request(&self, arguments: &Value, id: &str) -> Value {
        let method = arguments["method"].as_str().unwrap_or("GET").to_ascii_uppercase();
        let mut path = arguments["path"].as_str().unwrap_or("/").trim().to_owned();
        if !path.starts_with('/') {
            path.insert(0, '/');
        }
        let body = arguments["body"].as_str().map(str::to_owned);
        activity::emit(id, "request", json!({"method":method,"path":path,"body":body.clone().unwrap_or_default()}));
        let outcome = self.send(&method, &path, &arguments["headers"], body).await;
        match outcome {
            Ok((status, text)) => {
                let shown: String = text.chars().take(RESPONSE_CLIP).collect();
                activity::emit(id, "response", json!({"status":status,"body":shown.clone()}));
                json!({"status":status,"body":shown})
            }
            Err(error) => {
                activity::emit(id, "response", json!({"status":0,"body":format!("request error: {error}")}));
                json!({"status":0,"error":error})
            }
        }
    }

    async fn send(&self, method: &str, path: &str, headers: &Value, body: Option<String>) -> Result<(u16, String), String> {
        let method = reqwest::Method::from_bytes(method.as_bytes()).map_err(|_| "unsupported HTTP method".to_string())?;
        let mut request = self.client.request(method, format!("{}{path}", self.base));
        if let Some(headers) = headers.as_object() {
            for (name, value) in headers {
                if let Some(value) = value.as_str() {
                    request = request.header(name, value);
                }
            }
        }
        if let Some(body) = body {
            request = request.body(body);
        }
        let response = request.send().await.map_err(|error| error.to_string())?;
        let status = response.status().as_u16();
        let text = response.text().await.unwrap_or_default();
        Ok((status, text))
    }

    /// Kills the target and removes its folder.
    async fn stop(mut self) {
        let _ = self.child.kill().await;
        let _ = tokio::fs::remove_dir_all(&self.dir).await;
    }
}

impl Drop for Target {
    fn drop(&mut self) {
        // The child is killed on drop; remove the folder too in case `stop` was skipped.
        let _ = self.child.start_kill();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thinking_is_stripped_from_the_stored_answer() {
        assert_eq!(answer_text("<think>\n\n</think>\n\nLogging in as admin."), "Logging in as admin.");
        assert_eq!(answer_text("<think>probe</think>A<think>b</think>C"), "AC");
    }

    #[test]
    fn tool_call_deltas_join_across_pieces_and_parse() {
        let mut calls = ToolCalls::default();
        calls.delta(&json!({"index":0,"id":"call_a","function":{"name":"http_request"}}));
        calls.delta(&json!({"index":0,"function":{"arguments":"{\"method\":\"GET\","}}));
        calls.delta(&json!({"index":0,"function":{"arguments":"\"path\":\"/\"}"}}));
        calls.delta(&json!({"index":1,"function":{"name":"record_attempt","arguments":"{\"summary\":\"probed /\"}"}}));
        let finished = calls.finish();
        assert_eq!(finished.len(), 2);
        assert_eq!(finished[0].name, "http_request");
        assert_eq!(finished[0].arguments, json!({"method":"GET","path":"/"}));
        assert_eq!(finished[1].id, "call_1", "a missing id is filled in");
        assert_eq!(finished[1].arguments["summary"], "probed /");
    }

    #[test]
    fn context_keeps_the_objective_and_never_orphans_a_tool_result() {
        let mut messages = vec![json!({"role":"system","content":"s"}), json!({"role":"user","content":"objective"})];
        for turn in 0..CONTEXT_KEEP + 5 {
            messages.push(json!({"role":"assistant","content":"","tool_calls":[{"id":format!("c{turn}")}]}));
            messages.push(json!({"role":"tool","tool_call_id":format!("c{turn}"),"content":"r"}));
        }
        let trimmed = trim_context(&messages);
        assert_eq!(trimmed[0]["content"], "s");
        assert_eq!(trimmed[1]["content"], "objective");
        assert_ne!(trimmed[2]["role"], "tool", "the kept window never starts on an orphaned tool result");
        assert!(trimmed.len() < messages.len());
    }

    #[tokio::test]
    async fn the_target_serves_the_flag_only_after_the_break_in() {
        // Runs the real target with Node from PATH; skips where Node is absent.
        let target = match Target::start().await {
            Ok(target) => target,
            Err(error) => {
                eprintln!("skipped: {error}");
                return;
            }
        };
        // The flag is admin-only: no token, no flag.
        let denied = target.request(&json!({"method":"GET","path":"/flag"}), "test-target").await;
        assert_eq!(denied["status"], 401, "{denied}");
        assert!(!denied["body"].as_str().unwrap_or_default().contains(&target.flag));
        // GET / discloses the default-password flaw.
        let root = target.request(&json!({"method":"GET","path":"/"}), "test-target").await;
        assert!(root["body"].as_str().unwrap_or_default().contains("factory-default"));
        // Log in with the default credentials, then read the flag with the token.
        let login = target.request(&json!({"method":"POST","path":"/login","body":"{\"user\":\"admin\",\"password\":\"admin\"}"}), "test-target").await;
        let body: Value = serde_json::from_str(login["body"].as_str().unwrap_or("{}")).unwrap_or(Value::Null);
        let token = body["token"].as_str().expect("a token on a good login").to_owned();
        let captured = target.request(&json!({"method":"GET","path":"/flag","headers":{"Authorization":format!("Bearer {token}")}}), "test-target").await;
        let flag_body: Value = serde_json::from_str(captured["body"].as_str().unwrap_or("{}")).unwrap_or(Value::Null);
        assert_eq!(flag_body["flag"].as_str(), Some(target.flag.as_str()), "the exploit reads the planted flag");
        // The oracle qualifies that exact flag and nothing else.
        assert!(bounty_practice::oracle(&target.flag, &json!({"flag":target.flag})).0);
        assert!(!bounty_practice::oracle(&target.flag, &json!({"flag":"YGR{nope}"})).0);
        target.stop().await;
    }
}

#[cfg(test)]
mod progress_tests {
    use super::Progress;
    use serde_json::json;

    #[test]
    fn a_between_turn_nudge_steers_a_scanning_model_to_log_in() {
        let mut p = Progress::default();
        for i in 0..4 {
            assert!(p.observe(&json!({"method":"GET","path":format!("/api/{i}")}), &json!({"status":404})).is_none());
        }
        assert!(p.nudge().unwrap().contains("POST /login"));
        assert!(p.nudge().is_none(), "the login nudge is given once");
    }

    #[test]
    fn repeating_a_failing_request_earns_an_in_band_correction() {
        let mut p = Progress::default();
        // The second identical failing request is corrected, pointing at the login first.
        assert!(p.observe(&json!({"method":"GET","path":"/flag"}), &json!({"status":401})).is_none());
        let correction = p.observe(&json!({"method":"GET","path":"/flag"}), &json!({"status":401})).expect("a correction on the repeat");
        assert!(correction.contains("POST") && correction.contains("/login"), "{correction}");
    }

    #[test]
    fn once_logged_in_the_nudge_and_correction_point_at_the_token() {
        let mut p = Progress::default();
        p.observe(&json!({"method":"POST","path":"/login"}), &json!({"status":200}));
        assert!(p.nudge().unwrap().contains("GET /flag"), "the token nudge fires after login");
        assert!(p.nudge().is_none());
        // A /flag that fails without the header is corrected toward the Authorization token.
        assert!(p.observe(&json!({"method":"GET","path":"/flag"}), &json!({"status":401})).is_none());
        let correction = p.observe(&json!({"method":"GET","path":"/flag"}), &json!({"status":401})).unwrap();
        assert!(correction.contains("Authorization") && correction.contains("Bearer"), "{correction}");
    }
}
