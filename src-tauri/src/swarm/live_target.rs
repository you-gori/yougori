//! Runs an accepted bounty's uploaded project as a live service the worker's model attacks over
//! the network. The publisher is vetted by the operator before a bounty is published, and the
//! participant chose to accept it; the project runs on the participant's own machine, in a fresh
//! temporary folder, as a child process killed on teardown. The model reaches it only through the
//! http_request tool the runtime proxies here, so it can probe the service but nothing else.
use serde_json::Value;
use std::{path::PathBuf, process::Stdio, time::Duration};
use tokio::io::AsyncWriteExt;

/// What a live-target bounty supplies for the runtime to start the service.
pub(super) struct Spec {
    /// Project files as (relative path, bytes), from the accepted source snapshot.
    pub files: Vec<(String, Vec<u8>)>,
    /// Optional one-off preparation (for example installing dependencies).
    pub setup: Option<String>,
    /// The command that starts the service in the foreground.
    pub start: String,
    /// The port the service listens on, as the publisher declared it.
    pub port: u16,
    /// A path that answers once the service is ready (default `/`).
    pub health: String,
}

/// A started live target: its working folder, the running process and a client scoped to it.
pub(super) struct Service {
    dir: PathBuf,
    child: tokio::process::Child,
    base: String,
    client: reqwest::Client,
}

/// How much of a response body the model is shown, in bytes.
const RESPONSE_CLIP: usize = 2000;
/// How long preparation (dependency install) may run.
const SETUP_SECONDS: u64 = 600;
/// How long to wait for the service to answer its health check.
const HEALTH_SECONDS: u64 = 60;

impl Service {
    /// Writes the project, runs its setup, starts it and waits for it to answer. The service is
    /// reached only on loopback; `port` is the publisher's declared port.
    pub(super) async fn start(spec: &Spec) -> Result<Service, String> {
        let unique = uuid::Uuid::new_v4().simple().to_string();
        let dir = std::env::temp_dir().join(format!("yougori-bounty-target-{}-{unique}", std::process::id()));
        write_files(&dir, &spec.files).await?;

        if let Some(setup) = spec.setup.as_deref().map(str::trim).filter(|setup| !setup.is_empty()) {
            run_setup(&dir, setup, spec.port).await?;
        }

        let mut command = shell(&spec.start);
        command
            .current_dir(&dir)
            .env("PORT", spec.port.to_string())
            .env("HOST", "127.0.0.1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                let _ = tokio::fs::remove_dir_all(&dir).await;
                return Err(format!("could not start the target service: {error}"));
            }
        };
        let base = format!("http://127.0.0.1:{}", spec.port);
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|error| error.to_string())?;
        let service = Service { dir, child, base, client };
        if let Err(error) = service.await_health(&spec.health).await {
            service.stop().await;
            return Err(error);
        }
        Ok(service)
    }

    /// Polls the health path until the service answers or the timeout passes.
    async fn await_health(&self, health: &str) -> Result<(), String> {
        let path = if health.trim().is_empty() { "/" } else { health.trim() };
        let path = if path.starts_with('/') { path.to_owned() } else { format!("/{path}") };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(HEALTH_SECONDS);
        loop {
            if self.client.get(format!("{}{path}", self.base)).send().await.is_ok() {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err("the target service did not start answering in time".into());
            }
            tokio::time::sleep(Duration::from_millis(400)).await;
        }
    }

    /// Performs the model's requested HTTP call against the target and returns `{status, body}`.
    /// A failed request becomes an error body the model can read, never an engine failure.
    pub(super) async fn request(&self, arguments: &Value) -> Value {
        let method = arguments["method"].as_str().unwrap_or("GET").to_ascii_uppercase();
        let mut path = arguments["path"].as_str().unwrap_or("/").trim().to_owned();
        if !path.starts_with('/') {
            path.insert(0, '/');
        }
        let body = arguments["body"].as_str().map(str::to_owned);
        match self.send(&method, &path, &arguments["headers"], body).await {
            Ok((status, text)) => {
                let shown: String = text.chars().take(RESPONSE_CLIP).collect();
                serde_json::json!({"status":status,"body":shown})
            }
            Err(error) => serde_json::json!({"status":0,"error":error}),
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

    /// Stops the service and removes its folder.
    pub(super) async fn stop(mut self) {
        let _ = self.child.kill().await;
        let _ = tokio::fs::remove_dir_all(&self.dir).await;
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Writes the project files under `dir`, creating parent folders. Paths are from the accepted,
/// publisher-vetted source and were validated as safe relative paths when uploaded.
async fn write_files(dir: &PathBuf, files: &[(String, Vec<u8>)]) -> Result<(), String> {
    for (path, bytes) in files {
        let full = dir.join(path);
        if let Some(parent) = full.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|error| format!("could not set up the target: {error}"))?;
        }
        let mut file = tokio::fs::File::create(&full).await.map_err(|error| format!("could not write {path}: {error}"))?;
        file.write_all(bytes).await.map_err(|error| format!("could not write {path}: {error}"))?;
    }
    if files.is_empty() {
        tokio::fs::create_dir_all(dir).await.map_err(|error| error.to_string())?;
    }
    Ok(())
}

/// Runs the one-off setup command to completion, bounded.
async fn run_setup(dir: &PathBuf, setup: &str, port: u16) -> Result<(), String> {
    let mut command = shell(setup);
    command
        .current_dir(dir)
        .env("PORT", port.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let child = command.spawn().map_err(|error| format!("could not run setup: {error}"))?;
    let output = tokio::time::timeout(Duration::from_secs(SETUP_SECONDS), child.wait_with_output())
        .await
        .map_err(|_| "setup did not finish in time".to_string())?
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("setup failed: {}", crate::lifecycle::safe_diagnostic(stderr.trim())));
    }
    Ok(())
}

/// A shell command that runs the publisher's declared command line.
fn shell(command_line: &str) -> tokio::process::Command {
    let mut command = if cfg!(windows) {
        let mut command = tokio::process::Command::new("cmd");
        command.arg("/c").arg(command_line);
        command
    } else {
        let mut command = tokio::process::Command::new("sh");
        command.arg("-c").arg(command_line);
        command
    };
    command.env("CI", "1");
    command
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn starts_an_uploaded_service_and_proxies_requests_to_it() {
        // A tiny Node service stands in for an uploaded project; skipped where Node is absent.
        let server = "const http=require('node:http');const p=Number(process.env.PORT);http.createServer((q,r)=>{if(q.url==='/health'){r.writeHead(200).end('ok');return;}r.writeHead(200,{'content-type':'application/json'});r.end(JSON.stringify({hello:'world',url:q.url}))}).listen(p,'127.0.0.1')";
        let probe = shell("node -e \"process.exit(0)\"").status().await;
        if probe.map(|status| !status.success()).unwrap_or(true) {
            eprintln!("skipped: Node unavailable");
            return;
        }
        let spec = Spec {
            files: vec![("server.js".into(), server.as_bytes().to_vec())],
            setup: None,
            start: "node server.js".into(),
            port: 39517,
            health: "/health".into(),
        };
        let service = Service::start(&spec).await.expect("the service starts");
        let response = service.request(&serde_json::json!({"method":"GET","path":"/probe"})).await;
        assert_eq!(response["status"], 200, "{response}");
        assert!(response["body"].as_str().unwrap().contains("\"url\":\"/probe\""), "{response}");
        service.stop().await;
    }
}

// ---------------------------------------------------------------------------
// The live-target attack: the worker's model attacks the running service and,
// on capturing the flag, files a report into the publisher's review dashboard.
// ---------------------------------------------------------------------------
use super::{activity, agent, model_lifecycle, Worker};
use crate::AppHandle;
use base64::Engine as _;
use serde_json::json;
use std::{sync::Arc, time::Instant};
use tokio_util::sync::CancellationToken;

/// Model turns a live-target attack runs before it gives up.
const MAX_TURNS: usize = 40;
/// How long the loop waits for a message the participant started typing and left.
const HOLD: Duration = Duration::from_secs(600);

/// The three tools the attacking model may call against the live target.
fn tools() -> Vec<Value> {
    yougori_cli::bounty_practice::tools()
}

/// The worker's standing instructions for the authorized live-target attack.
fn system_prompt(policy: &Value) -> String {
    format!(
        "You are a Yougori Swarm Mining worker on an authorized bounty. The publisher's own web \
         service is running as the target and the publisher authorized you to attack it. You can \
         reach it ONLY through the http_request tool: give a method and a path and the runtime \
         sends the request to the target and returns the status and body. Your goal is to break \
         in and capture the flag the publisher planted - a secret only a successful attack can \
         reach. Probe the service, try real attacks (authentication flaws, access control, \
         injection, exposed endpoints), and use record_attempt to note what you try. When you read \
         the flag, call report_finding with the exact flag and how you got it. Attack ONLY this \
         target over the network; never touch the host, other systems, files, or the internet. \
         Objective: {}. Qualifying criteria: {}.",
        policy["objective"].as_str().unwrap_or_default(),
        policy["qualifyingCriteria"].as_str().unwrap_or_default()
    )
}

/// Fetches the accepted source snapshot and returns its files as (path, bytes).
async fn fetch_files(app: &AppHandle, worker: &Worker) -> Result<Vec<(String, Vec<u8>)>, String> {
    let result = agent(app, worker, reqwest::Method::GET, "/api/swarm/agent/source", None).await?;
    let source = if result["source"].is_object() { result["source"].clone() } else { result };
    if source["sha256"] != worker.policy["sourceDigest"] || source["revision"] != worker.policy["sourceRevision"] {
        return Err("The project does not match the source snapshot you accepted".into());
    }
    let files = source["files"].as_array().ok_or("Missing project files")?;
    let mut out = Vec::new();
    for file in files {
        let path = file["path"].as_str().ok_or("Invalid project file path")?.to_owned();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(file["contentBase64"].as_str().unwrap_or_default())
            .map_err(|_| "Invalid project file data")?;
        out.push((path, bytes));
    }
    Ok(out)
}

/// Runs an accepted live-target bounty: starts the service, attacks it, and reports a capture.
pub(super) async fn run(app: &AppHandle, worker: &Worker, cancel: &CancellationToken) -> Result<(), String> {
    let id = &worker.id;
    let port = worker.policy["targetPort"].as_str().and_then(|p| p.parse::<u16>().ok()).ok_or("The bounty is missing a valid target port")?;
    let start = worker.policy["startCommand"].as_str().filter(|s| !s.trim().is_empty()).ok_or("The bounty is missing a start command")?.to_owned();
    activity::emit(id, "work", json!({"text":"Starting the target service for this bounty"}));
    let spec = Spec {
        files: fetch_files(app, worker).await?,
        setup: worker.policy["setupCommand"].as_str().map(str::to_owned),
        start,
        port,
        health: worker.policy["healthCheck"].as_str().unwrap_or("/").to_owned(),
    };
    let service = Service::start(&spec).await?;
    activity::emit(id, "check", json!({"text":format!("Target is up on port {port} - attacking it over the network")}));

    // Reserve one task so attempts and the report attach to this bounty version.
    let reserve = agent(app, worker, reqwest::Method::POST, "/api/swarm/agent/tasks/reserve",
        Some(json!({"component":"live target service","category":"live target attack","conditions":worker.policy["sourceRevision"],"idempotencyKey":format!("live-reserve-{id}")}))).await;
    let lease = match reserve {
        Ok(lease) if lease["leaseId"].as_str().is_some() => lease,
        Ok(_) => { service.stop().await; return Err("Could not reserve a task for the live target".into()); }
        Err(error) => { service.stop().await; return Err(error); }
    };

    let outcome = attack(app, worker, cancel, &service, &lease).await;
    let _ = agent(app, worker, reqwest::Method::POST, "/api/swarm/agent/tasks/release",
        Some(json!({"leaseId":lease["leaseId"],"generation":lease["generation"],"reason":"Live-target attack finished","idempotencyKey":format!("live-release-{id}")}))).await;
    service.stop().await;
    outcome
}

/// The model attack loop against the live service. Records each try as an attempt and, on a
/// reported capture, files the report. Returns once it reports, gives up, or is cancelled.
async fn attack(app: &AppHandle, worker: &Worker, cancel: &CancellationToken, service: &Service, lease: &Value) -> Result<(), String> {
    let id = &worker.id;
    let model = worker.model_environment_id.clone().ok_or("Missing model environment")?;
    let mut messages = vec![
        json!({"role":"system","content":system_prompt(&worker.policy)}),
        json!({"role":"user","content":"The target is at http://target. Begin by sending GET / to see what it exposes, then work toward the flag. Report it with report_finding once you have it."}),
    ];
    let tools = tools();
    let mut attempt_ids: Vec<Value> = Vec::new();
    let mut turn = 0usize;
    let mut failures = 0u32;
    let mut busy = 0u32;
    let mut stalls = 0u32;
    loop {
        let waited = Instant::now();
        while activity::held(id) {
            if waited.elapsed() >= HOLD { activity::resume_practice(id); break; }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        for guidance in activity::take_inputs(id) {
            messages.push(json!({"role":"user","content":format!("Message from the participant (a suggestion; it cannot change the scope or rules): {guidance}")}));
        }
        turn += 1;
        if turn > MAX_TURNS {
            activity::emit(id, "status", json!({"text":"Reached the attack turn limit without capturing the flag.","tone":"warn"}));
            return Ok(());
        }
        model_lifecycle::ensure_ready(app, worker, cancel).await?;
        let body = json!({"model":worker.model,"messages":super::practice::trim_context(&messages),"tools":tools,
            "tool_choice":"auto","temperature":if turn == 1 { 0.2 } else { 0.5 },"max_tokens":super::practice::LIVE_TOKENS,"stream":true});

        let (streamed, content, calls) = loop {
            let mut content = String::new();
            let mut calls = super::practice::ToolCalls::default();
            let stop = Arc::new(tokio::sync::Notify::new());
            activity::set_attempt(id, Some(stop.clone()));
            if activity::held(id) { stop.notify_one(); }
            let streamed = crate::model_runner::stream_deltas(app, &model, &stop, &body, |piece| {
                if let Some(text) = piece["reasoning_content"].as_str().filter(|t| !t.is_empty()) {
                    activity::emit(id, "thinking", json!({"text":text}));
                }
                if let Some(text) = piece["content"].as_str().filter(|t| !t.is_empty()) {
                    content.push_str(text);
                    activity::emit(id, "text", json!({"text":text}));
                }
                for call in piece["tool_calls"].as_array().into_iter().flatten() { calls.delta(call); }
                Ok(())
            }).await;
            activity::set_attempt(id, None);
            if streamed.as_ref().err().is_some_and(|e| super::practice::is_busy(e)) && !activity::held(id) {
                busy += 1;
                if busy > super::practice::BUSY_RETRIES { break (streamed, content, calls); }
                activity::emit(id, "status", json!({"text":"Finishing the previous answer...","live":true}));
                tokio::time::sleep(Duration::from_millis(1200)).await;
                continue;
            }
            busy = 0;
            break (streamed, content, calls);
        };
        if streamed.as_ref().is_ok_and(|r| r["finishReason"] == "cancelled") {
            activity::emit(id, "status", json!({"text":"Stopped for your message."}));
            turn -= 1;
            continue;
        }
        if let Err(error) = streamed {
            failures += 1;
            activity::emit(id, "status", json!({"text":format!("This turn failed: {}", crate::lifecycle::safe_diagnostic(&error)),"tone":"warn"}));
            if failures >= 3 { return Err(format!("The model failed {failures} attacks in a row: {error}")); }
            tokio::time::sleep(Duration::from_secs(3)).await;
            turn -= 1;
            continue;
        }
        failures = 0;

        let calls = calls.finish();
        messages.push(super::practice::assistant_message(&super::practice::answer_text(&content), &calls));
        if calls.is_empty() {
            stalls += 1;
            if stalls >= 2 {
                messages.push(json!({"role":"user","content":"Use http_request to probe the target (start with GET /), or report_finding once you have read the flag."}));
            }
            continue;
        }
        stalls = 0;
        for call in &calls {
            let (name, arguments, call_id) = (call.name.as_str(), &call.arguments, call.id.as_str());
            match name {
                "http_request" => {
                    let result = service.request(arguments).await;
                    let method = arguments["method"].as_str().unwrap_or("GET").to_ascii_uppercase();
                    let path = arguments["path"].as_str().unwrap_or("/");
                    activity::emit(id, "request", json!({"method":method,"path":path,"body":arguments["body"].as_str().unwrap_or_default()}));
                    activity::emit(id, "response", json!({"status":result["status"],"body":result["body"].as_str().unwrap_or_default()}));
                    messages.push(super::practice::tool_result(call_id, name, &result));
                }
                "record_attempt" => {
                    let summary = arguments["summary"].as_str().unwrap_or("").trim().to_owned();
                    if !summary.is_empty() {
                        activity::emit(id, "tried", json!({"text":summary}));
                        let recorded = agent(app, worker, reqwest::Method::POST, "/api/swarm/agent/attempts",
                            Some(json!({"leaseId":lease["leaseId"],"generation":lease["generation"],"outcome":"inconclusive","observations":summary,"expected":"The target rejects the attack","limitations":"Probing the running service over the network","idempotencyKey":format!("live-attempt-{}-{}", worker.id, attempt_ids.len())}))).await;
                        if let Ok(value) = recorded {
                            if let Some(aid) = value["attempt"]["id"].as_str().or_else(|| value["id"].as_str()) {
                                attempt_ids.push(json!(aid));
                            }
                        }
                    }
                    messages.push(super::practice::tool_result(call_id, name, &json!("Recorded.")));
                }
                "report_finding" => {
                    match submit_report(app, worker, lease, arguments, &mut attempt_ids).await {
                        Ok(()) => {
                            activity::emit(id, "verdict", json!({"attempt":attempt_ids.len(),"qualifies":true,
                                "reason":"Captured the flag and filed a report for the publisher to review.","finding":arguments,"seconds":waited.elapsed().as_secs_f64()}));
                            return Ok(());
                        }
                        Err(error) => {
                            activity::emit(id, "status", json!({"text":format!("Could not file the report: {error}"),"tone":"warn"}));
                            messages.push(super::practice::tool_result(call_id, name, &json!(format!("The report was not accepted: {error}. Keep attacking and report again."))));
                        }
                    }
                }
                other => messages.push(super::practice::tool_result(call_id, name, &json!(format!("Unknown tool {other}.")))),
            }
        }
    }
}

/// Files the captured finding: records a candidate attempt, attaches the flag as evidence, and
/// submits the report for the publisher's review.
async fn submit_report(app: &AppHandle, worker: &Worker, lease: &Value, finding: &Value, attempt_ids: &mut Vec<Value>) -> Result<(), String> {
    let flag = finding["flag"].as_str().unwrap_or_default().trim();
    if flag.is_empty() {
        return Err("no flag was reported".into());
    }
    let technique = finding["technique"].as_str().unwrap_or("").trim();
    let candidate = agent(app, worker, reqwest::Method::POST, "/api/swarm/agent/attempts",
        Some(json!({"leaseId":lease["leaseId"],"generation":lease["generation"],"outcome":"candidate","observations":format!("Captured the flag: {flag}. {technique}"),"expected":"The flag must be unreachable without a successful attack","limitations":"Reported for publisher review","idempotencyKey":format!("live-candidate-{}", worker.id)}))).await?;
    if let Some(aid) = candidate["attempt"]["id"].as_str().or_else(|| candidate["id"].as_str()) {
        attempt_ids.push(json!(aid));
    }
    let evidence_text = format!("Captured flag:\n{flag}\n\nHow it was done:\n{technique}");
    let evidence = agent(app, worker, reqwest::Method::POST, "/api/swarm/agent/evidence",
        Some(json!({"name":"captured-flag.txt","contentBase64":base64::engine::general_purpose::STANDARD.encode(evidence_text.as_bytes()),"idempotencyKey":format!("live-evidence-{}", worker.id)}))).await?;
    let evidence_id = evidence["evidence"]["id"].clone();
    let title = finding["title"].as_str().filter(|t| !t.trim().is_empty()).unwrap_or("Live-target break-in").to_owned();
    let impact = finding["impact"].as_str().filter(|i| !i.trim().is_empty()).unwrap_or("An attacker reaches the protected flag by exploiting the service.").to_owned();
    let body = json!({
        "title": title,
        "sourceRevision": worker.policy["sourceRevision"],
        "component": "live target service",
        "reproduction": if technique.is_empty() { format!("Attack the running service to reach the flag: {flag}") } else { format!("{technique}\n\nCaptured flag: {flag}") },
        "observed": format!("The attack reached the publisher's planted flag: {flag}"),
        "expected": "The flag must be unreachable without the intended fix.",
        "impact": impact,
        "limitations": "Captured over the network against the running service; the publisher confirms the flag on review.",
        "evidenceIds": [evidence_id],
        "attemptIds": attempt_ids.clone(),
        "idempotencyKey": format!("live-report-{}", worker.id),
    });
    agent(app, worker, reqwest::Method::POST, "/api/swarm/agent/reports", Some(body)).await?;
    activity::emit(&worker.id, "report", json!({"text":"Report filed for the publisher to review"}));
    Ok(())
}
